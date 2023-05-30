package Logger

import (
	"CTngV2/CA"
	"CTngV2/crypto"
	"CTngV2/definition"
	"CTngV2/util"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"strconv"
)

type Direction uint
type MerkleNode struct {
	hash         []byte
	neighbor     *MerkleNode
	left         *MerkleNode
	right        *MerkleNode
	Poi          CA.ProofOfInclusion
	Sth          definition.Gossip_object
	SubjectKeyId []byte
	Issuer       string
}

func doubleHash(data1 []byte, data2 []byte) []byte {
	if data1[0] < data2[0] {
		return hash(append(data1, data2...))
	} else {
		return hash(append(data2, data1...))
	}
}
func VerifyPOI(sth definition.STH, poi CA.ProofOfInclusion, cert x509.Certificate) bool {
	certBytes, _ := json.Marshal(cert)
	testHash := hash(certBytes)
	n := len(poi.SiblingHashes)
	poi.SiblingHashes[n-1] = poi.NeighborHash
	for i := n - 1; i >= 0; i-- {
		testHash = doubleHash(poi.SiblingHashes[i], testHash)
	}
	return string(testHash) == string(sth.RootHash)
}

func ComputeRoot(sth definition.STH, POI CA.ProofOfInclusion, cert x509.Certificate) string {
	certBytes, _ := json.Marshal(cert)
	testHash := hash(certBytes)
	n := len(POI.SiblingHashes)
	POI.SiblingHashes[n-1] = POI.NeighborHash
	for i := n - 1; i >= 0; i-- {
		testHash = doubleHash(POI.SiblingHashes[i], testHash)
	}
	return string(testHash)
}

func BuildMerkleTreeFromCerts(certs []x509.Certificate, ctx LoggerContext, periodNum int) (definition.Gossip_object, definition.STH, []MerkleNode) {
	n := len(certs)
	nodes := make([]MerkleNode, n)
	for i := 0; i < n; i++ {
		certBytes, _ := json.Marshal(certs[i])
		nodes[i] = MerkleNode{hash: hash(certBytes), SubjectKeyId: certs[i].SubjectKeyId, Issuer: string(certs[i].Issuer.CommonName)}
	}
	if len(nodes)%2 == 1 {
		certBytes, _ := json.Marshal(certs[n-1])
		nodes = append(nodes, MerkleNode{hash: hash(certBytes)})
	}
	root, leafs := generateMerkleTree(nodes)
	STH1 := definition.STH{
		Signer:    string(ctx.Logger_private_config.Signer),
		Timestamp: util.GetCurrentTimestamp(),
		Period:    util.GetCurrentPeriod(),
		RootHash:  string(root.hash),
		TreeSize:  n,
	}
	payload0 := string(ctx.Logger_private_config.Signer)
	sth_payload, _ := json.Marshal(STH1)
	payload1 := string(sth_payload)
	payload2 := ""
	signature, _ := crypto.RSASign([]byte(payload0+payload1+payload2), &ctx.PrivateKey, crypto.CTngID(ctx.Logger_private_config.Signer))
	gossipSTH := definition.Gossip_object{
		Application:   "CTng",
		Type:          definition.STH_INIT,
		Period:        strconv.Itoa(periodNum),
		Signer:        string(ctx.Logger_private_config.Signer),
		Timestamp:     STH1.Timestamp,
		Signature:     [2]string{signature.String(), ""},
		Crypto_Scheme: "RSA",
		Payload:       [3]string{payload0, payload1, payload2},
	}
	addPOI(&root, nil, make([][]byte, 0))
	for i := 0; i < len(leafs); i++ {
		leafs[i].Poi.NeighborHash = leafs[i].neighbor.hash
	}
	return gossipSTH, STH1, leafs
}

func addPOI(root *MerkleNode, neighbor *MerkleNode, previousSiblingHashes [][]byte) {
	if neighbor != nil {
		previousSiblingHashes = append(previousSiblingHashes, neighbor.hash)
		root.Poi = CA.ProofOfInclusion{SiblingHashes: previousSiblingHashes}
	}

	if root.left != nil {
		addPOI(root.left, root.right, previousSiblingHashes)
	}
	if root.right != nil {
		addPOI(root.right, root.left, previousSiblingHashes)
	}
}

func hash(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

func addPOIAndSTH(node *MerkleNode, SiblingHashes [][]byte, sth definition.Gossip_object) {
	if node.left == nil && node.right == nil {
		if node.neighbor != nil {
			SiblingHashes = append(SiblingHashes, node.neighbor.hash)
		}
		node.Poi = CA.ProofOfInclusion{SiblingHashes: SiblingHashes}
		node.Sth = sth
		return
	}
	if node.neighbor != nil {
		SiblingHashes = append(SiblingHashes, node.neighbor.hash)
	}
	addPOIAndSTH(node.left, SiblingHashes, sth)
	addPOIAndSTH(node.right, SiblingHashes, sth)
}

func generateMerkleTree(leafs []MerkleNode) (MerkleNode, []MerkleNode) {
	currentLevel := leafs
	for i := 0; i < len(currentLevel); i += 2 {
		currentLevel[i].neighbor = &currentLevel[i+1]
		currentLevel[i+1].neighbor = &currentLevel[i]
	}
	for len(currentLevel) > 1 {
		nextLevel := make([]MerkleNode, 0)
		for i := 0; i < len(currentLevel); i += 2 {
			if i+1 >= len(currentLevel) {
				nextLevel = append(nextLevel, MerkleNode{
					left:  &currentLevel[i-1],
					right: &currentLevel[i],
					hash:  doubleHash(currentLevel[i-1].hash, currentLevel[i].hash),
				})
				break
			}
			newNode := MerkleNode{
				left:  &currentLevel[i],
				right: &currentLevel[i+1],
				hash:  doubleHash(currentLevel[i].hash, currentLevel[i+1].hash),
			}
			nextLevel = append(nextLevel, newNode)
		}
		currentLevel = nextLevel
		if len(currentLevel) == 1 {
			continue
		}
		for i := 0; i < len(currentLevel)-1; i += 2 {
			currentLevel[i].neighbor = &currentLevel[i+1]
			currentLevel[i+1].neighbor = &currentLevel[i]
		}
		if len(currentLevel)%2 == 0 {
			currentLevel[len(currentLevel)-1].neighbor = &currentLevel[len(currentLevel)-2]
			currentLevel[len(currentLevel)-2].neighbor = &currentLevel[len(currentLevel)-1]
		} else {
			currentLevel[len(currentLevel)-1].neighbor = &currentLevel[len(currentLevel)-2]
		}
	}
	return currentLevel[0], leafs
}
