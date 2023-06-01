package Logger

import (
	"CTngV2/crypto"
	"CTngV2/definition"
	"CTngV2/util"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"strconv"
)

func BuildMerkleTreeFromCerts(certs []x509.Certificate, ctx LoggerContext, periodNum int) (definition.Gossip_object, []byte, []crypto.POI_for_transmission) {
	leafs := make([]crypto.POI_for_transmission, 0)
	blocks := crypto.GenerateDataBlocks(certs)
	tree, _ := crypto.GenerateMerkleTree(blocks)
	POI := crypto.GeneratePOI(tree)
	roothash := crypto.GenerateRootHash(tree)
	for i, cert := range certs {
		leafs = append(leafs, crypto.POI_for_transmission{
			Poi:          POI[i],
			SubjectKeyId: cert.SubjectKeyId,
			Issuer:       cert.Issuer.CommonName,
			LoggerID:     ctx.Logger_private_config.Signer,
		})
	}
	STH1 := definition.STH{
		Signer:    string(ctx.Logger_private_config.Signer),
		Timestamp: util.GetCurrentTimestamp(),
		Period:    util.GetCurrentPeriod(),
		RootHash:  hex.EncodeToString(roothash),
		TreeSize:  len(blocks),
	}
	payload0 := string(ctx.Logger_private_config.Signer)
	sth_payload, _ := json.Marshal(STH1)
	payload1 := hex.EncodeToString(sth_payload)
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
	return gossipSTH, roothash, leafs
}
