package crypto

import (
	"crypto/x509"
	"strconv"

	merkletree "github.com/txaty/go-merkletree"
)

type Certblock struct {
	Content x509.Certificate
}

func (c *Certblock) Serialize() ([]byte, error) {
	//This is an oversimplification of the serialization process for just demonstration purposes
	// In reality, the serialization process is much more complicated
	// in CTng extension, we need to extract the TBS certificate and serialize it
	// However the CA will sign the whole certificate with the CTng extension, which means the TBS certificate field the CA signed is not the same as the TBS certificate field the logger logged
	return c.Content.RawSubject, nil
}

/*
func (c *Certblock) Serialize() ([]byte, error) {
	return c.Content.Raw, nil
}*/

type POI_for_transmission struct {
	Poi          *merkletree.Proof `json:"poi,omitempty"`
	SubjectKeyId []byte            `json:"subjectKeyId,omitempty"`
	Issuer       string            `json:"issuer,omitempty"`
	LoggerID     string            `json:"loggerID,omitempty"`
}

func Generatedummycertlist(size int) (certs []x509.Certificate) {
	certs = make([]x509.Certificate, 0)
	for i := 0; i < size; i++ {
		subjectKeyIdBytes := []byte(strconv.Itoa(i))
		certs = append(certs, x509.Certificate{
			Version:      i,
			SubjectKeyId: subjectKeyIdBytes,
		})
	}
	return
}

func GenerateDataBlocks(certs []x509.Certificate) (dataBlocks []merkletree.DataBlock) {
	dataBlocks = make([]merkletree.DataBlock, 0)
	for _, cert := range certs {
		dataBlock := &Certblock{Content: cert}
		dataBlocks = append(dataBlocks, dataBlock)
	}
	return
}

func GenerateMerkleTree(blocks []merkletree.DataBlock) (tree *merkletree.MerkleTree, error error) {
	tree, error = merkletree.New(nil, blocks)
	return
}

func GenerateRootHash(tree *merkletree.MerkleTree) (rootHash []byte) {
	rootHash = tree.Root
	return
}
func GeneratePOI(tree *merkletree.MerkleTree) (proofs []*merkletree.Proof) {
	proofs = tree.Proofs
	return
}

func VerifyPOI(rootHash []byte, poi *merkletree.Proof, cert x509.Certificate) (ok bool, err error) {
	ok, err = merkletree.Verify(&Certblock{Content: cert}, poi, rootHash, nil)
	return
}
