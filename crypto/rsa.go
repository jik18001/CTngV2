package crypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
)

type RsaSignatures interface {
	NewRSAPrivateKey() (*rsa.PrivateKey, error)
	GetPublicKey(privateKey *rsa.PrivateKey) (*rsa.PublicKey, error)
	Sign(msg []byte, privateKey *rsa.PrivateKey) ([]byte, error)
	//Verify returns an error if the signature couldnt be verified.
	Verify(msg []byte, signature []byte, publicKey []byte, config *CryptoConfig) error
}

func NewRSAPrivateKey() (*rsa.PrivateKey, error) {
	// 2048 = Specification requirement for RSA keys
	return rsa.GenerateKey(rand.Reader, 2048)
}

func GetPublicKey(privateKey *rsa.PrivateKey) (*rsa.PublicKey, error) {
	return &privateKey.PublicKey, nil
}

func RSASign(msg []byte, privateKey *rsa.PrivateKey, id CTngID) (RSASig, error) {
	// SHA256 = Specification Requirement for RSA signatures
	hash, err := GenerateSHA256(msg)
	if err != nil {
		return RSASig{}, err
	}
	sig, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash)
	return RSASig{
		Sig: sig,
		ID:  id}, err
}

func RSAVerify(msg []byte, signature RSASig, pub *rsa.PublicKey) error {
	hash, err := GenerateSHA256(msg)
	if err != nil {
		return err
	}
	return rsa.VerifyPKCS1v15(pub, crypto.SHA256, hash, signature.Sig)
}
