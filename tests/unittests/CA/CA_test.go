package main

import (
	"CTngV2/crypto"
	"CTngV2/util"
	"crypto/x509"
	"testing"
)

func testCreatecerts(t *testing.T) {
	// get our ca and server certificate
	path_prefix := "../ca_testconfig/1"
	path := path_prefix + "/CA_crypto_config.json"
	cryptoconf, _ := crypto.ReadCryptoConfig(path)
	privK := cryptoconf.SignSecretKey
	root := GenerateRootCA("1", *cryptoconf)
	util.SaveCertificateToDisk(root.Raw, "ca_cert.crt")
	cert, key := GenerateDummyCert("1", root, privK)
	util.SaveCertificateToDisk(cert.Raw, "subject_cert.crt")
	util.SaveKeyToDisk(key, "subject_key.key")
}

func testCreateRoot(t *testing.T) {
	path_prefix := "../ca_testconfig/1"
	path := path_prefix + "/CA_crypto_config.json"
	cryptoconf, _ := crypto.ReadCryptoConfig(path)
	root := GenerateRootCA("1", *cryptoconf)
	util.SaveCertificateToDisk(root.Raw, "ca_cert.crt")
}

func TestCreateCert(t *testing.T) {
	rootbyte, err := util.ReadCertificateFromDisk("ca_cert.crt")
	if err != nil {
		t.Fail()
	}
	root, err := x509.ParseCertificate(rootbyte)
	if err != nil {
		t.Fail()
	}
	path_prefix := "../ca_testconfig/1"
	path := path_prefix + "/CA_crypto_config.json"
	cryptoconf, _ := crypto.ReadCryptoConfig(path)
	privK := cryptoconf.SignSecretKey
	cert, key := GenerateDummyCert("1", root, privK)
	util.SaveCertificateToDisk(cert.Raw, "subject_cert.crt")
	util.SaveKeyToDisk(key, "subject_key.key")
}
