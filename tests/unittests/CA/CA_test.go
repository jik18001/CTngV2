package main

import (
	"CTngV2/crypto"
	"CTngV2/util"
	"testing"
)

func TestCreatecerts(t *testing.T) {
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
