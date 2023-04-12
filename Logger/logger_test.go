package Logger

import (

	//"CTng/crypto"
	//"CTng/util"
	//"bytes"

	"encoding/json"

	//"net/http"

	"log"
	"testing"
	"crypto/x509"

	//"strings"
	//"strconv"
	//"github.com/gorilla/mux"
)

func TestMerkleTree(t *testing.T) {
	certs := make([]x509.Certificate, 0)
	for i := 0; i < 9; i++ {
		subjectKeyIdBytes, _ := json.Marshal(i)
		certs = append(certs, x509.Certificate{
			Version: i, SubjectKeyId: subjectKeyIdBytes,
		})
	}
	periodNum := 0
	ctx := InitializeLoggerContext("../Gen/logger_testconfig/1/Logger_public_config.json", "../Gen/logger_testconfig/1/Logger_private_config.json", "../Gen/logger_testconfig/1/Logger_crypto_config.json")
	_, sth, nodes := BuildMerkleTreeFromCerts(certs, *ctx, periodNum)
	testExistsSubjectKeyId, _ := json.Marshal(2)
	testCertExists := x509.Certificate{Version: 2, SubjectKeyId: testExistsSubjectKeyId}
	for _, node := range nodes {
		if string(node.SubjectKeyId) == string(testExistsSubjectKeyId) {
			if !(VerifyPOI(sth, node.Poi, testCertExists)) {
				log.Fatal("Expected certificate does not exist")
			}
		}
	}
	testCertDoesNotExist := x509.Certificate{Version: 32, SubjectKeyId: testExistsSubjectKeyId}
	if VerifyPOI(sth, nodes[0].Poi, testCertDoesNotExist) {
		log.Fatal("Not existent certificate passed verification")
	}
}
