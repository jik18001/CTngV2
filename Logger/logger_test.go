package Logger

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"strconv"
	"testing"

	"github.com/jik18001/CTngV2/crypto"
	"github.com/jik18001/CTngV2/definition"
	"github.com/jik18001/CTngV2/util"
)

func TestMerkle(t *testing.T) {
	certs := make([]x509.Certificate, 0)
	for i := 0; i < 2; i++ {
		subjectKeyIdBytes := []byte(strconv.Itoa(i))
		certs = append(certs, x509.Certificate{
			SubjectKeyId: subjectKeyIdBytes,
		})
	}
	periodNum := 0
	ctx := InitializeLoggerContext("../tests/networktests/logger_testconfig/1/Logger_public_config.json",
		"../tests/networktests/logger_testconfig/1/Logger_private_config.json",
		"../tests/networktests/logger_testconfig/1/Logger_crypto_config.json",
	)
	// Verify the root hash
	STH_G, rootHash, leaves := BuildMerkleTreeFromCerts(certs, *ctx, periodNum)
	rootfromSTH, _ := definition.ExtractRootHash(STH_G)
	if string(rootHash) != string(rootfromSTH) {
		t.Errorf("Root hash is not correct")
	}
	testExistsSubjectKeyId := []byte("1")
	testExistsCert := x509.Certificate{
		SubjectKeyId: testExistsSubjectKeyId,
	}
	testNotExistsSubjectKeyId := []byte("4")
	testNotExistsCert := x509.Certificate{
		SubjectKeyId: testNotExistsSubjectKeyId,
	}
	counter := 0
	// Verify the POI
	// try encode and decode the leaves to see whether the POI is correct
	encodedleaves, _ := json.Marshal(leaves)
	var decodedleaves []crypto.POI_for_transmission
	json.Unmarshal(encodedleaves, &decodedleaves)
	for _, POI := range decodedleaves {
		if string(POI.SubjectKeyId) == string(testExistsSubjectKeyId) {
			pass, err := crypto.VerifyPOI(rootHash, POI.Poi, testExistsCert)
			if pass != true || err != nil {
				t.Errorf("POI is not correct")
			} else {
				counter++
			}
		}
		if string(POI.SubjectKeyId) == string(testNotExistsSubjectKeyId) {
			pass, err := crypto.VerifyPOI(rootHash, POI.Poi, testNotExistsCert)
			if pass != false || err == nil {
				t.Errorf("POI is correct but it should not be")
			}
		}
	}
	if counter != 1 {
		t.Errorf("Merkle tree is not working correctly")
	}
}

func TestCertPoolMerk(t *testing.T) {
	certs := make([]x509.Certificate, 0)
	for i := 0; i < 2; i++ {
		rawsubject := []byte(strconv.Itoa(i))
		subjectKeyIdBytes := []byte(strconv.Itoa(i))
		certs = append(certs, x509.Certificate{
			SubjectKeyId: subjectKeyIdBytes,
			RawSubject:   rawsubject,
			Issuer: pkix.Name{
				CommonName: "CA 1",
			},
		})
	}
	ctx := InitializeLoggerContext("../tests/networktests/logger_testconfig/1/Logger_public_config.json",
		"../tests/networktests/logger_testconfig/1/Logger_private_config.json",
		"../tests/networktests/logger_testconfig/1/Logger_crypto_config.json",
	)
	for _, cert := range certs {
		precert := util.ParseTBSCertificate(&cert)
		ctx.CurrentPrecertPool.AddCert(precert)
	}
	fmt.Println(len(ctx.CurrentPrecertPool.GetCerts()))
	certs_from_pool := ctx.CurrentPrecertPool.GetCerts()
	for _, cert := range certs_from_pool {
		fmt.Println(cert.Issuer)
	}
}
