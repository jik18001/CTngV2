package CA

import (
	"CTngV2/definition"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/bits-and-blooms/bitset"
)

func testCRV(t *testing.T) {
	newCRV := CRV_init()
	newCRV.Revoke(1)
	newCRV.Revoke(4)
	fmt.Println(newCRV.CRV_current)
	fmt.Println(newCRV.CRV_pre_update)
	var newbitset = new(bitset.BitSet)
	newbitset.UnmarshalBinary(newCRV.GetDeltaCRV())
	fmt.Println(newbitset)
}

func testCAContext(t *testing.T) {
	ctx := InitializeCAContext("../Gen/ca_testconfig/1/CA_public_config.json", "../Gen/ca_testconfig/1/CA_private_config.json", "../Gen/ca_testconfig/1/CA_crypto_config.json")
	ctx.CRV.Revoke(1)
	ctx.CRV.Revoke(4)
	//fmt.Println(ctx.CRV.CRV_current)
	REV := Generate_Revocation(ctx, "0", 0)
	//REV_fake := Generate_Revocation(ctx, "0", 1)
	rev_json, _ := json.Marshal(REV)
	var rev2 definition.Gossip_object
	json.Unmarshal(rev_json, &rev2)
	var revca Revocation
	json.Unmarshal([]byte(rev2.Payload[2]), &revca)
	var newbitset = new(bitset.BitSet)
	newbitset.UnmarshalBinary(revca.Delta_CRV)
	fmt.Println(newbitset)

	//fmt.Println(REV.Payload[2])
	//fmt.Println(REV_fake.Payload[2])
	//ctx.REV_storage["0"] = REV
	//ctx.REV_storage_fake["0"] = REV_fake
	//fmt.Println(ctx.REV_storage["0"].Payload[2])
	//fmt.Println(ctx.REV_storage_fake["0"].Payload[2])
}

func testCertMarshal(t *testing.T) {
	ctx := InitializeCAContext("testFiles/ca_testconfig/1/CA_public_config.json", "testFiles/ca_testconfig/1/CA_private_config.json", "testFiles/ca_testconfig/1/CA_crypto_config.json")
	//Generate N signed pre-certificates
	issuer := Generate_Issuer(ctx.CA_private_config.Signer)
	// generate host
	host := "www.example.com"
	// generate valid duration
	validFor := 365 * 24 * time.Hour
	isCA := false
	// generate pre-certificates
	certs := Generate_N_Signed_PreCert(ctx, 64, host, validFor, isCA, issuer, ctx.Rootcert, false, &ctx.PrivateKey, 0)
	bytearr := certs[0].Raw
	var cert *x509.Certificate
	cert = Unmarshall_Signed_PreCert(bytearr)
	fmt.Println(cert)
}

func testPOIjson(t *testing.T) {
	SiblingHashes := make([][]byte, 0)
	SiblingHashes = append(SiblingHashes, []byte("1"))
	NeighborHash := []byte("2")
	newpoi := ProofOfInclusion{SiblingHashes, NeighborHash}
	newPOI := POI{newpoi, []byte{1}, "localhost:9000"}
	fmt.Println(newPOI)
	poi_json, _ := json.Marshal(newPOI)
	var newpoi2 POI
	json.Unmarshal(poi_json, &newpoi2)
	fmt.Println(newpoi2)
}

func testCtngExtension(t *testing.T) {
	ctx := InitializeCAContext("../Gen/ca_testconfig/1/CA_public_config.json", "../Gen/ca_testconfig/1/CA_private_config.json", "../Gen/ca_testconfig/1/CA_crypto_config.json")
	//Generate N signed pre-certificates
	issuer := Generate_Issuer(ctx.CA_private_config.Signer)
	// generate host
	host := "www.example.com"
	// generate valid duration
	validFor := 365 * 24 * time.Hour
	isCA := false
	// generate pre-certificates
	certs := Generate_N_Signed_PreCert(ctx, 1, host, validFor, isCA, issuer, ctx.Rootcert, false, &ctx.PrivateKey, 0)
	ctx.CurrentCertificatePool.AddCert(certs[0])
	fmt.Println(GetCTngExtensions(certs[0]))
	// now add STH and POI to it
	// first generate STH
	STH := definition.Gossip_object{
		Type: definition.STH_INIT,
	}
	poi := ProofOfInclusion{make([][]byte, 0), []byte("1")}
	newctngext := CTngExtension{
		STH: STH,
		POI: poi,
	}
	target_cert := ctx.CurrentCertificatePool.GetCertBySubjectKeyID(string(certs[0].SubjectKeyId))
	target_cert = AddCTngExtension(target_cert, newctngext)
	ctx.CurrentCertificatePool.UpdateCertBySubjectKeyID(string(certs[0].SubjectKeyId), target_cert)
	fmt.Println(GetCTngExtensions(ctx.CurrentCertificatePool.GetCertBySubjectKeyID(string(certs[0].SubjectKeyId))))
	signed_certs := SignAllCerts(ctx)
	fmt.Println(GetCTngExtensions(&signed_certs[0]))
}

func testGenerateKeypairs(t *testing.T) {
	subjectlist := Generate_N_Subjects(1, 0)
	publ, privl := Generate_and_return_N_KeyPairs(subjectlist)
	pub1 := *publ["Testing Dummy 0"]
	pub2 := privl["Testing Dummy 0"].PublicKey
	fmt.Println(pub1)
	fmt.Println(pub1 == pub2)

}

func TestREV(t *testing.T) {
	ctx := InitializeCAContext("testFiles/ca_testconfig/1/CA_public_config.json", "testFiles/ca_testconfig/1/CA_private_config.json", "testFiles/ca_testconfig/1/CA_crypto_config.json")
	// get current period
	period := GetCurrentPeriod()
	// convert string to int
	periodnum, err := strconv.Atoi(period)
	if err != nil {
	}
	// add 1 to current period
	periodnum = periodnum + 1
	// convert int to string
	period = strconv.Itoa(periodnum)
	rev := Generate_Revocation(ctx, period, 0)
	fake_rev := Generate_Revocation(ctx, period, 1)
	ctx.REV_storage[period] = rev
	ctx.REV_storage[period] = fake_rev
	bool1 := rev.Verify(ctx.CA_crypto_config)
	bool2 := fake_rev.Verify(ctx.CA_crypto_config)
	fmt.Println(rev.Type == fake_rev.Type)
	fmt.Println(bool1)
	fmt.Println(bool2)

}

func TestTask(t *testing.T) {
	ctx := InitializeCAContext("testFiles/ca_testconfig/1/CA_public_config.json", "testFiles/ca_testconfig/1/CA_private_config.json", "testFiles/ca_testconfig/1/CA_crypto_config.json")
	StartCA(ctx)
}
