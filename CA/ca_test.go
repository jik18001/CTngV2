package CA

import (
	"CTngV2/crypto"
	"CTngV2/definition"
	"CTngV2/util"
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
	ctx := InitializeCAContext("testFiles/ca_testconfig/1/CA_public_config.json", "testFiles/ca_testconfig/1/CA_private_config.json", "testFiles/ca_testconfig/1/CA_crypto_config.json")
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

func TestCtngExtension(t *testing.T) {
	ctx := InitializeCAContext("testFiles/ca_testconfig/1/CA_public_config.json", "testFiles/ca_testconfig/1/CA_private_config.json", "testFiles/ca_testconfig/1/CA_crypto_config.json")
	issuer := Generate_Issuer(ctx.CA_private_config.Signer)
	// generate host
	host := "www.example.com"
	// generate valid duration
	validFor := 365 * 24 * time.Hour
	isCA := false
	// generate pre-certificates
	certs := Generate_N_Signed_PreCert(ctx, 2, host, validFor, isCA, issuer, ctx.Rootcert, false, &ctx.PrivateKey, 0)
	cert_to_sign := GetPrecertfromCert(certs[0])
	ctx.CurrentCertificatePool.AddCert(cert_to_sign)
	fmt.Println(ParseCTngextension(cert_to_sign))
	// now add STH and POI to it
	// first generate STH
	STH := definition.Gossip_object{
		Type:   definition.STH_INIT,
		Signer: "localhost:3333",
	}
	poi := crypto.POI_for_transmission{
		SubjectKeyId: cert_to_sign.SubjectKeyId,
	}
	newloggerinfo := LoggerInfo{
		STH: STH,
		POI: poi,
	}
	target_cert := ctx.CurrentCertificatePool.GetCertBySubjectKeyID(string(cert_to_sign.SubjectKeyId))
	target_cert = UpdateCTngExtension(target_cert, newloggerinfo)
	fmt.Println(ParseCTngextension(target_cert))
	ctx.CurrentCertificatePool.UpdateCertBySubjectKeyID(string(cert_to_sign.SubjectKeyId), target_cert)
	fmt.Println(ParseCTngextension(ctx.CurrentCertificatePool.GetCertBySubjectKeyID(string(cert_to_sign.SubjectKeyId))))
	signed_certs := SignAllCerts(ctx)
	fmt.Println(len(signed_certs))
	fmt.Println(ParseCTngextension(signed_certs[0]))
	util.SaveCertificateToDisk(signed_certs[0].Raw, "testFiles/1.crt")
	certbyte_from_disk, _ := util.ReadCertificateFromDisk("testFiles/1.crt")
	cert_from_disk, _ := x509.ParseCertificate(certbyte_from_disk)
	fmt.Println(ParseCTngextension(cert_from_disk))
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
	fmt.Println(rev.Type, fake_rev.Type)
	fmt.Println(bool1)
	fmt.Println(bool2)

}

func testTask(t *testing.T) {
	ctx := InitializeCAContext("testFiles/ca_testconfig/1/CA_public_config.json", "testFiles/ca_testconfig/1/CA_private_config.json", "testFiles/ca_testconfig/1/CA_crypto_config.json")
	StartCA(ctx)
}
