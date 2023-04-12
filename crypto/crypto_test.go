package crypto

import (
	"encoding/hex"
	"fmt"
	"math/rand" // for list shuffling
	"sort"
	"testing"
)

// For randomized signature aggregation testing
func shuffleSigs(sigs *[]SigFragment) {
	rand.Shuffle(len(*sigs), func(i, j int) {
		(*sigs)[i], (*sigs)[j] = (*sigs)[j], (*sigs)[i]
	})
}

func confirmNil(t *testing.T, err error) {
	if err != nil {
		t.Errorf("%s", err.Error())
	}
}

/*
Referenced test certificate-transparency-go/tls/hash_test.go
*/
func TestMD5(t *testing.T) {
	// Our tests are a list of structs with the following properties:
	var tests = []struct {
		input    string
		expected string
	}{
		{"abcd", "e2fc714c4727ee9395f324cd2e7f331f"},
		{"ctng", "daea5db32af0be91417e4ad1a5ba54ef"},
		{"finn", "ee67bdedf89e0d0313d587bf40061242"},
		{"finn", "ee67bdedf89e0d0313d587bf40061242"},
	}

	for _, test := range tests {
		// When taking the hash, we cast the value to a byte array.
		got, err := GenerateMD5(([]byte)(test.input))
		if err != nil {
			t.Errorf("Error recieved: %s", err.Error())
		}
		//When printing/visually reading a hash, we encode it to a string with hex.EncodeToString
		if hex.EncodeToString(got) != (test.expected) {
			t.Errorf("Incorrect hash: %s gave %s but expected %s",
				test.input, hex.EncodeToString(got), test.expected)
		}
	}
}
func TestSHA256(t *testing.T) {
	// Our tests are a list of structs with the following properties:
	var tests = []struct {
		input    string
		expected string
	}{
		{"abcd", "88d4266fd4e6338d13b845fcf289579d209c897823b9217da3e161936f031589"},
		{"ctng", "1c51a831a9b145f1f8b94a3f52c93c00bb9b0b181253fd3d3e0a6afd239a293b"},
		{"finn", "e0e2087b3efad83c23c899efb0059a16d9ee9d4ef51349c6066548b8d01f1ab8"},
		{"finn", "e0e2087b3efad83c23c899efb0059a16d9ee9d4ef51349c6066548b8d01f1ab8"},
	}

	for _, test := range tests {
		// When taking the hash, we cast the value to a byte array.
		got, err := GenerateSHA256(([]byte)(test.input))
		confirmNil(t, err)
		//When printing/visually reading a hash, we encode it to a string with hex.EncodeToString
		if hex.EncodeToString(got) != (test.expected) {
			t.Errorf("Incorrect hash: %s gave %s but expected %s",
				test.input, hex.EncodeToString(got), test.expected)
		}
	}
}

// This function tests when there are exactlu enough signatures to aggregate.
func TestBLSFunctionality(T *testing.T) {
	entities := []CTngID{
		"a",
		"b",
		"c",
		"d",
		"e",
	}
	n := len(entities)
	threshold := 2

	// First term is list of BLS ids. We now derive the BLS ids from the CTngIDs, so it can be ignored.
	_, pubs, privs, err := GenerateThresholdKeypairs(entities, threshold)

	confirmNil(T, err)

	sigs := make([]SigFragment, n)

	data := "Test information for signing"
	wrongData := "Incorrect Information"

	// Have all entities sign the message
	for i := 0; i < n; i++ {
		priv := privs[entities[i]]
		sigs[i] = ThresholdSign(data, &priv, entities[i])
		//secret.Sign will panic() if it fails, not return an error.
	}

	// Verify individual signatures validate
	for i := 0; i < n; i++ {
		if sigs[i].Verify(data, &pubs) == false {
			T.Errorf("Signature %d failed to verify!", i)
		}
	}

	// Verifying a signature with an incorrect public key should fail
	// It does: The test takes work to structure with the current datatypes so I've removed it for now.

	// Verifying incorrect data should fail
	if sigs[0].Verify(wrongData, &pubs) != false {
		T.Errorf("Signature verified incorrect data!")
	}

	// any group of "config.Threshold" signatures can Aggregate the message
	// Shuffle the list, and run a 'sliding door' over it of size threshold.
	shuffleSigs(&sigs)
	for l := 0; l < (n - threshold); l++ {
		r := l + threshold
		//Aggregate first, then confirm the aggregates verify'
		agg, err := ThresholdAggregate(sigs[l:r], threshold)
		confirmNil(T, err)
		if agg.Verify(data, &pubs) == false {
			T.Errorf("Aggregate failed to verify!")
		}
		fmt.Println(agg)
		// Provide an incorrect signer and confirm that the aggregate fails to verify
		agg.IDs[0] = sigs[r%n].ID
		if agg.Verify(data, &pubs) != false {
			T.Errorf("Aggregate verified with incorrect signer!")
		}
		// Remove a signer and confirm that the aggregate fails to verify
		agg.IDs = agg.IDs[1:]
		if agg.Verify(data, &pubs) != false {
			T.Errorf("Aggregate verified with insufficient signers!")
		}
	}

}

func TestBLSFunctionality2(T *testing.T) {
	entities := []CTngID{
		"a",
		"b",
		"c",
		"d",
		"e",
	}
	n := len(entities)
	threshold := 2

	// First term is list of BLS ids. We now derive the BLS ids from the CTngIDs, so it can be ignored.
	_, pubs, privs, err := GenerateThresholdKeypairs(entities, threshold)

	confirmNil(T, err)

	sigs := make([]SigFragment, n)

	data := "Test information for signing"
	wrongData := "Incorrect Information"

	// Have all entities sign the message
	for i := 0; i < n; i++ {
		priv := privs[entities[i]]
		sigs[i] = ThresholdSign(data, &priv, entities[i])
		//secret.Sign will panic() if it fails, not return an error.
	}

	// Verify individual signatures validate
	for i := 0; i < n; i++ {
		if sigs[i].Verify(data, &pubs) == false {
			T.Errorf("Signature %d failed to verify!", i)
		}
	}

	// Verifying a signature with an incorrect public key should fail
	// It does: The test takes work to structure with the current datatypes so I've removed it for now.

	// Verifying incorrect data should fail
	if sigs[0].Verify(wrongData, &pubs) != false {
		T.Errorf("Signature verified incorrect data!")
	}

	// any group of "config.Threshold" signatures can Aggregate the message
	// Shuffle the list, and run a 'sliding door' over it of size threshold.
	shuffleSigs(&sigs)

	for l := threshold; l < n; l++ {
		agg, err := ThresholdAggregate(sigs[0:l], threshold)
		confirmNil(T, err)
		if agg.Verify(data, &pubs) == false {
			T.Errorf("Aggregate failed to verify!")
		}
		fmt.Println(agg)
	}
}

// USE RSA Sign for testing only
// For implementation, if we have the crypto config, we can just call sign directly
func TestRSAFunctionality(T *testing.T) {
	// Generate a keypair
	priv, err := NewRSAPrivateKey()
	confirmNil(T, err)
	pub := priv.PublicKey
	// Generate a signature
	msg := "Test message"
	sig, err := RSASign([]byte(msg), priv, "1.1.1.1")
	confirmNil(T, err)
	// Verify the signature
	err = RSAVerify([]byte(msg), sig, &pub)
	confirmNil(T, err)
	sigstr := sig.String()
	sig2, err := RSASigFromString(sigstr)
	confirmNil(T, err)
	err = RSAVerify([]byte(msg), sig2, &pub)
	confirmNil(T, err)
}

// This test verifies that CTng IDs can be sorted,
// This is important because it allows sent threshold signature payloads to be identical when signed.
func TestCTngIDs(T *testing.T) {
	entities := []CTngID{"e", "d", "c", "b", "a"}
	fmt.Println(entities)
	sort.Sort(CTngIDs(entities))
	fmt.Println(entities)
	if entities[0] != "a" {
		T.Errorf("CTngID Sorting error")
	}
}

func TestCryptoIO(T *testing.T) {
	// Declare test entities
	entities := []CTngID{"1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4", "5.5.5.5", "6.6.6.6", "7.7.7.7", "8.8.8.8", "9.9.9.9", "10.10.10.10"}
	threshold := 4
	// Generate the crypto files for each entity
	configs, err := GenerateEntityCryptoConfigs(entities, threshold)
	confirmNil(T, err)
	// Write the Configs to files
	SaveCryptoFiles("./testFiles/", configs)
	readConfigs := make([]*CryptoConfig, len(configs))
	// Load the crypto files for each entity, sign a message, and verify the joint signature is valid.
	for i := 0; i < len(entities); i++ {
		c, err := ReadCryptoConfig("./testFiles/" + (string)(entities[i]) + ".test.json")
		confirmNil(T, err)
		readConfigs[i] = c
	}
	// Confirm RSA Sign+Verify work using the loaded configs
	msg := "Test message"
	sig, err := readConfigs[0].Sign([]byte(msg))
	confirmNil(T, err)
	err = readConfigs[1].Verify([]byte(msg), sig)
	confirmNil(T, err)
	// Confirm Threshold Sign+Verify work using the loaded configs.
	frags := make([]SigFragment, threshold)
	for i := 0; i < threshold; i++ {
		frag, err := (readConfigs[i]).ThresholdSign(msg)
		confirmNil(T, err)

		// Have the next config verify the previous one
		err = (readConfigs[i+1]).FragmentVerify(msg, frag)
		if err != nil {
			T.Errorf("Fragment verification failed for %d", i)
		}
		frags[i] = frag
	}
	// Convert from and to a string first
	fragStr := frags[0].String()
	fmt.Println(fragStr)
	frag, err := SigFragmentFromString(fragStr)
	if err != nil {
		T.Errorf("Failed to convert SigFragment from string")
	}
	frags[0] = frag
	// Write + read the first signature
	agg, err := readConfigs[threshold].ThresholdAggregate(frags)
	confirmNil(T, err)
	// Convert the Aggregate to a string
	aggStr, err := agg.String()
	confirmNil(T, err)
	fmt.Println(aggStr)
	agg, err = ThresholdSigFromString(aggStr)
	// Verify the aggregate
	err = readConfigs[threshold+1].ThresholdVerify(msg, agg)
	confirmNil(T, err)
}
