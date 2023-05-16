package crypto

import (
	"errors"
	"sort"

	bls "github.com/herumi/bls-go-binary/bls"
)

// Train of thought: "github.com/prysmaticlabs/prysm/v2/crypto/bls", while natively in go, can't generate keys in Go.
// Therefore we will use a precomiled C library that

/*
	Threshold signatures will use the BLS12-381 signature scheme, which also happens to be used by Ethereum 2.0.

/* The "k of n" Threshold signature scheme which we rely on is described here:

	https://github.com/herumi/bls/blob/master/sample/minsample.c#L20
	View The Go function translations here:
	https://github.com/herumi/bls-go-binary/blob/master/bls/bls.go
*/
type BLSThresholdSignatures interface {
	GenerateThresholdKeypairs([]CTngID, int) ([]bls.ID, BlsPublicMap, BlsPrivateMap, error)
	ThresholdSign(msg string, secret bls.SecretKey) (SigFragment, error)
	ThresholdAggregate([]SigFragment, int) (ThresholdSig, error)
	VerifyAggregate(msg string, fragments []SigFragment, config *CryptoConfig) error
}

// Generate mappings of IDs to Private Keys and Public Keys Based on a config's parameters
func GenerateThresholdKeypairs(entities []CTngID, threshold int) ([]bls.ID, BlsPublicMap, BlsPrivateMap, error) {
	if threshold < 2 {
		return nil, nil, nil, errors.New("Threshold must be greater than 1")
	}
	//ids for n entities
	n := len(entities)
	ids := make([]bls.ID, n)
	mainSecrets := make([]bls.SecretKey, threshold)
	privs := make(BlsPrivateMap)
	pubs := make(BlsPublicMap)
	//Generate all IDs and Keypairs.
	for i := 0; i < n; i++ {
		// blsIDs should be derived from the CTngIDs. In this case, we use hex string conversion.
		// Note that blsIDs are only used when keys are generated, not sure when else.
		sec := new(bls.SecretKey)
		ids[i] = *entities[i].BlsID()
		// For the first "threshold" number of entities, we generate unique secrets.
		if i < threshold {
			sec.SetByCSPRNG()
			privs[entities[i]] = *sec
			mainSecrets[i] = *sec
		} else {
			// The remaining entities are constructed using this threshold amount.
			// (bls.SecretKey.Set) calls blsSecretKeyShare.
			sec.Set(mainSecrets, &ids[i])
			privs[entities[i]] = *sec
		}
		pubs[entities[i]] = *sec.GetPublicKey()
		//Generate all the PublicKeys (for distribution to individual entities later)
	}
	// None of the above functions return errors. Instead they panic.
	// If cryptography information fails to generate then we cannot proceed.
	return ids, pubs, privs, nil
}

// ThresholdSign will generate a signature fragment for the given message.
func ThresholdSign(msg string, sec *bls.SecretKey, SelfID CTngID) SigFragment {
	// Simple: sign the message using the secret key and package with the ID.
	sig := sec.Sign(msg)
	return SigFragment{
		Sign: sig,
		ID:   SelfID,
	}
}

// Aggregate signature Fragments into a ThresholdSig.
func ThresholdAggregate(sigs []SigFragment, threshold int) (ThresholdSig, error) {
	var aggregate = ThresholdSig{
		IDs:  make([]CTngID, len(sigs)),
		Sign: new(bls.Sign),
	}
	if len(sigs) < threshold {
		return aggregate, errors.New("Not enough signatures to aggregate")
	}
	// create list of []bls.Sign for aggregate.
	realSigs := make([]bls.Sign, len(sigs))
	for i := range sigs {
		aggregate.IDs[i] = sigs[i].ID
		realSigs[i] = *sigs[i].Sign
	}
	// Sort the ordering of IDs for consistency.
	sort.Sort(CTngIDs(aggregate.IDs))
	aggregate.Sign.Aggregate(realSigs)
	return aggregate, nil
}

// Verify an aggregated threshold signature against the message and the public keys
func (sig ThresholdSig) Verify(msg string, pubs *BlsPublicMap) bool {
	// Construct the list of public keys
	pubList := make([]bls.PublicKey, len(sig.IDs))
	for i := range sig.IDs {
		pubList[i] = (*pubs)[sig.IDs[i]]
	}
	// FastAggregateVerify agregates the public signatures of the signers of the message and then verifies the message against that aggregated signature.
	return sig.Sign.FastAggregateVerify(pubList, []byte(msg))
}

// Given a message and a public key mapping, verify the signature runs.
func (f SigFragment) Verify(msg string, pubs *BlsPublicMap) bool {
	pub := (*pubs)[f.ID]
	return (f.Sign).Verify(&pub, msg)
}

func init() {
	// The init function needs to be immediately called upon import.
	x := bls.BLS12_381
	bls.Init(x)
}
