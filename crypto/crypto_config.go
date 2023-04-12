package crypto

import "errors"
//import "fmt"

// CryptoConfig Method Versions of all crypto functions.
// In each entity, these methods should be used when working with any crypto.
// Passing the pointer to a config/CryptoConfig struct
// will make it easy to globally use these values in each entity.

type CryptoConfigInterface interface {
	Hash([]byte) ([]byte, error)
	Sign([]byte) (RSASig, error)
	Verify([]byte, RSASig) error
	ThresholdSign(string) (SigFragment, error)
	ThresholdAggregate([]SigFragment) (ThresholdSig, error)
	ThresholdVerify(string, ThresholdSig) error
	FragmentVerify(string, SigFragment) error
}

// Hash a message using the configured hash scheme.
func (c *CryptoConfig) Hash(msg []byte) ([]byte, error) {
	if c.HashScheme == SHA256 {
		return GenerateSHA256(msg)
	} else if c.HashScheme == MD5 {
		return GenerateMD5(msg)
	}
	return nil, errors.New("Hash Scheme not supported")
}

// Sign a message using the configured "normal signature" scheme.
// Note: This is not a threshold signature/threshold signature fragment.
func (c *CryptoConfig) Sign(msg []byte) (RSASig, error) {
	if c.SignScheme == "rsa" {
		return RSASign(msg, &c.RSAPrivateKey, c.SelfID)
	}
	return RSASig{}, errors.New("Sign Scheme not supported")
}

// Verify a message using the configured "normal signature" scheme, and the stored public keys.
func (c *CryptoConfig) Verify(msg []byte, sig RSASig) error {
	if c.SignScheme == "rsa" {
		pub := c.SignaturePublicMap[sig.ID]
		//fmt.Println("PublicKey Found: ",pub)
		return RSAVerify(msg, sig, &pub)
	}
	return errors.New("Sign Scheme not supported")
}

// Sign a message to make a keyfragment using the configured "threshold signature" scheme.
func (c *CryptoConfig) ThresholdSign(msg string) (SigFragment, error) {
	if c.ThresholdScheme == "bls" {
		return ThresholdSign(msg, &c.ThresholdSecretKey, c.SelfID), nil
	}
	// Other threshold schemes could go Here
	return SigFragment{}, errors.New("Threshold Scheme not supported")
}

// Aggregate a list of threshold signature fragments to make a threshold signature.
func (c *CryptoConfig) ThresholdAggregate(sigs []SigFragment) (ThresholdSig, error) {
	if c.ThresholdScheme == "bls" {
		sig, err := ThresholdAggregate(sigs, c.Threshold)
		if err != nil {
			return ThresholdSig{}, err
		} else {
			return sig, nil
		}
	}
	return ThresholdSig{}, errors.New("Threshold Scheme not supported")
}

// Verify a threshold signature using the configured "threshold signature" scheme, and the stored public keys.
// Uses the keys stored in the CryptoConfig struct to verify the signature.
func (c *CryptoConfig) ThresholdVerify(msg string, sig ThresholdSig) error {
	if c.ThresholdScheme == "bls" {
		if sig.Verify(msg, &c.ThresholdPublicMap) {
			return nil
		} else {
			return errors.New("Threshold Signature Verification Failed")
		}
	}
	return errors.New("Threshold Scheme not supported")
}

// Verify the validity of a single signature fragment using the configured "threshold signature" scheme.
// Uses the keys stored in the CryptoConfig struct to verify the signature.
func (c *CryptoConfig) FragmentVerify(msg string, sig SigFragment) error {
	if c.ThresholdScheme == "bls" {
		if sig.Verify(msg, &c.ThresholdPublicMap) {
			return nil
		} else {
			return errors.New("Signature Fragment Verification Failed")
		}
	}
	return errors.New("Threshold Scheme not supported")
}
