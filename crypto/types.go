package crypto

//This file is for the various types we use in our cryptography.
// Some hashing portions have been pulled from certificate-transparency-go/tls/types.

import (
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/herumi/bls-go-binary/bls"
)

// Generic Ids are URLS.
type CTngID string

func (id CTngID) String() string {
	return string(id)
}

// BLS IDs should be derived directly from the CTngID.
// This essentially maps every CTngID to a unique BLS ID.
func (id CTngID) BlsID() *bls.ID {
	b := new(bls.ID)
	err := b.SetHexString(hex.EncodeToString([]byte(id)))
	// This shouldn't happen if IDs are being used appropriately, so I think a panic is warranted.
	if err != nil {
		panic(err)
	}
	return b
}

// The reverse of CTngID.BlsID().
func CTngIDfromBlsID(blsid *bls.ID) (CTngID, error) {
	id, err := hex.DecodeString(blsid.SerializeToHexStr())
	return CTngID(id), err
}

// Implemented functions for sorting
// The following types are neccessary for the sorting of CTng IDs.
// We sort CTngIds in aggregated signatures for consistency when transporting.
// Otherwise, payloads which contain the CTng IDs may not be consistent.
type CTngIDs []CTngID

func (ids CTngIDs) Less(i, j int) bool {
	return string(ids[i]) < string(ids[j])
}
func (ids CTngIDs) Len() int {
	return len(ids)
}
func (ids CTngIDs) Swap(i, j int) {
	ids[i], ids[j] = ids[j], ids[i]
}

// Enum is an unsigned integer.
type Enum uint64

// HashAlgorithm enum from RFC 5246 s7.4.1.4.1.
type HashAlgorithm Enum

// HashAlgorithm constants from RFC 5246 s7.4.1.4.1.
const (
	None   HashAlgorithm = 0
	MD5    HashAlgorithm = 1
	SHA1   HashAlgorithm = 2
	SHA224 HashAlgorithm = 3
	SHA256 HashAlgorithm = 4
	SHA384 HashAlgorithm = 5
	SHA512 HashAlgorithm = 6
)

func (h HashAlgorithm) String() string {
	switch h {
	case None:
		return "None"
	case MD5:
		return "MD5"
	case SHA1:
		return "SHA1"
	case SHA224:
		return "SHA224"
	case SHA256:
		return "SHA256"
	case SHA384:
		return "SHA384"
	case SHA512:
		return "SHA512"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", h)
	}
}

// RSASig contains the ID of the signer and the rsa signature.
type RSASig struct {
	Sig []byte
	ID  CTngID
}

//String -> RSASig conversion
func (s RSASig) String() string {
	return fmt.Sprintf(`{"sig":"%s","id":"%s"}`, hex.EncodeToString(s.Sig), s.ID.String())
}

//RSASig -> String conversion
func RSASigFromString(str string) (RSASig, error) {
	stringmap := make(map[string]string)
	sig := new(RSASig)
	err := json.Unmarshal([]byte(str), &stringmap)
	if err != nil {
		return *sig, err
	}
	sig.Sig = make([]byte, hex.DecodedLen(len(stringmap["sig"])))
	_, err = hex.Decode(sig.Sig, []byte(stringmap["sig"]))
	if err != nil {
		return *sig, err
	}
	sig.ID = CTngID(stringmap["id"])
	return *sig, err
}

// Public key maps for the configuration files.
// Follows the security assumption that "All public keys are known to all parties."
type RSAPublicMap map[CTngID]rsa.PublicKey

type BlsPublicMap map[CTngID]bls.PublicKey

// Serialization of these fields for transportation.
// Note that this is an inconvenience of this specific BLS library.
// Normally, we would be able to just Marshal/Unmarshal a mapping.
// This is likely an inconvenience of using the C implementation of BLS.
func (p *BlsPublicMap) Serialize() map[string][]byte {
	serialized := make(map[string][]byte)
	for id, key := range *p {
		serialized[id.String()] = (&key).Serialize()
	}
	return serialized
}

// Deserialize takes the serialized version of the public map, deserializes it, and puts it in p.
// p should be allocated space for the BLSPublicMap to be stored.
func (p *BlsPublicMap) Deserialize(serialized map[string][]byte) error {
	var err error
	blsPub := new(bls.PublicKey)
	for key, val := range serialized {
		err = blsPub.Deserialize(val)
		if err != nil {
			return err
		}
		(*p)[CTngID(key)] = *blsPub
	}
	return nil
}

// This privatekey map is returned by the key generator. Individual private keys should be
// stored in the crypto configuration file of each entity.
type BlsPrivateMap map[CTngID]bls.SecretKey

// As of April 2022, the code is refactored so that storing blsIDs is no longer necessary.
// BLS ids are required for signing and verifying functions
// Thus, we give each Entity a BLS ID.
// type BlsIDMap map[CTngID]bls.ID

// func (idMap *BlsIDMap) Serialize() map[CTngID]string {
// 	serIDMap := make(map[CTngID]string)
// 	for key, val := range *idMap {
// 		serIDMap[key] = (&val).SerializeToHexStr()
// 	}
// 	return serIDMap
// }
// func (idMap *BlsIDMap) Deserialize(serIDMap map[CTngID]string) error {
// 	b := bls.ID{}
// 	for key, val := range serIDMap {
// 		err := (&b).DeserializeHexStr(val)
// 		if err != nil {
// 			// return err
// 		}
// 		(*idMap)[key] = b
// 	}
// 	return nil
// }

// Signature Fragments store the signer and the signature.
// This information can safely be sent, as it does not contain the private key.
// This information may be too much here: the gossiper should be able to deduce the
// signer(s) from the gossip object, as opposed to having it stored in the signature.
// Two possible refactors: remove the ID field altogether, or change it to a CTngID.
type SigFragment struct {
	Sign *bls.Sign
	ID   CTngID
}

// Convert a SigFragment to a string.
// Signatures need to be turned into strings to be stored in Gossip Objects.
// To convert back, use SigFragmentFromString().
func (s SigFragment) String() string {
	return fmt.Sprintf(`{"sign":"%s","id":"%s"}`, s.Sign.SerializeToHexStr(), s.ID.String())
}

// Returns a signature fragment generated from a string.
func SigFragmentFromString(str string) (SigFragment, error) {
	s := new(SigFragment)
	s.Sign = new(bls.Sign)
	stringmap := make(map[string]string)
	err := json.Unmarshal([]byte(str), &stringmap)
	if err != nil {
		return *s, err
	}
	err = s.Sign.DeserializeHexStr(stringmap["sign"])
	if err != nil {
		return *s, err
	}
	s.ID = CTngID(stringmap["id"])
	return *s, err
}

type ThresholdSig struct {
	IDs  []CTngID // Users must know the list of IDs that created the theshold signature to verify.
	Sign *bls.Sign
}

func (t ThresholdSig) String() (string, error) {
	ids := make([]string, len(t.IDs))
	for i, id := range t.IDs {
		ids[i] = string(id)
	}
	idsStr, err := json.Marshal(ids)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf(`{"sign":"%s", "ids":%s}`, t.Sign.SerializeToHexStr(), idsStr), nil
}

func ThresholdSigFromString(str string) (ThresholdSig, error) {
	t := new(ThresholdSig)
	// Capture the fields in the struct generated below
	tstr := struct {
		Sign string
		IDs  []string
	}{}
	err := json.Unmarshal([]byte(str), &tstr)
	if err != nil {
		return *t, err
	}
	// Convert the IDS to CTngIDs
	t.IDs = make([]CTngID, len(tstr.IDs))
	for i, id := range tstr.IDs {
		t.IDs[i] = CTngID(id)
	}
	t.Sign = new(bls.Sign)
	err = t.Sign.DeserializeHexStr(tstr.Sign)
	return *t, err
}

//
type CryptoConfig struct {
	Threshold       int //f+1 is the threshold for signing
	N               int //n is the number of participants
	HashScheme      HashAlgorithm
	SignScheme      string // "rsa" is the only valid value currently.
	ThresholdScheme string // "bls" is the only valid value currently.
	//entityIDs          []CTngID      // id of each entity (DNS string), should really exist outside of this struct.
	SelfID             CTngID         // id of the current entity
	SignPublicMap      RSAPublicMap   // map of entityID to RSA public key
	SignSecretKey      rsa.PrivateKey // RSA private key
	ThresholdPublicMap BlsPublicMap   // mapping of BLS IDs to public keys
	ThresholdSecretKey bls.SecretKey  // secret key for the current entity
}

//without threshold scheme
type BasicCryptoConfig struct {
	HashScheme HashAlgorithm
	SignScheme string // "rsa" is the only valid value currently.
	//entityIDs          []CTngID      // id of each entity (DNS string), should really exist outside of this struct.
	SelfID             CTngID         // id of the current entity
	SignaturePublicMap RSAPublicMap   // map of entityID to RSA public key
	RSAPrivateKey      rsa.PrivateKey // RSA private key
}

// This  is the serialized version of CryptoConfig.
// Again, this is required because we're using the bls C implementation which can't be
// stored without serialization.
type StoredCryptoConfig struct {
	SelfID          CTngID // id of the current entity
	Threshold       int    //f+1 is the threshold for signing
	N               int    //n is the number of participants
	HashScheme      int
	SignScheme      string // "rsa" is the only valid value currently.
	ThresholdScheme string // "bls" is the only valid value currently.
	//entityIDs          []CTngID      // id of each entity (DNS string), should really exist outside of this struct.
	SignPublicMap      RSAPublicMap      // map of entityID to RSA public key
	SignSecretKey      rsa.PrivateKey    // RSA private key
	ThresholdPublicMap map[string][]byte // mapping of BLS IDs to public keys
	ThresholdSecretKey []byte
}
