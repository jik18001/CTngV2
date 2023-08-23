package definition

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jik18001/CTngV2/crypto"
	"github.com/jik18001/CTngV2/util"
	//"strings"
	//"time"
)

// Types of errors that can occur when parsing a Gossip_object
const (
	No_Sig_Match = "Signatures don't match"
	Mislabel     = "Fields mislabeled"
	Invalid_Type = "Invalid Type"
)

func Verify_CON(g Gossip_object, c *crypto.CryptoConfig) error {
	rsaSig1, sigerr1 := crypto.RSASigFromString(g.Signature[0])
	rsaSig2, sigerr2 := crypto.RSASigFromString(g.Signature[1])
	// Verify the signatures were made successfully
	if sigerr1 == nil && sigerr2 == nil {
		err1 := c.Verify([]byte(g.Payload[1]), rsaSig1)
		err2 := c.Verify([]byte(g.Payload[2]), rsaSig2)
		//fmt.Print(util.YELLOW, err1, err2, util.RESET)
		if err1 == nil && err2 == nil {
			return nil
		} else {
			return errors.New("Message Signature Mismatch" + fmt.Sprint(err1) + fmt.Sprint(err2))
		}
	} else {
		fmt.Println(util.RED, "RSAsigConversionerror", util.RESET)
	}
	return errors.New("Message Signature Mismatch" + fmt.Sprint(sigerr1) + fmt.Sprint(sigerr2))
}

// verifies signature fragments match with payload
func Verify_PayloadFrag(g Gossip_object, c *crypto.CryptoConfig) error {
	if g.Signature[0] != "" && g.Payload[0] != "" {
		sig, _ := crypto.SigFragmentFromString(g.Signature[0])
		err := c.FragmentVerify(g.Payload[0]+g.Payload[1]+g.Payload[2], sig)
		if err != nil {
			return errors.New(No_Sig_Match)
		}
		return nil
	} else {
		return errors.New(Mislabel)
	}
}

// verifies threshold signatures match payload
func Verify_PayloadThreshold(g Gossip_object, c *crypto.CryptoConfig) error {
	if g.Signature[0] != "" && g.Payload[0] != "" {
		sig, _ := crypto.ThresholdSigFromString(g.Signature[0])
		err := c.ThresholdVerify(g.Payload[0]+g.Payload[1]+g.Payload[2], sig)
		if err != nil {
			return errors.New(No_Sig_Match)
		}
		return nil
	} else {
		return errors.New(Mislabel)
	}
}

// Verifies RSAsig matches payload, wait.... i think this just works out of the box with what we have
func Verify_RSAPayload(g Gossip_object, c *crypto.CryptoConfig) error {
	if g.Signature[0] != "" && g.Payload[0] != "" {
		sig, err := crypto.RSASigFromString(g.Signature[0])
		if err != nil {
			return errors.New(No_Sig_Match)
		}
		return c.Verify([]byte(g.Payload[0]+g.Payload[1]+g.Payload[2]), sig)

	} else {
		return errors.New(Mislabel)
	}
}

// Verifies Gossip object based on the type:
// STH and Revocations use RSA
// Trusted information Fragments use BLS SigFragments
// PoMs use Threshold signatures
func (g Gossip_object) Verify(c *crypto.CryptoConfig) error {
	// If everything Verified correctly, we return nil
	switch g.Type {
	case STH_INIT:
		return Verify_RSAPayload(g, c)
	case REV_INIT:
		return Verify_RSAPayload(g, c)
	case ACC_INIT:
		return Verify_RSAPayload(g, c)
	case CON_INIT:
		return Verify_CON(g, c)
	case STH_FRAG:
		return Verify_PayloadFrag(g, c)
	case REV_FRAG:
		return Verify_PayloadFrag(g, c)
	case ACC_FRAG:
		return Verify_PayloadFrag(g, c)
	case STH_FULL:
		return Verify_PayloadThreshold(g, c)
	case REV_FULL:
		return Verify_PayloadThreshold(g, c)
	case ACC_FULL:
		return Verify_PayloadThreshold(g, c)
	default:
		fmt.Println(util.RED, "the type is: ", g.Type, util.RESET)
		return errors.New(Invalid_Type)
	}
}

func ExtractRootHash(gossipSTH Gossip_object) ([]byte, error) {
	payload1 := gossipSTH.Payload[1]

	sthBytes, err := hex.DecodeString(payload1)
	if err != nil {
		return nil, fmt.Errorf("failed to decode STH payload: %v", err)
	}

	var STH1 STH
	err = json.Unmarshal(sthBytes, &STH1)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal STH: %v", err)
	}

	roothash, err := hex.DecodeString(STH1.RootHash)
	if err != nil {
		return nil, fmt.Errorf("failed to decode root hash: %v", err)
	}

	return roothash, nil
}
