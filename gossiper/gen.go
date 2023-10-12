package gossiper

import (
	"fmt"

	"github.com/jik18001/CTngV2/crypto"
	"github.com/jik18001/CTngV2/definition"
	"github.com/jik18001/CTngV2/util"
)

func (ctx *GossiperContext) Generate_Gossip_Object_FRAG(g definition.Gossip_object) definition.Gossip_object {
	sig_frag, err := ctx.Gossiper_crypto_config.ThresholdSign(g.Payload[0] + g.Payload[1] + g.Payload[2])
	if err != nil {
		fmt.Println("Error in threshold signing: " + err.Error())
	}
	g.Signature[0] = sig_frag.String()
	g.Signer = ctx.Gossiper_crypto_config.SelfID.String()
	g.Crypto_Scheme = "bls"
	switch g.Type {
	case definition.STH_INIT:
		g.Type = definition.STH_FRAG
	case definition.REV_INIT:
		g.Type = definition.REV_FRAG
	case definition.ACC_INIT:
		g.Type = definition.ACC_FRAG
	}
	return g
}

func (ctx *GossiperContext) Generate_Gossip_Object_FULL(g_list []definition.Gossip_object, TargetType string) definition.Gossip_object {
	// Extract all the signatures from the gossip objects
	sig_frag_list := []crypto.SigFragment{}
	signer_list := []string{}
	for _, g := range g_list {
		sig_frag, err := crypto.SigFragmentFromString(g.Signature[0])
		if err != nil {
			fmt.Println("Error in converting signature fragment: " + err.Error())
		}
		sig_frag_list = append(sig_frag_list, sig_frag)
		signer_list = append(signer_list, g.Signer)
	}
	// Aggregate the signatures
	sig_full, err := ctx.Gossiper_crypto_config.ThresholdAggregate(sig_frag_list)
	if err != nil {
		fmt.Println("Error in threshold aggregating: " + err.Error())
	}
	sig_full_string, err := sig_full.String()
	if err != nil {
		fmt.Println("Error in converting signature to string: " + err.Error())
	}
	// Generate the full gossip object
	return definition.Gossip_object{
		Application:   definition.CTNG_APPLICATION,
		Type:          TargetType,
		Period:        util.GetCurrentPeriod(),
		Signer:        "",
		Signers:       signer_list,
		Signature:     [2]string{sig_full_string, ""},
		Timestamp:     util.GetCurrentTimestamp(),
		Crypto_Scheme: "bls",
		Payload:       g_list[0].Payload,
	}
}

func (ctx *GossiperContext) Generate_CON_INIT(obj1 definition.Gossip_object, obj2 definition.Gossip_object) definition.Gossip_object {
	D2_POM := definition.Gossip_object{
		Application: definition.CTNG_APPLICATION,
		Type:        definition.CON_INIT,
		Period:      util.GetCurrentPeriod(),
		Signer:      "",
		Timestamp:   util.GetCurrentTimestamp(),
		Signature:   [2]string{obj1.Signature[0], obj2.Signature[0]},
		Payload:     [3]string{obj1.Payload[0], obj1.Payload[0] + obj1.Payload[1] + obj1.Payload[2], obj2.Payload[0] + obj2.Payload[1] + obj2.Payload[2]},
	}
	return D2_POM
}
