package gossiper

import (
	"CTngV2/crypto"
	"CTngV2/definition"
	"CTngV2/util"
	"fmt"
)

func (ctx GossiperContext) Generate_Gossip_Object_FRAG(g definition.Gossip_object) definition.Gossip_object {
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
	case definition.CON_INIT:
		g.Type = definition.CON_FRAG
	}
	return g
}

func (ctx GossiperContext) Generate_Gossip_Object_FULL(g_list []definition.Gossip_object, TargetType string) definition.Gossip_object {
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

func (ctx GossiperContext) Generate_NUM_FRAG(n definition.PoM_Counter) definition.PoM_Counter {
	// Generate a signature fragment
	sig, _ := ctx.Gossiper_crypto_config.ThresholdSign(n.ACC_FULL_Counter + n.CON_FULL_Counter + n.Period)
	return definition.PoM_Counter{
		ACC_FULL_Counter: n.ACC_FULL_Counter,
		CON_FULL_Counter: n.CON_FULL_Counter,
		Period:           n.Period,
		Signer_Gossiper:  ctx.Gossiper_crypto_config.SelfID.String(),
		Crypto_Scheme:    "bls",
		Signature:        sig.String(),
	}
}

func (ctx GossiperContext) Generate_NUM_FULL(n_list []definition.PoM_Counter) definition.PoM_Counter {
	// Extract all the signatures from the gossip objects
	sig_frag_list := []crypto.SigFragment{}
	signer_list := []string{}
	for _, n := range n_list {
		sig_frag, err := crypto.SigFragmentFromString(n.Signature)
		if err != nil {
			fmt.Println("Error in converting signature fragment: " + err.Error())
		}
		sig_frag_list = append(sig_frag_list, sig_frag)
		signer_list = append(signer_list, n.Signer_Gossiper)
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
	return definition.PoM_Counter{
		ACC_FULL_Counter: n_list[0].ACC_FULL_Counter,
		CON_FULL_Counter: n_list[0].CON_FULL_Counter,
		Period:           n_list[0].Period,
		Signers:          signer_list,
		Crypto_Scheme:    "bls",
		Signature:        sig_full_string,
	}
}

func (ctx GossiperContext) Generate_CON_INIT(obj1 definition.Gossip_object, obj2 definition.Gossip_object) definition.Gossip_object {
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
