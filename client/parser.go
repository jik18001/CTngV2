package client

import (
	"CTngV2/CA"
	"CTngV2/definition"
	"encoding/json"
	"fmt"

	"github.com/bits-and-blooms/bitset"
)

type SRH_with_ID struct {
	Signature string `json:"sig"`
	Id        string `json:"id"`
}

func Get_SRH_and_DCRV(rev definition.Gossip_object) (string, bitset.BitSet) {
	var revocation CA.Revocation
	err := json.Unmarshal([]byte(rev.Payload[2]), &revocation)
	if err != nil {
		fmt.Println(err)
	}
	newSRH := revocation.SRH
	var newDCRV bitset.BitSet
	err = newDCRV.UnmarshalBinary(revocation.Delta_CRV)
	if err != nil {
		fmt.Println(err)
	}
	return newSRH, newDCRV
}

func GetSRH(data MonitorData) []SRH_with_ID {
	var out []SRH_with_ID

	// Iterate over each STH
	for _, sth := range data {
		// Parse the payload field in the STH as a map
		var payload map[string]string
		err := json.Unmarshal([]byte(sth.Payload[2]), &payload)
		if err != nil {
			// fmt.Println(payload)
			fmt.Println(err)
			return out
		}

		// Parse SRH as a struct with signature and id fields
		var srh SRH_with_ID
		err = json.Unmarshal([]byte(payload["SRH"]), &srh)
		if err != nil {
			// fmt.Println(payload)
			fmt.Println(err)
			return out
		}

		out = append(out, srh)
	}
	return out
}

func GetDeltaCRV(data MonitorData) []string {
	var out []string

	// Iterate over each STH
	for _, rev := range data {
		// Parse the payload field in the STH as a map
		var payload map[string]any
		err := json.Unmarshal([]byte(rev.Payload[2]), &payload)
		if err != nil {
			// fmt.Println(payload)
			fmt.Println(err)
			return out
		}

		// Parse Delta CRV value as a string and append it to the array
		out = append(out, payload["Delta_CRV"].(string))
	}

	return out
}

func GetRootHash(data MonitorData) []string {
	var out []string

	// Iterate over each REV
	for _, sth := range data {
		// Parse the payload field in the REV as a map
		var payload map[string]any
		err := json.Unmarshal([]byte(sth.Payload[1]), &payload)
		if err != nil {
			// fmt.Println(payload)
			fmt.Println(err)
			return out
		}

		// Parse Root Hash value as a string and append it to the array
		out = append(out, payload["RootHash"].(string))
	}

	return out
}
