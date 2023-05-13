package main

import (
	"encoding/asn1"
	"fmt"
	"time"
)

type Gossip_object struct {
	Application   string    `json:"application"`
	Period        string    `json:"period"`
	Type          string    `json:"type"`
	Signer        string    `json:"signer"`
	Signers       []string  `json:"signers,omitempty"`
	Signature     [2]string `json:"signature"`
	Timestamp     string    `json:"timestamp"`
	Crypto_Scheme string    `json:"crypto_scheme"`
	Payload       [3]string `json:"payload,omitempty"`
}

type Gossip_object_asn1 struct {
	Application   string
	Period        string
	Type          string
	Signer        string
	Signers       []string
	Signature     []string
	Timestamp     time.Time
	Crypto_Scheme string
	Payload       []string
}

func ConvertToASN1(g Gossip_object) (Gossip_object_asn1, error) {
	timestamp, err := time.Parse(time.RFC3339, g.Timestamp)
	if err != nil {
		return Gossip_object_asn1{}, err
	}

	g_asn1 := Gossip_object_asn1{
		Application:   g.Application,
		Period:        g.Period,
		Type:          g.Type,
		Signer:        g.Signer,
		Signers:       g.Signers,
		Signature:     g.Signature[:],
		Timestamp:     timestamp,
		Crypto_Scheme: g.Crypto_Scheme,
		Payload:       g.Payload[:],
	}

	return g_asn1, nil
}

func ConvertFromASN1(g_asn1 Gossip_object_asn1) Gossip_object {
	timestamp := g_asn1.Timestamp.Format(time.RFC3339)

	g := Gossip_object{
		Application:   g_asn1.Application,
		Period:        g_asn1.Period,
		Type:          g_asn1.Type,
		Signer:        g_asn1.Signer,
		Signers:       g_asn1.Signers,
		Signature:     [2]string{g_asn1.Signature[0], g_asn1.Signature[1]},
		Timestamp:     timestamp,
		Crypto_Scheme: g_asn1.Crypto_Scheme,
		Payload:       [3]string{g_asn1.Payload[0], g_asn1.Payload[1], g_asn1.Payload[2]},
	}

	return g
}

func main() {
	STH := Gossip_object{
		Type:          "1",
		Application:   "CTng",
		Period:        "0",
		Signer:        "localhost:9000",
		Timestamp:     time.Now().UTC().Format(time.RFC3339),
		Crypto_Scheme: "RSA",
		Payload:       [3]string{"data1", "data2", ""},
		Signature:     [2]string{"111", "222"},
	}

	STH_asn1, err := ConvertToASN1(STH)
	if err != nil {
		fmt.Println("Error converting to ASN.1:", err)
		return
	}

	// Encode ASN.1 to bytes
	newb, err := asn1.Marshal(STH_asn1)
	if err != nil {
		fmt.Println("Error encoding ASN.1:", err)
		return
	}

	// Decode bytes to ASN.1
	var newSTH_asn1 Gossip_object_asn1
	_, err = asn1.Unmarshal(newb, &newSTH_asn1)
	if err != nil {
		fmt.Println("Error decoding ASN.1:", err)
		return
	}

	// Convert ASN.1 to Gossip_object
	newSTH := ConvertFromASN1(newSTH_asn1)

	fmt.Println("________________________________________________________")
	fmt.Printf("Original: %+v\n", STH)
	fmt.Printf("Decoded: %+v\n", newSTH)
	fmt.Println("________________________________________________________")
}
