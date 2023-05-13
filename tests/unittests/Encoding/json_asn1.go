package main

import (
	"encoding/asn1"
	"encoding/json"
	"fmt"
)

func main() {
	// Example JSON string
	jsonString := `{"key": "value"}`

	// Convert JSON string to byte slice
	jsonBytes := []byte(jsonString)

	// Create an ASN.1 OCTET STRING from the JSON byte slice
	octetString := asn1.RawValue{
		Tag:   asn1.TagOctetString,
		Bytes: jsonBytes,
	}

	// Encode the OCTET STRING using ASN.1
	encodedOCTETString, _ := asn1.Marshal(octetString)

	fmt.Printf("Encoded OCTET STRING: %x\n", encodedOCTETString)

	_, err := asn1.Unmarshal(encodedOCTETString, &octetString)
	if err != nil {
		fmt.Println("Error decoding OCTET STRING:", err)
		return
	}

	// Unmarshal the OCTET STRING value (JSON) into a JSON structure
	var jsonStructure interface{}
	err = json.Unmarshal(octetString.Bytes, &jsonStructure)
	if err != nil {
		fmt.Println("Error unmarshaling JSON:", err)
		return
	}

	fmt.Println("Decoded JSON structure:", jsonStructure)
}
