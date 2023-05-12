package main

import (
	"CTngV2/CA"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

func main() {
	err := verifyTLSCertificate("localhost")
	if err != nil {
		log.Fatalf("Failed to verify TLS certificate: %v", err)
	}
	fmt.Println("TLS certificate verification succeeded!")
}

type CTngExtensions struct {
	SequenceNumber int
	Loggerinfo     CA.CTngExtension
}

var (
	oidCustomExtension = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 67847871} // Replace with your own OID
)

func parseCTngextensions(cert *x509.Certificate) CTngExtensions {
	var ctngext CTngExtensions
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidCustomExtension) {
			decoded, err := decodeCTngExtensions(ext.Value)
			if err != nil {
				fmt.Println("Error decoding extensions")
			}
			ctngext = decoded
			return ctngext
		}
	}
	return ctngext
}
func encodeCTngExtensions(ext CTngExtensions) []byte {
	bytes, _ := asn1.Marshal(ext)
	return bytes
}

func decodeCTngExtensions(ext []byte) (CTngExtensions, error) {
	var decoded CTngExtensions
	_, err := asn1.Unmarshal(ext, &decoded)
	return decoded, err
}

func verifyTLSCertificate(serverAddr string) error {
	caCert, err := ioutil.ReadFile("../CA/ca_cert.crt")
	if err != nil {
		fmt.Println("Failed to read CA certificate:", err)
	}
	// Create certificate pool and add CA certificate
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Configure the tls.Config to use the CA certificates
	tlsConfig := &tls.Config{
		RootCAs:    caCertPool,
		ServerName: serverAddr,
	}

	// Create a TLS connection
	conn, err := tls.Dial("tcp", serverAddr+":8000", tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to establish a TLS connection: %v", err)
	}
	defer conn.Close()

	// Verify the server's certificate chain
	err = conn.VerifyHostname(serverAddr)
	if err != nil {
		return fmt.Errorf("failed to verify the server's certificate chain: %v", err)
	}

	url := "https://localhost:8000/"

	// Create a TLS configuration with InsecureSkipVerify set to true,
	// to allow the use of self-signed certificates
	//tlsConfig = &tls.Config{InsecureSkipVerify: true}
	tlsConfig = &tls.Config{RootCAs: caCertPool, ServerName: serverAddr}
	// Create an HTTP client with the TLS configuration
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}}

	// Send a GET request to the server and get the response
	resp, err := client.Get(url)
	if err != nil {
		fmt.Println("Error:", err)
	}
	// Get the certificate from the server's TLS connection state
	cert := resp.TLS.PeerCertificates[0]
	ext := parseCTngextensions(cert)
	fmt.Println("CTngextension: ", ext)

	// Print the certificate information
	fmt.Println("Subject:", cert.Subject.CommonName)
	fmt.Println("Issuer:", cert.Issuer.CommonName)
	fmt.Println("Valid from:", cert.NotBefore)
	fmt.Println("Valid until:", cert.NotAfter)

	return nil
}
