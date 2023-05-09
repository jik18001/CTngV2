package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

func main() {
	err := verifyTLSCertificate("localhost:8000")
	if err != nil {
		log.Fatalf("Failed to verify TLS certificate: %v", err)
	}
	fmt.Println("TLS certificate verification succeeded!")
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
	conn, err := tls.Dial("tcp", serverAddr, tlsConfig)
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

	// Print the certificate information
	fmt.Println("Subject:", cert.Subject.CommonName)
	fmt.Println("Issuer:", cert.Issuer.CommonName)
	fmt.Println("Valid from:", cert.NotBefore)
	fmt.Println("Valid until:", cert.NotAfter)

	return nil
}
