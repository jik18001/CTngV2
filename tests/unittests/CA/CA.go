package main

import (
	"CTngV2/crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"time"
)

func main() {
	normalMux := http.NewServeMux()
	normalMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "Hello, HTTPS!")
	})

	tlscert, error := tls.LoadX509KeyPair("subject_cert.crt", "subject_key.key")
	if error != nil {
		fmt.Println(error)
	}
	//run a HTTP server to serve the certificate
	normalServer := http.Server{
		Addr: "localhost:8000",
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{tlscert},
		},
		Handler: normalMux,
	}

	certbyte := tlscert.Certificate[0]
	cert, _ := x509.ParseCertificate(certbyte)
	fmt.Println("Server is running on port 8000. Visit https://localhost:8000/ to view the certificate for ", cert.Subject.CommonName, " Issued by ", cert.Issuer.CommonName, ".")
	// Start the HTTPS server using the ListenAndServeTLS method
	if err := normalServer.ListenAndServeTLS("subject_cert.crt", "subject_key.key"); err != nil {
		fmt.Printf("Failed to start server: %v\n", err)
	}
}

type CTngExtension struct {
	SequenceNumber int
}

func GenerateRootCA(ID string, ctx crypto.CryptoConfig) *x509.Certificate {
	// set up our CA certificate
	ID_int, _ := strconv.Atoi(ID)
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(int64(ID_int * 1000)),
		// Generate Root certificate
		Subject: pkix.Name{
			CommonName:    "CTng CA " + ID,
			Organization:  []string{"UCONN"},
			Country:       []string{"US"},
			PostalCode:    []string{"06269"},
			Locality:      []string{"Storrs"},
			Province:      []string{"CT"},
			StreetAddress: []string{"371 Fairfield Way"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// create our private and public key
	caPrivKey := ctx.SignSecretKey

	// create the CA
	caBytes, _ := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, &caPrivKey)

	Rootcert, _ := x509.ParseCertificate(caBytes)
	//fmt.Print(Rootcert.RawTBSCertificate)
	return Rootcert
}

func GenerateDummyCert(ID string, Rootcert *x509.Certificate, priv rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey) {
	// set up our server certificate
	ID_int, _ := strconv.Atoi(ID)
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(int64(ID_int * 1001)),
		Subject: pkix.Name{
			CommonName:    "localhost:8000",
			Organization:  []string{"UCONN"},
			Country:       []string{"US"},
			PostalCode:    []string{"06269"},
			Locality:      []string{"Storrs"},
			Province:      []string{"CT"},
			StreetAddress: []string{"371 Fairfield Way"},
		},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		SubjectKeyId: []byte(ID),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	cert.DNSNames = []string{"localhost:8000"}
	newext := CTngExtension{
		SequenceNumber: 0,
	}
	bytes, _ := json.Marshal(newext)
	cert.CRLDistributionPoints = []string{string(bytes)}
	certPrivKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	certBytes, _ := x509.CreateCertificate(rand.Reader, cert, Rootcert, &certPrivKey.PublicKey, &priv)
	cert1, _ := x509.ParseCertificate(certBytes)
	//fmt.Println(cert1.RawTBSCertificate)
	return cert1, certPrivKey
}
