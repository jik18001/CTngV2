package main

import (
	"CTngV2/crypto"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"strconv"
	"time"
)

func main() {
	// get our ca and server certificate
	path_prefix := "../ca_testconfig/1"
	path := path_prefix + "/CA_crypto_config.json"
	cryptoconf, _ := crypto.ReadCryptoConfig(path)
	privK := cryptoconf.SignSecretKey
	//pubK := cryptoconf.SignPublicMap[cryptoconf.SelfID]
	//fmt.Println(privK, pubK)
	root := GenerateRootCA("1", *cryptoconf)
	GenerateDummyCert("1", root, privK)
	//fmt.Println(dummy.RawTBSCertificate)
	certsetup()
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
		NotAfter:              time.Now().AddDate(365, 0, 0),
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

func GenerateDummyCert(ID string, Rootcert *x509.Certificate, priv rsa.PrivateKey) *x509.Certificate {
	// set up our server certificate
	ID_int, _ := strconv.Atoi(ID)
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(int64(ID_int * 1001)),
		Subject: pkix.Name{
			CommonName:    "CTng Dummy " + ID,
			Organization:  []string{"UCONN"},
			Country:       []string{"US"},
			PostalCode:    []string{"06269"},
			Locality:      []string{"Storrs"},
			Province:      []string{"CT"},
			StreetAddress: []string{"371 Fairfield Way"},
		},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(365, 0, 0),
		SubjectKeyId: []byte(ID),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	newext := CTngExtension{
		SequenceNumber: 0,
	}
	bytes, _ := json.Marshal(newext)
	cert.CRLDistributionPoints = []string{string(bytes)}
	certPrivKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	certBytes, _ := x509.CreateCertificate(rand.Reader, cert, Rootcert, &certPrivKey.PublicKey, &priv)
	cert1, _ := x509.ParseCertificate(certBytes)
	//fmt.Println(cert1.RawTBSCertificate)
	return cert1
}

func certsetup() {
	// set up our CA certificate
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization:  []string{"Company, INC."},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{"Golden Gate Bridge"},
			PostalCode:    []string{"94016"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// create our private and public key
	caPrivKey, _ := rsa.GenerateKey(rand.Reader, 4096)

	// create the CA
	caBytes, _ := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)

	// pem encode
	caPEM := new(bytes.Buffer)
	pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})

	caPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(caPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caPrivKey),
	})

	// set up our server certificate
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization:  []string{"Company, INC."},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{"Golden Gate Bridge"},
			PostalCode:    []string{"94016"},
		},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	tbscertderbyte := cert.RawTBSCertificate
	fmt.Println(tbscertderbyte)

	newext := CTngExtension{
		SequenceNumber: 0,
	}
	bytes, _ := json.Marshal(newext)
	cert.CRLDistributionPoints = []string{string(bytes)}

	certPrivKey, _ := rsa.GenerateKey(rand.Reader, 4096)
	certBytes, _ := x509.CreateCertificate(rand.Reader, cert, ca, &certPrivKey.PublicKey, caPrivKey)
	cert1, _ := x509.ParseCertificate(certBytes)
	tbscertderbyte2 := cert1.RawTBSCertificate

	fmt.Println(tbscertderbyte2)
}
