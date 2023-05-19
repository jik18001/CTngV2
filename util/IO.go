package util

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
)

//This read function reads from a Json file as a byte array and returns it.
//This function will be called for all the reading from json functions

func ReadByte(filename string) ([]byte, error) {
	jsonFile, err := os.Open(filename)
	// if we os.Open returns an error then handle it
	if err != nil {
		return nil, err
	}
	// defer the closing of our jsonFile so that we can parse it later on
	defer jsonFile.Close()

	// read our opened xmlFile as a byte array.
	byteValue, err := ioutil.ReadAll(jsonFile)
	if err != nil {
		return nil, err
	}
	return byteValue, nil
}

// Writes arbitrary data as a JSON File.
// If the file does not exist, it will be created.
func WriteData(filename string, data interface{}) error {
	jsonFile, err := os.Open(filename)
	// if we os.Open returns an error then handle it
	if err != nil && strings.Contains(err.Error(), "no such file or directory") {
		jsonFile, err = os.Create(filename)
	}
	if err != nil {
		return err
	}
	// defer the closing of our jsonFile so that we can parse it later on
	defer jsonFile.Close()
	//write to the corresponding file
	file, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(filename, file, 0644)
	if err != nil {
		return err
	}
	return nil
}

func CreateFile(path string) {
	// check if file exists
	var _, err = os.Stat(path)

	// create file if not exists
	if os.IsNotExist(err) {
		var file, err = os.Create(path)
		if err != nil {
			return
		}
		defer file.Close()
	}
}

func CreateDir(path string) {
	// check if directory exists
	var _, err = os.Stat(path)
	// create directory if not exists
	if os.IsNotExist(err) {
		errDir := os.MkdirAll(path, 0755)
		if errDir != nil {
			return
		}
	}
}

func DeleteFilesAndDirectories(path string) error {
	// Open the directory specified by the path
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()

	// Read all the contents of the directory
	fileInfos, err := dir.Readdir(0)
	if err != nil {
		return err
	}

	// Loop through all the files and directories in the directory
	for _, fileInfo := range fileInfos {
		// Create the full path to the file or directory
		fullPath := path + "/" + fileInfo.Name()

		// If the file or directory is a directory, recursively delete it
		if fileInfo.IsDir() {
			if err := DeleteFilesAndDirectories(fullPath); err != nil {
				return err
			}
		} else {
			// Otherwise, delete the file
			if err := os.Remove(fullPath); err != nil {
				return err
			}
		}
	}

	// Finally, delete the directory itself
	if err := os.Remove(path); err != nil {
		return err
	}

	return nil
}

func LoadConfiguration(config interface{}, file string) { //takes in the struct that it is updating and the file it is updating with
	// Let's first read the file
	content, err := ioutil.ReadFile(file)
	if err != nil {
		log.Fatal("Error when opening file: ", err)
	}
	// Now let's unmarshall the data into `payload`
	err = json.Unmarshal(content, config)
	if err != nil {
		log.Fatal("Error during Unmarshal(): ", err)
	}
}

func SaveCertificateToDisk(certBytes []byte, filePath string) {
	certOut, err := os.Create(filePath)
	if err != nil {
		log.Fatalf("Failed to open %s for writing: %v", filePath, err)
	}
	if err := pem.Encode(certOut, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	}); err != nil {
		log.Fatalf("Failed to write data to %s: %v", filePath, err)
	}
	if err := certOut.Close(); err != nil {
		log.Fatalf("Error closing %s: %v", filePath, err)
	}
}

func SaveKeyToDisk(privKey *rsa.PrivateKey, filePath string) {
	keyOut, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalf("Failed to open %s for writing: %v", filePath, err)
		return
	}
	privBytes, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		log.Fatalf("Unable to marshal private key: %v", err)
	}
	if err := pem.Encode(keyOut, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privBytes,
	}); err != nil {
		log.Fatalf("Failed to write data to %s: %v", filePath, err)
	}
	if err := keyOut.Close(); err != nil {
		log.Fatalf("Error closing %s: %v", filePath, err)
	}
}

func ParseTBSCertificate(cert *x509.Certificate) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber:          cert.SerialNumber,
		Subject:               cert.Subject,
		NotBefore:             cert.NotBefore,
		NotAfter:              cert.NotAfter,
		KeyUsage:              cert.KeyUsage,
		ExtKeyUsage:           cert.ExtKeyUsage,
		UnknownExtKeyUsage:    cert.UnknownExtKeyUsage,
		BasicConstraintsValid: cert.BasicConstraintsValid,
		IsCA:                  cert.IsCA,
		// only keep the first entry in the CRL distribution points
		SubjectKeyId: cert.SubjectKeyId,
		Issuer:       cert.Issuer,
		PublicKey:    cert.PublicKey,
	}
}

func ReadCertificateFromDisk(filePath string) ([]byte, error) {
	certFile, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer certFile.Close()

	pemFileInfo, err := certFile.Stat()
	if err != nil {
		return nil, err
	}

	var certBytes []byte = make([]byte, pemFileInfo.Size())
	_, err = certFile.Read(certBytes)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(certBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode certificate PEM data")
	}

	return block.Bytes, nil
}

func ReadKeyFromDisk(filePath string) (*rsa.PrivateKey, error) {
	keyFile, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer keyFile.Close()

	pemFileInfo, err := keyFile.Stat()
	if err != nil {
		return nil, err
	}

	var keyBytes []byte = make([]byte, pemFileInfo.Size())
	_, err = keyFile.Read(keyBytes)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode private key PEM data")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	privKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not RSA")
	}

	return privKey, nil
}
