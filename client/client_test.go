package client

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"testing"

	"github.com/jik18001/CTngV2/monitor"
	"github.com/jik18001/CTngV2/util"

	"github.com/bits-and-blooms/bitset"
)

func testGet_SRH_and_DCRV(t *testing.T) {
	//read from client_test/ClientData/Period 0/FromMonitor/ClientUpdate_at_Period 0.json"3"
	client_json, err := util.ReadByte("monitor_testdata/1/Period_19/ClientUpdate.json")
	if err != nil {
		t.Error(err)
	}
	var clientUpdate monitor.ClientUpdate
	err = json.Unmarshal(client_json, &clientUpdate)
	if err != nil {
		t.Error(err)
	}
	var SRHs []string
	var DCRVs []bitset.BitSet
	for _, rev := range clientUpdate.REVs {
		newSRH, newDCRV := Get_SRH_and_DCRV(rev)
		SRHs = append(SRHs, newSRH)
		DCRVs = append(DCRVs, newDCRV)
	}
	fmt.Println(SRHs)
	fmt.Println(DCRVs)
}

func testGetRootHash(t *testing.T) {
	// Load client update file from disk
	clientRaw, err := util.ReadByte("monitor_testdata/1/Period_19/ClientUpdate.json")
	if err != nil {
		t.Error(err)
	}
	var clientUpdate monitor.ClientUpdate
	err = json.Unmarshal(clientRaw, &clientUpdate)
	if err != nil {
		t.Error(err)
	}

	// Extract root hashes from client update and print
	fmt.Println("root hash:")
	fmt.Println("[")
	for i, rootHash := range GetRootHash(clientUpdate.STHs) {
		fmt.Printf("%d: %s\n", i, rootHash)
	}
	fmt.Println("]")
}

func loadCertificate(certPath string) (*x509.Certificate, error) {
	// Load the PEM file
	certPEM, err := ioutil.ReadFile(certPath)
	if err != nil {
		return nil, err
	}

	// Decode the PEM file
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the certificate")
	}

	// Parse the certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

func TestInit(t *testing.T) {
	ctx := &ClientContext{
		Status:          "NEW",
		Config_filepath: "client/Client_config.json",
		Crypto_filepath: "client/Client_crypto_config.json",
		Config:          &ClientConfig{},
	}
	ctx.InitializeClientContext()
	//fmt.Println(ctx.Crypto.SignPublicMap)
	//fmt.Println(ctx.Crypto.ThresholdPublicMap)
}

func testHandleUpdate(t *testing.T) {
	ctx := &ClientContext{
		Status:          "NEW",
		Config_filepath: "client/Client_config.json",
		Crypto_filepath: "client/Client_crypto_config.json",
		Config:          &ClientConfig{},
	}
	ctx.InitializeClientContext()
	update_1 := ctx.LoadUpdate("monitor_testdata/1/Period_55/ClientUpdate.json")
	update_2 := ctx.LoadUpdate("monitor_testdata/1/Period_56/ClientUpdate.json")
	update_3 := ctx.LoadUpdate("monitor_testdata/1/Period_57/ClientUpdate.json")
	ctx.HandleUpdate(update_1, true, true)
	ctx.HandleUpdate(update_2, true, true)
	ctx.HandleUpdate(update_3, true, true)
	fmt.Println("Presenting STH database:")
	fmt.Println(ctx.STH_database)
	fmt.Println("Presenting CRV database:")
	fmt.Println(ctx.CRV_database)
	fmt.Println("Presenting PoM database:")
	//only print key
	for key, _ := range ctx.POM_database {
		fmt.Println(key)
	}
}

func TestCert(t *testing.T) {
	ctx := &ClientContext{
		Status:          "NEW",
		Config_filepath: "client/Client_config.json",
		Crypto_filepath: "client/Client_crypto_config.json",
		Config:          &ClientConfig{},
	}
	ctx.InitializeClientContext()
	update_1 := ctx.LoadUpdate("monitor_testdata/1/Period_55/ClientUpdate.json")
	update_2 := ctx.LoadUpdate("monitor_testdata/1/Period_56/ClientUpdate.json")
	//update_3 := ctx.LoadUpdate("monitor_testdata/1/Period_57/ClientUpdate.json")
	ctx.HandleUpdate(update_1, true, true)
	ctx.HandleUpdate(update_2, true, true)
	//ctx.HandleUpdate(update_3, true, true)
	fmt.Println("Presenting STH database:")
	fmt.Println(ctx.STH_database)
	fmt.Println("Presenting CRV database:")
	fmt.Println(ctx.CRV_database)
	fmt.Println("Presenting PoM database:")
	//only print key
	for key, _ := range ctx.POM_database {
		fmt.Println(key)
	}
	// Load the certificate
	certbyte, err := util.ReadCertificateFromDisk("badcertafter2.crt")
	if err != nil {
		t.Error(err)
	}
	cert, err := x509.ParseCertificate(certbyte)
	if err != nil {
		t.Error(err)
	}
	ctx.VerifyCTngextension(cert)

}
