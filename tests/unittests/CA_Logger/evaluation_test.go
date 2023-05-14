package main

import (
	"CTngV2/CA"
	"CTngV2/crypto"
	"CTngV2/definition"
	"CTngV2/util"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"reflect"
	"testing"
)

func Test1(t *testing.T) {
	//path1 := "ca_extensions.json"
	path2 := "ca_certjsons_.json"
	path3 := "logger_certjsons_.json"
	byte1, _ := util.ReadByte(path2)
	byte2, _ := util.ReadByte(path3)
	//fmt.Println(byte1)
	//fmt.Println(byte2)
	if !reflect.DeepEqual(byte1, byte2) {
		t.Fail()
	}
}

func Test2(t *testing.T) {
	certpath := "Testing Dummy 0_RID_1.crt"
	keypath := "Testing Dummy 0_RID_1.key"
	_, err := tls.LoadX509KeyPair(certpath, keypath)
	if err != nil {
		fmt.Println("LoadX509KeyPair failed")
		t.Fail()
	}
	certbyte, _ := util.ReadCertificateFromDisk(certpath)
	cert, err := x509.ParseCertificate(certbyte)
	if err != nil {
		fmt.Println("ParseCertificate failed")
		t.Fail()
	}
	var CTngExtension CA.CTngExtension
	err = json.Unmarshal([]byte(cert.CRLDistributionPoints[1]), &CTngExtension)
	if err != nil {
		log.Fatalf("Failed to parse certificate: %v", err)
	}
	var sth_example definition.Gossip_object
	sth_example = CTngExtension.STH
	rsasig, err := crypto.RSASigFromString(sth_example.Signature[0])
	if err != nil {
		log.Fatalf("Failed to parse signature: %v", err)
	}
	fmt.Println(rsasig)

}
