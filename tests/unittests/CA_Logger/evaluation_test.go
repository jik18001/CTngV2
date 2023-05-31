package main

import (
	"CTngV2/CA"
	"CTngV2/Logger"
	"CTngV2/definition"
	"CTngV2/util"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
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
	certpath := "Testing Dummy 1_RID_1.crt"
	keypath := "Testing Dummy 1_RID_1.key"
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
	CTngExtension = CA.ParseCTngextension(cert)
	fmt.Println(CTngExtension)
	var treeinfo definition.STH
	json.Unmarshal([]byte(CTngExtension.LoggerInformation[0].STH.Payload[1]), &treeinfo)
	POI_json, _ := json.Marshal(CTngExtension.LoggerInformation[0].POI)
	fmt.Println("POI given: ", POI_json)
	fmt.Println("RootHash in Byte array given: ", []byte(treeinfo.RootHash))
	Precert := util.ParseTBSCertificate(cert)
	computed := Logger.ComputeRoot(treeinfo, CTngExtension.LoggerInformation[0].POI, *Precert)
	fmt.Println("RootHash in Byte array computed: ", []byte(computed))
}
