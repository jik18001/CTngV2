package main

import (
	"CTngV2/util"
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
