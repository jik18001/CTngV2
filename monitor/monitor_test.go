package monitor

import (
	"CTngV2/definition"
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"testing"
)

type ClientMock struct{}

func dummyGossipObject() definition.Gossip_object {
	return definition.Gossip_object{
		Application: "test", Period: "0", Type: "", Signer: "",
		Signers:       []string{},
		Signature:     [2]string{"", ""},
		Timestamp:     "",
		Crypto_Scheme: "",
		Payload:       [3]string{"", "", ""},
	}
}

func (c *ClientMock) GoodRequest(req *http.Request) (*http.Request, error) {
	mockedRes := dummyGossipObject()
	b, err := json.Marshal(mockedRes)
	if err != nil {
		log.Panic("Error reading a mockedRes from mocked client", err)
	}

	return &http.Request{Body: ioutil.NopCloser(bytes.NewBuffer(b))}, nil
}

func (c *ClientMock) BadRequest(req *http.Request) (*http.Request, error) {
	mockedResBad := "bad"
	b, err := json.Marshal(mockedResBad)
	if err != nil {
		log.Panic("Error reading a mockedRes from mocked client", err)
	}

	return &http.Request{Body: ioutil.NopCloser(bytes.NewBuffer(b))}, nil
}

func testReceiveGossip(t *testing.T) {
	monitorContext := MonitorContext{}
	req, _ := (&ClientMock{}).GoodRequest(&http.Request{})
	receiveGossip(&monitorContext, nil, req)
}

func testPanicOnBadReceiveGossip(t *testing.T) {
	monitorContext := MonitorContext{}
	// Catch Panic
	defer func() { _ = recover() }()

	req, _ := (&ClientMock{}).BadRequest(&http.Request{})
	receiveGossip(&monitorContext, nil, req)

	t.Errorf("Expected panic")
}

func testPrepareClientupdate(t *testing.T) {
	// TODO
	ctx_monitor_1 := InitializeMonitorContext("../Gen/monitor_testconfig/1/Monitor_public_config.json", "../Gen/monitor_testconfig/1/Monitor_private_config.json", "../Gen/monitor_testconfig/1/Monitor_crypto_config.json", "1")
	update, err := PrepareClientUpdate(ctx_monitor_1, "../client_test/ClientData/Period 0/FromMonitor/ClientUpdate_at_Period 0.json")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(update)
}

func testLoadStorage(t *testing.T) {
	// TODO
	ctx_monitor_1 := InitializeMonitorContext("../Gen/monitor_testconfig/1/Monitor_public_config.json", "../Gen/monitor_testconfig/1/Monitor_private_config.json", "../Gen/monitor_testconfig/1/Monitor_crypto_config.json", "1")
	//ctx_monitor_1.LoadOneStorage(definition.CON_INIT, "../testserver/POM_TSS.json")
	ctx_monitor_1.LoadOneStorage(definition.STH_FULL, "../testserver/REV_TSS.json")
	ctx_monitor_1.LoadOneStorage(definition.REV_FULL, "../testserver/STH_TSS.json")
	//fmt.Println(ctx_monitor_1.GetObjectNumber(definition.CON_FULL))
	fmt.Println(ctx_monitor_1.GetObjectNumber(definition.STH_FULL))
	fmt.Println(ctx_monitor_1.GetObjectNumber(definition.REV_FULL))
}

func testSaveStorage(t *testing.T) {
	// TODO
	ctx_monitor_1 := InitializeMonitorContext("../Gen/monitor_testconfig/1/Monitor_public_config.json", "../Gen/monitor_testconfig/1/Monitor_private_config.json", "../Gen/monitor_testconfig/1/Monitor_crypto_config.json", "1")
	//ctx_monitor_1.LoadOneStorage(definition.CON_FULL, "../testserver/POM_TSS.json")
	ctx_monitor_1.LoadOneStorage(definition.STH_FULL, "../testserver/REV_TSS.json")
	ctx_monitor_1.LoadOneStorage(definition.REV_FULL, "../testserver/STH_TSS.json")
	ctx_monitor_1.InitializeMonitorStorage("../testserver")
	fmt.Println(ctx_monitor_1.StorageDirectory)
	//ctx_monitor_1.SaveStorage("0")
}

func testMonitorServer(t *testing.T) {
	ctx_monitor_1 := InitializeMonitorContext("../Gen/monitor_testconfig/1/Monitor_public_config.json", "../Gen/monitor_testconfig/1/Monitor_private_config.json", "../Gen/monitor_testconfig/1/Monitor_crypto_config.json", "1")
	//over write ctx_monitor_1.Mode to 1 if you want to test the monitor server without waiting
	ctx_monitor_1.Mode = 1
	StartMonitorServer(ctx_monitor_1)
}

/*
func TestNUM(t *testing.T) {
	ctx_monitor_1 := InitializeMonitorContext("../network/monitor_testconfig/1/Monitor_public_config.json", "../network/monitor_testconfig/1/Monitor_private_config.json", "../Gen/monitor_testconfig/1/Monitor_crypto_config.json", "1")
	ctx_gossiper_1 := definition.InitializeGossiperContext("../network/gossiper_testconfig/1/Gossiper_public_config.json", "../network/gossiper_testconfig/1/Gossiper_private_config.json", "../Gen/gossiper_testconfig/1/Gossiper_crypto_config.json", "1")
	ctx_gossiper_2 := definition.InitializeGossiperContext("../network/gossiper_testconfig/2/Gossiper_public_config.json", "../network/gossiper_testconfig/2/Gossiper_private_config.json", "../Gen/gossiper_testconfig/2/Gossiper_crypto_config.json", "2")
	num_1 := definition.NUM{
		NUM_ACC_FULL:   "0",
		NUM_CON_FULL:   "0",
		Period:         "0",
		Signer_Monitor: ctx_monitor_1.Monitor_crypto_config.SelfID.String(),
		Crypto_Scheme:  "rsa",
	}
	signature, _ := ctx_monitor_1.Monitor_crypto_config.Sign([]byte(num_1.NUM_ACC_FULL + num_1.NUM_CON_FULL + num_1.Period + num_1.Signer_Monitor))
	num_1.Signature = signature.String()
	err := num_1.Verify(ctx_gossiper_1.Config.Crypto)
	if err != nil {
		fmt.Println(err)
	}
	num_frag_1 := definition.Generate_NUM_FRAG(&num_1, ctx_gossiper_1.Config.Crypto)
	err = num_frag_1.Verify(ctx_gossiper_2.Config.Crypto)
	if err != nil {
		fmt.Println(err)
	}
	num_frag_2 := definition.Generate_NUM_FRAG(&num_1, ctx_gossiper_2.Config.Crypto)
	err = num_frag_2.Verify(ctx_gossiper_1.Config.Crypto)
	if err != nil {
		fmt.Println(err)
	}
	num_frag_list := []*definition.NUM_FRAG{num_frag_1, num_frag_2}
	num_full := definition.Generate_NUM_FULL(num_frag_list, ctx_gossiper_1.Config.Crypto)
	err = num_full.Verify(ctx_gossiper_1.Config.Crypto)
	if err != nil {
		fmt.Println(err)
	}
}

*/
