package gossiper

import (
	"fmt"
	"testing"
	"time"

	"github.com/jik18001/CTngV2/definition"
)

// This function tests
// 1. Initialization of the gossiper context
// 2. Storing gossip objects/PoM counters
// 3. Duplicate detection
// 4. Malicious detection

func pf(testsuit string, boolean bool) {
	if boolean {
		fmt.Println(testsuit, ": PASS")
	} else {
		fmt.Println(testsuit, ": FAIL")
	}
}
func test_Store_Duplicate_Malicious(t *testing.T) {
	STH_INIT_1 := definition.Gossip_object{
		Application:   definition.CTNG_APPLICATION,
		Period:        "1",
		Type:          definition.STH_INIT,
		Signer:        "1",
		Signers:       []string{"1"},
		Signature:     [2]string{"1"},
		Timestamp:     "1",
		Crypto_Scheme: "1",
		Payload:       [3]string{"1", "1", "1"},
	}
	STH_INIT_2 := definition.Gossip_object{
		Application:   definition.CTNG_APPLICATION,
		Period:        "1",
		Type:          definition.STH_INIT,
		Signer:        "1",
		Signers:       []string{"1"},
		Signature:     [2]string{"2"},
		Timestamp:     "1",
		Crypto_Scheme: "1",
		Payload:       [3]string{"1", "2", "2"},
	}
	ctx_g1 := InitializeGossiperContext("testFiles/gossiper_testconfig/1/Gossiper_public_config.json", "testFiles/gossiper_testconfig/1/Gossiper_private_config.json", "testFiles/gossiper_testconfig/1/Gossiper_crypto_config.json", "1")
	STH_FRAG_1 := ctx_g1.Generate_Gossip_Object_FRAG(STH_INIT_1)
	ctx_g1.Store(STH_INIT_1)
	ctx_g1.Store(STH_FRAG_1)
	num, err := ctx_g1.GetItemCount(STH_FRAG_1.GetID(), definition.STH_FRAG)
	if err != nil {
		fmt.Println(err)
	}
	r1, _ := ctx_g1.IsDuplicate(STH_INIT_1)
	r2, _ := ctx_g1.IsDuplicate(STH_INIT_2)
	r4 := num == 1
	r5 := ctx_g1.IsMalicious(STH_INIT_2)
	r6 := ctx_g1.IsMalicious(STH_INIT_1)
	pf("r1", r1)
	pf("!r2", !r2)
	pf("r4", r4)
	pf("r5", r5)
	pf("!r6", !r6)
	//fmt.Println(len(ctx_g1.Gossip_object_storage.STH_INIT[STH_INIT_1.GetID()]))
}

func testBlacklist(t *testing.T) {
	ctx_g1 := InitializeGossiperContext("testFiles/gossiper_testconfig/1/Gossiper_public_config.json", "testFiles/gossiper_testconfig/1/Gossiper_private_config.json", "testFiles/gossiper_testconfig/1/Gossiper_crypto_config.json", "1")
	CON_INIT_1 := definition.Gossip_object{
		Application: definition.CTNG_APPLICATION,
		Period:      "1",
		Type:        definition.CON_INIT,
		Payload:     [3]string{"1", "2", "3"},
	}
	ctx_g1.Store(CON_INIT_1)
	r1 := ctx_g1.InBlacklistPerm(CON_INIT_1.Payload[0])
	r3 := ctx_g1.InBlacklist(CON_INIT_1.Payload[0])
	pf("!r1", !r1)
	pf("r3", r3)
}

func testFRAG(t *testing.T) {
	STH_INIT_1 := definition.Gossip_object{
		Application:   definition.CTNG_APPLICATION,
		Period:        "1",
		Type:          definition.STH_INIT,
		Signer:        "1",
		Signers:       []string{"1"},
		Signature:     [2]string{"1"},
		Timestamp:     "1",
		Crypto_Scheme: "1",
		Payload:       [3]string{"1", "1", "1"},
	}
	STH_INIT_2 := definition.Gossip_object{
		Application:   definition.CTNG_APPLICATION,
		Period:        "1",
		Type:          definition.STH_INIT,
		Signer:        "1",
		Signers:       []string{"1"},
		Signature:     [2]string{"2"},
		Timestamp:     "1",
		Crypto_Scheme: "1",
		Payload:       [3]string{"1", "2", "2"},
	}
	ctx_g1 := InitializeGossiperContext("testFiles/gossiper_testconfig/1/Gossiper_public_config.json", "testFiles/gossiper_testconfig/1/Gossiper_private_config.json", "testFiles/gossiper_testconfig/1/Gossiper_crypto_config.json", "1")
	Handle_Gossip_object(ctx_g1, STH_INIT_1)
	Handle_Gossip_object(ctx_g1, STH_INIT_2)
	//ctx_g1.log_Gossiper_data()
	//fmt.Println(ctx_g1.Gossiper_log)

}
func testSTH_handler(t *testing.T) {
	// Create a channel that will receive a message after 10 seconds
	done := make(chan bool, 1)
	go func() {
		time.Sleep(10 * time.Second)
		done <- true
	}()

	ctx_g1 := InitializeGossiperContext("testFiles/gossiper_testconfig/1/Gossiper_public_config.json", "testFiles/gossiper_testconfig/1/Gossiper_private_config.json", "testFiles/gossiper_testconfig/1/Gossiper_crypto_config.json", "1")
	STH_INIT_1 := definition.Gossip_object{
		Application:   definition.CTNG_APPLICATION,
		Period:        "1",
		Type:          definition.STH_INIT,
		Signer:        "1",
		Signers:       []string{"1"},
		Signature:     [2]string{"1"},
		Timestamp:     "1",
		Crypto_Scheme: "1",
		Payload:       [3]string{"1", "1", "1"},
	}
	STH_INIT_2 := definition.Gossip_object{
		Application:   definition.CTNG_APPLICATION,
		Period:        "1",
		Type:          definition.STH_INIT,
		Signer:        "1",
		Signers:       []string{"1"},
		Signature:     [2]string{"2"},
		Timestamp:     "1",
		Crypto_Scheme: "1",
		Payload:       [3]string{"1", "2", "2"},
	}
	STH_INIT_3 := definition.Gossip_object{
		Application:   definition.CTNG_APPLICATION,
		Period:        "1",
		Type:          definition.STH_INIT,
		Signer:        "1",
		Signers:       []string{"1"},
		Signature:     [2]string{"3"},
		Timestamp:     "1",
		Crypto_Scheme: "1",
		Payload:       [3]string{"1", "3", "3"},
	}
	Handle_Gossip_object(ctx_g1, STH_INIT_1)
	Handle_Gossip_object(ctx_g1, STH_INIT_2)
	fmt.Println(ctx_g1.Gossip_object_storage.CON_INIT)
	Handle_Gossip_object(ctx_g1, STH_INIT_3)
	fmt.Println(ctx_g1.Gossip_object_storage.CON_INIT)

	f := func() {
		//ctx_g1.log_Gossiper_data()
		fmt.Println(ctx_g1.Gossiper_log)
		fmt.Println(ctx_g1.Gossip_object_storage.CON_INIT)
		return
	}
	time.AfterFunc(8*time.Second, f)

	// Wait for either the timer to fire or the channel to receive a message
	select {
	case <-done:
		// The channel received a message, indicating that the test has completed
		return
	case <-time.After(11 * time.Second):
		// The timer fired, indicating that the test has timed out
		t.Errorf("test timed out after 10 seconds")
		return
	}

}

func testCONhandler(t *testing.T) {
	// Create a channel that will receive a message after 10 seconds
	done := make(chan bool, 1)
	go func() {
		time.Sleep(10 * time.Second)
		done <- true
	}()
	STH_INIT_1 := definition.Gossip_object{
		Application:   definition.CTNG_APPLICATION,
		Period:        "1",
		Type:          definition.STH_INIT,
		Signer:        "1",
		Signers:       []string{"1"},
		Signature:     [2]string{"1"},
		Timestamp:     "1",
		Crypto_Scheme: "1",
		Payload:       [3]string{"1", "1", "1"},
	}
	STH_INIT_2 := definition.Gossip_object{
		Application:   definition.CTNG_APPLICATION,
		Period:        "1",
		Type:          definition.STH_INIT,
		Signer:        "1",
		Signers:       []string{"1"},
		Signature:     [2]string{"2"},
		Timestamp:     "1",
		Crypto_Scheme: "1",
		Payload:       [3]string{"1", "2", "2"},
	}
	STH_INIT_3 := definition.Gossip_object{
		Application:   definition.CTNG_APPLICATION,
		Period:        "1",
		Type:          definition.STH_INIT,
		Signer:        "1",
		Signers:       []string{"1"},
		Signature:     [2]string{"3"},
		Timestamp:     "1",
		Crypto_Scheme: "1",
		Payload:       [3]string{"1", "3", "3"},
	}
	ctx_g1 := InitializeGossiperContext("testFiles/gossiper_testconfig/1/Gossiper_public_config.json", "testFiles/gossiper_testconfig/1/Gossiper_private_config.json", "testFiles/gossiper_testconfig/1/Gossiper_crypto_config.json", "1")
	CON_1 := ctx_g1.Generate_CON_INIT(STH_INIT_1, STH_INIT_2)
	CON_2 := ctx_g1.Generate_CON_INIT(STH_INIT_1, STH_INIT_3)
	Handle_Gossip_object(ctx_g1, CON_1)
	Handle_Gossip_object(ctx_g1, CON_2)
	Handle_Gossip_object(ctx_g1, CON_1)
	// Wait for either the timer to fire or the channel to receive a message
	select {
	case <-done:
		// The channel received a message, indicating that the test has completed
		return
	case <-time.After(11 * time.Second):
		// The timer fired, indicating that the test has timed out
		t.Errorf("test timed out after 10 seconds")
		return
	}

}

func testFragHandler(t *testing.T) {
	// Create a channel that will receive a message after 10 seconds
	done := make(chan bool, 1)
	go func() {
		time.Sleep(10 * time.Second)
		done <- true
	}()
	REV_INIT_1 := definition.Gossip_object{
		Application:   definition.CTNG_APPLICATION,
		Period:        "1",
		Type:          definition.REV_INIT,
		Signer:        "1",
		Signers:       []string{"1"},
		Signature:     [2]string{"1"},
		Timestamp:     "1",
		Crypto_Scheme: "1",
		Payload:       [3]string{"1", "1", "1"},
	}
	ctx_g1 := InitializeGossiperContext("testFiles/gossiper_testconfig/1/Gossiper_public_config.json", "testFiles/gossiper_testconfig/1/Gossiper_private_config.json", "testFiles/gossiper_testconfig/1/Gossiper_crypto_config.json", "1")
	ctx_g2 := InitializeGossiperContext("testFiles/gossiper_testconfig/2/Gossiper_public_config.json", "testFiles/gossiper_testconfig/2/Gossiper_private_config.json", "testFiles/gossiper_testconfig/2/Gossiper_crypto_config.json", "2")
	ctx_g3 := InitializeGossiperContext("testFiles/gossiper_testconfig/3/Gossiper_public_config.json", "testFiles/gossiper_testconfig/3/Gossiper_private_config.json", "testFiles/gossiper_testconfig/3/Gossiper_crypto_config.json", "3")
	ctx_g4 := InitializeGossiperContext("testFiles/gossiper_testconfig/4/Gossiper_public_config.json", "testFiles/gossiper_testconfig/4/Gossiper_private_config.json", "testFiles/gossiper_testconfig/4/Gossiper_crypto_config.json", "4")
	//REV_FRAG_1 := ctx_g1.Generate_Gossip_Object_FRAG(REV_INIT_1)
	REV_FRAG_2 := ctx_g2.Generate_Gossip_Object_FRAG(REV_INIT_1)
	REV_FRAG_3 := ctx_g3.Generate_Gossip_Object_FRAG(REV_INIT_1)
	REV_FRAG_4 := ctx_g4.Generate_Gossip_Object_FRAG(REV_INIT_1)
	//Handle_Gossip_object(ctx_g1, REV_INIT_1)
	//Handle_Gossip_object(ctx_g1, REV_INIT_1)
	Handle_Gossip_object(ctx_g1, REV_INIT_1)
	Handle_Gossip_object(ctx_g1, REV_FRAG_2)
	Handle_Gossip_object(ctx_g1, REV_FRAG_3)
	Handle_Gossip_object(ctx_g1, REV_FRAG_4)
	//Handle_Gossip_object(ctx_g1, REV_FRAG_2)
	f := func() {
		//ctx_g1.log_Gossiper_data()
		ctx_g1.Save()
		fmt.Println(ctx_g1.Gossiper_log)
		return
	}
	time.AfterFunc(8*time.Second, f)
	// Wait for either the timer to fire or the channel to receive a message
	select {
	case <-done:
		// The channel received a message, indicating that the test has completed
		return
	case <-time.After(11 * time.Second):
		// The timer fired, indicating that the test has timed out
		t.Errorf("test timed out after 10 seconds")
		return
	}
}
