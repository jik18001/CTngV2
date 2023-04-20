package gossiper

import (
	"CTngV2/definition"
	"CTngV2/util"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/gorilla/mux"
)

func bindContext(context *GossiperContext, fn func(context *GossiperContext, w http.ResponseWriter, r *http.Request)) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		fn(context, w, r)
	}
}

func handleRequests(c *GossiperContext) {
	// MUX which routes HTTP directories to functions.
	gorillaRouter := mux.NewRouter().StrictSlash(true)
	// Gossip Objects endpoints
	gorillaRouter.HandleFunc("/gossip/sth_init", bindContext(c, Gossip_object_handler)).Methods("POST")
	gorillaRouter.HandleFunc("/gossip/rev_init", bindContext(c, Gossip_object_handler)).Methods("POST")
	gorillaRouter.HandleFunc("/gossip/acc_init", bindContext(c, Gossip_object_handler)).Methods("POST")
	gorillaRouter.HandleFunc("/gossip/con_init", bindContext(c, Gossip_object_handler)).Methods("POST")
	gorillaRouter.HandleFunc("/gossip/sth_frag", bindContext(c, Gossip_object_handler)).Methods("POST")
	gorillaRouter.HandleFunc("/gossip/rev_frag", bindContext(c, Gossip_object_handler)).Methods("POST")
	gorillaRouter.HandleFunc("/gossip/acc_frag", bindContext(c, Gossip_object_handler)).Methods("POST")
	gorillaRouter.HandleFunc("/gossip/con_frag", bindContext(c, Gossip_object_handler)).Methods("POST")
	gorillaRouter.HandleFunc("/gossip/sth_full", bindContext(c, Gossip_object_handler)).Methods("POST")
	gorillaRouter.HandleFunc("/gossip/rev_full", bindContext(c, Gossip_object_handler)).Methods("POST")
	gorillaRouter.HandleFunc("/gossip/acc_full", bindContext(c, Gossip_object_handler)).Methods("POST")
	gorillaRouter.HandleFunc("/gossip/con_full", bindContext(c, Gossip_object_handler)).Methods("POST")
	// POM counter endpoints
	gorillaRouter.HandleFunc("/gossip/num_init", bindContext(c, PoM_counter_handler)).Methods("POST")
	gorillaRouter.HandleFunc("/gossip/num_frag", bindContext(c, PoM_counter_handler)).Methods("POST")
	gorillaRouter.HandleFunc("/gossip/num_full", bindContext(c, PoM_counter_handler)).Methods("POST")
	// Start the HTTP server.
	http.Handle("/", gorillaRouter)
	fmt.Println(util.BLUE+"Listening on port:", c.Gossiper_private_config.Port, util.RESET)
	err := http.ListenAndServe(":"+c.Gossiper_private_config.Port, nil)
	// We wont get here unless there's an error.
	log.Fatal("ListenAndServe: ", err)
	os.Exit(1)
}

func Gossip_object_handler(c *GossiperContext, w http.ResponseWriter, r *http.Request) {
	var gossip_obj definition.Gossip_object
	err := json.NewDecoder(r.Body).Decode(&gossip_obj)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Verify the object is valid, if invalid we just ignore it
	// CON do not have a signature on it yet
	err = gossip_obj.Verify(c.Gossiper_crypto_config)
	if err != nil {
		//fmt.Println("Received invalid object "+TypeString(gossip_obj.Type)+" from " + util.GetSenderURL(r) + ".")
		fmt.Println(util.RED, "Received invalid object "+definition.TypeString(gossip_obj.Type)+" signed by "+gossip_obj.Signer+".", util.RESET)
		http.Error(w, err.Error(), http.StatusOK)
		return
	}
	Handle_Gossip_object(c, gossip_obj)
}

func Handle_Gossip_object(c *GossiperContext, gossip_obj definition.Gossip_object) {
	// check duplicate before proceeding
	dup, err := c.IsDuplicate(gossip_obj)
	if err != nil {
		return
	}
	if dup {
		// it is a duplicate, we just ignore it
		//fmt.Println(util.RED, "Received duplicate object "+definition.TypeString(gossip_obj.Type)+" signed by "+gossip_obj.Signer+".", util.RESET)
		return
	}
	if c.InBlacklistPerm(gossip_obj.Payload[0]) {
		return
	}
	switch gossip_obj.Type {
	case definition.STH_INIT:
		Handle_STH_INIT(c, gossip_obj)
	case definition.REV_INIT:
		Handle_REV_INIT(c, gossip_obj)
	case definition.ACC_INIT:
		Handle_ACC_INIT(c, gossip_obj)
	case definition.CON_INIT:
		Handle_CON_INIT(c, gossip_obj)
	case definition.STH_FRAG, definition.REV_FRAG, definition.ACC_FRAG, definition.CON_FRAG:
		Handle_OBJ_FRAG(c, gossip_obj)
	case definition.STH_FULL, definition.REV_FULL, definition.ACC_FULL, definition.CON_FULL:
		Handle_OBJ_FULL(c, gossip_obj)
	}
}

func PoM_counter_handler(c *GossiperContext, w http.ResponseWriter, r *http.Request) {
	var pom_counter definition.PoM_Counter
	err := json.NewDecoder(r.Body).Decode(&pom_counter)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Verify the object is valid, if invalid we just ignore it
	err = pom_counter.Verify(c.Gossiper_crypto_config)
	if err != nil {
		switch pom_counter.Type {
		case definition.NUM_INIT:
			fmt.Println(util.RED, "Received invalid PoM_counter NUM_INIT signed by "+pom_counter.Signer_Monitor+".", util.RESET)
		case definition.NUM_FRAG:
			fmt.Println(util.RED, "Received invalid PoM_counter NUM_FRAG signed by "+pom_counter.Signer_Gossiper+".", util.RESET)
		case definition.NUM_FULL:
			fmt.Println(util.RED, "Received invalid PoM_counter NUM_FULL"+".", util.RESET)
		}
		http.Error(w, err.Error(), http.StatusOK)
		return
	}
	Handle_PoM_Counter(c, pom_counter)
}

func Handle_PoM_Counter(c *GossiperContext, pom_counter definition.PoM_Counter) {
	// check duplicate before proceeding
	dup, err := c.IsDuplicate(pom_counter)
	if err != nil {
		//fmt.Println(err)
		return
	}
	if dup {
		// it is a duplicate, we just ignore it
		//fmt.Println(util.RED, "Received duplicate PoM_counter "+definition.TypeString(pom_counter.Type)+" signed by "+pom_counter.Signer_Gossiper+".", util.RESET)
		return
	}
	fmt.Println(util.BLUE, "Received PoM_counter "+definition.TypeString(pom_counter.Type)+" signed by "+pom_counter.Signer_Gossiper+".", util.RESET)
	switch pom_counter.Type {
	case definition.NUM_INIT:
		Handle_NUM_INIT(c, pom_counter)
	case definition.NUM_FRAG:
		Handle_NUM_FRAG(c, pom_counter)
	case definition.NUM_FULL:
		Handle_NUM_FULL(c, pom_counter)
	}
}
func Handle_STH_INIT(c *GossiperContext, gossip_obj definition.Gossip_object) {
	icount, _ := c.GetItemCount(gossip_obj.GetID(), definition.STH_FULL)
	if icount > 0 {
		// we already have the full object, we just ignore the init
		return
	}
	icount, _ = c.GetItemCount(gossip_obj.GetID(), definition.STH_FRAG)
	if icount >= c.Gossiper_crypto_config.Threshold {
		// we already have enough fragments, we just ignore the init
		return
	}
	//check Malicious
	if c.IsMalicious(gossip_obj) {
		// if it is malicious, the list is not empty
		fmt.Println(util.RED, "Received malicious object STH_INIT signed by "+gossip_obj.Signer+".", util.RESET)
		obj_1 := c.GetObject(gossip_obj.GetID(), gossip_obj.Type)
		obj_2 := gossip_obj
		CON := c.Generate_CON_INIT(obj_1, obj_2)
		//fmt.Println("CON: ", CON)
		Handle_Gossip_object(c, CON)
		return
	}
	// if not malicious, we store the object
	c.Store(gossip_obj)
	// we send the object to the gossipers
	c.Send_to_Gossipers(gossip_obj)
	// wait and sign the object
	f := func() {
		if c.InBlacklist(gossip_obj.Payload[0]) {
			return
		}
		STH_FRAG := c.Generate_Gossip_Object_FRAG(gossip_obj)
		Handle_Gossip_object(c, STH_FRAG)
	}
	time.AfterFunc(time.Duration(c.Gossiper_public_config.Gossip_wait_time)*time.Second, f)
	return
}

func Handle_REV_INIT(c *GossiperContext, gossip_obj definition.Gossip_object) {
	icount, _ := c.GetItemCount(gossip_obj.GetID(), definition.REV_FULL)
	if icount > 0 {
		// we already have the full object, we just ignore the init
		return
	}
	icount, _ = c.GetItemCount(gossip_obj.GetID(), definition.REV_FRAG)
	if icount >= c.Gossiper_crypto_config.Threshold {
		// we already have enough fragments, we just ignore the init
		return
	}
	//check Malicious
	if c.IsMalicious(gossip_obj) {
		// if it is malicious, the list is not empty
		obj_1 := c.GetObject(gossip_obj.GetID(), gossip_obj.Type)
		obj_2 := gossip_obj
		CON := c.Generate_CON_INIT(obj_1, obj_2)
		Handle_Gossip_object(c, CON)
		return
	}
	// if not malicious, we store the object
	// we send the object to the gossipers
	c.Store(gossip_obj)
	c.Send_to_Gossipers(gossip_obj)
	// wait and sign the object
	f := func() {
		if c.InBlacklist(gossip_obj.Payload[0]) {
			return
		}
		REV_FRAG := c.Generate_Gossip_Object_FRAG(gossip_obj)
		Handle_Gossip_object(c, REV_FRAG)
	}
	time.AfterFunc(time.Duration(c.Gossiper_public_config.Gossip_wait_time)*time.Second, f)
	return
}

func Handle_ACC_INIT(c *GossiperContext, gossip_obj definition.Gossip_object) {
	icount, _ := c.GetItemCount(gossip_obj.GetID(), definition.ACC_FULL)
	if icount > 0 {
		// we already have the full object, we just ignore the init
		return
	}
	icount, _ = c.GetItemCount(gossip_obj.GetID(), definition.ACC_FRAG)
	if icount >= c.Gossiper_crypto_config.Threshold {
		// we already have enough fragments, we just ignore the init
		return
	}
	// if not malicious, we store the object
	c.Store(gossip_obj)
	f := func() {
		if c.InBlacklist(gossip_obj.Payload[0]) {
			return
		}
		ACC_FRAG := c.Generate_Gossip_Object_FRAG(gossip_obj)
		Handle_Gossip_object(c, ACC_FRAG)
	}
	time.AfterFunc(time.Duration(c.Gossiper_public_config.Gossip_wait_time)*time.Second, f)
	return
}

func Handle_CON_INIT(c *GossiperContext, gossip_obj definition.Gossip_object) {
	icount, _ := c.GetItemCount(gossip_obj.GetID(), definition.CON_FULL)
	if icount > 0 {
		return
	}
	icount, _ = c.GetItemCount(gossip_obj.GetID(), definition.CON_FRAG)
	if icount >= c.Gossiper_crypto_config.Threshold {
		return
	}
	CON2 := c.GetObject(gossip_obj.GetID(), gossip_obj.Type)
	//fmt.Println("CON2: ", CON2)
	count, _ := c.GetItemCount(gossip_obj.GetID(), gossip_obj.Type)
	if count == 0 {
		c.Store(gossip_obj)
		c.Send_to_Gossipers(gossip_obj)
	}
	// if in the store, we compare the ID
	if count == 1 && gossip_obj.Get_CON_ID() > CON2.Get_CON_ID() {
		fmt.Println(util.BLUE, "Received CON_INIT with higher CON ID than the one in the store.", util.RESET)
		c.Store(gossip_obj)
		c.Send_to_Gossipers(gossip_obj)
	}
	// wait and sign the CON
	f := func() {
		obj_tbs := c.GetObject(gossip_obj.GetID(), gossip_obj.Type)
		CON_FRAG := c.Generate_Gossip_Object_FRAG(obj_tbs)
		//fmt.Println("CON_FRAG: ", CON_FRAG)
		Handle_Gossip_object(c, CON_FRAG)
	}
	time.AfterFunc(time.Duration(c.Gossiper_public_config.Gossip_wait_time)*time.Second, f)
	return
}

func Handle_OBJ_FRAG(c *GossiperContext, gossip_obj definition.Gossip_object) {
	icount := 0
	switch gossip_obj.Type {
	case definition.STH_FRAG:
		icount, _ = c.GetItemCount(gossip_obj.GetID(), definition.STH_FULL)
	case definition.REV_FRAG:
		icount, _ = c.GetItemCount(gossip_obj.GetID(), definition.REV_FULL)
	case definition.ACC_FRAG:
		icount, _ = c.GetItemCount(gossip_obj.GetID(), definition.ACC_FULL)
	case definition.CON_FRAG:
		icount, _ = c.GetItemCount(gossip_obj.GetID(), definition.CON_FULL)
	}
	if icount > 0 {
		// we already have the full object, we just ignore the init
		fmt.Println(util.BLUE, "Received a fragment for a full object.", util.RESET)
		return
	}

	itemcount, _ := c.GetItemCount(gossip_obj.GetID(), gossip_obj.Type)
	if itemcount < c.Gossiper_crypto_config.Threshold {
		c.Store(gossip_obj)
		c.Send_to_Gossipers(gossip_obj)
	}
	if itemcount == c.Gossiper_crypto_config.Threshold-1 {
		itemlist := c.GetObjectList(gossip_obj.GetID(), gossip_obj.Type)
		target_type := gossip_obj.GetTargetType()
		obj := c.Generate_Gossip_Object_FULL(itemlist, target_type)
		fmt.Println(util.BLUE, "Generated full object: ", obj, util.RESET)
		Handle_Gossip_object(c, obj)
	}
	return
}

func Handle_OBJ_FULL(c *GossiperContext, gossip_obj definition.Gossip_object) {
	if c.InBlacklist(gossip_obj.Payload[0]) && (gossip_obj.Type == definition.STH_FULL || gossip_obj.Type == definition.REV_FULL || gossip_obj.Type == definition.ACC_FULL) {
		return
	}
	icount, _ := c.GetItemCount(gossip_obj.GetID(), gossip_obj.Type)
	if icount == 0 {
		c.Store(gossip_obj)
		c.Send_to_Gossipers(gossip_obj)
		c.Send_to_Monitor(gossip_obj)
	}
	return
}

func Handle_NUM_INIT(c *GossiperContext, pom_counter definition.PoM_Counter) {
	icount, _ := c.GetItemCount(pom_counter.GetID(), definition.NUM_FULL)
	if icount > 0 {
		return
	}
	c.Store(pom_counter)
	c.Send_to_Gossipers(pom_counter)
	itemcount, _ := c.GetItemCount(pom_counter.GetID(), pom_counter.Type)
	//fmt.Println("itemcount: ", itemcount)
	//fmt.Println("threshold: ", c.Gossiper_crypto_config.Threshold)
	if itemcount >= c.Gossiper_crypto_config.Threshold {
		NUM_FRAG := c.Generate_NUM_FRAG(pom_counter)
		fmt.Println("NUM_FRAG: ", NUM_FRAG)
		Handle_PoM_Counter(c, NUM_FRAG)
	}

}
func Handle_NUM_FRAG(c *GossiperContext, pom_counter definition.PoM_Counter) {
	fmt.Println("Handle_NUM_FRAG")
	icount, _ := c.GetItemCount(pom_counter.GetID(), definition.NUM_FULL)
	if icount > 0 {
		return
	}
	itemcount, _ := c.GetItemCount(pom_counter.GetID(), pom_counter.Type)
	if itemcount < c.Gossiper_crypto_config.Threshold {
		c.Store(pom_counter)
		c.Send_to_Gossipers(pom_counter)
	}
	if itemcount == c.Gossiper_crypto_config.Threshold-1 {
		num_frag_list := c.GetNUMList(pom_counter.GetID())
		NUM_FULL := c.Generate_NUM_FULL(num_frag_list)
		Handle_PoM_Counter(c, NUM_FULL)
	}
}
func Handle_NUM_FULL(c *GossiperContext, pom_counter definition.PoM_Counter) {
	icount, _ := c.GetItemCount(pom_counter.GetID(), definition.NUM_FULL)
	if icount == 0 {
		c.Store(pom_counter)
		c.Send_to_Gossipers(pom_counter)
		c.Send_to_Monitor(pom_counter)
	}
}

func (c *GossiperContext) Send_to_Gossipers(obj any) error {
	switch obj.(type) {
	case definition.Gossip_object:
		return Send_obj_to_Gossipers(c, obj.(definition.Gossip_object))
	case definition.PoM_Counter:
		return Send_pom_counter_to_Gossipers(c, obj.(definition.PoM_Counter))
	}
	return errors.New("Type not supported")
}

func Send_obj_to_Gossipers(c *GossiperContext, gossip_obj definition.Gossip_object) error {
	//time.Sleep(100 * time.Millisecond)
	msg, err := json.Marshal(gossip_obj)
	if err != nil {
		panic(err)
	}
	dstendpoint := ""
	switch gossip_obj.Type {
	case definition.STH_INIT:
		dstendpoint = "/gossip/sth_init"
	case definition.REV_INIT:
		dstendpoint = "/gossip/rev_init"
	case definition.ACC_INIT:
		dstendpoint = "/gossip/acc_init"
	case definition.CON_INIT:
		dstendpoint = "/gossip/con_init"
	case definition.STH_FRAG:
		dstendpoint = "/gossip/sth_frag"
	case definition.REV_FRAG:
		dstendpoint = "/gossip/rev_frag"
	case definition.ACC_FRAG:
		dstendpoint = "/gossip/acc_frag"
	case definition.CON_FRAG:
		dstendpoint = "/gossip/con_frag"
	case definition.STH_FULL:
		dstendpoint = "/gossip/sth_full"
	case definition.REV_FULL:
		dstendpoint = "/gossip/rev_full"
	case definition.ACC_FULL:
		dstendpoint = "/gossip/acc_full"
	case definition.CON_FULL:
		dstendpoint = "/gossip/con_full"
	}
	for _, url := range c.Gossiper_private_config.Connected_Gossipers {
		// HTTP POST the data to the url or IP address.
		if dstendpoint == "" {
			panic("dstendpoint is empty")
		}
		resp, err := http.Post("http://"+url+dstendpoint, "application/json", bytes.NewBuffer(msg))
		fmt.Println("Sending data to", url+dstendpoint)
		if err != nil {
			if strings.Contains(err.Error(), "Client.Timeout") ||
				strings.Contains(err.Error(), "connection refused") {
				fmt.Println(util.RED+"Connection failed to "+url+"."+" Error message: ", err, util.RESET)
				// Don't accuse gossipers for inactivity.
				// defer Accuse(c, url)
			} else {
				fmt.Println(util.RED+err.Error(), "sending to "+url+".", util.RESET)
			}
			continue
		}
		defer func() {
			if resp != nil && resp.Body != nil {
				resp.Body.Close()
			}
		}()
		//fmt.Println("Response from server:", resp.Status)
	}
	return nil
}

func Send_pom_counter_to_Gossipers(c *GossiperContext, pom_counter definition.PoM_Counter) error {
	msg, err := json.Marshal(pom_counter)
	if err != nil {
		panic(err)
	}
	dstendpoint := ""
	switch pom_counter.Type {
	case definition.NUM_INIT:
		dstendpoint = "/gossip/num_init"
	case definition.NUM_FRAG:
		dstendpoint = "/gossip/num_frag"
	case definition.NUM_FULL:
		dstendpoint = "/gossip/num_full"
	}
	for _, url := range c.Gossiper_private_config.Connected_Gossipers {
		// HTTP POST the data to the url or IP address.
		if dstendpoint == "" {
			panic("dstendpoint is empty")
		}
		resp, err := c.Client.Post("http://"+url+dstendpoint, "application/json", bytes.NewBuffer(msg))
		fmt.Println("Sending data to", url+dstendpoint)
		if err != nil {
			if strings.Contains(err.Error(), "Client.Timeout") ||
				strings.Contains(err.Error(), "connection refused") {
				fmt.Println(util.RED+"Connection failed to "+url+"."+" Error message: ", err, util.RESET)
				// Don't accuse gossipers for inactivity.
				// defer Accuse(c, url)
			} else {
				fmt.Println(util.RED+err.Error(), "sending to "+url+".", util.RESET)
			}
			continue
		}
		// Close the response, mentioned by http.Post
		// Alernatively, we could return the response from this function.
		defer func() {
			if resp != nil && resp.Body != nil {
				resp.Body.Close()
			}
		}()
		//fmt.Println("Gossiped to " + url + " and recieved " + resp.Status)
	}
	return nil
}

func (c *GossiperContext) Send_to_Monitor(obj any) {
	// Convert gossip object to JSON
	msg, err := json.Marshal(obj)
	if err != nil {
		fmt.Println(err)
	}
	endpoint := ""
	objtype := reflect.TypeOf(obj)
	fmt.Println(util.BLUE+"Sending ", objtype, " to owner", util.RESET)
	switch obj.(type) {
	case definition.Gossip_object:
		endpoint = "/monitor/recieve-gossip-from-gossiper"
	case definition.PoM_Counter:
		endpoint = "/monitor/num_full"
	}
	// Send the gossip object to the owner.
	resp, postErr := c.Client.Post("http://"+c.Gossiper_private_config.Owner_URL+endpoint, "application/json", bytes.NewBuffer(msg))
	if postErr != nil {
		fmt.Println("Error sending object to owner: " + postErr.Error())
	} else {
		// Close the response, mentioned by http.Post
		// Alernatively, we could return the response from this function.
		defer resp.Body.Close()
		if c.Verbose {
			fmt.Println("Owner responded with " + resp.Status)
		}
	}

}

func PeriodicTasks(c *GossiperContext) {
	// Immediately queue up the next task to run at next MMD.
	// Doing this first means: no matter how long the rest of the function takes,
	// the next call will always occur after the correct amount of time.
	f := func() {
		PeriodicTasks(c)
	}
	time.AfterFunc(time.Duration(c.Gossiper_public_config.MMD)*time.Second, f)
	// Run the periodic tasks.
	f1 := func() {
		c.Save()
		c.WipeStorage()
	}
	time.AfterFunc(time.Duration(c.Gossiper_public_config.MMD-20)*time.Second, f1)
}

func StartGossiperServer(c *GossiperContext) {
	// Check if the storage file exists in this directory
	//InitializeGossiperStorage(c)
	// Create the http client to be used.
	tr := &http.Transport{}
	c.Client = &http.Client{
		Transport: tr,
	}
	// HTTP Server Loop
	go PeriodicTasks(c)
	handleRequests(c)
}
