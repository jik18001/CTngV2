package gossiper

import (
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

	"github.com/jik18001/CTngV2/definition"
	"github.com/jik18001/CTngV2/util"

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
	gorillaRouter.HandleFunc("/gossip/new_payload_request", bindContext(c, Gossip_request_handler)).Methods("POST")
	gorillaRouter.HandleFunc("/gossip/new_payload_notification", bindContext(c, Gossip_notification_handler)).Methods("POST")
	// Start the HTTP server.
	http.Handle("/", gorillaRouter)
	fmt.Println(util.BLUE+"Listening on port:", c.Gossiper_private_config.Port, util.RESET)
	err := http.ListenAndServe(":"+c.Gossiper_private_config.Port, nil)
	// We wont get here unless there's an error.
	log.Fatal("ListenAndServe: ", err)
	os.Exit(1)
}

func Gossip_notification_handler(c *GossiperContext, w http.ResponseWriter, r *http.Request) {
	fmt.Println(util.BLUE + "Received a new payload notification." + util.RESET)
	var notification Gossip_Notification
	err := json.NewDecoder(r.Body).Decode(&notification)
	bytecount := r.ContentLength
	r.Body.Close()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	c.Counter1_lock.Lock()
	c.Total_traffic_received += int(bytecount)
	c.Counter1_lock.Unlock()
	newID := definition.Gossip_ID{
		Period:     notification.Period,
		Type:       notification.Type,
		Entity_URL: notification.Entity_URL,
	}
	fmt.Println(util.BLUE+"Received notification from "+notification.Sender+".", util.RESET)
	fmt.Println("notification received: ", notification)
	fmt.Println("GossipID Parsed: ", newID)
	//fmt.Println(util.BLUE+"Received notification from "+notification.Sender+".", util.RESET)
	if c.SearchPayload(newID) == false {
		url := notification.Sender
		dstendpoint := "/gossip/new_payload_request"
		notification.Sender = c.Gossiper_crypto_config.SelfID.String()
		msg, _ := json.Marshal(notification)
		c.Counter2_lock.Lock()
		c.Total_traffic_sent += len(msg)
		c.Counter2_lock.Unlock()
		resp, err := c.Client.Post("http://"+url+dstendpoint, "application/json", bytes.NewBuffer(msg))
		if err != nil {
			if strings.Contains(err.Error(), "Client.Timeout") ||
				strings.Contains(err.Error(), "connection refused") {
				fmt.Println(util.RED+"Connection failed to "+url+"."+" Error message: ", err, util.RESET)
			} else {
				fmt.Println(util.RED+err.Error(), "sending to "+url+".", util.RESET)
			}
			return
		}
		defer func() {
			if resp != nil && resp.Body != nil {
				resp.Body.Close()
			}
		}()
	}

}

func Gossip_request_handler(c *GossiperContext, w http.ResponseWriter, r *http.Request) {
	var notification Gossip_Notification
	err := json.NewDecoder(r.Body).Decode(&notification)
	bytecount := r.ContentLength
	r.Body.Close()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	c.Counter1_lock.Lock()
	c.Total_traffic_received += int(bytecount)
	c.Counter1_lock.Unlock()
	newID := definition.Gossip_ID{
		Period:     notification.Period,
		Type:       notification.Type,
		Entity_URL: notification.Entity_URL,
	}
	obj := c.GetREVrequested(newID)
	fmt.Println(util.BLUE+"Received request from "+notification.Sender+".", util.RESET)
	fmt.Println("request received: ", notification)
	fmt.Println("GossipID Parsed: ", newID)
	fmt.Println("Object Payload found: ", obj.Payload)
	if obj.Payload[0] != "" {
		dstendpoint := "/gossip/rev_init"
		msg, _ := json.Marshal(obj)
		c.Counter2_lock.Lock()
		c.Total_traffic_sent += len(msg)
		c.Counter2_lock.Unlock()
		url := notification.Sender
		resp, err := c.Client.Post("http://"+url+dstendpoint, "application/json", bytes.NewBuffer(msg))
		if err != nil {
			if strings.Contains(err.Error(), "Client.Timeout") ||
				strings.Contains(err.Error(), "connection refused") {
				fmt.Println(util.RED+"Connection failed to "+url+"."+" Error message: ", err, util.RESET)
			} else {
				fmt.Println(util.RED+err.Error(), "sending to "+url+".", util.RESET)
			}
			return
		}
		defer func() {
			if resp != nil && resp.Body != nil {
				resp.Body.Close()
			}
		}()
	}
	return
}

func Gossip_object_handler(c *GossiperContext, w http.ResponseWriter, r *http.Request) {
	// add a random delay to simulate network delay, bounded by lower and upper bounds
	//time.Sleep(time.Duration(util.GetRandomLatency(c.Min_latency, c.Max_latency)) * time.Millisecond)
	var gossip_obj definition.Gossip_object
	err := json.NewDecoder(r.Body).Decode(&gossip_obj)
	bytecount := r.ContentLength
	r.Body.Close()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	c.Counter1_lock.Lock()
	c.Total_traffic_received += int(bytecount)
	c.Counter1_lock.Unlock()
	if bytecount > int64(c.Optimization_threshold) && gossip_obj.Type == definition.REV_INIT {
		c.SavePayload(gossip_obj)
	}
	if bytecount > int64(c.Optimization_threshold) && (gossip_obj.Type == definition.REV_FRAG) {
		gossip_obj = c.ReconstructPayload(gossip_obj)
	}
	// Verify the object is valid, if invalid we just ignore it
	// CON do not have a signature on it yet
	/*
		err = gossip_obj.Verify(c.Gossiper_crypto_config)
		if err != nil {
			//fmt.Println("Received invalid object "+TypeString(gossip_obj.Type)+" from " + util.GetSenderURL(r) + ".")
			fmt.Println(util.RED, "Received invalid object "+definition.TypeString(gossip_obj.Type)+" signed by "+gossip_obj.Signer+".", util.RESET)
			http.Error(w, err.Error(), http.StatusOK)
			return
		}
	*/
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
	case definition.STH_FRAG, definition.REV_FRAG, definition.ACC_FRAG:
		Handle_OBJ_FRAG(c, gossip_obj)
	case definition.STH_FULL, definition.REV_FULL, definition.ACC_FULL:
		Handle_OBJ_FULL(c, gossip_obj)
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
	proceed := c.Store(gossip_obj)
	if !proceed {
		return
	}
	// we send the object to the gossipers
	c.Send_to_Gossipers(gossip_obj)
	// also send to the monitor
	c.Send_to_Monitor(gossip_obj)
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
	proceed := c.Store(gossip_obj)
	if !proceed {
		return
	}
	c.Send_to_Gossipers(gossip_obj)
	// also send to the monitor
	c.Send_to_Monitor(gossip_obj)
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
	proceed := c.Store(gossip_obj)
	if !proceed {
		return
	}
	if c.InBlacklist(gossip_obj.Payload[0]) {
		return
	}
	ACC_FRAG := c.Generate_Gossip_Object_FRAG(gossip_obj)
	Handle_Gossip_object(c, ACC_FRAG)
	return
}

func Handle_CON_INIT(c *GossiperContext, gossip_obj definition.Gossip_object) {
	count, _ := c.GetItemCount(gossip_obj.GetID(), gossip_obj.Type)
	if count == 0 {
		proceed := c.Store(gossip_obj)
		if !proceed {
			return
		}
		c.Send_to_Gossipers(gossip_obj)
		c.Send_to_Monitor(gossip_obj)
	}
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
	}
	if icount > 0 {
		// we already have the full object, we just ignore the fragment
		fmt.Println(util.BLUE, "Received a fragment for a full object.", util.RESET)
		return
	}
	itemcount := 0
	switch gossip_obj.Type {
	case definition.STH_FRAG, definition.REV_FRAG, definition.ACC_FRAG:
		itemcount = c.Read_and_Store_If_Needed(gossip_obj)
	}
	//fmt.Println(itemcount)
	if itemcount == c.Gossiper_crypto_config.Threshold-1 {
		itemlist := c.GetObjectList(gossip_obj.GetID(), gossip_obj.Type)
		target_type := gossip_obj.GetTargetType()
		obj := c.Generate_Gossip_Object_FULL(itemlist, target_type)
		fmt.Println(util.BLUE, "Generated full object: ", obj.Type, util.RESET)
		Handle_Gossip_object(c, obj)
	}
	if itemcount < c.Gossiper_crypto_config.Threshold {
		c.Send_to_Gossipers(gossip_obj)
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
		c.Send_to_Monitor(gossip_obj)
	}
	if c.IsConvergent() {
		c.Converge_time = util.GetCurrentSecond()
		fmt.Println(util.BLUE, "Converge time: ", c.Converge_time, util.RESET)
	}

	return
}

func (c *GossiperContext) Send_to_Gossipers(obj any) error {
	switch obj.(type) {
	case definition.Gossip_object:
		return Send_obj_to_Gossipers(c, obj.(definition.Gossip_object))
	}
	return errors.New("Type not supported")
}

/*
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
	case definition.STH_FULL:
		dstendpoint = "/gossip/sth_full"
	case definition.REV_FULL:
		dstendpoint = "/gossip/rev_full"
	case definition.ACC_FULL:
		dstendpoint = "/gossip/acc_full"
	}
	for _, url := range c.Gossiper_private_config.Connected_Gossipers {
		// HTTP POST the data to the url or IP address.
		if dstendpoint == "" {
			panic("dstendpoint is empty")
		}
		resp, err := http.Post("http://"+url+dstendpoint, "application/json", bytes.NewBuffer(msg))
		//fmt.Println("Sending data to", url+dstendpoint)
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
*/

func Send_obj_to_Gossipers(c *GossiperContext, gossip_obj definition.Gossip_object) error {
	msg, err := json.Marshal(gossip_obj)
	if err != nil {
		panic(err)
	}
	dstendpoint := ""
	bytecount := len(msg)
	if bytecount > c.Optimization_threshold && (gossip_obj.Type == definition.REV_INIT) {
		//fmt.Println("Optimization threshold reached")
		var notification Gossip_Notification
		GID := gossip_obj.GetID()
		notification.Sender = c.Gossiper_crypto_config.SelfID.String()
		notification.Period = GID.Period
		notification.Type = GID.Type
		notification.Entity_URL = GID.Entity_URL
		msg, _ = json.Marshal(notification)
		bytecount = len(msg)
		c.Counter2_lock.Lock()
		c.Total_traffic_sent += bytecount * len(c.Gossiper_private_config.Connected_Gossipers)
		c.Counter2_lock.Unlock()
		dstendpoint = "/gossip/new_payload_notification"
	} else {
		if bytecount > c.Optimization_threshold && (gossip_obj.Type == definition.REV_FRAG) {
			gossip_obj := c.Remove_Payload(gossip_obj)
			msg, _ = json.Marshal(gossip_obj)
			bytecount = len(msg)
		}
		c.Counter2_lock.Lock()
		c.Total_traffic_sent += bytecount * len(c.Gossiper_private_config.Connected_Gossipers)
		c.Counter2_lock.Unlock()
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
		case definition.STH_FULL:
			dstendpoint = "/gossip/sth_full"
		case definition.REV_FULL:
			dstendpoint = "/gossip/rev_full"
		case definition.ACC_FULL:
			dstendpoint = "/gossip/acc_full"
		}
	}
	for _, url := range c.Gossiper_private_config.Connected_Gossipers {
		go func(url, dstendpoint string) {
			if c.Max_latency > 0 {
				time.Sleep(time.Duration(util.GetRandomLatency(c.Min_latency, c.Max_latency)) * time.Millisecond) // Delay before sending
			}

			resp, err := c.Client.Post("http://"+url+dstendpoint, "application/json", bytes.NewBuffer(msg))
			if err != nil {
				if strings.Contains(err.Error(), "Client.Timeout") ||
					strings.Contains(err.Error(), "connection refused") {
					fmt.Println(util.RED + "Connection failed to " + url + "." + " Error message: " + err.Error() + util.RESET)
					// Don't accuse gossipers for inactivity.
					// defer Accuse(c, url)
				} else {
					fmt.Println(util.RED + err.Error() + " sending to " + url + "." + util.RESET)
				}
				return
			}

			defer func() {
				if resp != nil && resp.Body != nil {
					resp.Body.Close()
				}
			}()

			//fmt.Println("Response from server:", resp.Status)
		}(url, dstendpoint)
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
		endpoint = "/monitor/receive-gossip-from-gossiper"
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
	time_wait := util.Getwaitingtime(c.Gossiper_public_config.MMD)
	fmt.Println("Waiting for ", time_wait, " seconds")
	time.Sleep(time.Duration(time_wait) * time.Second)
	tr := &http.Transport{
		MaxIdleConnsPerHost: 300,
		MaxConnsPerHost:     300,
		WriteBufferSize:     1024 * 1024, // 1MB
		ReadBufferSize:      1024 * 1024, // 1MB
	}
	c.Client = &http.Client{
		Transport: tr,
	}
	// HTTP Server Loop
	go PeriodicTasks(c)
	handleRequests(c)
}
