package monitor

import (
	"CTngV2/crypto"
	"CTngV2/definition"
	"CTngV2/util"
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/bits-and-blooms/bitset"
)

/*
func receiveGossip(c *MonitorContext, w http.ResponseWriter, r *http.Request) {
	// Post request, parse sent object.
	body, err := ioutil.ReadAll(r.Body)
	// If there is an error, post the error and terminate.
	if err != nil {
		panic(err)
	}
	// Converts JSON passed in the body of a POST to a Gossip_object.
	var gossip_obj definition.Gossip_object
	err = json.NewDecoder(r.Body).Decode(&gossip_obj)
	// Prints the body of the post request to the server console
	log.Println(string(body))
	// Use a mapped empty interface to store the JSON object.
	var postData map[string]interface{}
	// Decode the JSON object stored in the body
	err = json.Unmarshal(body, &postData)
	// If there is an error, post the error and terminate.
	if err != nil {
		panic(err)
	}
}*/

func handle_gossip_from_gossiper(c *MonitorContext, w http.ResponseWriter, r *http.Request) {
	var gossip_obj definition.Gossip_object
	err := json.NewDecoder(r.Body).Decode(&gossip_obj)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
	if c.IsDuplicate(gossip_obj) {
		// If the object is already stored, still return OK.{
		//fmt.Println("Duplicate:", definition.TypeString(gossip_obj.Type), util.GetSenderURL(r)+".")
		http.Error(w, "Gossip object already stored.", http.StatusOK)
		// processDuplicateObject(c, gossip_obj, stored_obj)
		return
	} else {
		fmt.Println("received new, valid", definition.TypeString(gossip_obj.Type), "from gossiper.")
		switch gossip_obj.Type {
		case definition.STH_INIT, definition.REV_INIT:
			c.StoreObject(gossip_obj)
		default:
			Process_valid_object(c, gossip_obj)
		}
	}
}

/*
func handle_gossip(c *MonitorContext, w http.ResponseWriter, r *http.Request) {
	// Parse sent object.
	// Converts JSON passed in the body of a POST to a Gossip_object.
	var gossip_obj definition.Gossip_object
	err := json.NewDecoder(r.Body).Decode(&gossip_obj)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
	// Verify the object is valid.
	err = gossip_obj.Verify(c.Monitor_crypto_config)
	if err != nil {
		fmt.Println("received invalid object from " + util.GetSenderURL(r) + ".")
		AccuseEntity(c, gossip_obj.Signer)
		http.Error(w, err.Error(), http.StatusOK)
		return
	}
	// Check for duplicate object.
	if c.IsDuplicate(gossip_obj) {
		// If the object is already stored, still return OK.{
		//fmt.Println("Duplicate:", definition.TypeString(gossip_obj.Type), util.GetSenderURL(r)+".")
		http.Error(w, "Gossip object already stored.", http.StatusOK)
		// processDuplicateObject(c, gossip_obj, stored_obj)
		return
	} else {
		fmt.Println("received new, valid", gossip_obj.Type, ".")
		Process_valid_object(c, gossip_obj)
	}
	http.Error(w, "Gossip object Processed.", http.StatusOK)
}
*/

func QueryLoggers(c *MonitorContext) {
	for _, logger := range c.Monitor_private_config.Logger_URLs {
		// var today = time.Now().UTC().Format(time.RFC3339)[0:10]
		if Check_entity_pom(c, logger) {
			fmt.Println(util.RED, "There is a PoM against this Logger. Query will not be initiated", util.RESET)
		} else {
			fmt.Println(util.GREEN + "Querying Logger Initiated" + util.RESET)
			sthResp, err1 := http.Get(PROTOCOL + logger + "/ctng/v2/get-sth/")
			if err1 != nil {
				//log.Println(util.RED+"Query Logger Failed: "+err.Error(), util.RESET)
				log.Println(util.RED+"Query Logger Failed, connection refused.", util.RESET)
				Wait_then_accuse(c, logger, "logger")
				return
			} else {
				sthBody, err2 := ioutil.ReadAll(sthResp.Body)
				var STH definition.Gossip_object
				err2 = json.Unmarshal(sthBody, &STH)
				if err2 != nil {
					log.Println(util.RED+err2.Error(), util.RESET)
					Wait_then_accuse(c, logger, "logger")
					return
				} else {
					err3 := STH.Verify(c.Monitor_crypto_config)
					if err3 != nil {
						log.Println(util.RED+"STH signature verification failed", err3.Error(), util.RESET)
						Wait_then_accuse(c, logger, "logger")
						return
					} else {
						Process_valid_object(c, STH)
					}
				}
			}
		}
	}

}

// Queries CAs for revocation information
// The revocation datapath hasn't been very fleshed out currently, nor has this function.
func QueryAuthorities(c *MonitorContext) {
	for _, CA := range c.Monitor_private_config.CA_URLs {

		// Get today's revocation information from CA.
		// Get today's date in format YYYY-MM-DD
		// var today = time.Now().UTC().Format(time.RFC3339)[0:10]
		if Check_entity_pom(c, CA) {
			fmt.Println(util.RED, "There is a PoM against this CA. Query will not be initiated", util.RESET)
		} else {
			fmt.Println(util.GREEN + "Querying CA Initiated" + util.RESET)
			revResp, err1 := http.Get(PROTOCOL + CA + "/ctng/v2/get-revocation/")
			if err1 != nil {
				//log.Println(util.RED+"Query CA failed: "+err.Error(), util.RESET)
				log.Println(util.RED+"Query CA Failed, connection refused.", util.RESET)
				Wait_then_accuse(c, CA, "ca")
				continue
			} else {
				revBody, err2 := ioutil.ReadAll(revResp.Body)
				if err2 != nil {
					log.Println(util.RED+err2.Error(), util.RESET)
					Wait_then_accuse(c, CA, "ca")
					return
				} else {
					var REV definition.Gossip_object
					err3 := json.Unmarshal(revBody, &REV)
					if err3 != nil {
						log.Println(util.RED+err3.Error(), util.RESET)
						Wait_then_accuse(c, CA, "ca")
						return
					} else {
						err4 := REV.Verify(c.Monitor_crypto_config)
						if err4 != nil {
							log.Println(util.RED+"Revocation information signature verification failed", err4.Error(), util.RESET)
							Wait_then_accuse(c, CA, "ca")
							return
						} else {
							SRH, DCRV := Get_SRH_and_DCRV(REV)
							key := REV.Payload[0]
							pass := c.VerifySRH(SRH, &DCRV, key, REV.Period)
							if !pass {
								fmt.Println("SRH verification failed")
								Wait_then_accuse(c, CA, "ca")
								return
							} else {
								fmt.Println("REV Payload: " + REV.Payload[0] + REV.Payload[1] + REV.Payload[2])
								Process_valid_object(c, REV)
							}
						}
					}
				}
			}
		}
	}
}

// This function accuses the entity if the domain name is provided
// It is called when the gossip object received is not valid, or the monitor didn't get response when querying the logger or the CA
// Accused = Domain name of the accused entity (logger etc.)
func AccuseEntity(c *MonitorContext, Accused string) {
	if Check_entity_pom(c, Accused) {
		return
	}
	msg := Accused
	var payloadarray [3]string
	payloadarray[0] = msg
	payloadarray[1] = ""
	payloadarray[2] = ""
	signature, _ := c.Monitor_crypto_config.Sign([]byte(payloadarray[0] + payloadarray[1] + payloadarray[2]))
	var sigarray [2]string
	sigarray[0] = signature.String()
	sigarray[1] = ""
	accusation := definition.Gossip_object{
		Application:   "CTng",
		Type:          definition.ACC_INIT,
		Period:        util.GetCurrentPeriod(),
		Signer:        c.Monitor_crypto_config.SelfID.String(),
		Timestamp:     util.GetCurrentTimestamp(),
		Signature:     sigarray,
		Crypto_Scheme: "RSA",
		Payload:       payloadarray,
	}
	//fmt.Println(util.BLUE+"New accusation from ",accusation.Signer, c.Monitor_crypto_Monitor_private_configSignaturePublicMap[signature.ID], "generated, Sending to gossiper"+util.RESET)
	Send_to_gossiper(c, accusation)
}

func Wait_then_accuse(c *MonitorContext, Accused string, Entity_type string) {
	var GID definition.Gossip_ID
	var ok bool
	f := func() {
		if Entity_type == "logger" {
			GID = definition.Gossip_ID{
				Period:     util.GetCurrentPeriod(),
				Type:       definition.STH_INIT,
				Entity_URL: Accused,
			}
			_, ok = (*c.Storage_TEMP)[GID]
		} else if Entity_type == "ca" {
			GID = definition.Gossip_ID{
				Period:     util.GetCurrentPeriod(),
				Type:       definition.REV_INIT,
				Entity_URL: Accused,
			}
			_, ok = (*c.Storage_TEMP)[GID]
		}
		if Check_entity_pom(c, Accused) == false && !ok {
			AccuseEntity(c, Accused)
		}
	}
	time.AfterFunc(time.Duration(c.Monitor_public_config.Gossip_wait_time)*time.Second, f)
}

// Send the input gossip object to its gossiper
func Send_to_gossiper(c *MonitorContext, g definition.Gossip_object) {
	// Convert gossip object to JSON
	msg, err := json.Marshal(g)
	if err != nil {
		fmt.Println(err)
	}
	// Send the gossip object to the gossiper.
	gossiperendpoint := ""
	switch g.Type {
	case definition.ACC_INIT:
		gossiperendpoint = "/gossip/acc_init"
	case definition.STH_INIT:
		gossiperendpoint = "/gossip/sth_init"
	case definition.REV_INIT:
		gossiperendpoint = "/gossip/rev_init"
	}
	resp, postErr := c.Client.Post(PROTOCOL+c.Monitor_private_config.Gossiper_URL+gossiperendpoint, "application/json", bytes.NewBuffer(msg))
	if postErr != nil {
		fmt.Println(util.RED+"Error sending object to Gossiper: ", postErr.Error(), util.RESET)
	} else {
		// Close the response, mentioned by http.Post
		// Alernatively, we could return the response from this function.
		defer resp.Body.Close()
		fmt.Println(util.BLUE+"Sent", definition.TypeString(g.Type), "to Gossiper, received "+resp.Status, util.RESET)
	}

}

// this function takes the name of the entity as input and check if there is a POM against it
// this should be invoked after the monitor receives the information from its loggers and CAs prior to threshold signning it
func Check_entity_pom(c *MonitorContext, Accused string) bool {
	GID := definition.Gossip_ID{
		Period:     util.GetCurrentPeriod(),
		Type:       definition.ACC_FULL,
		Entity_URL: Accused,
	}
	if _, ok := (*c.Storage_ACCUSATION_POM)[GID]; ok {
		fmt.Println(util.BLUE + "Entity has Accusation_PoM on file, no need for more accusations." + util.RESET)
		return true
	}
	GID2 := definition.Gossip_ID{
		Period:     "0",
		Type:       definition.CON_INIT,
		Entity_URL: Accused,
	}
	if _, ok := (*c.Storage_CONFLICT_POM)[GID2]; ok {
		fmt.Println(util.BLUE + "Entity has Conflict_PoM on file, no need for more accusations." + util.RESET)
		return true
	}
	return false
}

func IsLogger(c *MonitorContext, loggerURL string) bool {
	for _, url := range c.Monitor_public_config.All_Logger_URLs {
		if url == loggerURL {
			return true
		}
	}
	return false
}

func IsAuthority(c *MonitorContext, authURL string) bool {
	for _, url := range c.Monitor_public_config.All_CA_URLs {
		if url == authURL {
			return true
		}
	}
	return false
}

func GenerateUpdate(c *MonitorContext) ClientUpdate {
	storageList_sth_full := []definition.Gossip_object{}
	storageList_rev_full := []definition.Gossip_object{}
	storageList_pom_con := []definition.Gossip_object{}
	storageList_pom_acc := []definition.Gossip_object{}
	for _, gossipObject := range *c.Storage_STH_FULL {
		storageList_sth_full = append(storageList_sth_full, gossipObject)
	}
	for _, gossipObject := range *c.Storage_REV_FULL {
		storageList_rev_full = append(storageList_rev_full, gossipObject)
	}
	for _, gossipObject := range *c.Storage_CONFLICT_POM_DELTA {
		storageList_pom_con = append(storageList_pom_con, gossipObject)
	}
	for _, gossipObject := range *c.Storage_ACCUSATION_POM_DELTA {
		storageList_pom_acc = append(storageList_pom_acc, gossipObject)
	}
	CTupdate := ClientUpdate{
		STHs:      storageList_sth_full,
		REVs:      storageList_rev_full,
		POM_CONs:  storageList_pom_con,
		POM_ACCs:  storageList_pom_acc,
		MonitorID: c.Monitor_crypto_config.SelfID.String(),
		Period:    util.GetCurrentPeriod(),
	}
	return CTupdate
}

func PeriodicTasks(c *MonitorContext) {
	// Immediately queue up the next task to run at next MMD.
	// Doing this first means: no matter how long the rest of the function takes,
	// the next call will always occur after the correct amount of time.
	f := func() {
		PeriodicTasks(c)
	}
	time.AfterFunc(time.Duration(c.Monitor_public_config.MMD)*time.Second, f)
	// Run the periodic tasks.
	if c.Maxdrift_miliseconds > 0 {
		tasks := func() {
			QueryLoggers(c)
			QueryAuthorities(c)
		}
		time.AfterFunc(time.Duration(c.Maxdrift_miliseconds)*time.Millisecond, tasks)
	} else {
		QueryLoggers(c)
		QueryAuthorities(c)
	}
	f1 := func() {
		c.Clean_Conflicting_Object()
		c.WipeStorage()
		update := GenerateUpdate(c)
		current, _ := strconv.Atoi(util.GetCurrentPeriod())
		offsetint, _ := strconv.Atoi(c.Period_Offset)
		PeriodIO := strconv.Itoa(current - offsetint)
		c.SaveStorage(PeriodIO, update)
	}
	time.AfterFunc(time.Duration(c.Monitor_public_config.MMD-20)*time.Second, f1)
}

// This function is called by handle_gossip in monitor_server.go under the server folder
// It will be called if the gossip object is validated
func Process_valid_object(c *MonitorContext, g definition.Gossip_object) {
	//This handles the STHS from querying loggers
	if g.Type == definition.STH_INIT && IsLogger(c, g.Signer) {
		// Send an unsigned copy to the gossiper if the STH is from the logger
		//fmt.Println(g.Signature[0])
		Send_to_gossiper(c, g)
	}
	//this handles revocation information from querying CAs
	if g.Type == definition.REV_INIT && IsAuthority(c, g.Signer) {
		// Send an unsigned copy to the gossiper if the REV is received from a CA
		Send_to_gossiper(c, g)
	}
	//this handles processed gossip object from the gossiper, verfications will be added when if needed
	if g.Type == definition.ACC_FULL || g.Type == definition.CON_INIT || g.Type == definition.STH_FULL || g.Type == definition.REV_FULL {
		c.StoreObject(g)
	}
	return
}

func (ctx *MonitorContext) VerifySRH(srh string, dCRV *bitset.BitSet, CAID string, Period string) bool {
	// find the corresponding CRV
	CRV_old := ctx.Storage_CRV[CAID]
	if CRV_old == nil {
		CRV_old = dCRV
	}
	// verify the SRH
	hashmsg1, _ := CRV_old.MarshalBinary()
	hashmsg2, _ := dCRV.MarshalBinary()
	hash1, _ := crypto.GenerateSHA256(hashmsg1)
	hash2, _ := crypto.GenerateSHA256(hashmsg2)

	localhash, _ := crypto.GenerateSHA256([]byte(Period + string(hash1) + string(hash2)))
	// the localhash will be te message we used to verify the Signature on the SRH
	// verify the signature
	rsasig, err := crypto.RSASigFromString(srh)
	if err != nil {
		fmt.Println("Fail to convert the signature from the SRH to RSA signature")
	}
	ca_publickey := ctx.Monitor_crypto_config.SignPublicMap[rsasig.ID]
	err = crypto.RSAVerify(localhash, rsasig, &ca_publickey)
	if err != nil {
		fmt.Println("Fail to verify the signature on the SRH")
		return false
	}
	//fmt.Println("SRH verification success")
	return true
}
