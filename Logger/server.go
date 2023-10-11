package Logger

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"strconv"
	"time"

	"github.com/jik18001/CTngV2/CA"
	"github.com/jik18001/CTngV2/crypto"
	"github.com/jik18001/CTngV2/definition"
	"github.com/jik18001/CTngV2/util"

	"github.com/gorilla/mux"
)

const PROTOCOL = "http://"

// bind Logger context to the function
func bindLoggerContext(context *LoggerContext, fn func(context *LoggerContext, w http.ResponseWriter, r *http.Request)) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		fn(context, w, r)
	}
}

func handleLoggerRequests(ctx *LoggerContext) {
	// MUX which routes HTTP directories to functions.
	gorillaRouter := mux.NewRouter().StrictSlash(true)
	// POST functions

	// receive precerts from CA
	gorillaRouter.HandleFunc("/Logger/receive-precerts", bindLoggerContext(ctx, receive_pre_cert)).Methods("POST")
	// get sth request from Monitor
	gorillaRouter.HandleFunc("/ctng/v2/get-sth", bindLoggerContext(ctx, requestSTH)).Methods("GET")
	//start the HTTP server
	http.Handle("/", gorillaRouter)
	// Listen on port set by config until server is stopped.
	log.Fatal(http.ListenAndServe(":"+ctx.Logger_private_config.Port, nil))
}

func requestSTH(c *LoggerContext, w http.ResponseWriter, r *http.Request) {
	if c.Maxlatency > 0 {
		time.Sleep(time.Duration(rand.Intn(c.Maxlatency)) * time.Millisecond)
	}
	// get current period
	Period := util.GetCurrentPeriod()
	c.Request_Count_lock.Lock()
	defer c.Request_Count_lock.Unlock()
	c.Request_Count = c.Request_Count + 1
	switch c.Logger_Type {
	case 0:
		// normal logger
		json.NewEncoder(w).Encode(c.STH_storage[Period])
		return
	case 1:
		// split-world logger
		if c.Request_Count%c.MisbehaviorInterval == 0 && c.OnlineDuration == 1 {
			// misbehave
			json.NewEncoder(w).Encode(c.STH_storage_fake[Period])
			return
		} else {
			json.NewEncoder(w).Encode(c.STH_storage[Period])
			return
		}
	case 2:
		// ALways unresponsive logger
		// do nothing
		return
	case 3:
		// sometimes unresponsive logger
		if c.Request_Count%c.MisbehaviorInterval == 0 || c.OnlineDuration == 1 {
			// misbehave
			return
		} else {
			json.NewEncoder(w).Encode(c.STH_storage[Period])
			return
		}
	case 4:
		// Split-world-logger on second round since requested by monitor, behave normally on other rounds
		if c.Request_Count%c.MisbehaviorInterval == 0 && c.OnlineDuration == 1 {
			json.NewEncoder(w).Encode(c.STH_storage_fake[Period])
			return
		} else {
			json.NewEncoder(w).Encode(c.STH_storage[Period])
			return
		}
	case 5:
		// always unresponsive logger on second round since requested by monitor, behave normally on other rounds
		if c.OnlineDuration == 1 {
			return
		} else {
			json.NewEncoder(w).Encode(c.STH_storage[Period])
			return
		}
	case 6:
		// sometimes unreponsive on second round since requested by monitor, behave normally on other rounds
		if c.Request_Count%c.MisbehaviorInterval == 0 && c.OnlineDuration == 1 {
			return
		} else {
			json.NewEncoder(w).Encode(c.STH_storage[Period])
			return
		}
	}
}

// receive precert from CA
func receive_pre_cert(c *LoggerContext, w http.ResponseWriter, r *http.Request) {
	// Unmarshal the request body into a precert
	var cert_ca *x509.Certificate
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		fmt.Printf("Error: %s\n", err)
		return
	}
	// Parse the DER-encoded certificate
	cert_ca = CA.Unmarshall_Signed_PreCert(body)
	// remove signature
	precert := util.ParseTBSCertificate(cert_ca)
	fmt.Println(precert.SubjectKeyId)
	// add to precert pool
	c.CertPool_lock.Lock()
	c.CurrentPrecertPool.AddCert(precert)
	c.CertPool_lock.Unlock()
}

// send STH to CA
func Send_STH_to_CA(c *LoggerContext, sth definition.Gossip_object, ca string) {
	//roohashsent, _ := definition.ExtractRootHash(sth)
	//fmt.Println("RootHash sent: ", roohashsent)
	sth_json, err := json.Marshal(sth)
	if err != nil {
		log.Fatalf("Failed to marshal STH: %v", err)
	}
	resp, err := c.Client.Post(PROTOCOL+ca+"/CA/receive-sth", "application/json", bytes.NewBuffer(sth_json))
	if err != nil {
		fmt.Println("Failed to send STH to CA: ", err)
	} else {
		defer resp.Body.Close()
	}
}

// Send one POI to CA
func Send_POI_to_CA(c *LoggerContext, poi crypto.POI_for_transmission, ca string) {
	poi_json, err := json.Marshal(poi)
	if err != nil {
		log.Fatalf("Failed to marshal POI: %v", err)
	}
	//fmt.Println("POI sent: ", poi_json)
	resp, err := c.Client.Post(PROTOCOL+ca+"/CA/receive-poi", "application/json", bytes.NewBuffer(poi_json))
	if err != nil {
		fmt.Println("Failed to send POI to CA: ", err)
	}
	defer resp.Body.Close()
}

func Send_POIs_to_CAs(c *LoggerContext, POIs []crypto.POI_for_transmission, roothash []byte) {
	//iterate over the POIs
	for i := 0; i < len(POIs); i++ {
		// create POI, using merkle node.ProofofInclusion and node.SubjectKeyId
		if len(POIs[i].SubjectKeyId) != 0 {
			//fmt.Println([]byte(POIs[i].SubjectKeyId))
			precert := c.CurrentPrecertPool.GetCertBySubjectKeyID(string(POIs[i].SubjectKeyId))
			pass, err := crypto.VerifyPOI(roothash, POIs[i].Poi, *precert)
			if err != nil || pass == false {
				fmt.Println("POI verification failed: ", err)
				return
			}
			// Get the Issuer CA
			ca := POIs[i].Issuer
			// send POI to CA
			Send_POI_to_CA(c, POIs[i], ca)
			SaveToStorage(*c)
		}
	}
}

func GetCurrentPeriod() string {
	timerfc := time.Now().UTC().Format(time.RFC3339)
	Miniutes, err := strconv.Atoi(timerfc[14:16])
	Periodnum := strconv.Itoa(Miniutes)
	if err != nil {
	}
	return Periodnum
}

func GerCurrentSecond() string {
	timerfc := time.Now().UTC().Format(time.RFC3339)
	Second, err := strconv.Atoi(timerfc[17:19])
	Secondnum := strconv.Itoa(Second)
	if err != nil {
	}
	return Secondnum
}

// Periodic task
func PeriodicTask(ctx *LoggerContext) {
	f := func() {
		PeriodicTask(ctx)
	}
	time.AfterFunc(time.Duration(ctx.Logger_public_config.MMD)*time.Second, f)
	fmt.Println("——————————————————————————————————Logger Running Tasks at Period ", GetCurrentPeriod(), "——————————————————————————————————")
	f1 := func() {
		//fmt.Println(GerCurrentSecond())
		// update online period
		ctx.OnlinePeriod = ctx.OnlinePeriod + 1
		// Compute STH and POIs
		period := util.GetCurrentPeriod()
		// convert to int, and add 1 then convert back to string
		periodint, err := strconv.Atoi(period)
		if err != nil {
		}
		periodint = periodint + 1
		period = strconv.Itoa(periodint)
		// add a leading zero if the period is less than 10
		if periodint < 10 {
			period = "0" + period
		}
		// update STH
		certlist := ctx.CurrentPrecertPool.GetCerts()
		fmt.Println("len of certlist: ", len(certlist))
		//fmt.Println("certlist: ", certlist)
		STH, sth, POIs := BuildMerkleTreeFromCerts(certlist, *ctx, periodint)
		// duplicate the STH for testing
		certlist2 := ctx.CurrentPrecertPool.GetCerts()
		certlist2 = append(certlist2, certlist2[0])
		fmt.Println("len of certlist2: ", len(certlist2))
		STH_FAKE, _, _ := BuildMerkleTreeFromCerts(certlist2, *ctx, periodint)
		//fmt.Println("STH: ", STH)
		// update STH storage
		ctx.STH_storage[period] = STH
		ctx.STH_storage_fake[period] = STH_FAKE
		// send STH to all CAs
		// fmt.Println(ctx.Logger_public_config.All_CA_URLs)
		for i := 0; i < len(ctx.Logger_public_config.All_CA_URLs); i++ {
			Send_STH_to_CA(ctx, STH, ctx.Logger_public_config.All_CA_URLs[i])
		}
		// send POI to the Issuer CA
		Send_POIs_to_CAs(ctx, POIs, sth)
		ctx.Request_Count_lock.Lock()
		if ctx.Request_Count > 0 {
			ctx.OnlineDuration = ctx.OnlineDuration + 1
		}
		ctx.Request_Count = 0
		ctx.Request_Count_lock.Unlock()
		// clear the cert pool
		ctx.CurrentPrecertPool = crypto.NewCertPool()
	}
	time.AfterFunc(time.Duration(ctx.Logger_public_config.MMD-20)*time.Second, f1)
}

// Start the logger
func StartLogger(c *LoggerContext) {
	// set up HTTP client
	tr := &http.Transport{
		MaxIdleConnsPerHost: 300,
		MaxConnsPerHost:     300,
		WriteBufferSize:     1024 * 1024, // 1MB
		ReadBufferSize:      1024 * 1024, // 1MB
	}
	c.Client = &http.Client{
		Transport: tr,
	}
	// start at second 0
	currentsecond := GerCurrentSecond()
	// if current second is not 0
	if currentsecond != "0" {
		// wait for 60 - current second
		second, err := strconv.Atoi(currentsecond)
		if err != nil {
		}
		second = 60 - second
		//print wait time
		fmt.Println("Logger will start after", second, "seconds")
		time.Sleep(time.Duration(second) * time.Second)
	}
	// handle request and wait 55 seconds
	go PeriodicTask(c)
	handleLoggerRequests(c)
}
