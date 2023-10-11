package monitor

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/jik18001/CTngV2/util"

	"github.com/gorilla/mux"
)

const PROTOCOL = "http://"

func bindMonitorContext(context *MonitorContext, fn func(context *MonitorContext, w http.ResponseWriter, r *http.Request)) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		fn(context, w, r)
	}
}

func handleMonitorRequests(c *MonitorContext) {
	// MUX which routes HTTP directories to functions.
	gorillaRouter := mux.NewRouter().StrictSlash(true)
	// POST functions
	gorillaRouter.HandleFunc("/monitor/get-update", bindMonitorContext(c, requestupdate)).Methods("GET")
	//gorillaRouter.HandleFunc("/monitor/receive-gossip", bindMonitorContext(c, handle_gossip)).Methods("POST")
	gorillaRouter.HandleFunc("/monitor/receive-gossip-from-gossiper", bindMonitorContext(c, handle_gossip_from_gossiper)).Methods("POST")
	// Start the HTTP server.
	http.Handle("/", gorillaRouter)
	// Listen on port set by config until server is stopped.
	log.Fatal(http.ListenAndServe(":"+c.Monitor_private_config.Port, nil))
}

func StartMonitorServer(c *MonitorContext) {
	if c.Mode == 0 {
		time_wait := util.Getwaitingtime(c.Monitor_public_config.MMD)
		fmt.Println("Waiting for ", time_wait, " seconds")
		time.Sleep(time.Duration(time_wait) * time.Second)
	}
	time.Sleep(time.Duration(c.Clockdrift_miliseconds) * time.Millisecond)
	tr := &http.Transport{
		MaxIdleConnsPerHost: 10,
		MaxConnsPerHost:     300,
		WriteBufferSize:     1024 * 1024, // 1MB
		ReadBufferSize:      1024 * 1024, // 1MB
	}
	c.Client = &http.Client{
		Transport: tr,
	}
	fmt.Println("Monitor ", c.StorageID, " running on Period ", util.GetCurrentPeriod())
	// Run a go routine to handle tasks that must occur every MMD
	go PeriodicTasks(c)
	// Start HTTP server loop on the main thread
	handleMonitorRequests(c)
}
