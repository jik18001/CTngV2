package main

import (
	"CTngV2/CA"
	"CTngV2/Logger"
	"CTngV2/gossiper"
	"CTngV2/monitor"
	"CTngV2/util"
	"fmt"
	"os"
	"time"
)

// Sometimes unresponsive CA and Logger

func StartCA(id string) {
	pathPrefix := "../ca_testconfig/" + id
	path1 := pathPrefix + "/CA_public_config.json"
	path2 := pathPrefix + "/CA_private_config.json"
	path3 := pathPrefix + "/CA_crypto_config.json"
	caContext := CA.InitializeCAContext(path1, path2, path3)
	caContext.OnlineDuration = 0
	caContext.MisbehaviorInterval = 8 // Every other period (i.e., 8 requests)
	caContext.CA_Type = 3
	CA.StartCA(caContext)
}

func StartLogger(id string) {
	pathPrefix := "../logger_testconfig/" + id
	path1 := pathPrefix + "/Logger_public_config.json"
	path2 := pathPrefix + "/Logger_private_config.json"
	path3 := pathPrefix + "/Logger_crypto_config.json"
	loggerContext := Logger.InitializeLoggerContext(path1, path2, path3)
	loggerContext.OnlineDuration = 0
	loggerContext.MisbehaviorInterval = 8
	loggerContext.Logger_Type = 3
	Logger.StartLogger(loggerContext)
}

func StartMonitor(id string) {
	pathPrefix := "../monitor_testconfig/" + id
	path1 := pathPrefix + "/Monitor_public_config.json"
	path2 := pathPrefix + "/Monitor_private_config.json"
	path3 := pathPrefix + "/Monitor_crypto_config.json"
	monitorContext := monitor.InitializeMonitorContext(path1, path2, path3, id)

	// clean up the storage
	monitorContext.InitializeMonitorStorage("monitor_testdata/")

	// delete all the files in the storage
	monitorContext.CleanUpMonitorStorage()

	// wait for 60 seconds
	fmt.Println("Monitor server will start in 1 minute")
	time.Sleep(60 * time.Second)
	monitor.StartMonitorServer(monitorContext)
}

func StartGossiper(id string) {
	pathPrefix := "../gossiper_testconfig/" + id
	path1 := pathPrefix + "/Gossiper_public_config.json"
	path2 := pathPrefix + "/Gossiper_private_config.json"
	path3 := pathPrefix + "/Gossiper_crypto_config.json"
	gossiperContext := gossiper.InitializeGossiperContext(path1, path2, path3, id)
	gossiperContext.StorageDirectory = "gossiper_testdata/" + gossiperContext.StorageID + "/"
	gossiperContext.StorageFile = "gossiper_testdata.json"
	gossiperContext.CleanUpGossiperStorage()

	// create the storage directory if not exist
	util.CreateDir(gossiperContext.StorageDirectory)

	// create the storage file if not exist
	util.CreateFile(gossiperContext.StorageDirectory + gossiperContext.StorageFile)
	gossiper.StartGossiperServer(gossiperContext)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("usage: go run test3.go <ca|logger|monitor|gossiper> <id>")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "ca":
		StartCA(os.Args[2])
	case "logger":
		StartLogger(os.Args[2])
	case "monitor":
		StartMonitor(os.Args[2])
	case "gossiper":
		StartGossiper(os.Args[2])
	default:
		fmt.Println("usage: go run test3.go <ca|logger|monitor|gossiper> <id>")
		os.Exit(1)
	}
}
