package main

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/jik18001/CTngV2/CA"
	"github.com/jik18001/CTngV2/Logger"
	"github.com/jik18001/CTngV2/gossiper"
	"github.com/jik18001/CTngV2/monitor"
	"github.com/jik18001/CTngV2/util"
)

func StartCA(CID string) {
	path_prefix := "../ca_testconfig/" + CID
	path_1 := path_prefix + "/CA_public_config.json"
	path_2 := path_prefix + "/CA_private_config.json"
	path_3 := path_prefix + "/CA_crypto_config.json"
	ctx_ca := CA.InitializeCAContext(path_1, path_2, path_3)
	ctx_ca.CA_Type = 3
	ctx_ca.MisbehaviorInterval = 2
	ctx_ca.Maxlatency = 500
	CA.StartCA(ctx_ca)
}

func StartLogger(LID string) {
	path_prefix := "../logger_testconfig/" + LID
	path_1 := path_prefix + "/Logger_public_config.json"
	path_2 := path_prefix + "/Logger_private_config.json"
	path_3 := path_prefix + "/Logger_crypto_config.json"
	ctx_logger := Logger.InitializeLoggerContext(path_1, path_2, path_3)
	ctx_logger.Logger_Type = 3
	ctx_logger.MisbehaviorInterval = 2
	ctx_logger.Maxlatency = 500
	Logger.StartLogger(ctx_logger)
}

func StartMonitor(MID string) {
	path_prefix := "../monitor_testconfig/" + MID
	path_1 := path_prefix + "/Monitor_public_config.json"
	path_2 := path_prefix + "/Monitor_private_config.json"
	path_3 := path_prefix + "/Monitor_crypto_config.json"
	ctx_monitor := monitor.InitializeMonitorContext(path_1, path_2, path_3, MID)
	// clean up the storage
	ctx_monitor.InitializeMonitorStorage("monitor_testdata/")
	// delete all the files in the storage
	ctx_monitor.CleanUpMonitorStorage()
	//ctx_monitor.Mode = 0
	//wait for 60 seconds
	fmt.Println("Delay 60 seconds to start monitor server")
	time.Sleep(60 * time.Second)
	ctx_monitor.Period_Offset = util.GetCurrentPeriod()
	MID_int, _ := strconv.Atoi(MID)
	ctx_monitor.Clockdrift_miliseconds = 200 * MID_int
	ctx_monitor.Maxdrift_miliseconds = 200 * MID_int * ctx_monitor.Monitor_crypto_config.N
	monitor.StartMonitorServer(ctx_monitor)
}

func StartGossiper(GID string) {
	path_prefix := "../gossiper_testconfig/" + GID
	path_1 := path_prefix + "/Gossiper_public_config.json"
	path_2 := path_prefix + "/Gossiper_private_config.json"
	path_3 := path_prefix + "/Gossiper_crypto_config.json"
	ctx_gossiper := gossiper.InitializeGossiperContext(path_1, path_2, path_3, GID)
	ctx_gossiper.StorageDirectory = "gossiper_testdata/" + ctx_gossiper.StorageID + "/"
	ctx_gossiper.StorageFile = "gossiper_testdata.json"
	ctx_gossiper.CleanUpGossiperStorage()
	ctx_gossiper.Min_latency = 20
	ctx_gossiper.Max_latency = 500
	// create the storage directory if not exist
	util.CreateDir(ctx_gossiper.StorageDirectory)
	// create the storage file if not exist
	util.CreateFile(ctx_gossiper.StorageDirectory + ctx_gossiper.StorageFile)
	gossiper.StartGossiperServer(ctx_gossiper)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run Test1.go <CA|Logger|Monitor|Gossiper> <ID>")
		os.Exit(1)
	}
	switch os.Args[1] {
	case "CA":
		StartCA(os.Args[2])
	case "Logger":
		StartLogger(os.Args[2])
	case "Monitor":
		StartMonitor(os.Args[2])
	case "Gossiper":
		StartGossiper(os.Args[2])
	default:
		fmt.Println("Usage: go run Test1.go <CA|Logger|Monitor|Gossiper> <ID>")
		os.Exit(1)
	}
}
