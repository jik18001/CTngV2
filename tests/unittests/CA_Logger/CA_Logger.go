package main

import (
	"CTngV2/CA"
	"CTngV2/Logger"
	"fmt"
	"os"
)

func StartCA(CID string) {
	path_prefix := "../ca_testconfig/" + CID
	path_1 := path_prefix + "/CA_public_config.json"
	path_2 := path_prefix + "/CA_private_config.json"
	path_3 := path_prefix + "/CA_crypto_config.json"
	path_4 := "ca_extensions.json"
	path_5 := "ca_certjsons_.json"
	ctx_ca := CA.InitializeCAContext(path_1, path_2, path_3)
	ctx_ca.StoragePath1 = path_4
	ctx_ca.StoragePath2 = path_5
	CA.StartCA(ctx_ca)
}

func StartLogger(LID string) {
	path_prefix := "../logger_testconfig/" + LID
	path_1 := path_prefix + "/Logger_public_config.json"
	path_2 := path_prefix + "/Logger_private_config.json"
	path_3 := path_prefix + "/Logger_crypto_config.json"
	path_4 := "logger_certjsons_.json"
	ctx_logger := Logger.InitializeLoggerContext(path_1, path_2, path_3)
	ctx_logger.StoragePath = path_4
	Logger.StartLogger(ctx_logger)
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
	default:
		fmt.Println("Usage: go run Test1.go <CA|Logger|Monitor|Gossiper> <ID>")
		os.Exit(1)
	}
}
