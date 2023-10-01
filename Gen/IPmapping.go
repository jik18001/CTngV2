package Gen

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"

	"github.com/jik18001/CTngV2/CA"
	"github.com/jik18001/CTngV2/Logger"
	"github.com/jik18001/CTngV2/crypto"
	"github.com/jik18001/CTngV2/gossiper"
	"github.com/jik18001/CTngV2/monitor"
	"github.com/jik18001/CTngV2/util"
)

type IP_Json struct {
	Monitor_ip_map  map[int]string `json:"monitor_ip_map"`
	Gossiper_ip_map map[int]string `json:"gossiper_ip_map"`
	Logger_ip_map   map[int]string `json:"logger_ip_map"`
	CA_ip_map       map[int]string `json:"ca_ip_map"`
}

func Generate_IP_Json_template(num_monitor_gossiper int, num_ca int, num_logger int, mg_mask string, mg_offset int, ca_mask string, ca_offset int, logger_mask string, logger_offset int) IP_Json {
	var monitor_ip_map map[int]string
	var gossiper_ip_map map[int]string
	var logger_ip_map map[int]string
	var ca_ip_map map[int]string
	// initialize the map
	monitor_ip_map = make(map[int]string)
	gossiper_ip_map = make(map[int]string)
	logger_ip_map = make(map[int]string)
	ca_ip_map = make(map[int]string)
	for i := 0; i < num_ca; i++ {
		ca_ip_map[i] = ca_mask + strconv.Itoa(i+ca_offset)
	}
	for i := 0; i < num_logger; i++ {
		logger_ip_map[i] = logger_mask + strconv.Itoa(i+logger_offset)
	}
	for i := 0; i < num_monitor_gossiper; i++ {
		monitor_ip_map[i] = mg_mask + strconv.Itoa(i+mg_offset)
		gossiper_ip_map[i] = mg_mask + strconv.Itoa(i+mg_offset)
	}
	var new_ip_json_template IP_Json
	new_ip_json_template.CA_ip_map = ca_ip_map
	new_ip_json_template.Logger_ip_map = logger_ip_map
	new_ip_json_template.Monitor_ip_map = monitor_ip_map
	new_ip_json_template.Gossiper_ip_map = gossiper_ip_map

	return new_ip_json_template
}

func Read_IP_Json_from_files(filepath string) IP_Json {
	var new_ip_json IP_Json
	file, err := os.Open(filepath)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	bytes, _ := io.ReadAll(file)
	json.Unmarshal(bytes, &new_ip_json)
	return new_ip_json
}

func Write_IP_Json_to_files(fp string, new_ip_json IP_Json) {
	//check if filepath exists, if not, create it
	dir := filepath.Dir(fp)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		os.MkdirAll(dir, 0755)
	}
	//write to file
	file, _ := json.MarshalIndent(new_ip_json, "", " ")
	_ = os.WriteFile(fp, file, 0644)
}

func Map_local_to_IP_crypto_config(crypto_config_path string, ip_json_config IP_Json, ID int, num_logger int, num_ca int, num_monitor_gossiper int) {
	cryptoconfig, _ := crypto.ReadCryptoConfig(crypto_config_path)
	//prefix is localhost:x, first 10 characters
	self_prefix := cryptoconfig.SelfID.String()[0:11]
	switch self_prefix {
	case prefix_CA:
		semicolon_and_port := cryptoconfig.SelfID.String()[len(cryptoconfig.SelfID.String())-5:]
		new_dest := ip_json_config.CA_ip_map[ID-1] + semicolon_and_port
		cryptoconfig.SelfID = crypto.CTngID(new_dest)
	case prefix_logger:
		semicolon_and_port := cryptoconfig.SelfID.String()[len(cryptoconfig.SelfID.String())-5:]
		new_dest := ip_json_config.Logger_ip_map[ID-1] + semicolon_and_port
		cryptoconfig.SelfID = crypto.CTngID(new_dest)
	case prefix_monitor:
		semicolon_and_port := cryptoconfig.SelfID.String()[len(cryptoconfig.SelfID.String())-5:]
		new_dest := ip_json_config.Monitor_ip_map[ID-1] + semicolon_and_port
		cryptoconfig.SelfID = crypto.CTngID(new_dest)
	case prefix_gossiper:
		semicolon_and_port := cryptoconfig.SelfID.String()[len(cryptoconfig.SelfID.String())-5:]
		new_dest := ip_json_config.Gossiper_ip_map[ID-1] + semicolon_and_port
		cryptoconfig.SelfID = crypto.CTngID(new_dest)
	default:
		log.Fatal("entity type not supported: ", self_prefix)
	}
	//iterate over the keys in the map, sequence is CA, logger, monitor, gossiper
	// create a new map
	new_map := make(crypto.RSAPublicMap)
	new_map_2 := make(crypto.BlsPublicMap)
	for key, value := range cryptoconfig.SignPublicMap {
		//take the data out and slice out the last 5 characters
		semicolon_and_port := key.String()[len(key.String())-5:]
		// take last 3 characters of the key, convert to int and ignore leading 0
		// use it as the key
		NID, _ := strconv.Atoi(key.String()[len(key.String())-3:])
		//check the prefix
		switch key.String()[0:11] {
		case prefix_CA:
			new_dest := ip_json_config.CA_ip_map[NID] + semicolon_and_port
			new_key := crypto.CTngID(new_dest)
			new_map[new_key] = value
		case prefix_logger:
			new_dest := ip_json_config.Logger_ip_map[NID] + semicolon_and_port
			new_key := crypto.CTngID(new_dest)
			new_map[new_key] = value
		case prefix_monitor:
			new_dest := ip_json_config.Monitor_ip_map[NID] + semicolon_and_port
			new_key := crypto.CTngID(new_dest)
			new_map[new_key] = value
		case prefix_gossiper:
			new_dest := ip_json_config.Gossiper_ip_map[NID] + semicolon_and_port
			new_key := crypto.CTngID(new_dest)
			new_map[new_key] = value
		default:
			log.Fatal("entity type not supported")
		}
	}
	for key, value := range cryptoconfig.ThresholdPublicMap {
		//take the data out and slice out the last 5 characters
		semicolon_and_port := key.String()[len(key.String())-5:]
		// take last 3 characters of the key, convert to int and ignore leading 0
		// use it as the key
		NID, _ := strconv.Atoi(key.String()[len(key.String())-3:])
		//check the prefix
		switch key.String()[0:11] {
		case prefix_CA:
			new_dest := ip_json_config.CA_ip_map[NID] + semicolon_and_port
			new_key := crypto.CTngID(new_dest)
			new_map_2[new_key] = value
		case prefix_logger:
			new_dest := ip_json_config.Logger_ip_map[NID] + semicolon_and_port
			new_key := crypto.CTngID(new_dest)
			new_map_2[new_key] = value
		case prefix_monitor:
			new_dest := ip_json_config.Monitor_ip_map[NID] + semicolon_and_port
			new_key := crypto.CTngID(new_dest)
			new_map_2[new_key] = value
		case prefix_gossiper:
			new_dest := ip_json_config.Gossiper_ip_map[NID] + semicolon_and_port
			new_key := crypto.CTngID(new_dest)
			new_map_2[new_key] = value
		default:
			log.Fatal("entity type not supported: ")
		}
	}

	// swap the old map with the new map
	cryptoconfig.SignPublicMap = new_map
	cryptoconfig.ThresholdPublicMap = new_map_2

	storedcryptoconfig := crypto.NewStoredCryptoConfig(cryptoconfig)
	util.WriteData(crypto_config_path, storedcryptoconfig)
}

func Map_local_to_IP_priv_config(priv_config_path string, pub_config_path string, crypto_config_path string, entity_type string, ip_json_config IP_Json, entityID int) {
	switch entity_type {
	case "monitor":
		Map_local_to_Monitor_IP_priv_config(priv_config_path, ip_json_config, entityID)
	case "gossiper":
		Map_local_to_Gossiper_IP_priv_config(priv_config_path, ip_json_config, entityID)
	case "ca":
		Map_local_to_CA_IP_priv_config(priv_config_path, ip_json_config, entityID)
	case "logger":
		Map_local_to_Logger_IP_priv_config(priv_config_path, ip_json_config, entityID)
	default:
		log.Fatal("entity type not supported: " + entity_type)
	}
}

func Map_local_to_IP_public_config(priv_config_path string, pub_config_path string, crypto_config_path string, entity_type string, ip_json_config IP_Json, entityID int) {
	switch entity_type {
	case "monitor":
		Map_local_to_Monitor_IP_pub_config(pub_config_path, ip_json_config, entityID)
	case "gossiper":
		Map_local_to_Gossiper_IP_pub_config(pub_config_path, ip_json_config, entityID)
	case "ca":
		Map_local_to_CA_IP_pub_config(pub_config_path, ip_json_config, entityID)
	case "logger":
		Map_local_to_Logger_IP_pub_config(pub_config_path, ip_json_config, entityID)
	default:
		log.Fatal("entity type not supported: " + entity_type)
	}
}

func Map_local_to_Monitor_IP_priv_config(priv_config_path string, ip_json_config IP_Json, MID int) {
	var monitor_priv_config *monitor.Monitor_private_config
	util.LoadConfiguration(&monitor_priv_config, priv_config_path)
	for index, ca := range monitor_priv_config.CA_URLs {
		//change localhost to actual IP
		//take the data out and slice out the last 5 characters
		semicolon_and_port := ca[len(ca)-5:]
		new_dest := ip_json_config.CA_ip_map[index] + semicolon_and_port
		monitor_priv_config.CA_URLs[index] = new_dest
	}
	// iterate over Logger_URL (a list)
	for index, logger := range monitor_priv_config.Logger_URLs {
		//change localhost to actual IP
		//take the data out and slice out the last 5 characters
		semicolon_and_port := logger[len(logger)-5:]
		new_dest := ip_json_config.Logger_ip_map[index] + semicolon_and_port
		monitor_priv_config.Logger_URLs[index] = new_dest
	}
	//change localhost to actual IP for gossiper
	//take the data out and slice out the last 5 characters
	semicolon_and_port := monitor_priv_config.Gossiper_URL[len(monitor_priv_config.Gossiper_URL)-5:]
	new_dest := ip_json_config.Gossiper_ip_map[MID-1] + semicolon_and_port
	monitor_priv_config.Gossiper_URL = new_dest
	//change signer URL
	//take the data out and slice out the last 5 characters
	semicolon_and_port = monitor_priv_config.Signer[len(monitor_priv_config.Signer)-5:]
	new_dest = ip_json_config.Monitor_ip_map[MID-1] + semicolon_and_port
	monitor_priv_config.Signer = new_dest
	fmt.Println("monitor_priv_config.Signer: ", monitor_priv_config.Signer)
	util.WriteData(priv_config_path, monitor_priv_config)
}

func Map_local_to_Gossiper_IP_priv_config(priv_config_path string, ip_json_config IP_Json, MID int) {
	var gossiper_priv_config *gossiper.Gossiper_private_config
	util.LoadConfiguration(&gossiper_priv_config, priv_config_path)
	for index, gossipers := range gossiper_priv_config.Connected_Gossipers {
		//change localhost to actual IP
		//take the data out and slice out the last 5 characters
		//index should be the last 3 characters of the port number (ignore leading 0)
		sindex, _ := strconv.Atoi(gossipers[len(gossipers)-3:])
		semicolon_and_port := gossipers[len(gossipers)-5:]
		new_dest := ip_json_config.Gossiper_ip_map[sindex] + semicolon_and_port
		gossiper_priv_config.Connected_Gossipers[index] = new_dest
	}
	semicolon_and_port_1 := gossiper_priv_config.Owner_URL[len(gossiper_priv_config.Owner_URL)-5:]
	gossiper_priv_config.Owner_URL = ip_json_config.Gossiper_ip_map[MID-1] + semicolon_and_port_1
	fmt.Println("gossiper_priv_config.Owner_URL: ", gossiper_priv_config.Owner_URL)
	util.WriteData(priv_config_path, gossiper_priv_config)
}

func Map_local_to_CA_IP_priv_config(priv_config_path string, ip_json_config IP_Json, MID int) {
	var ca_priv_config *CA.CA_private_config
	util.LoadConfiguration(&ca_priv_config, priv_config_path)
	ca_ip := ip_json_config.CA_ip_map[MID-1]
	semicolon_and_port_1 := ca_priv_config.Signer[len(ca_priv_config.Signer)-5:]
	new_dest_1 := ca_ip + semicolon_and_port_1
	ca_priv_config.Signer = new_dest_1
	fmt.Println("ca_priv_config.Signer: ", ca_priv_config.Signer)
	// iterate over LoggerList
	for index, logger := range ca_priv_config.Loggerlist {
		//change localhost to actual IP
		//take the data out and slice out the last 5 characters
		semicolon_and_port := logger[len(logger)-5:]
		new_dest := ip_json_config.Logger_ip_map[MID-1] + semicolon_and_port
		ca_priv_config.Loggerlist[index] = new_dest
	}
	// iterate over MonitorList
	for index, monitor := range ca_priv_config.Monitorlist {
		//change localhost to actual IP
		//take the data out and slice out the last 5 characters
		semicolon_and_port := monitor[len(monitor)-5:]
		new_dest := ip_json_config.Monitor_ip_map[index] + semicolon_and_port
		ca_priv_config.Monitorlist[index] = new_dest
	}
	// iterate over GossiperList
	for index, gossiper := range ca_priv_config.Gossiperlist {
		//change localhost to actual IP
		//take the data out and slice out the last 5 characters
		semicolon_and_port := gossiper[len(gossiper)-5:]
		new_dest := ip_json_config.Gossiper_ip_map[index] + semicolon_and_port
		ca_priv_config.Gossiperlist[index] = new_dest
	}
	util.WriteData(priv_config_path, ca_priv_config)
}

func Map_local_to_Logger_IP_priv_config(priv_config_path string, ip_json_config IP_Json, MID int) {
	var logger_priv_config *Logger.Logger_private_config
	util.LoadConfiguration(&logger_priv_config, priv_config_path)
	logger_ip := ip_json_config.Logger_ip_map[MID-1]
	semicolon_and_port_1 := logger_priv_config.Signer[len(logger_priv_config.Signer)-5:]
	new_dest_1 := logger_ip + semicolon_and_port_1
	logger_priv_config.Signer = new_dest_1
	fmt.Println("logger_priv_config.Signer: ", logger_priv_config.Signer)
	// iterate over MonitorList
	for index, monitor := range logger_priv_config.Monitorlist {
		//change localhost to actual IP
		//take the data out and slice out the last 5 characters
		semicolon_and_port := monitor[len(monitor)-5:]
		new_dest := ip_json_config.Monitor_ip_map[index] + semicolon_and_port
		logger_priv_config.Monitorlist[index] = new_dest
	}
	// iterate over GossiperList
	for index, gossiper := range logger_priv_config.Gossiperlist {
		//change localhost to actual IP
		//take the data out and slice out the last 5 characters
		semicolon_and_port := gossiper[len(gossiper)-5:]
		new_dest := ip_json_config.Gossiper_ip_map[index] + semicolon_and_port
		logger_priv_config.Gossiperlist[index] = new_dest
	}
	util.WriteData(priv_config_path, logger_priv_config)
}

func Map_local_to_Monitor_IP_pub_config(pub_config_path string, ip_json_config IP_Json, MID int) {
	var monitor_pub_config *monitor.Monitor_public_config
	util.LoadConfiguration(&monitor_pub_config, pub_config_path)
	for index, ca := range monitor_pub_config.All_CA_URLs {
		//change localhost to actual IP
		//take the data out and slice out the last 5 characters
		semicolon_and_port := ca[len(ca)-5:]
		new_dest := ip_json_config.CA_ip_map[index] + semicolon_and_port
		monitor_pub_config.All_CA_URLs[index] = new_dest
	}
	// iterate over Logger_URL (a list)
	for index, logger := range monitor_pub_config.All_Logger_URLs {
		//change localhost to actual IP
		//take the data out and slice out the last 5 characters
		semicolon_and_port := logger[len(logger)-5:]
		new_dest := ip_json_config.Logger_ip_map[index] + semicolon_and_port
		monitor_pub_config.All_Logger_URLs[index] = new_dest
	}
	util.WriteData(pub_config_path, monitor_pub_config)
}

func Map_local_to_Gossiper_IP_pub_config(pub_config_path string, ip_json_config IP_Json, MID int) {
	var gossiper_pub_config *gossiper.Gossiper_public_config
	util.LoadConfiguration(&gossiper_pub_config, pub_config_path)
	for index, gossiper := range gossiper_pub_config.Gossiper_URLs {
		//change localhost to actual IP
		//take the data out and slice out the last 5 characters
		semicolon_and_port := gossiper[len(gossiper)-5:]
		new_dest := ip_json_config.Gossiper_ip_map[index] + semicolon_and_port
		gossiper_pub_config.Gossiper_URLs[index] = new_dest
	}
	for index, monitor := range gossiper_pub_config.Signer_URLs {
		//change localhost to actual IP
		//take the data out and slice out the last 5 characters
		semicolon_and_port := monitor[len(monitor)-5:]
		new_dest := ip_json_config.Monitor_ip_map[index] + semicolon_and_port
		gossiper_pub_config.Signer_URLs[index] = new_dest
	}
	util.WriteData(pub_config_path, gossiper_pub_config)
}

func Map_local_to_CA_IP_pub_config(pub_config_path string, ip_json_config IP_Json, MID int) {
	//same as Monitor public config
	var ca_pub_config *CA.CA_public_config
	util.LoadConfiguration(&ca_pub_config, pub_config_path)
	for index, ca := range ca_pub_config.All_CA_URLs {
		//change localhost to actual IP
		//take the data out and slice out the last 5 characters
		semicolon_and_port := ca[len(ca)-5:]
		new_dest := ip_json_config.CA_ip_map[index] + semicolon_and_port
		ca_pub_config.All_CA_URLs[index] = new_dest
	}
	// iterate over Logger_URL (a list)
	for index, logger := range ca_pub_config.All_Logger_URLs {
		//change localhost to actual IP
		//take the data out and slice out the last 5 characters
		semicolon_and_port := logger[len(logger)-5:]
		new_dest := ip_json_config.Logger_ip_map[index] + semicolon_and_port
		ca_pub_config.All_Logger_URLs[index] = new_dest
	}
	util.WriteData(pub_config_path, ca_pub_config)
}

func Map_local_to_Logger_IP_pub_config(pub_config_path string, ip_json_config IP_Json, MID int) {
	//same as Monitor public config
	var logger_pub_config *Logger.Logger_public_config
	util.LoadConfiguration(&logger_pub_config, pub_config_path)
	for index, ca := range logger_pub_config.All_CA_URLs {
		//change localhost to actual IP
		//take the data out and slice out the last 5 characters
		semicolon_and_port := ca[len(ca)-5:]
		new_dest := ip_json_config.CA_ip_map[index] + semicolon_and_port
		logger_pub_config.All_CA_URLs[index] = new_dest
	}
	// iterate over Logger_URL (a list)
	for index, logger := range logger_pub_config.All_Logger_URLs {
		//change localhost to actual IP
		//take the data out and slice out the last 5 characters
		semicolon_and_port := logger[len(logger)-5:]
		new_dest := ip_json_config.Logger_ip_map[index] + semicolon_and_port
		logger_pub_config.All_Logger_URLs[index] = new_dest
	}
	util.WriteData(pub_config_path, logger_pub_config)
}

func Map_all(num_ca int, num_logger int, num_mg int, ip_json_config IP_Json) {
	// iterate over all cas
	ca_path := "ca_testconfig/"
	for i := 0; i < num_ca; i++ {
		ca_privconfig_path := ca_path + strconv.Itoa(i+1) + "/CA_private_config.json"
		ca_pubconfig_path := ca_path + strconv.Itoa(i+1) + "/CA_public_config.json"
		ca_cryptoconfig_path := ca_path + strconv.Itoa(i+1) + "/CA_crypto_config.json"
		Map_local_to_IP_priv_config(ca_privconfig_path, ca_pubconfig_path, ca_cryptoconfig_path, "ca", ip_json_config, i+1)
		Map_local_to_IP_public_config(ca_privconfig_path, ca_pubconfig_path, ca_cryptoconfig_path, "ca", ip_json_config, i+1)
		Map_local_to_IP_crypto_config(ca_cryptoconfig_path, ip_json_config, i+1, num_logger, num_ca, num_mg)
	}

	// iterate over all loggers
	logger_path := "logger_testconfig/"
	for i := 0; i < num_logger; i++ {
		logger_privconfig_path := logger_path + strconv.Itoa(i+1) + "/Logger_private_config.json"
		logger_pubconfig_path := logger_path + strconv.Itoa(i+1) + "/Logger_public_config.json"
		logger_cryptoconfig_path := logger_path + strconv.Itoa(i+1) + "/Logger_crypto_config.json"
		Map_local_to_IP_priv_config(logger_privconfig_path, logger_pubconfig_path, logger_cryptoconfig_path, "logger", ip_json_config, i+1)
		Map_local_to_IP_public_config(logger_privconfig_path, logger_pubconfig_path, logger_cryptoconfig_path, "logger", ip_json_config, i+1)
		Map_local_to_IP_crypto_config(logger_cryptoconfig_path, ip_json_config, i+1, num_logger, num_ca, num_mg)
	}

	// iterate over all monitors
	monitor_path := "monitor_testconfig/"
	for i := 0; i < num_mg; i++ {
		monitor_privconfig_path := monitor_path + strconv.Itoa(i+1) + "/Monitor_private_config.json"
		monitor_pubconfig_path := monitor_path + strconv.Itoa(i+1) + "/Monitor_public_config.json"
		monitor_cryptoconfig_path := monitor_path + strconv.Itoa(i+1) + "/Monitor_crypto_config.json"
		Map_local_to_IP_priv_config(monitor_privconfig_path, monitor_pubconfig_path, monitor_cryptoconfig_path, "monitor", ip_json_config, i+1)
		Map_local_to_IP_public_config(monitor_privconfig_path, monitor_pubconfig_path, monitor_cryptoconfig_path, "monitor", ip_json_config, i+1)
		Map_local_to_IP_crypto_config(monitor_cryptoconfig_path, ip_json_config, i+1, num_logger, num_ca, num_mg)
	}

	// iterate over all gossipers
	gossiper_path := "gossiper_testconfig/"
	for i := 0; i < num_mg; i++ {
		gossiper_privconfig_path := gossiper_path + strconv.Itoa(i+1) + "/Gossiper_private_config.json"
		gossiper_pubconfig_path := gossiper_path + strconv.Itoa(i+1) + "/Gossiper_public_config.json"
		gossiper_cryptoconfig_path := gossiper_path + strconv.Itoa(i+1) + "/Gossiper_crypto_config.json"
		Map_local_to_IP_priv_config(gossiper_privconfig_path, gossiper_pubconfig_path, gossiper_cryptoconfig_path, "gossiper", ip_json_config, i+1)
		Map_local_to_IP_public_config(gossiper_privconfig_path, gossiper_pubconfig_path, gossiper_cryptoconfig_path, "gossiper", ip_json_config, i+1)
		Map_local_to_IP_crypto_config(gossiper_cryptoconfig_path, ip_json_config, i+1, num_logger, num_ca, num_mg)
	}
}
