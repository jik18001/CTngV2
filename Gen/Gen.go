package Gen

import (
	"CTngV2/CA"
	"CTngV2/Logger"
	"CTngV2/crypto"
	"CTngV2/gossiper"
	"CTngV2/monitor"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
)

const (
	prefix_CA            = "localhost:6"
	prefix_logger        = "localhost:7"
	prefix_monitor       = "localhost:8"
	prefix_gossiper      = "localhost:9"
	port_prefix_CA       = "6"
	port_prefix_logger   = "7"
	port_prefix_monitor  = "8"
	port_prefix_gossiper = "9"
)

func Port_Postfix(key int) string {
	if key < 10 {
		return "00" + fmt.Sprint(key)
	} else if key < 100 {
		return "0" + fmt.Sprint(key)
	} else if key < 1000 {
		return fmt.Sprint(key)
	}
	// Handling case for key >= 1000, if needed
	return ""
}

func GenerateCryptoconfig_map(Total int, Threshold int, entitytype string) map[string]crypto.StoredCryptoConfig {
	// Assuming these prefixes are defined elsewhere in your code as constants
	var prefix string
	switch entitytype {
	case "CA":
		prefix = prefix_CA
	case "Logger":
		prefix = prefix_logger
	case "Monitor":
		prefix = prefix_monitor
	case "Gossiper":
		prefix = prefix_gossiper
	default:
		prefix = "localhost:000" // Default prefix if none of the above cases match
	}
	cryptoConfigs := make(map[string]crypto.StoredCryptoConfig)
	for i := 0; i < Total; i++ {
		postfix := Port_Postfix(i)
		newcryptoConfig := crypto.StoredCryptoConfig{
			SelfID:          crypto.CTngID(prefix + postfix),
			Threshold:       Threshold,
			N:               Total,
			HashScheme:      4,
			SignScheme:      "rsa",
			ThresholdScheme: "bls",
		}
		cryptoConfigs[prefix+postfix] = newcryptoConfig
	}
	return cryptoConfigs
}

func Generate_all_list(num_MG int, num_CA int, num_logger int) ([]string, []string, []string, []string) {
	G_list := make([]string, num_MG)
	M_list := make([]string, num_MG)
	C_list := make([]string, num_CA)
	L_list := make([]string, num_logger)
	for i := 0; i < num_MG; i++ {
		G_list[i] = prefix_gossiper + Port_Postfix(i)
		M_list[i] = prefix_monitor + Port_Postfix(i)
	}
	for i := 0; i < num_CA; i++ {
		C_list[i] = prefix_CA + Port_Postfix(i)
	}
	for i := 0; i < num_logger; i++ {
		L_list[i] = prefix_logger + Port_Postfix(i)
	}
	return G_list, M_list, C_list, L_list
}

func GenerateCA_private_config_map(G_list []string, M_list []string, L_list []string, num_CA int, num_cert int) map[string]CA.CA_private_config {
	ca_private_map := make(map[string]CA.CA_private_config)
	for i := 0; i < num_CA; i++ {
		// generate CA config
		ca_private_config := CA.GenerateCA_private_config_template()
		// Signer
		ca_private_config.Signer = prefix_CA + Port_Postfix(i)
		// Port
		ca_private_config.Port = port_prefix_CA + Port_Postfix(i)
		// Cert_per_period
		ca_private_config.Cert_per_period = num_cert
		// Gossiperlist
		ca_private_config.Gossiperlist = G_list
		// Monitorlist
		ca_private_config.Monitorlist = M_list
		// Loggerlist
		ca_private_config.Loggerlist = append(ca_private_config.Loggerlist, L_list[i%len(L_list)])
		// append to caConfigs
		ca_private_map[ca_private_config.Signer] = *ca_private_config
	}
	return ca_private_map
}

func GenerateLogger_private_config_map(G_list []string, M_list []string, C_list []string, num_logger int) map[string]Logger.Logger_private_config {
	logger_private_map := make(map[string]Logger.Logger_private_config)
	for i := 0; i < num_logger; i++ {
		// generate logger config
		logger_private_config := Logger.GenerateLogger_private_config_template()
		// Signer
		logger_private_config.Signer = prefix_logger + Port_Postfix(i)
		// Port
		logger_private_config.Port = port_prefix_logger + Port_Postfix(i)
		// Gossiperlist
		logger_private_config.Gossiperlist = G_list
		// Monitorlist
		logger_private_config.Monitorlist = M_list
		// Loggerlist
		logger_private_config.CAlist = C_list
		// append to loggerConfigs
		logger_private_map[logger_private_config.Signer] = *logger_private_config
	}
	return logger_private_map
}

func GenerateCA_public_config(L_list []string, C_list []string, MMD int, MRD int, Http_vers []string) *CA.CA_public_config {
	// generate CA config
	ca_public_config := CA.GenerateCA_public_config_template()
	// All_CA_URLs
	ca_public_config.All_CA_URLs = C_list
	// All_Logger_URLs
	ca_public_config.All_Logger_URLs = L_list
	// MMD
	ca_public_config.MMD = MMD
	// MRD
	ca_public_config.MRD = MRD
	// Http_vers
	ca_public_config.Http_vers = Http_vers
	return ca_public_config
}

func GenerateLogger_public_config(L_list []string, C_list []string, MMD int, MRD int, Http_vers []string) *Logger.Logger_public_config {
	// generate logger config
	logger_public_config := Logger.GenerateLogger_public_config_template()
	// All_CA_URLs
	logger_public_config.All_CA_URLs = C_list
	// All_Logger_URLs
	logger_public_config.All_Logger_URLs = L_list
	// MMD
	logger_public_config.MMD = MMD
	// MRD
	logger_public_config.MRD = MRD
	// Http_vers
	logger_public_config.Http_vers = Http_vers
	return logger_public_config
}

func GenerateMonitor_public_config(G_list []string, M_list []string, C_list []string, L_list []string, MMD int, MRD int, Gossip_wait_time int, Http_vers []string) *monitor.Monitor_public_config {
	return &monitor.Monitor_public_config{
		All_CA_URLs:      C_list,
		All_Logger_URLs:  L_list,
		Gossip_wait_time: Gossip_wait_time,
		MMD:              MMD,
		MRD:              MRD,
	}
}

func GenerateMonitor_private_config_map(G_list []string, M_list []string, C_list []string, L_list []string, MMD int, MRD int, Gossip_wait_time int, Http_vers []string, filepath string) map[string]monitor.Monitor_private_config {
	Monitor_private_map := make(map[string]monitor.Monitor_private_config)
	for i := 0; i < len(M_list); i++ {
		// generate monitor config
		monitor_private_config := &monitor.Monitor_private_config{
			CA_URLs:               C_list,
			Logger_URLs:           L_list,
			Signer:                M_list[i],
			Gossiper_URL:          G_list[i],
			Inbound_gossiper_port: port_prefix_gossiper + Port_Postfix(i),
			Port:                  port_prefix_monitor + Port_Postfix(i),
		}
		// append to monitorConfigs
		Monitor_private_map[monitor_private_config.Signer] = *monitor_private_config
	}
	return Monitor_private_map
}

func GenerateGossiper_public_config(G_list []string, M_list []string, C_list []string, L_list []string, MMD int, MRD int, Gossip_wait_time int, Communiation_delay int, Http_vers []string) *gossiper.Gossiper_public_config {
	return &gossiper.Gossiper_public_config{
		Gossip_wait_time: Gossip_wait_time,
		MMD:              MMD,
		MRD:              MRD,
		Gossiper_URLs:    G_list,
		Signer_URLs:      M_list,
	}
}

func GenerateGossiper_private_config_map(G_list []string, M_list []string, C_list []string, L_list []string, MMD int, MRD int, Gossip_wait_time int, Communiation_delay int, Http_vers []string, filepath string) map[string]gossiper.Gossiper_private_config {
	Gossiper_private_map := make(map[string]gossiper.Gossiper_private_config)
	for i := 0; i < len(G_list); i++ {
		// connected gossiper should be all except itself
		connected_gossiper := make([]string, 0)
		for j := 0; j < len(G_list); j++ {
			if i != j {
				connected_gossiper = append(connected_gossiper, G_list[j])
			}
		}
		// generate gossiper config
		gossiper_private_config := &gossiper.Gossiper_private_config{
			// Crypto_config_location: filepath,
			Connected_Gossipers: connected_gossiper,
			Owner_URL:           M_list[i],
			Port:                port_prefix_gossiper + Port_Postfix(i),
		}
		// append to gossiperConfigs
		Gossiper_private_map[G_list[i]] = *gossiper_private_config
	}
	return Gossiper_private_map
}

func write_all_configs_to_file(public_config interface{}, private_config interface{}, crypto_config interface{}, filepath string, entitytype string) {
	// write to file
	public_config_path := filepath + entitytype + "_public_config.json"
	private_config_path := filepath + entitytype + "_private_config.json"
	crypto_config_path := filepath + entitytype + "_crypto_config.json"
	public_config_json, _ := json.MarshalIndent(public_config, " ", " ")
	private_config_json, _ := json.MarshalIndent(private_config, " ", " ")
	crypto_config_json, _ := json.MarshalIndent(crypto_config, " ", " ")
	ioutil.WriteFile(public_config_path, public_config_json, 0644)
	ioutil.WriteFile(private_config_path, private_config_json, 0644)
	ioutil.WriteFile(crypto_config_path, crypto_config_json, 0644)
}

func write_config_to_file(config interface{}, filepath string, entitytype string, configtype string) {
	// write to file
	config_path := filepath + entitytype + "_" + configtype + "_config.json"
	config_json, _ := json.MarshalIndent(config, " ", " ")
	ioutil.WriteFile(config_path, config_json, 0644)
}

func RSA_gen(entity_list []string) (crypto.RSAPublicMap, map[string]*rsa.PrivateKey) {
	// generate RSA key pairs
	// public key map
	public_key_map := make(crypto.RSAPublicMap)
	// private key map
	private_key_map := make(map[string]*rsa.PrivateKey)
	// generate RSA key pairs for all entities
	for i := 0; i < len(entity_list); i++ {
		sk, err := crypto.NewRSAPrivateKey()
		if err != nil {
			fmt.Println("Error generating RSA key pair")
		}
		pk := sk.PublicKey
		public_key_map[crypto.CTngID(entity_list[i])] = pk
		private_key_map[entity_list[i]] = sk
	}
	return public_key_map, private_key_map
}
func RSA_gen_all(G_list []string, M_list []string, C_list []string, L_list []string) (crypto.RSAPublicMap, map[string]*rsa.PrivateKey) {
	//use RSA_gen to generate all RSA keys
	entity_list := append(G_list, M_list...)
	entity_list = append(entity_list, C_list...)
	entity_list = append(entity_list, L_list...)
	return RSA_gen(entity_list)
}

func BLS_gen_all(G_list []string) (map[string][]byte, map[string][]byte) {
	//create a list of crypto.CTngID
	var entity_list []crypto.CTngID
	for i := 0; i < len(G_list); i++ {
		entity_list = append(entity_list, crypto.CTngID(G_list[i]))
	}
	//generate BLS key pairs for all entities
	_, pub, priv, err := crypto.GenerateThresholdKeypairs(entity_list, len(G_list))
	if err != nil {
		fmt.Println("Error generating BLS key pair")
	}
	// public key map
	public_key_map := pub.Serialize()
	// private key map
	private_key_map := make(map[string][]byte)
	for i := 0; i < len(G_list); i++ {
		blspriv := priv[entity_list[i]]
		private_key_map[G_list[i]] = blspriv.Serialize()
	}
	return public_key_map, private_key_map
}

func Update_crypto_config(crypto_config *crypto.StoredCryptoConfig, SignaturePublicMap crypto.RSAPublicMap, BLSPublicMap map[string][]byte, SignaturePrivateMap map[string]*rsa.PrivateKey, BLSPrivateMap map[string][]byte) {
	// update crypto config
	crypto_config.SignPublicMap = SignaturePublicMap
	crypto_config.ThresholdPublicMap = BLSPublicMap
	crypto_config.SignSecretKey = *SignaturePrivateMap[crypto_config.SelfID.String()]
	crypto_config.ThresholdSecretKey = BLSPrivateMap[crypto_config.SelfID.String()]
}

func Generateall(num_gossiper int, Threshold int, num_logger int, num_ca int, num_cert int, MMD int, MRD int, config_path string) {
	Total := num_gossiper
	G_list, M_list, C_list, L_list := Generate_all_list(num_gossiper, num_ca, num_logger)
	ca_private_config_map := make(map[string]CA.CA_private_config)
	ca_crypto_config_map := make(map[string]crypto.StoredCryptoConfig)
	logger_private_config_map := make(map[string]Logger.Logger_private_config)
	logger_crypto_config_map := make(map[string]crypto.StoredCryptoConfig)
	monitor_private_config_map := make(map[string]monitor.Monitor_private_config)
	monitor_crypto_config_map := make(map[string]crypto.StoredCryptoConfig)
	gossiper_private_config_map := make(map[string]gossiper.Gossiper_private_config)
	gossiper_crypto_config_map := make(map[string]crypto.StoredCryptoConfig)
	RSAPublicMap := make(crypto.RSAPublicMap)
	RSAPrivateMap := make(map[string]*rsa.PrivateKey)
	BLSPublicMap := make(map[string][]byte)
	BLSPrivateMap := make(map[string][]byte)
	// Generate RSA key pair
	RSAPublicMap, RSAPrivateMap = RSA_gen_all(G_list, M_list, C_list, L_list)
	// Generate BLS key pair
	BLSPublicMap, BLSPrivateMap = BLS_gen_all(G_list)
	// Generate CA public config map
	ca_public_config := GenerateCA_public_config(L_list, C_list, MMD, MMD, []string{"1.1"})
	// Generate CA private config map
	ca_private_config_map = GenerateCA_private_config_map(G_list, M_list, L_list, num_ca, num_cert)
	// Generate CA crypto config map
	ca_crypto_config_map = GenerateCryptoconfig_map(Total, Threshold, "CA")
	// Create CA directory
	os.Mkdir("ca_testconfig", 0777)
	// Generate Logger public config map
	logger_public_config := GenerateLogger_public_config(L_list, C_list, MMD, MMD, []string{"1.1"})
	// Generate Logger private config map
	logger_private_config_map = GenerateLogger_private_config_map(G_list, M_list, C_list, num_logger)
	// Generate Logger crypto config map
	logger_crypto_config_map = GenerateCryptoconfig_map(Total, Threshold, "Logger")
	// Create Logger directory
	os.Mkdir("logger_testconfig", 0777)
	// write all CA public config, private config, crypto config to file
	for i := 0; i < num_ca; i++ {
		// create a new folder for each CA if not exist
		os.Mkdir(config_path+"ca_testconfig/"+fmt.Sprint(i+1), 0777)
		filepath := config_path + "ca_testconfig/" + fmt.Sprint(i+1) + "/"
		crypto_config := ca_crypto_config_map[C_list[i]]
		//update threshold public map
		crypto_config.ThresholdPublicMap = BLSPublicMap
		//update RSA public map
		crypto_config.SignPublicMap = RSAPublicMap
		// update RSA Secret key
		crypto_config.SignSecretKey = *RSAPrivateMap[C_list[i]]
		// update BLS Secret key with empty byte array
		crypto_config.ThresholdSecretKey = []byte{}
		write_all_configs_to_file(ca_public_config, ca_private_config_map[C_list[i]], crypto_config, filepath, "CA")
	}
	// write all Logger public config, private config, crypto config to file
	for i := 0; i < num_logger; i++ {
		// create a new folder for each Logger
		os.Mkdir(config_path+"logger_testconfig/"+fmt.Sprint(i+1), 0777)
		filepath := config_path + "logger_testconfig/" + fmt.Sprint(i+1) + "/"
		crypto_config := logger_crypto_config_map[L_list[i]]
		//update threshold public map
		crypto_config.ThresholdPublicMap = BLSPublicMap
		//update RSA public map
		crypto_config.SignPublicMap = RSAPublicMap
		// update RSA Secret key
		crypto_config.SignSecretKey = *RSAPrivateMap[L_list[i]]
		// update BLS Secret key with empty byte array
		crypto_config.ThresholdSecretKey = []byte{}
		write_all_configs_to_file(logger_public_config, logger_private_config_map[L_list[i]], crypto_config, filepath, "Logger")
	}
	// Generate Monitor public config map
	monitor_public_config := GenerateMonitor_public_config(G_list, M_list, C_list, L_list, MMD, MMD, 5, []string{"1.1"})
	// Generate Monitor private config map
	monitor_private_config_map = GenerateMonitor_private_config_map(G_list, M_list, C_list, L_list, MMD, MMD, 5, []string{"1.1"}, " ")
	// Generate Monitor crypto config map
	monitor_crypto_config_map = GenerateCryptoconfig_map(Total, Threshold, "Monitor")
	// Create Monitor directory
	os.Mkdir("monitor_testconfig", 0777)
	// write all Monitor public config, private config, crypto config to file
	for i := 0; i < num_gossiper; i++ {
		// create a new folder for each Monitor
		os.Mkdir(config_path+"monitor_testconfig/"+fmt.Sprint(i+1), 0777)
		filepath := config_path + "monitor_testconfig/" + fmt.Sprint(i+1) + "/"
		//update the monitor private config with the monitor crypto config path
		monitor_private_config := monitor_private_config_map[M_list[i]]
		crypto_config := monitor_crypto_config_map[M_list[i]]
		//update threshold public map
		crypto_config.ThresholdPublicMap = BLSPublicMap
		//update RSA public map
		crypto_config.SignPublicMap = RSAPublicMap
		// update RSA Secret key
		crypto_config.SignSecretKey = *RSAPrivateMap[M_list[i]]
		// update BLS Secret key with empty byte array
		crypto_config.ThresholdSecretKey = []byte{}
		write_all_configs_to_file(monitor_public_config, monitor_private_config, crypto_config, filepath, "Monitor")
	}
	// Generate Gossiper public config map
	gossiper_public_config := GenerateGossiper_public_config(G_list, M_list, C_list, L_list, MMD, MMD, 5, 5, []string{"1.1"})
	// Generate Gossiper private config map
	gossiper_private_config_map = GenerateGossiper_private_config_map(G_list, M_list, C_list, L_list, MMD, MMD, 5, 5, []string{"1.1"}, " ")
	// Generate Gossiper crypto config map
	gossiper_crypto_config_map = GenerateCryptoconfig_map(Total, Threshold, "Gossiper")
	// Create Gossiper directory
	os.Mkdir("gossiper_testconfig", 0777)
	// write all Gossiper public config, private config, crypto config to file
	for i := 0; i < num_gossiper; i++ {
		// create a new folder for each Gossiper
		os.Mkdir(config_path+"gossiper_testconfig/"+fmt.Sprint(i+1), 0777)
		filepath := config_path + "gossiper_testconfig/" + fmt.Sprint(i+1) + "/"
		//update the gossiper private config with the gossiper crypto config path
		gossiper_private_config := gossiper_private_config_map[G_list[i]]
		crypto_config := gossiper_crypto_config_map[G_list[i]]
		//update threshold public map
		crypto_config.ThresholdPublicMap = BLSPublicMap
		//update RSA public map
		crypto_config.SignPublicMap = RSAPublicMap
		// update RSA Secret key
		crypto_config.SignSecretKey = *RSAPrivateMap[G_list[i]]
		// update Threshold Secret key
		crypto_config.ThresholdSecretKey = BLSPrivateMap[G_list[i]]
		write_all_configs_to_file(gossiper_public_config, gossiper_private_config, crypto_config, filepath, "Gossiper")
	}
}

// warning: Only use this function after generating all the config files in SAME directory
func InitializeOneEntity(entity_type string, entity_id string) any {
	// initialize CA context
	if entity_type == "CA" {
		path_1 := "ca_testconfig/" + entity_id + "/CA_public_config.json"
		path_2 := "ca_testconfig/" + entity_id + "/CA_private_config.json"
		path_3 := "ca_testconfig/" + entity_id + "/CA_crypto_config.json"
		return CA.InitializeCAContext(path_1, path_2, path_3)
	}
	// initialze Logger context
	if entity_type == "Logger" {
		path_1 := "logger_testconfig/" + entity_id + "/Logger_public_config.json"
		path_2 := "logger_testconfig/" + entity_id + "/Logger_private_config.json"
		path_3 := "logger_testconfig/" + entity_id + "/Logger_crypto_config.json"
		return Logger.InitializeLoggerContext(path_1, path_2, path_3)
	}
	// initialze Monitor context
	if entity_type == "Monitor" {
		path_1 := "monitor_testconfig/" + entity_id + "/Monitor_public_config.json"
		path_2 := "monitor_testconfig/" + entity_id + "/Monitor_private_config.json"
		path_3 := "monitor_testconfig/" + entity_id + "/Monitor_crypto_config.json"
		return monitor.InitializeMonitorContext(path_1, path_2, path_3, entity_id)
	}
	// initialze Gossiper context
	if entity_type == "Gossiper" {
		path_1 := "gossiper_testconfig/" + entity_id + "/Gossiper_public_config.json"
		path_2 := "gossiper_testconfig/" + entity_id + "/Gossiper_private_config.json"
		path_3 := "gossiper_testconfig/" + entity_id + "/Gossiper_crypto_config.json"
		return gossiper.InitializeGossiperContext(path_1, path_2, path_3, entity_id)
	}
	return nil
}
