package Gen

import (
	"crypto/rsa"
	"fmt"
	"os"
	"testing"

	"github.com/jik18001/CTngV2/CA"
	"github.com/jik18001/CTngV2/Logger"
	"github.com/jik18001/CTngV2/crypto"
	"github.com/jik18001/CTngV2/gossiper"
	"github.com/jik18001/CTngV2/monitor"
)

var num_gossiper int
var num_logger int
var num_ca int
var num_cert int
var Threshold int
var MMD int
var MRD int
var Total int
var G_list []string
var M_list []string
var C_list []string
var L_list []string
var ca_public_config *CA.CA_public_config
var ca_private_config_map map[string]CA.CA_private_config
var ca_crypto_config_map map[string]crypto.StoredCryptoConfig
var logger_public_config *Logger.Logger_public_config
var logger_private_config_map map[string]Logger.Logger_private_config
var logger_crypto_config_map map[string]crypto.StoredCryptoConfig
var monitor_public_config *monitor.Monitor_public_config
var monitor_private_config_map map[string]monitor.Monitor_private_config
var monitor_crypto_config_map map[string]crypto.StoredCryptoConfig
var gossiper_public_config *gossiper.Gossiper_public_config
var gossiper_private_config_map map[string]gossiper.Gossiper_private_config
var gossiper_crypto_config_map map[string]crypto.StoredCryptoConfig
var RSAPublicMap crypto.RSAPublicMap
var RSAPrivateMap map[string]*rsa.PrivateKey
var BLSPublicMap map[string][]byte
var BLSPrivateMap map[string][]byte

func test_init(t *testing.T) {
	num_gossiper = 4
	num_logger = 2
	num_ca = 2
	num_cert = 4
	Threshold = 2
	MMD = 60
	MRD = 60
	Total = num_gossiper
	G_list, M_list, C_list, L_list = Generate_all_list(num_gossiper, num_ca, num_logger)
	ca_private_config_map = make(map[string]CA.CA_private_config)
	ca_crypto_config_map = make(map[string]crypto.StoredCryptoConfig)
	logger_private_config_map = make(map[string]Logger.Logger_private_config)
	logger_crypto_config_map = make(map[string]crypto.StoredCryptoConfig)
	monitor_private_config_map = make(map[string]monitor.Monitor_private_config)
	monitor_crypto_config_map = make(map[string]crypto.StoredCryptoConfig)
	gossiper_private_config_map = make(map[string]gossiper.Gossiper_private_config)
	gossiper_crypto_config_map = make(map[string]crypto.StoredCryptoConfig)
	RSAPublicMap = make(crypto.RSAPublicMap)
	RSAPrivateMap = make(map[string]*rsa.PrivateKey)
	BLSPublicMap = make(map[string][]byte)
	BLSPrivateMap = make(map[string][]byte)
}

func test_key_gen(t *testing.T) {
	// Generate RSA key pair
	RSAPublicMap, RSAPrivateMap = RSA_gen_all(G_list, M_list, C_list, L_list)
	// Generate BLS key pair
	BLSPublicMap, BLSPrivateMap = BLS_gen_all(G_list)
}
func test_gen_CA_Logger(t *testing.T) {
	// Generate CA public config map
	ca_public_config = GenerateCA_public_config(C_list, L_list, MMD, MMD, []string{"1.1"})
	// Generate CA private config map
	ca_private_config_map = GenerateCA_private_config_map(G_list, M_list, L_list, num_cert, num_ca)
	// Generate CA crypto config map
	ca_crypto_config_map = GenerateCryptoconfig_map(Total, Threshold, "CA")
	// Create CA directory
	os.Mkdir("ca_testconfig", 0777)
	// Generate Logger public config map
	logger_public_config = GenerateLogger_public_config(C_list, L_list, MMD, MMD, []string{"1.1"})
	// Generate Logger private config map
	logger_private_config_map = GenerateLogger_private_config_map(G_list, M_list, C_list, num_logger)
	// Generate Logger crypto config map
	logger_crypto_config_map = GenerateCryptoconfig_map(Total, Threshold, "Logger")
	// Create Logger directory
	os.Mkdir("logger_testconfig", 0777)
	// write all CA public config, private config, crypto config to file
	for i := 0; i < num_ca; i++ {
		// create a new folder for each CA if not exist
		os.Mkdir("ca_testconfig/"+fmt.Sprint(i+1), 0777)
		filepath := "ca_testconfig/" + fmt.Sprint(i+1) + "/"
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
		os.Mkdir("logger_testconfig/"+fmt.Sprint(i+1), 0777)
		filepath := "logger_testconfig/" + fmt.Sprint(i+1) + "/"
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
}

func test_gen_Monitor_Gossiper(t *testing.T) {
	// Generate Monitor public config map
	monitor_public_config := GenerateMonitor_public_config(G_list, M_list, C_list, L_list, MMD, MMD, 5, []string{"1.1"})
	// Generate Monitor private config map
	monitor_private_config_map := GenerateMonitor_private_config_map(G_list, M_list, C_list, L_list, MMD, MMD, 5, []string{"1.1"}, " ")
	// Generate Monitor crypto config map
	monitor_crypto_config_map := GenerateCryptoconfig_map(Total, Threshold, "Monitor")
	// Create Monitor directory
	os.Mkdir("monitor_testconfig", 0777)
	// write all Monitor public config, private config, crypto config to file
	for i := 0; i < num_gossiper; i++ {
		// create a new folder for each Monitor
		os.Mkdir("monitor_testconfig/"+fmt.Sprint(i+1), 0777)
		filepath := "monitor_testconfig/" + fmt.Sprint(i+1) + "/"
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
	gossiper_private_config_map := GenerateGossiper_private_config_map(G_list, M_list, C_list, L_list, MMD, MMD, 5, 5, []string{"1.1"}, " ")
	// Generate Gossiper crypto config map
	gossiper_crypto_config_map := GenerateCryptoconfig_map(Total, Threshold, "Gossiper")
	// Create Gossiper directory
	os.Mkdir("gossiper_testconfig", 0777)
	// write all Gossiper public config, private config, crypto config to file
	for i := 0; i < num_gossiper; i++ {
		// create a new folder for each Gossiper
		os.Mkdir("gossiper_testconfig/"+fmt.Sprint(i+1), 0777)
		filepath := "gossiper_testconfig/" + fmt.Sprint(i+1) + "/"
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

func TestGenall(t *testing.T) {
	Generateall(4, 2, 4, 4, 4, 60, 60, "")
	newtemp := Generate_IP_Json_template(4, 4, 4, "172.30.0.", 11, "172.30.0.", 15, "172.30.0.", 19)
	Write_IP_Json_to_files("IPLIST.json", newtemp)
	IPLIST := Read_IP_Json_from_files("IPLIST.json")
	Map_all(4, 4, 4, IPLIST)
}
