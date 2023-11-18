package Logger

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"sync"

	"github.com/jik18001/CTngV2/crypto"
	"github.com/jik18001/CTngV2/definition"
	"github.com/jik18001/CTngV2/util"
	//"fmt"
)

type Logger_public_config struct {
	All_CA_URLs     []string
	All_Logger_URLs []string
	MMD             int
	MRD             int
	Http_vers       []string
}

type Logger_private_config struct {
	Signer       string
	Port         string
	CAlist       []string
	Monitorlist  []string
	Gossiperlist []string
}

type LoggerContext struct {
	Client                *http.Client
	SerialNumber          int
	Logger_public_config  *Logger_public_config
	Logger_private_config *Logger_private_config
	Logger_crypto_config  *crypto.CryptoConfig
	PublicKey             rsa.PublicKey
	PrivateKey            rsa.PrivateKey
	CurrentPrecertPool    *crypto.CertPool
	PrecertStorage        *PrecertStorage
	OnlinePeriod          int
	Logger_Type           int                                 //0 for normal Logger, 1 for Split-world Logger, 2 for always unreponsive Logger, 3 for sometimes unreponsive Logger
	Request_Count         int                                 //Only used for sometimes unreponsive Logger and Split-world Logger
	STH_storage           map[string]definition.Gossip_object //for monitor to query
	STH_storage_fake      map[string]definition.Gossip_object //for monitor to query
	MisbehaviorInterval   int                                 //for sometimes unreponsive Logger and Split-world Logger, misbehave every x requests
	OnlineDuration        int                                 //for sometimes unreponsive Logger and Split-world Logger, misbehave every x requests
	StorageDirectory      string
	StorageFile           string
	Request_Count_lock    *sync.Mutex
	CertPool_lock         *sync.Mutex
	StoragePath           string
	Max_latency           int
	Min_latency           int
}

type PrecertStorage struct {
	PrecertPools map[string]*crypto.CertPool
}

// check if an item is in a list
func inList(item string, list []string) bool {
	for _, i := range list {
		if i == item {
			return true
		}
	}
	return false
}

func Verifyprecert(precert x509.Certificate, ctx LoggerContext) bool {
	issuer := precert.Issuer.CommonName
	//check if issuer is in CAlist
	if !inList(issuer, ctx.Logger_private_config.CAlist) {
		return false
	}
	//retrieve the public key of the issuer
	issuerPublicKey := ctx.Logger_crypto_config.SignPublicMap[crypto.CTngID(issuer)]
	//retrieve the signature of the precert
	signature := precert.Signature
	rsasig := new(crypto.RSASig)
	(*rsasig).Sig = signature
	(*rsasig).ID = crypto.CTngID(issuer)
	//check if the signature is valid
	if err := crypto.RSAVerify(precert.RawTBSCertificate, *rsasig, &issuerPublicKey); err != nil {
		return false
	}
	return true
}

// initialize Logger context
func InitializeLoggerContext(public_config_path string, private_config_file_path string, crypto_config_path string) *LoggerContext {
	// Load public config from file
	pubconf := new(Logger_public_config)
	util.LoadConfiguration(&pubconf, public_config_path)
	// Load private config from file
	privconf := new(Logger_private_config)
	util.LoadConfiguration(&privconf, private_config_file_path)
	// Load crypto config from file
	cryptoconfig, err := crypto.ReadCryptoConfig(crypto_config_path)
	if err != nil {
		//fmt.Println("read crypto config failed")
	}
	// Initialize Logger Context
	loggerContext := &LoggerContext{
		SerialNumber:          0,
		Logger_public_config:  pubconf,
		Logger_private_config: privconf,
		Logger_crypto_config:  cryptoconfig,
		PublicKey:             cryptoconfig.SignPublicMap[cryptoconfig.SelfID],
		PrivateKey:            cryptoconfig.SignSecretKey,
		CurrentPrecertPool:    crypto.NewCertPool(),
		PrecertStorage:        &PrecertStorage{PrecertPools: make(map[string]*crypto.CertPool)},
		OnlinePeriod:          0,
		Logger_Type:           0,
		Request_Count:         0,
		OnlineDuration:        0,
		Max_latency:           290,
		Min_latency:           0,
		STH_storage:           make(map[string]definition.Gossip_object),
		STH_storage_fake:      make(map[string]definition.Gossip_object),
		MisbehaviorInterval:   0,
		Request_Count_lock:    &sync.Mutex{},
		CertPool_lock:         &sync.Mutex{},
	}
	// Initialize http client
	tr := &http.Transport{}
	loggerContext.Client = &http.Client{
		Transport: tr,
	}
	return loggerContext
}

func GenerateLogger_private_config_template() *Logger_private_config {
	return &Logger_private_config{
		Signer:       "",
		Port:         "",
		CAlist:       []string{},
		Monitorlist:  []string{},
		Gossiperlist: []string{},
	}
}

func GenerateLogger_public_config_template() *Logger_public_config {
	return &Logger_public_config{
		All_CA_URLs:     []string{},
		All_Logger_URLs: []string{},
		MMD:             0,
		MRD:             0,
		Http_vers:       []string{},
	}
}

func GenerateLogger_crypto_config_template() *crypto.StoredCryptoConfig {
	return &crypto.StoredCryptoConfig{
		SelfID:             crypto.CTngID("0"),
		Threshold:          0,
		N:                  0,
		HashScheme:         0,
		SignScheme:         "",
		ThresholdScheme:    "",
		SignPublicMap:      crypto.RSAPublicMap{},
		SignSecretKey:      rsa.PrivateKey{},
		ThresholdPublicMap: map[string][]byte{},
		ThresholdSecretKey: []byte{},
	}
}

func SaveToStorage(ctx LoggerContext) {
	certs := ctx.CurrentPrecertPool.GetCerts()
	data := [][]any{}
	for _, cert := range certs {
		cert_json, _ := json.Marshal(cert)
		data = append(data, []any{cert_json})
	}
	util.WriteData(ctx.StoragePath, data)

}
