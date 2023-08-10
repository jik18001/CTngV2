package client

import (
	"CTngV2/crypto"
	"CTngV2/definition"
	"CTngV2/monitor"
	"CTngV2/util"
	"encoding/json"
	"log"
	"sync"

	"github.com/bits-and-blooms/bitset"
)

type ClientConfig struct {
	Monitor_URLs []string
	//This is the URL of the monitor where the client will get the information from
	Client_URL           string
	Port                 string
	MMD                  int
	MRD                  int
	STH_Storage_filepath string
	CRV_Storage_filepath string
	PoM_Store_filepath   string
}

type ClientContext struct {
	Config              *ClientConfig
	Crypto              *crypto.CryptoConfig
	Current_Monitor_URL string
	// the databases are shared resources and should be protected with mutex
	STH_database  map[string]string         // key = entity_ID + @ + Period, content = RootHash
	CRV_database  map[string]*bitset.BitSet // key = entity_ID, content = CRV
	POM_database  map[string]definition.Gossip_object
	STH_DB_RWLock *sync.RWMutex
	CRV_DB_RWLock *sync.RWMutex
	POM_DB_RWLock *sync.RWMutex
	// Don't need lock for monitor integerity DB because it is only checked once per period
	Config_filepath string
	Crypto_filepath string
	Status          string
}

func SaveSTHDatabase(ctx *ClientContext) {
	util.WriteData(ctx.Config.STH_Storage_filepath, ctx.STH_database)
}

func SaveCRVDatabase(ctx *ClientContext) {
	var crvstorage = make(map[string][]byte)
	for key, value := range ctx.CRV_database {
		crvstorage[key], _ = value.MarshalBinary()
	}
	util.WriteData(ctx.Config.CRV_Storage_filepath, crvstorage)
}

func SavePomDatabase(ctx *ClientContext) {
	util.WriteData(ctx.Config.PoM_Store_filepath, ctx.POM_database)
}

func LoadSTHDatabase(ctx *ClientContext) {
	databyte, err := util.ReadByte(ctx.Config.STH_Storage_filepath)
	if err != nil {
		ctx.STH_database = make(map[string]string)
		return
	}
	json.Unmarshal(databyte, &ctx.STH_database)
	if err != nil {
		log.Fatal(err)
	}
}

func LoadCRVDatabase(ctx *ClientContext) {
	databyte, err := util.ReadByte(ctx.Config.CRV_Storage_filepath)
	if err != nil {
		ctx.CRV_database = make(map[string]*bitset.BitSet)
		return
	}
	var crvstorage = make(map[string][]byte)
	err = json.Unmarshal(databyte, &crvstorage)
	if err != nil {
		log.Fatal(err)
	}
	for key, value := range crvstorage {
		var crv_entry bitset.BitSet
		crv_entry.UnmarshalBinary(value)
		ctx.CRV_database[key] = &crv_entry
	}
}

func LoadPoMdatabase(ctx *ClientContext) {
	databyte, err := util.ReadByte(ctx.Config.PoM_Store_filepath)
	if err != nil {
		ctx.POM_database = make(map[string]definition.Gossip_object)
		return
	}
	json.Unmarshal(databyte, &ctx.POM_database)
	if err != nil {
		log.Fatal(err)
	}
}
func (ctx *ClientContext) LoadUpdate(filepath string) monitor.ClientUpdate {
	update_json, err := util.ReadByte(filepath)
	if err != nil {
		log.Fatal(err)
	}
	var update_m monitor.ClientUpdate
	err = json.Unmarshal(update_json, &update_m)
	if err != nil {
		log.Fatal(err)
	}
	return update_m
}

func (ctx *ClientContext) InitializeClientContext() {
	util.LoadConfiguration(ctx.Config, ctx.Config_filepath)
	CryptoConfig, err := crypto.ReadVerifyOnlyCryptoConfig(ctx.Crypto_filepath)
	ctx.Crypto = CryptoConfig
	// initialize the Locks for the databases
	ctx.STH_DB_RWLock = &sync.RWMutex{}
	ctx.CRV_DB_RWLock = &sync.RWMutex{}
	ctx.POM_DB_RWLock = &sync.RWMutex{}
	// initialize the databases
	ctx.STH_database = make(map[string]string)
	ctx.CRV_database = make(map[string]*bitset.BitSet)
	ctx.POM_database = make(map[string]definition.Gossip_object)
	// load the databases
	if err != nil {
		log.Fatal(err)
	}
	if ctx.Status != "NEW" {
		LoadSTHDatabase(ctx)
		LoadCRVDatabase(ctx)
	}
}
