package monitor

import (
	"CTngV2/crypto"
	"CTngV2/definition"
	"CTngV2/util"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"

	"github.com/bits-and-blooms/bitset"
)

type MonitorContext struct {
	Monitor_private_config *Monitor_private_config
	Monitor_public_config  *Monitor_public_config
	Monitor_crypto_config  *crypto.CryptoConfig
	Storage_TEMP           *definition.Gossip_Storage
	// Gossip objects from the gossiper will be assigned to their dedicated storage
	Storage_CONFLICT_POM       *definition.Gossip_Storage
	Storage_CONFLICT_POM_DELTA *definition.Gossip_Storage
	Storage_ACCUSATION_POM     *definition.Gossip_Storage
	Storage_STH_FULL           *definition.Gossip_Storage
	Storage_REV_FULL           *definition.Gossip_Storage
	Storage_NUM_FULL           *definition.PoM_Counter
	Storage_CRV                map[string]*bitset.BitSet
	// Utilize Storage directory: A folder for the files of each MMD.
	// Folder should be set to the current MMD "Period" String upon initialization.
	StorageFile_CRV  string
	StorageDirectory string
	StorageID        string
	// The below could be used to prevent a Monitor from sending duplicate Accusations,
	// Currently, if a monitor accuses two entities in the same Period, it will trigger a gossip PoM.
	// Therefore, a monitor can only accuse once per Period. I believe this is a temporary solution.
	Verbose       bool
	Client        *http.Client
	Mode          int
	Period_Offset string
}

type Monitor_private_config struct {
	CA_URLs               []string
	Logger_URLs           []string
	Signer                string
	Gossiper_URL          string
	Inbound_gossiper_port string
	Port                  string
}

type Monitor_public_config struct {
	All_CA_URLs      []string
	All_Logger_URLs  []string
	Gossip_wait_time int
	MMD              int
	MRD              int
}

func (c *MonitorContext) GetObjectNumber(objtype string) int {
	switch objtype {
	case definition.CON_FULL:
		return len(*c.Storage_CONFLICT_POM)
	case definition.ACC_FULL:
		return len(*c.Storage_ACCUSATION_POM)
	case definition.STH_FULL:
		return len(*c.Storage_STH_FULL)
	case definition.REV_FULL:
		return len(*c.Storage_REV_FULL)
	}
	return 0
}
func (c *MonitorContext) Clean_Conflicting_Object() {
	GID := definition.Gossip_ID{}
	for key := range *c.Storage_STH_FULL {
		GID = definition.Gossip_ID{
			Period:     "0",
			Type:       definition.CON_FULL,
			Entity_URL: key.Entity_URL,
		}
		if _, ok := (*c.Storage_CONFLICT_POM)[GID]; ok {
			fmt.Println(util.BLUE + "Logger: " + key.Entity_URL + "has Conflict_PoM on file, cleared the STH from this Logger this MMD" + util.RESET)
			delete(*c.Storage_STH_FULL, key)
		}
	}
	for key := range *c.Storage_REV_FULL {
		GID = definition.Gossip_ID{
			Period:     "0",
			Type:       definition.CON_FULL,
			Entity_URL: key.Entity_URL,
		}
		if _, ok := (*c.Storage_CONFLICT_POM)[GID]; ok {
			fmt.Println(util.BLUE + "CA: " + key.Entity_URL + "has Conflict_PoM on file, cleared the REV from this CA this MRD" + util.RESET)
			delete(*c.Storage_REV_FULL, key)
		}
	}
}

func (c *MonitorContext) SaveStorage(Period string, update ClientUpdate) error {
	// should be string
	// Create the storage directory, should be StorageDirectory/Period
	newdir := c.StorageDirectory + "/Period_" + Period
	util.CreateDir(newdir)
	clientUpdate_path := newdir + "/ClientUpdate.json"
	util.CreateFile(clientUpdate_path)
	util.WriteData(clientUpdate_path, update)
	//save CRV
	var crvstorage = make(map[string][]byte)
	for key, value := range c.Storage_CRV {
		crvstorage[key], _ = value.MarshalBinary()
	}
	util.WriteData(c.StorageFile_CRV, crvstorage)
	fmt.Println(util.BLUE, "File Storage Complete for Period: ", util.GetCurrentPeriod(), util.RESET)
	return nil
}

func (c *MonitorContext) LoadOneStorage(name string, filepath string) error {
	storageList := []definition.Gossip_object{}
	bytes, err := util.ReadByte(filepath)
	if err != nil {
		return err
	}
	err = json.Unmarshal(bytes, &storageList)
	if err != nil {
		return err
	}
	switch name {
	case definition.CON_FULL:
		for _, gossipObject := range storageList {
			(*c.Storage_CONFLICT_POM)[gossipObject.GetID()] = gossipObject
		}
	case definition.ACC_FULL:
		for _, gossipObject := range storageList {
			(*c.Storage_ACCUSATION_POM)[gossipObject.GetID()] = gossipObject
		}
	case definition.STH_FULL:
		for _, gossipObject := range storageList {
			(*c.Storage_STH_FULL)[gossipObject.GetID()] = gossipObject
		}
	case definition.REV_FULL:
		for _, gossipObject := range storageList {
			(*c.Storage_REV_FULL)[gossipObject.GetID()] = gossipObject
		}
	}
	return errors.New("Mismatch")
}

func (c *MonitorContext) GetObject(id definition.Gossip_ID) definition.Gossip_object {
	GType := id.Type
	switch GType {
	case definition.CON_FULL:
		obj := (*c.Storage_CONFLICT_POM)[id]
		return obj
	case definition.ACC_FULL:
		obj := (*c.Storage_ACCUSATION_POM)[id]
		return obj
	case definition.STH_FULL:
		obj := (*c.Storage_STH_FULL)[id]
		return obj
	case definition.REV_FULL:
		obj := (*c.Storage_REV_FULL)[id]
		return obj
	case definition.STH_INIT:
		obj := (*c.Storage_TEMP)[id]
		return obj
	case definition.REV_INIT:
		obj := (*c.Storage_TEMP)[id]
		return obj
	}
	return definition.Gossip_object{}

}
func (c *MonitorContext) IsDuplicate(g definition.Gossip_object) bool {
	//no public period time for monitor :/
	id := g.GetID()
	obj := c.GetObject(id)
	return reflect.DeepEqual(obj, g)
}

func (c *MonitorContext) StoreObject(o definition.Gossip_object) {
	switch o.Type {
	case definition.CON_FULL:
		(*c.Storage_CONFLICT_POM)[o.GetID()] = o
		(*c.Storage_CONFLICT_POM_DELTA)[o.GetID()] = o
		fmt.Println(util.BLUE, "CONFLICT_POM Stored", util.RESET)
	case definition.ACC_FULL:
		//ACCUSATION POM does not need to be stored, but this function is here for testing purposes
		(*c.Storage_ACCUSATION_POM)[o.GetID()] = o
		fmt.Println(util.BLUE, "ACCUSATION_POM Stored", util.RESET)
	case definition.STH_FULL:
		(*c.Storage_STH_FULL)[o.GetID()] = o
		fmt.Println(util.BLUE, "STH_FULL Stored", util.RESET)
	case definition.REV_FULL:
		(*c.Storage_REV_FULL)[o.GetID()] = o
		SRH, DCRV := Get_SRH_and_DCRV(o)
		key := o.Payload[0]
		//verif REV_FULL
		//verify SRH
		if !c.VerifySRH(SRH, &DCRV, key, o.Period) {
			fmt.Println("SRH verification failed")
			return
		}
		//Update CRV
		// look for CRV first
		if _, ok := c.Storage_CRV[key]; !ok {
			c.Storage_CRV[key] = &DCRV
		} else {
			c.Storage_CRV[key].SymmetricDifference(&DCRV)
		}
		fmt.Println(util.BLUE, "REV_FULL Stored", util.RESET)
	default:
		(*c.Storage_TEMP)[o.GetID()] = o
	}

}

// wipe all temp data
func (c *MonitorContext) WipeStorage() {
	for key := range *c.Storage_TEMP {
		if key.Period != util.GetCurrentPeriod() {
			delete(*c.Storage_ACCUSATION_POM, key)
		}
	}
	for key := range *c.Storage_CONFLICT_POM_DELTA {
		if key.Period != util.GetCurrentPeriod() {
			delete(*c.Storage_CONFLICT_POM_DELTA, key)
		}
	}
	// we can clear All STH and REV storage, because we will write them to file at the end of the period
	for key := range *c.Storage_STH_FULL {
		if key.Period != util.GetCurrentPeriod() {
			delete(*c.Storage_STH_FULL, key)
		}
	}
	for key := range *c.Storage_REV_FULL {
		if key.Period != util.GetCurrentPeriod() {
			delete(*c.Storage_REV_FULL, key)
		}
	}
	fmt.Println(util.BLUE, "Temp storage has been wiped.", util.RESET)
}

func (c *MonitorContext) InitializeMonitorStorage(filepath string) {
	c.StorageDirectory = filepath + "/" + c.StorageID + "/"
	c.StorageFile_CRV = filepath + "/" + c.StorageID + "/" + "CRV.json"
}

func (c *MonitorContext) CleanUpMonitorStorage() {
	//delete all files in storage directory
	err := util.DeleteFilesAndDirectories(c.StorageDirectory)
	if err != nil {
		fmt.Println(err)
	}
}

func InitializeMonitorContext(public_config_path string, private_config_path string, crypto_config_path string, storageID string) *MonitorContext {
	var priv *Monitor_private_config
	var pub *Monitor_public_config
	util.LoadConfiguration(&priv, private_config_path)
	util.LoadConfiguration(&pub, public_config_path)
	crypto, _ := crypto.ReadCryptoConfig(crypto_config_path)
	// Space is allocated for all storage fields, and then make is run to initialize these spaces.
	storage_temp := new(definition.Gossip_Storage)
	*storage_temp = make(definition.Gossip_Storage)
	storage_conflict_pom := new(definition.Gossip_Storage)
	*storage_conflict_pom = make(definition.Gossip_Storage)
	storage_conflict_pom_delta := new(definition.Gossip_Storage)
	*storage_conflict_pom_delta = make(definition.Gossip_Storage)
	storage_accusation_pom := new(definition.Gossip_Storage)
	*storage_accusation_pom = make(definition.Gossip_Storage)
	storage_sth_full := new(definition.Gossip_Storage)
	*storage_sth_full = make(definition.Gossip_Storage)
	storage_rev_full := new(definition.Gossip_Storage)
	*storage_rev_full = make(definition.Gossip_Storage)
	ctx := MonitorContext{
		Monitor_private_config:     priv,
		Monitor_public_config:      pub,
		Monitor_crypto_config:      crypto,
		Storage_TEMP:               storage_temp,
		Storage_CONFLICT_POM:       storage_conflict_pom,
		Storage_CONFLICT_POM_DELTA: storage_conflict_pom_delta,
		Storage_ACCUSATION_POM:     storage_accusation_pom,
		Storage_STH_FULL:           storage_sth_full,
		Storage_REV_FULL:           storage_rev_full,
		Storage_NUM_FULL:           &definition.PoM_Counter{},
		Storage_CRV:                make(map[string]*bitset.BitSet),
		StorageID:                  storageID,
		Mode:                       0,
	}
	return &ctx
}

func Get_SRH_and_DCRV(rev definition.Gossip_object) (string, bitset.BitSet) {
	var revocation definition.Revocation
	err := json.Unmarshal([]byte(rev.Payload[2]), &revocation)
	if err != nil {
		fmt.Println(err)
	}
	newSRH := revocation.SRH
	var newDCRV bitset.BitSet
	err = newDCRV.UnmarshalBinary(revocation.Delta_CRV)
	if err != nil {
		fmt.Println(err)
	}
	return newSRH, newDCRV
}
