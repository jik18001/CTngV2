package gossiper

import (
	"CTngV2/crypto"
	"CTngV2/definition"
	"net/http"
	"sync"
)

type Gossiper_public_config struct {
	Communiation_delay int
	Gossip_wait_time   int
	Max_push_size      int
	Period_interval    int64
	Expiration_time    int // if 0, no expiration.
	MMD                int
	MRD                int
	Gossiper_URLs      []string
	Signer_URLs        []string // List of all potential signers' DNS names.
}

type Gossiper_private_config struct {
	Crypto_config_location string
	Connected_Gossipers    []string
	Owner_URL              string
	Port                   string
	Crypto                 *crypto.CryptoConfig
	Public                 *Gossiper_public_config
}

type Gossip_object_storage struct {
	STH_INIT      map[definition.Gossip_ID]definition.Gossip_object
	REV_INIT      map[definition.Gossip_ID]definition.Gossip_object
	ACC_INIT      map[definition.Gossip_ID]definition.Gossip_object
	CON_INIT      map[definition.Gossip_ID]definition.Gossip_object
	STH_FRAG      map[definition.Gossip_ID][]definition.Gossip_object
	REV_FRAG      map[definition.Gossip_ID][]definition.Gossip_object
	ACC_FRAG      map[definition.Gossip_ID][]definition.Gossip_object
	CON_FRAG      map[definition.Gossip_ID][]definition.Gossip_object
	STH_FULL      map[definition.Gossip_ID]definition.Gossip_object
	REV_FULL      map[definition.Gossip_ID]definition.Gossip_object
	ACC_FULL      map[definition.Gossip_ID]definition.Gossip_object
	CON_FULL      map[definition.Gossip_ID]definition.Gossip_object
	STH_INIT_LOCK sync.RWMutex
	REV_INIT_LOCK sync.RWMutex
	ACC_INIT_LOCK sync.RWMutex
	CON_INIT_LOCK sync.RWMutex
	STH_FRAG_LOCK sync.RWMutex
	REV_FRAG_LOCK sync.RWMutex
	ACC_FRAG_LOCK sync.RWMutex
	CON_FRAG_LOCK sync.RWMutex
	STH_FULL_LOCK sync.RWMutex
	REV_FULL_LOCK sync.RWMutex
	ACC_FULL_LOCK sync.RWMutex
	CON_FULL_LOCK sync.RWMutex
}

type Gossip_blacklist struct {
	BLACKLIST_TEMP      map[string]bool
	BLACKLIST_PERM      map[string]bool
	BLACKLIST_TEMP_LOCK sync.RWMutex
	BLACKLIST_PERM_LOCK sync.RWMutex
}

type Gossip_PoM_Counter struct {
	NUM_INIT      map[string][]string
	NUM_FRAG      []definition.PoM_Counter
	NUM_FULL      bool
	NUM_INIT_LOCK sync.RWMutex
	NUM_FRAG_LOCK sync.RWMutex
	NUM_FULL_LOCK sync.RWMutex
}

type GossiperContext struct {
	Gossiper_private_config *Gossiper_private_config
	Gossiper_public_config  *Gossiper_public_config
	Gossiper_crypto_config  *crypto.CryptoConfig
	// Storage
	Gossip_object_storage *Gossip_object_storage
	Gossip_blacklist      *Gossip_blacklist
	Gossip_PoM_Counter    *Gossip_PoM_Counter
	Gossiper_log          *Gossiper_log
	//File I/O
	StorageID        string
	StorageFile      string
	StorageDirectory string
	Client           *http.Client
	Verbose          bool
}

type Gossiper_log_entry struct {
	Period             int `json:"period"` // Period of the log
	NUM_STH_INIT       int `json:"num_sth_init"`
	NUM_REV_INIT       int `json:"num_rev_init"`
	NUM_ACC_INIT       int `json:"num_acc_init"`
	NUM_CON_INIT       int `json:"num_con_init"`
	NUM_STH_FRAG       int `json:"num_sth_frag"`
	NUM_REV_FRAG       int `json:"num_rev_frag"`
	NUM_ACC_FRAG       int `json:"num_acc_frag"`
	NUM_CON_FRAG       int `json:"num_con_frag"`
	NUM_STH_FULL       int `json:"num_sth_full"`
	NUM_REV_FULL       int `json:"num_rev_full"`
	NUM_ACC_FULL       int `json:"num_acc_full"`
	NUM_CON_FULL       int `json:"num_con_full"`
	NUM_BLACKLIST_TEMP int `json:"num_blacklist_temp"`
	NUM_BLACKLIST_PERM int `json:"num_blacklist_perm"`
	NUM_POM_INIT       int `json:"num_pom_init"`
	NUM_POM_FRAG       int `json:"num_pom_frag"`
	NUM_POM_FULL       int `json:"num_pom_full"`
}

type Gossiper_log map[int]Gossiper_log_entry
