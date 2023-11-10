package gossiper

import (
	"math/rand"
	"net/http"
	"sync"
	"time"

	"github.com/jik18001/CTngV2/crypto"
	"github.com/jik18001/CTngV2/definition"
)

type Gossiper_public_config struct {
	Gossip_wait_time int
	MMD              int
	MRD              int
	Gossiper_URLs    []string
	Signer_URLs      []string // List of all potential signers' DNS names.
}

type Gossiper_private_config struct {
	Connected_Gossipers []string
	Owner_URL           string
	Port                string
}

type Gossip_object_storage struct {
	STH_INIT         map[definition.Gossip_ID]definition.Gossip_object
	REV_INIT         map[definition.Gossip_ID]definition.Gossip_object
	ACC_INIT         map[definition.Gossip_ID]definition.Gossip_object
	CON_INIT         map[definition.Gossip_ID]definition.Gossip_object
	STH_FRAG         map[definition.Gossip_ID][]definition.Gossip_object
	REV_FRAG         map[definition.Gossip_ID][]definition.Gossip_object
	ACC_FRAG         map[definition.Gossip_ID][]definition.Gossip_object
	STH_FULL         map[definition.Gossip_ID]definition.Gossip_object
	REV_FULL         map[definition.Gossip_ID]definition.Gossip_object
	ACC_FULL         map[definition.Gossip_ID]definition.Gossip_object
	REV_PAYLOAD      map[definition.Gossip_ID][3]string
	STH_INIT_LOCK    sync.RWMutex
	REV_INIT_LOCK    sync.RWMutex
	ACC_INIT_LOCK    sync.RWMutex
	CON_INIT_LOCK    sync.RWMutex
	STH_FRAG_LOCK    sync.RWMutex
	REV_FRAG_LOCK    sync.RWMutex
	ACC_FRAG_LOCK    sync.RWMutex
	STH_FULL_LOCK    sync.RWMutex
	REV_FULL_LOCK    sync.RWMutex
	ACC_FULL_LOCK    sync.RWMutex
	CON_FULL_LOCK    sync.RWMutex
	REV_PAYLOAD_LOCK sync.RWMutex
}

type Gossip_blacklist struct {
	BLACKLIST_PERM      map[string]bool
	BLACKLIST_PERM_LOCK sync.RWMutex
}

type GossiperContext struct {
	Gossiper_private_config *Gossiper_private_config
	Gossiper_public_config  *Gossiper_public_config
	Gossiper_crypto_config  *crypto.CryptoConfig
	// Storage
	Gossip_object_storage *Gossip_object_storage
	Gossip_blacklist      *Gossip_blacklist
	Gossiper_log          *Gossiper_log
	Converge_time         string
	Converge_time_init    string
	//File I/O
	StorageID        string
	StorageFile      string
	StorageDirectory string
	Client           *http.Client
	Verbose          bool
	//For Testing only
	Total_Logger           int
	Total_CA               int
	Min_latency            int
	Max_latency            int
	Total_traffic_sent     int
	Total_traffic_received int
	Optimization_threshold int
	Counter1_lock          sync.Mutex
	Counter2_lock          sync.Mutex
	Timerlist              []float64
}

type Gossiper_log_entry struct {
	Period                 int       `json:"period"` // Period of the log
	Converge_time          string    `json:"converge_time"`
	Converge_time_init     string    `json:"converge_time_init"`
	Total_traffic_received int       `json:"total_traffic_received"`
	Total_traffic_sent     int       `json:"total_traffic_sent"`
	NUM_STH_INIT           int       `json:"num_sth_init"`
	NUM_REV_INIT           int       `json:"num_rev_init"`
	NUM_ACC_INIT           int       `json:"num_acc_init"`
	NUM_CON_INIT           int       `json:"num_con_init"`
	NUM_STH_FRAG           int       `json:"num_sth_frag"`
	NUM_REV_FRAG           int       `json:"num_rev_frag"`
	NUM_ACC_FRAG           int       `json:"num_acc_frag"`
	NUM_STH_FULL           int       `json:"num_sth_full"`
	NUM_REV_FULL           int       `json:"num_rev_full"`
	NUM_ACC_FULL           int       `json:"num_acc_full"`
	NUM_BLACKLIST_PERM     int       `json:"num_blacklist_perm"`
	Timerlist              []float64 `json:"total_time"`
}

type Gossip_Notification struct {
	Sender     string `json:"sender"`
	Period     string `json:"period"`
	Type       string `json:"type"`
	Entity_URL string `json:"entity_url"`
}

type Gossiper_log map[int]Gossiper_log_entry

func (ctx *GossiperContext) ComputeRandomlatency() time.Duration {
	return time.Duration((ctx.Min_latency + rand.Intn(ctx.Max_latency-ctx.Min_latency))) * time.Millisecond
}
