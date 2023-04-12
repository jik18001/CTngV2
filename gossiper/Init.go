package gossiper

import (
	"CTngV2/crypto"
	"CTngV2/definition"
	"CTngV2/util"
	"net/http"
	"sync"
)

func InitializeGossipObjectStorage() *Gossip_object_storage {
	return &Gossip_object_storage{
		STH_INIT:      make(map[definition.Gossip_ID]definition.Gossip_object),
		REV_INIT:      make(map[definition.Gossip_ID]definition.Gossip_object),
		ACC_INIT:      make(map[definition.Gossip_ID]definition.Gossip_object),
		CON_INIT:      make(map[definition.Gossip_ID]definition.Gossip_object),
		STH_FRAG:      make(map[definition.Gossip_ID][]definition.Gossip_object),
		REV_FRAG:      make(map[definition.Gossip_ID][]definition.Gossip_object),
		ACC_FRAG:      make(map[definition.Gossip_ID][]definition.Gossip_object),
		CON_FRAG:      make(map[definition.Gossip_ID][]definition.Gossip_object),
		STH_FULL:      make(map[definition.Gossip_ID]definition.Gossip_object),
		REV_FULL:      make(map[definition.Gossip_ID]definition.Gossip_object),
		ACC_FULL:      make(map[definition.Gossip_ID]definition.Gossip_object),
		CON_FULL:      make(map[definition.Gossip_ID]definition.Gossip_object),
		STH_INIT_LOCK: sync.RWMutex{},
		REV_INIT_LOCK: sync.RWMutex{},
		ACC_INIT_LOCK: sync.RWMutex{},
		CON_INIT_LOCK: sync.RWMutex{},
		STH_FRAG_LOCK: sync.RWMutex{},
		REV_FRAG_LOCK: sync.RWMutex{},
		ACC_FRAG_LOCK: sync.RWMutex{},
		CON_FRAG_LOCK: sync.RWMutex{},
		STH_FULL_LOCK: sync.RWMutex{},
		REV_FULL_LOCK: sync.RWMutex{},
		ACC_FULL_LOCK: sync.RWMutex{},
		CON_FULL_LOCK: sync.RWMutex{},
	}
}

func InitializeGossipBlacklist() *Gossip_blacklist {
	return &Gossip_blacklist{
		BLACKLIST_TEMP:      make(map[string]bool),
		BLACKLIST_PERM:      make(map[string]bool),
		BLACKLIST_TEMP_LOCK: sync.RWMutex{},
		BLACKLIST_PERM_LOCK: sync.RWMutex{},
	}
}

func InitializeGossipPoMCounter() *Gossip_PoM_Counter {
	return &Gossip_PoM_Counter{
		NUM_INIT:      make(map[string][]string),
		NUM_FRAG:      make([]definition.PoM_Counter, 0),
		NUM_FULL:      false,
		NUM_INIT_LOCK: sync.RWMutex{},
		NUM_FRAG_LOCK: sync.RWMutex{},
		NUM_FULL_LOCK: sync.RWMutex{},
	}
}

func InitializeGossiperLog() *Gossiper_log {
	g_log := make(Gossiper_log)
	return &g_log
}

func InitializeGossiperContext(public_config_path string, private_config_path string, crypto_config_path string, storageID string) *GossiperContext {
	var priv *Gossiper_private_config
	var pub *Gossiper_public_config
	util.LoadConfiguration(&priv, private_config_path)
	util.LoadConfiguration(&pub, public_config_path)
	crypto, _ := crypto.ReadCryptoConfig(crypto_config_path)
	ctx := &GossiperContext{
		Gossiper_private_config: priv,
		Gossiper_public_config:  pub,
		Gossiper_crypto_config:  crypto,
		Gossip_object_storage:   InitializeGossipObjectStorage(),
		Gossip_blacklist:        InitializeGossipBlacklist(),
		Gossip_PoM_Counter:      InitializeGossipPoMCounter(),
		Gossiper_log:            InitializeGossiperLog(),
		StorageID:               storageID,
		StorageFile:             storageID + ".json",
		StorageDirectory:        "Gossip_log/",
		Client:                  &http.Client{},
		Verbose:                 false,
	}
	return ctx
}
