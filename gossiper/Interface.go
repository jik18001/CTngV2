package gossiper

import (
	"CTngV2/definition"
	"CTngV2/util"
	"errors"
	"fmt"
	"os"
	"strconv"
)

type GossiperInterfact interface {
	InitializeGossiperContext(public_config_path string, private_config_path string, crypto_config_path string, storageID string) *GossiperContext
	InBlacklist(Entity_URL string) bool
	IsDuplicate(obj any) (bool, error)
	IsMalicious(obj definition.Gossip_object) (bool, error)
	Store(obj any)
	GetItemCount(ID any, TargetType string) (int, error)
	GetItem(ID any, TargetType string) (any, error)
	GetObjectList(GID definition.Gossip_ID, TargetType string) []definition.Gossip_object
	GetNUMList(PID string) []definition.PoM_Counter
	GetObject(GID definition.Gossip_ID, targettype string) definition.Gossip_object
	GetNum(PID string) definition.PoM_Counter
	CleanUpGossiperStorage()
	Save()
}

func countFragments(fragmentMap map[definition.Gossip_ID][]definition.Gossip_object) int {
	count := 0
	for _, fragments := range fragmentMap {
		count += len(fragments)
	}
	return count
}

func (ctx *GossiperContext) Save() {
	Period, _ := strconv.Atoi(util.GetCurrentPeriod())
	g_log_entry := Gossiper_log_entry{
		Period:             Period,
		NUM_STH_INIT:       len(ctx.Gossip_object_storage.STH_INIT),
		NUM_REV_INIT:       len(ctx.Gossip_object_storage.REV_INIT),
		NUM_ACC_INIT:       len(ctx.Gossip_object_storage.ACC_INIT),
		NUM_CON_INIT:       len(ctx.Gossip_object_storage.CON_INIT),
		NUM_STH_FRAG:       0,
		NUM_REV_FRAG:       0,
		NUM_ACC_FRAG:       0,
		NUM_CON_FRAG:       0,
		NUM_STH_FULL:       len(ctx.Gossip_object_storage.STH_FULL),
		NUM_REV_FULL:       len(ctx.Gossip_object_storage.REV_FULL),
		NUM_ACC_FULL:       len(ctx.Gossip_object_storage.ACC_FULL),
		NUM_CON_FULL:       len(ctx.Gossip_object_storage.CON_FULL),
		NUM_BLACKLIST_TEMP: len(ctx.Gossip_blacklist.BLACKLIST_TEMP),
		NUM_BLACKLIST_PERM: len(ctx.Gossip_blacklist.BLACKLIST_PERM),
		NUM_POM_INIT:       len(ctx.Gossip_PoM_Counter.NUM_INIT),
		NUM_POM_FRAG:       len(ctx.Gossip_PoM_Counter.NUM_FRAG),
		NUM_POM_FULL:       0,
	}
	g_log_entry.NUM_STH_FRAG = countFragments(ctx.Gossip_object_storage.STH_FRAG)
	g_log_entry.NUM_REV_FRAG = countFragments(ctx.Gossip_object_storage.REV_FRAG)
	g_log_entry.NUM_ACC_FRAG = countFragments(ctx.Gossip_object_storage.ACC_FRAG)
	g_log_entry.NUM_CON_FRAG = countFragments(ctx.Gossip_object_storage.CON_FRAG)

	if ctx.Gossip_PoM_Counter.NUM_FULL {
		g_log_entry.NUM_POM_FULL = 1
	} else {
		g_log_entry.NUM_POM_FULL = 0
	}
	// if not all entries are zero, log it
	if g_log_entry.NUM_STH_INIT != 0 || g_log_entry.NUM_REV_INIT != 0 || g_log_entry.NUM_ACC_INIT != 0 || g_log_entry.NUM_CON_INIT != 0 ||
		g_log_entry.NUM_STH_FRAG != 0 || g_log_entry.NUM_REV_FRAG != 0 || g_log_entry.NUM_ACC_FRAG != 0 || g_log_entry.NUM_CON_FRAG != 0 ||
		g_log_entry.NUM_STH_FULL != 0 || g_log_entry.NUM_REV_FULL != 0 || g_log_entry.NUM_ACC_FULL != 0 || g_log_entry.NUM_CON_FULL != 0 ||
		g_log_entry.NUM_BLACKLIST_TEMP != 0 || g_log_entry.NUM_BLACKLIST_PERM != 0 || g_log_entry.NUM_POM_INIT != 0 || g_log_entry.NUM_POM_FRAG != 0 || g_log_entry.NUM_POM_FULL != 0 {
		(*ctx.Gossiper_log)[Period] = g_log_entry
		err := util.WriteData(ctx.StorageDirectory+ctx.StorageFile, *ctx.Gossiper_log)
		if err != nil {
			fmt.Println("Error writing gossiper log")
		}
	}
}

func (ctx *GossiperContext) InBlacklistTemp(id string) bool {
	ctx.Gossip_blacklist.BLACKLIST_TEMP_LOCK.RLock()
	defer ctx.Gossip_blacklist.BLACKLIST_TEMP_LOCK.RUnlock()
	_, ok := ctx.Gossip_blacklist.BLACKLIST_TEMP[id]
	return ok
}

func (ctx *GossiperContext) InBlacklistPerm(id string) bool {
	ctx.Gossip_blacklist.BLACKLIST_PERM_LOCK.RLock()
	defer ctx.Gossip_blacklist.BLACKLIST_PERM_LOCK.RUnlock()
	_, ok := ctx.Gossip_blacklist.BLACKLIST_PERM[id]
	return ok
}

func (ctx *GossiperContext) Store_gossip_object(gossip_object definition.Gossip_object) {
	switch gossip_object.Type {
	case definition.STH_INIT:
		ctx.Gossip_object_storage.STH_INIT_LOCK.Lock()
		ctx.Gossip_object_storage.STH_INIT[gossip_object.GetID()] = gossip_object
		ctx.Gossip_object_storage.STH_INIT_LOCK.Unlock()
	case definition.REV_INIT:
		ctx.Gossip_object_storage.REV_INIT_LOCK.Lock()
		ctx.Gossip_object_storage.REV_INIT[gossip_object.GetID()] = gossip_object
		ctx.Gossip_object_storage.REV_INIT_LOCK.Unlock()
	case definition.ACC_INIT:
		ctx.Gossip_object_storage.ACC_INIT_LOCK.Lock()
		ctx.Gossip_object_storage.ACC_INIT[gossip_object.GetID()] = gossip_object
		ctx.Gossip_object_storage.ACC_INIT_LOCK.Unlock()
	case definition.CON_INIT:
		ctx.Gossip_object_storage.CON_INIT_LOCK.Lock()
		ctx.Gossip_object_storage.CON_INIT[gossip_object.GetID()] = gossip_object
		ctx.Gossip_object_storage.CON_INIT_LOCK.Unlock()
		// if not in perm blacklist, add it
		if !ctx.InBlacklistPerm(gossip_object.Payload[0]) {
			ctx.Gossip_blacklist.BLACKLIST_TEMP_LOCK.Lock()
			ctx.Gossip_blacklist.BLACKLIST_TEMP[gossip_object.Payload[0]] = true
			ctx.Gossip_blacklist.BLACKLIST_TEMP_LOCK.Unlock()
		}
	case definition.STH_FRAG:
		ctx.Gossip_object_storage.STH_FRAG_LOCK.Lock()
		ctx.Gossip_object_storage.STH_FRAG[gossip_object.GetID()] = append(ctx.Gossip_object_storage.STH_FRAG[gossip_object.GetID()], gossip_object)
		ctx.Gossip_object_storage.STH_FRAG_LOCK.Unlock()
	case definition.REV_FRAG:
		ctx.Gossip_object_storage.REV_FRAG_LOCK.Lock()
		ctx.Gossip_object_storage.REV_FRAG[gossip_object.GetID()] = append(ctx.Gossip_object_storage.REV_FRAG[gossip_object.GetID()], gossip_object)
		ctx.Gossip_object_storage.REV_FRAG_LOCK.Unlock()
	case definition.ACC_FRAG:
		ctx.Gossip_object_storage.ACC_FRAG_LOCK.Lock()
		ctx.Gossip_object_storage.ACC_FRAG[gossip_object.GetID()] = append(ctx.Gossip_object_storage.ACC_FRAG[gossip_object.GetID()], gossip_object)
		ctx.Gossip_object_storage.ACC_FRAG_LOCK.Unlock()
	case definition.CON_FRAG:
		ctx.Gossip_object_storage.CON_FRAG_LOCK.Lock()
		ctx.Gossip_object_storage.CON_FRAG[gossip_object.GetID()] = append(ctx.Gossip_object_storage.CON_FRAG[gossip_object.GetID()], gossip_object)
		ctx.Gossip_object_storage.CON_FRAG_LOCK.Unlock()
		// if not in perm blacklist, add it
		if !ctx.InBlacklistPerm(gossip_object.Payload[0]) {
			ctx.Gossip_blacklist.BLACKLIST_TEMP_LOCK.Lock()
			ctx.Gossip_blacklist.BLACKLIST_TEMP[gossip_object.Payload[0]] = true
			ctx.Gossip_blacklist.BLACKLIST_TEMP_LOCK.Unlock()
		}
	case definition.STH_FULL:
		ctx.Gossip_object_storage.STH_FULL_LOCK.Lock()
		ctx.Gossip_object_storage.STH_FULL[gossip_object.GetID()] = gossip_object
		ctx.Gossip_object_storage.STH_FULL_LOCK.Unlock()
	case definition.REV_FULL:
		ctx.Gossip_object_storage.REV_FULL_LOCK.Lock()
		ctx.Gossip_object_storage.REV_FULL[gossip_object.GetID()] = gossip_object
		ctx.Gossip_object_storage.REV_FULL_LOCK.Unlock()
	case definition.ACC_FULL:
		ctx.Gossip_object_storage.ACC_FULL_LOCK.Lock()
		ctx.Gossip_object_storage.ACC_FULL[gossip_object.GetID()] = gossip_object
		ctx.Gossip_object_storage.ACC_FULL_LOCK.Unlock()
		// if not in temp blacklist, add it
		if !ctx.InBlacklistTemp(gossip_object.Payload[0]) {
			ctx.Gossip_blacklist.BLACKLIST_TEMP_LOCK.Lock()
			ctx.Gossip_blacklist.BLACKLIST_TEMP[gossip_object.Payload[0]] = true
			ctx.Gossip_blacklist.BLACKLIST_TEMP_LOCK.Unlock()
		}
	case definition.CON_FULL:
		ctx.Gossip_object_storage.CON_FULL_LOCK.Lock()
		ctx.Gossip_object_storage.CON_FULL[gossip_object.GetID()] = gossip_object
		ctx.Gossip_object_storage.CON_FULL_LOCK.Unlock()
		// if not in perm blacklist, add it
		if !ctx.InBlacklistPerm(gossip_object.Payload[0]) {
			ctx.Gossip_blacklist.BLACKLIST_PERM_LOCK.Lock()
			ctx.Gossip_blacklist.BLACKLIST_PERM[gossip_object.Payload[0]] = true
			ctx.Gossip_blacklist.BLACKLIST_PERM_LOCK.Unlock()
		}
	}
}

func (ctx *GossiperContext) Store_PoMCounter(pom_counter definition.PoM_Counter) {
	switch pom_counter.Type {
	case definition.NUM_INIT:
		ctx.Gossip_PoM_Counter.NUM_INIT_LOCK.Lock()
		ctx.Gossip_PoM_Counter.NUM_INIT[pom_counter.GetID()] = append(ctx.Gossip_PoM_Counter.NUM_INIT[pom_counter.GetID()], pom_counter.Signer_Monitor)
		ctx.Gossip_PoM_Counter.NUM_INIT_LOCK.Unlock()
	case definition.NUM_FRAG:
		ctx.Gossip_PoM_Counter.NUM_FRAG_LOCK.Lock()
		ctx.Gossip_PoM_Counter.NUM_FRAG = append(ctx.Gossip_PoM_Counter.NUM_FRAG, pom_counter)
		ctx.Gossip_PoM_Counter.NUM_FRAG_LOCK.Unlock()
	case definition.NUM_FULL:
		ctx.Gossip_PoM_Counter.NUM_FULL_LOCK.Lock()
		ctx.Gossip_PoM_Counter.NUM_FULL = true
		ctx.Gossip_PoM_Counter.NUM_FULL_LOCK.Unlock()
	}
}
func (ctx *GossiperContext) IsDuplicate_G(gossip_object definition.Gossip_object) bool {
	switch gossip_object.Type {
	case definition.STH_INIT:
		ctx.Gossip_object_storage.STH_INIT_LOCK.RLock()
		defer ctx.Gossip_object_storage.STH_INIT_LOCK.RUnlock()
		if _, ok := ctx.Gossip_object_storage.STH_INIT[gossip_object.GetID()]; !ok {
			return false
		}
		return ctx.Gossip_object_storage.STH_INIT[gossip_object.GetID()].Signature == gossip_object.Signature
	case definition.REV_INIT:
		ctx.Gossip_object_storage.REV_INIT_LOCK.RLock()
		defer ctx.Gossip_object_storage.REV_INIT_LOCK.RUnlock()
		if _, ok := ctx.Gossip_object_storage.REV_INIT[gossip_object.GetID()]; !ok {
			return false
		}
		return ctx.Gossip_object_storage.REV_INIT[gossip_object.GetID()].Signature == gossip_object.Signature
	case definition.ACC_INIT:
		ctx.Gossip_object_storage.ACC_INIT_LOCK.RLock()
		defer ctx.Gossip_object_storage.ACC_INIT_LOCK.RUnlock()
		if _, ok := ctx.Gossip_object_storage.ACC_INIT[gossip_object.GetID()]; !ok {
			return false
		}
		return ctx.Gossip_object_storage.ACC_INIT[gossip_object.GetID()].Signature == gossip_object.Signature
	case definition.CON_INIT:
		ctx.Gossip_object_storage.CON_INIT_LOCK.RLock()
		defer ctx.Gossip_object_storage.CON_INIT_LOCK.RUnlock()
		if _, ok := ctx.Gossip_object_storage.CON_INIT[gossip_object.GetID()]; !ok {
			return false
		}
		return ctx.Gossip_object_storage.CON_INIT[gossip_object.GetID()].Signature == gossip_object.Signature
	case definition.STH_FRAG:
		ctx.Gossip_object_storage.STH_FRAG_LOCK.RLock()
		defer ctx.Gossip_object_storage.STH_FRAG_LOCK.RUnlock()
		if len(ctx.Gossip_object_storage.STH_FRAG[gossip_object.GetID()]) == 0 {
			return false
		}
		for _, v := range ctx.Gossip_object_storage.STH_FRAG[gossip_object.GetID()] {
			if v.Signature == gossip_object.Signature {
				return true
			}
		}

	case definition.REV_FRAG:
		ctx.Gossip_object_storage.REV_FRAG_LOCK.RLock()
		defer ctx.Gossip_object_storage.REV_FRAG_LOCK.RUnlock()
		if len(ctx.Gossip_object_storage.REV_FRAG[gossip_object.GetID()]) == 0 {
			return false
		}
		for _, v := range ctx.Gossip_object_storage.REV_FRAG[gossip_object.GetID()] {
			if v.Signature == gossip_object.Signature {
				return true
			}
		}
	case definition.ACC_FRAG:
		ctx.Gossip_object_storage.ACC_FRAG_LOCK.RLock()
		defer ctx.Gossip_object_storage.ACC_FRAG_LOCK.RUnlock()
		if len(ctx.Gossip_object_storage.ACC_FRAG[gossip_object.GetID()]) == 0 {
			return false
		}
		for _, v := range ctx.Gossip_object_storage.ACC_FRAG[gossip_object.GetID()] {
			if v.Signature == gossip_object.Signature {
				return true
			}
		}
	case definition.CON_FRAG:
		ctx.Gossip_object_storage.CON_FRAG_LOCK.RLock()
		defer ctx.Gossip_object_storage.CON_FRAG_LOCK.RUnlock()
		if len(ctx.Gossip_object_storage.CON_FRAG[gossip_object.GetID()]) == 0 {
			return false
		}
		for _, v := range ctx.Gossip_object_storage.CON_FRAG[gossip_object.GetID()] {
			if v.Signature == gossip_object.Signature {
				return true
			}
		}
	case definition.STH_FULL:
		ctx.Gossip_object_storage.STH_FULL_LOCK.RLock()
		defer ctx.Gossip_object_storage.STH_FULL_LOCK.RUnlock()
		if _, ok := ctx.Gossip_object_storage.STH_FULL[gossip_object.GetID()]; !ok {
			return false
		}
		return ctx.Gossip_object_storage.STH_FULL[gossip_object.GetID()].Signature == gossip_object.Signature
	case definition.REV_FULL:
		ctx.Gossip_object_storage.REV_FULL_LOCK.RLock()
		defer ctx.Gossip_object_storage.REV_FULL_LOCK.RUnlock()
		if _, ok := ctx.Gossip_object_storage.REV_FULL[gossip_object.GetID()]; !ok {
			return false
		}
		return ctx.Gossip_object_storage.REV_FULL[gossip_object.GetID()].Signature == gossip_object.Signature
	case definition.ACC_FULL:
		ctx.Gossip_object_storage.ACC_FULL_LOCK.RLock()
		defer ctx.Gossip_object_storage.ACC_FULL_LOCK.RUnlock()
		if _, ok := ctx.Gossip_object_storage.ACC_FULL[gossip_object.GetID()]; !ok {
			return false
		}
		return ctx.Gossip_object_storage.ACC_FULL[gossip_object.GetID()].Signature == gossip_object.Signature
	case definition.CON_FULL:
		ctx.Gossip_object_storage.CON_FULL_LOCK.RLock()
		defer ctx.Gossip_object_storage.CON_FULL_LOCK.RUnlock()
		if _, ok := ctx.Gossip_object_storage.CON_FULL[gossip_object.GetID()]; !ok {
			return false
		}
		return ctx.Gossip_object_storage.CON_FULL[gossip_object.GetID()].Signature == gossip_object.Signature
	}
	return false
}

func (ctx *GossiperContext) IsDuplicate_P(pom_counter definition.PoM_Counter) bool {
	switch pom_counter.Type {
	case definition.NUM_INIT:
		ctx.Gossip_PoM_Counter.NUM_INIT_LOCK.RLock()
		defer ctx.Gossip_PoM_Counter.NUM_INIT_LOCK.RUnlock()
		if _, ok := ctx.Gossip_PoM_Counter.NUM_INIT[pom_counter.GetID()]; ok {
			for _, counter := range ctx.Gossip_PoM_Counter.NUM_INIT[pom_counter.GetID()] {
				if counter == pom_counter.Signer_Monitor {
					return true
				}
			}
		}
	case definition.NUM_FRAG:
		ctx.Gossip_PoM_Counter.NUM_FRAG_LOCK.RLock()
		defer ctx.Gossip_PoM_Counter.NUM_FRAG_LOCK.RUnlock()
		for _, counter := range ctx.Gossip_PoM_Counter.NUM_FRAG {
			if counter.Signature == pom_counter.Signature {
				return true
			}
		}
	case definition.NUM_FULL:
		return ctx.Gossip_PoM_Counter.NUM_FULL

	}
	return false
}

func (ctx GossiperContext) Store(obj any) {
	switch obj.(type) {
	case definition.Gossip_object:
		gossip_object := obj.(definition.Gossip_object)
		ctx.Store_gossip_object(gossip_object)
	case definition.PoM_Counter:
		pom_counter := obj.(definition.PoM_Counter)
		ctx.Store_PoMCounter(pom_counter)
	}
}

func (ctx GossiperContext) IsDuplicate(obj any) (bool, error) {
	switch obj.(type) {
	case definition.Gossip_object:
		gossip_object := obj.(definition.Gossip_object)
		return ctx.IsDuplicate_G(gossip_object), nil
	case definition.PoM_Counter:
		pom_counter := obj.(definition.PoM_Counter)
		return ctx.IsDuplicate_P(pom_counter), nil
	}
	return false, errors.New("Unknown type")
}

func (ctx GossiperContext) InBlacklist(Entity_URL string) bool {
	return ctx.InBlacklistTemp(Entity_URL) || ctx.InBlacklistPerm(Entity_URL)
}

func (ctx GossiperContext) GetObjectList(GID definition.Gossip_ID, TargetType string) []definition.Gossip_object {
	var newlist []definition.Gossip_object
	switch TargetType {
	case definition.STH_FRAG:
		ctx.Gossip_object_storage.STH_FRAG_LOCK.RLock()
		defer ctx.Gossip_object_storage.STH_FRAG_LOCK.RUnlock()
		newlist = ctx.Gossip_object_storage.STH_FRAG[GID]
	case definition.REV_FRAG:
		ctx.Gossip_object_storage.REV_FRAG_LOCK.RLock()
		defer ctx.Gossip_object_storage.REV_FRAG_LOCK.RUnlock()
		newlist = ctx.Gossip_object_storage.REV_FRAG[GID]
	case definition.ACC_FRAG:
		ctx.Gossip_object_storage.ACC_FRAG_LOCK.RLock()
		defer ctx.Gossip_object_storage.ACC_FRAG_LOCK.RUnlock()
		newlist = ctx.Gossip_object_storage.ACC_FRAG[GID]
	case definition.CON_FRAG:
		ctx.Gossip_object_storage.CON_FRAG_LOCK.RLock()
		defer ctx.Gossip_object_storage.CON_FRAG_LOCK.RUnlock()
		newlist = ctx.Gossip_object_storage.CON_FRAG[GID]
	}
	return newlist
}

func (ctx GossiperContext) GetGossipObjectCount(GID definition.Gossip_ID, TargetType string) int {
	switch TargetType {
	case definition.STH_INIT:
		ctx.Gossip_object_storage.STH_INIT_LOCK.RLock()
		defer ctx.Gossip_object_storage.STH_INIT_LOCK.RUnlock()
		if _, ok := ctx.Gossip_object_storage.STH_INIT[GID]; !ok {
			return 0
		} else {
			return 1
		}
	case definition.REV_INIT:
		ctx.Gossip_object_storage.REV_INIT_LOCK.RLock()
		defer ctx.Gossip_object_storage.REV_INIT_LOCK.RUnlock()
		if _, ok := ctx.Gossip_object_storage.REV_INIT[GID]; !ok {
			return 0
		} else {
			return 1
		}
	case definition.ACC_INIT:
		ctx.Gossip_object_storage.ACC_INIT_LOCK.RLock()
		defer ctx.Gossip_object_storage.ACC_INIT_LOCK.RUnlock()
		if _, ok := ctx.Gossip_object_storage.ACC_INIT[GID]; !ok {
			return 0
		} else {
			return 1
		}
	case definition.CON_INIT:
		ctx.Gossip_object_storage.CON_INIT_LOCK.RLock()
		defer ctx.Gossip_object_storage.CON_INIT_LOCK.RUnlock()
		if _, ok := ctx.Gossip_object_storage.CON_INIT[GID]; !ok {
			return 0
		} else {
			return 1
		}
	case definition.STH_FRAG:
		ctx.Gossip_object_storage.STH_FRAG_LOCK.RLock()
		defer ctx.Gossip_object_storage.STH_FRAG_LOCK.RUnlock()
		return len(ctx.Gossip_object_storage.STH_FRAG[GID])
	case definition.REV_FRAG:
		ctx.Gossip_object_storage.REV_FRAG_LOCK.RLock()
		defer ctx.Gossip_object_storage.REV_FRAG_LOCK.RUnlock()
		return len(ctx.Gossip_object_storage.REV_FRAG[GID])
	case definition.ACC_FRAG:
		ctx.Gossip_object_storage.ACC_FRAG_LOCK.RLock()
		defer ctx.Gossip_object_storage.ACC_FRAG_LOCK.RUnlock()
		return len(ctx.Gossip_object_storage.ACC_FRAG[GID])
	case definition.CON_FRAG:
		ctx.Gossip_object_storage.CON_FRAG_LOCK.RLock()
		defer ctx.Gossip_object_storage.CON_FRAG_LOCK.RUnlock()
		return len(ctx.Gossip_object_storage.CON_FRAG[GID])
	case definition.STH_FULL:
		ctx.Gossip_object_storage.STH_FULL_LOCK.RLock()
		defer ctx.Gossip_object_storage.STH_FULL_LOCK.RUnlock()
		if _, ok := ctx.Gossip_object_storage.STH_FULL[GID]; !ok {
			return 0
		} else {
			return 1
		}
	case definition.REV_FULL:
		ctx.Gossip_object_storage.REV_FULL_LOCK.RLock()
		defer ctx.Gossip_object_storage.REV_FULL_LOCK.RUnlock()
		if _, ok := ctx.Gossip_object_storage.REV_FULL[GID]; !ok {
			return 0
		} else {
			return 1
		}
	case definition.ACC_FULL:
		ctx.Gossip_object_storage.ACC_FULL_LOCK.RLock()
		defer ctx.Gossip_object_storage.ACC_FULL_LOCK.RUnlock()
		if _, ok := ctx.Gossip_object_storage.ACC_FULL[GID]; !ok {
			return 0
		} else {
			return 1
		}
	case definition.CON_FULL:
		ctx.Gossip_object_storage.CON_FULL_LOCK.RLock()
		defer ctx.Gossip_object_storage.CON_FULL_LOCK.RUnlock()
		if _, ok := ctx.Gossip_object_storage.CON_FULL[GID]; !ok {
			return 0
		} else {
			return 1
		}
	}
	return 0
}

func (ctx GossiperContext) GetObject(GID definition.Gossip_ID, targettype string) definition.Gossip_object {
	switch targettype {
	case definition.STH_INIT:
		ctx.Gossip_object_storage.STH_INIT_LOCK.RLock()
		defer ctx.Gossip_object_storage.STH_INIT_LOCK.RUnlock()
		return ctx.Gossip_object_storage.STH_INIT[GID]
	case definition.REV_INIT:
		ctx.Gossip_object_storage.REV_INIT_LOCK.RLock()
		defer ctx.Gossip_object_storage.REV_INIT_LOCK.RUnlock()
		return ctx.Gossip_object_storage.REV_INIT[GID]
	case definition.ACC_INIT:
		ctx.Gossip_object_storage.ACC_INIT_LOCK.RLock()
		defer ctx.Gossip_object_storage.ACC_INIT_LOCK.RUnlock()
		return ctx.Gossip_object_storage.ACC_INIT[GID]
	case definition.CON_INIT:
		ctx.Gossip_object_storage.CON_INIT_LOCK.RLock()
		defer ctx.Gossip_object_storage.CON_INIT_LOCK.RUnlock()
		return ctx.Gossip_object_storage.CON_INIT[GID]
	case definition.STH_FULL:
		ctx.Gossip_object_storage.STH_FULL_LOCK.RLock()
		defer ctx.Gossip_object_storage.STH_FULL_LOCK.RUnlock()
		return ctx.Gossip_object_storage.STH_FULL[GID]
	case definition.REV_FULL:
		ctx.Gossip_object_storage.REV_FULL_LOCK.RLock()
		defer ctx.Gossip_object_storage.REV_FULL_LOCK.RUnlock()
		return ctx.Gossip_object_storage.REV_FULL[GID]
	case definition.ACC_FULL:
		ctx.Gossip_object_storage.ACC_FULL_LOCK.RLock()
		defer ctx.Gossip_object_storage.ACC_FULL_LOCK.RUnlock()
		return ctx.Gossip_object_storage.ACC_FULL[GID]
	case definition.CON_FULL:
		ctx.Gossip_object_storage.CON_FULL_LOCK.RLock()
		defer ctx.Gossip_object_storage.CON_FULL_LOCK.RUnlock()
		return ctx.Gossip_object_storage.CON_FULL[GID]
	}
	return definition.Gossip_object{}
}

func (ctx GossiperContext) GetNUMCount(NID string, TargetType string) int {
	switch TargetType {
	case definition.NUM_INIT:
		ctx.Gossip_PoM_Counter.NUM_INIT_LOCK.RLock()
		defer ctx.Gossip_PoM_Counter.NUM_INIT_LOCK.RUnlock()
		return len(ctx.Gossip_PoM_Counter.NUM_INIT[NID])
	case definition.NUM_FRAG:
		ctx.Gossip_PoM_Counter.NUM_FRAG_LOCK.RLock()
		defer ctx.Gossip_PoM_Counter.NUM_FRAG_LOCK.RUnlock()
		return len(ctx.Gossip_PoM_Counter.NUM_FRAG)
	case definition.NUM_FULL:
		ctx.Gossip_PoM_Counter.NUM_FULL_LOCK.RLock()
		defer ctx.Gossip_PoM_Counter.NUM_FULL_LOCK.RUnlock()
		if ctx.Gossip_PoM_Counter.NUM_FULL {
			return 1
		} else {
			return 0
		}
	}
	return 0
}

func (ctx GossiperContext) GetNUMList(NID string) []definition.PoM_Counter {
	ctx.Gossip_PoM_Counter.NUM_FRAG_LOCK.RLock()
	defer ctx.Gossip_PoM_Counter.NUM_FRAG_LOCK.RUnlock()
	return ctx.Gossip_PoM_Counter.NUM_FRAG
}

func (ctx GossiperContext) GetNum(NID string) []definition.PoM_Counter {
	ctx.Gossip_PoM_Counter.NUM_FRAG_LOCK.RLock()
	defer ctx.Gossip_PoM_Counter.NUM_FRAG_LOCK.RUnlock()
	return ctx.Gossip_PoM_Counter.NUM_FRAG
}

func (ctx GossiperContext) GetItemCount(ID any, TargetType string) (int, error) {
	switch ID.(type) {
	case definition.Gossip_ID:
		return ctx.GetGossipObjectCount(ID.(definition.Gossip_ID), TargetType), nil
	case string:
		return ctx.GetNUMCount(ID.(string), TargetType), nil
	}
	return 0, errors.New("Invalid ID Type")
}

func (ctx GossiperContext) GetItem(ID any, TargetType string) any {
	switch ID.(type) {
	case definition.Gossip_ID:
		return ctx.GetObject(ID.(definition.Gossip_ID), TargetType)
	case string:
		return ctx.GetNum(ID.(string))
	}
	return nil
}

func (ctx GossiperContext) IsMalicious(obj definition.Gossip_object) bool {
	switch obj.Type {
	case definition.STH_INIT:
		obj_2 := ctx.GetObject(obj.GetID(), definition.STH_INIT)
		if obj.Signer == obj_2.Signer && obj.Signature != obj_2.Signature {
			return true
		}
	case definition.REV_INIT:
		obj_2 := ctx.GetObject(obj.GetID(), definition.REV_INIT)
		if obj.Signer == obj_2.Signer && obj.Signature != obj_2.Signature {
			return true
		}
	}
	return false
}

func (ctx GossiperContext) WriteToFile() {
	// check if Directory exists
	if _, err := os.Stat(ctx.StorageDirectory); os.IsNotExist(err) {
		os.Mkdir(ctx.StorageDirectory, 0755)
	}
	// write gossip log
	util.WriteData(ctx.StorageDirectory+ctx.StorageFile, ctx.Gossiper_log)
}

func (ctx GossiperContext) WipeStorage() {
	// clear all storage
	CON_FULL := ctx.Gossip_object_storage.CON_FULL
	ctx.Gossip_object_storage = InitializeGossipObjectStorage()
	ctx.Gossip_object_storage.CON_FULL = CON_FULL
	// clear all temperary blacklist
	Blacklistperm := ctx.Gossip_blacklist.BLACKLIST_PERM
	ctx.Gossip_blacklist = InitializeGossipBlacklist()
	ctx.Gossip_blacklist.BLACKLIST_PERM = Blacklistperm
	// clear all PoM counter and gossiper log
	ctx.Gossip_PoM_Counter = InitializeGossipPoMCounter()
}

func (ctx GossiperContext) CleanUpGossiperStorage() {
	//delete all files in storage directory
	err := util.DeleteFilesAndDirectories(ctx.StorageDirectory)
	if err != nil {
		fmt.Println(err)
	}
}
