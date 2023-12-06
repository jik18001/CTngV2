package gossiper

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/jik18001/CTngV2/crypto"
	"github.com/jik18001/CTngV2/definition"
	"github.com/jik18001/CTngV2/util"
)

type GossiperInterface interface {
	InitializeGossiperContext(public_config_path string, private_config_path string, crypto_config_path string, storageID string) *GossiperContext
	InBlacklist(Entity_URL string) bool
	IsDuplicate(obj any) (bool, error)
	IsMalicious(obj definition.Gossip_object) (bool, error)
	Store(obj any)
	GetItemCount(ID any, TargetType string) (int, error)
	GetItem(ID any, TargetType string) (any, error)
	GetObjectList(GID definition.Gossip_ID, TargetType string) []definition.Gossip_object
	GetNUMList(PID string) []definition.Gossip_object
	GetObject(GID definition.Gossip_ID, targettype string) definition.Gossip_object
	GetNum(PID string) definition.Gossip_object
	CleanUpGossiperStorage()
	Save()
}

func ComputeobjHash(obj definition.Gossip_object) string {
	obj_json, _ := json.Marshal(obj)
	hash_byte, _ := crypto.GenerateSHA256(obj_json)
	return string(hash_byte)
}
func countFragments(fragmentMap map[definition.Gossip_ID][]definition.Gossip_object) int {
	count := 0
	for _, fragments := range fragmentMap {
		count += len(fragments)
	}
	return count
}

func (ctx *GossiperContext) SavePayload(g definition.Gossip_object) {
	err := g.Verify(ctx.Gossiper_crypto_config)
	if err != nil {
		fmt.Println(util.RED, "Invalid object "+definition.TypeString(g.Type)+" signed by "+g.Signer+".", util.RESET)
		return
	}
	ctx.Gossip_object_storage.REV_PAYLOAD_LOCK.Lock()
	ctx.Gossip_object_storage.REV_PAYLOAD[g.GetID()] = g
	ctx.Gossip_object_storage.REV_PAYLOAD_LOCK.Unlock()
}

func (ctx *GossiperContext) SearchPayload(gid definition.Gossip_ID, ohash string) bool {
	gid.Type = definition.REV_INIT
	ctx.Gossip_object_storage.REV_PAYLOAD_LOCK.RLock()
	defer ctx.Gossip_object_storage.REV_PAYLOAD_LOCK.RUnlock()
	if _, ok := ctx.Gossip_object_storage.REV_PAYLOAD[gid]; !ok {
		return false
	} else {
		obj := ctx.Gossip_object_storage.REV_PAYLOAD[gid]
		hash1 := ComputeobjHash(obj)
		if hash1 == ohash {
			return true
		} else {
			return false
		}
	}
}

func (ctx *GossiperContext) GetREVrequested(gid definition.Gossip_ID) definition.Gossip_object {
	gid.Type = definition.REV_INIT
	ctx.Gossip_object_storage.REV_PAYLOAD_LOCK.RLock()
	defer ctx.Gossip_object_storage.REV_PAYLOAD_LOCK.RUnlock()
	if _, ok := ctx.Gossip_object_storage.REV_PAYLOAD[gid]; ok {
		return ctx.Gossip_object_storage.REV_PAYLOAD[gid]
	}
	return definition.Gossip_object{}
}

func (ctx *GossiperContext) Save() {
	Period, _ := strconv.Atoi(util.GetCurrentPeriod())
	g_log_entry := Gossiper_log_entry{
		Period:                 Period,
		Converge_time:          ctx.Converge_time,
		Converge_time_init:     ctx.Converge_time_init,
		Total_traffic_received: ctx.Total_traffic_received,
		Total_traffic_sent:     ctx.Total_traffic_sent,
		NUM_STH_INIT:           len(ctx.Gossip_object_storage.STH_INIT),
		NUM_REV_INIT:           len(ctx.Gossip_object_storage.REV_INIT),
		NUM_ACC_INIT:           len(ctx.Gossip_object_storage.ACC_INIT),
		NUM_CON_INIT:           len(ctx.Gossip_object_storage.CON_INIT),
		NUM_STH_FRAG:           0,
		NUM_REV_FRAG:           0,
		NUM_ACC_FRAG:           0,
		NUM_STH_FULL:           len(ctx.Gossip_object_storage.STH_FULL),
		NUM_REV_FULL:           len(ctx.Gossip_object_storage.REV_FULL),
		NUM_ACC_FULL:           len(ctx.Gossip_object_storage.ACC_FULL),
		NUM_BLACKLIST_PERM:     len(ctx.Gossip_blacklist.BLACKLIST_PERM),
		Timerlist:              ctx.Timerlist,
	}
	g_log_entry.NUM_STH_FRAG = countFragments(ctx.Gossip_object_storage.STH_FRAG)
	g_log_entry.NUM_REV_FRAG = countFragments(ctx.Gossip_object_storage.REV_FRAG)
	g_log_entry.NUM_ACC_FRAG = countFragments(ctx.Gossip_object_storage.ACC_FRAG)

	// if not all entries are zero, log it
	if g_log_entry.NUM_STH_INIT != 0 || g_log_entry.NUM_REV_INIT != 0 || g_log_entry.NUM_ACC_INIT != 0 || g_log_entry.NUM_CON_INIT != 0 ||
		g_log_entry.NUM_STH_FRAG != 0 || g_log_entry.NUM_REV_FRAG != 0 || g_log_entry.NUM_ACC_FRAG != 0 ||
		g_log_entry.NUM_STH_FULL != 0 || g_log_entry.NUM_REV_FULL != 0 || g_log_entry.NUM_ACC_FULL != 0 ||
		g_log_entry.NUM_BLACKLIST_PERM != 0 {
		(*ctx.Gossiper_log)[Period] = g_log_entry
		err := util.WriteData(ctx.StorageDirectory+ctx.StorageFile, *ctx.Gossiper_log)
		if err != nil {
			fmt.Println("Error writing gossiper log")
		}
	}
}

func (ctx *GossiperContext) InBlacklistPerm(id string) bool {
	ctx.Gossip_blacklist.BLACKLIST_PERM_LOCK.RLock()
	defer ctx.Gossip_blacklist.BLACKLIST_PERM_LOCK.RUnlock()
	_, ok := ctx.Gossip_blacklist.BLACKLIST_PERM[id]
	return ok
}

func (ctx *GossiperContext) Store_gossip_object(gossip_object definition.Gossip_object) bool {
	err := gossip_object.Verify(ctx.Gossiper_crypto_config)
	if err != nil {
		fmt.Println(util.RED, "Invalid object "+definition.TypeString(gossip_object.Type)+" signed by "+gossip_object.Signer+".", util.RESET)
		return false
	}
	clock := util.GetCurrentSecond()
	clock_float, _ := strconv.ParseFloat(clock, 64)
	ctx.Timerlist = append(ctx.Timerlist, clock_float)
	switch gossip_object.Type {
	case definition.STH_INIT:
		ctx.Gossip_object_storage.STH_INIT_LOCK.Lock()
		// if it is a duplicate, ignore it
		if ctx.DupCheckInLock(gossip_object) {
			ctx.Gossip_object_storage.STH_INIT_LOCK.Unlock()
			return false
		}
		ctx.Gossip_object_storage.STH_INIT[gossip_object.GetID()] = gossip_object
		ctx.Gossip_object_storage.STH_INIT_LOCK.Unlock()
		if ctx.IsInitConvergent() {
			ctx.Converge_time_init = util.GetCurrentSecond()
			fmt.Println(util.BLUE, "INIT Converge time: ", ctx.Converge_time_init, util.RESET)
		}
	case definition.REV_INIT:
		ctx.Gossip_object_storage.REV_INIT_LOCK.Lock()
		// if it is a duplicate, ignore it
		if ctx.DupCheckInLock(gossip_object) {
			ctx.Gossip_object_storage.REV_INIT_LOCK.Unlock()
			return false
		}
		ctx.Gossip_object_storage.REV_INIT[gossip_object.GetID()] = gossip_object
		ctx.Gossip_object_storage.REV_INIT_LOCK.Unlock()
		if ctx.IsInitConvergent() {
			ctx.Converge_time_init = util.GetCurrentSecond()
			fmt.Println(util.BLUE, "INIT Converge time: ", ctx.Converge_time_init, util.RESET)
		}
	case definition.ACC_INIT:
		ctx.Gossip_object_storage.ACC_INIT_LOCK.Lock()
		// if it is a duplicate, ignore it
		if ctx.DupCheckInLock(gossip_object) {
			ctx.Gossip_object_storage.ACC_INIT_LOCK.Unlock()
			return false
		}
		ctx.Gossip_object_storage.ACC_INIT[gossip_object.GetID()] = gossip_object
		ctx.Gossip_object_storage.ACC_INIT_LOCK.Unlock()
		if ctx.IsInitConvergent() {
			ctx.Converge_time_init = util.GetCurrentSecond()
			fmt.Println(util.BLUE, "INIT Converge time: ", ctx.Converge_time_init, util.RESET)
		}
	case definition.CON_INIT:
		ctx.Gossip_object_storage.CON_INIT_LOCK.Lock()
		// if it is a duplicate, ignore it
		if ctx.DupCheckInLock(gossip_object) {
			ctx.Gossip_object_storage.CON_INIT_LOCK.Unlock()
			return false
		}
		ctx.Gossip_object_storage.CON_INIT[gossip_object.GetID()] = gossip_object
		ctx.Gossip_object_storage.CON_INIT_LOCK.Unlock()
		// if not in perm blacklist, add it
		if !ctx.InBlacklistPerm(gossip_object.Payload[0]) {
			ctx.Gossip_blacklist.BLACKLIST_PERM_LOCK.Lock()
			ctx.Gossip_blacklist.BLACKLIST_PERM[gossip_object.Payload[0]] = true
			ctx.Gossip_blacklist.BLACKLIST_PERM_LOCK.Unlock()
		}
		if ctx.IsInitConvergent() {
			ctx.Converge_time_init = util.GetCurrentSecond()
			fmt.Println(util.BLUE, "INIT Converge time: ", ctx.Converge_time_init, util.RESET)
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
		if !ctx.InBlacklistPerm(gossip_object.Payload[0]) {
			ctx.Gossip_blacklist.BLACKLIST_PERM_LOCK.Lock()
			ctx.Gossip_blacklist.BLACKLIST_PERM[gossip_object.Payload[0]] = true
			ctx.Gossip_blacklist.BLACKLIST_PERM_LOCK.Unlock()
		}
	}
	return true
}

func (ctx *GossiperContext) Read_and_Store_If_Needed(gossip_object definition.Gossip_object) int {
	switch gossip_object.Type {
	case definition.STH_FRAG:
		ctx.Gossip_object_storage.STH_FRAG_LOCK.Lock()
		defer ctx.Gossip_object_storage.STH_FRAG_LOCK.Unlock()
		before := len(ctx.Gossip_object_storage.STH_FRAG[gossip_object.GetID()])
		if len(ctx.Gossip_object_storage.STH_FRAG[gossip_object.GetID()]) < ctx.Gossiper_crypto_config.Threshold {
			ctx.Gossip_object_storage.STH_FRAG[gossip_object.GetID()] = append(ctx.Gossip_object_storage.STH_FRAG[gossip_object.GetID()], gossip_object)
		}
		return before
	case definition.REV_FRAG:
		ctx.Gossip_object_storage.REV_FRAG_LOCK.Lock()
		defer ctx.Gossip_object_storage.REV_FRAG_LOCK.Unlock()
		before := len(ctx.Gossip_object_storage.REV_FRAG[gossip_object.GetID()])
		if len(ctx.Gossip_object_storage.REV_FRAG[gossip_object.GetID()]) < ctx.Gossiper_crypto_config.Threshold {
			ctx.Gossip_object_storage.REV_FRAG[gossip_object.GetID()] = append(ctx.Gossip_object_storage.REV_FRAG[gossip_object.GetID()], gossip_object)
		}
		return before
	case definition.ACC_FRAG:
		ctx.Gossip_object_storage.ACC_FRAG_LOCK.Lock()
		defer ctx.Gossip_object_storage.ACC_FRAG_LOCK.Unlock()
		before := len(ctx.Gossip_object_storage.ACC_FRAG[gossip_object.GetID()])
		if len(ctx.Gossip_object_storage.ACC_FRAG[gossip_object.GetID()]) < ctx.Gossiper_crypto_config.Threshold {
			ctx.Gossip_object_storage.ACC_FRAG[gossip_object.GetID()] = append(ctx.Gossip_object_storage.ACC_FRAG[gossip_object.GetID()], gossip_object)
		}
		return before
	}
	return 0

}
func (ctx *GossiperContext) DupCheckInLock(gossip_object definition.Gossip_object) bool {
	switch gossip_object.Type {
	case definition.STH_INIT:
		if _, ok := ctx.Gossip_object_storage.STH_INIT[gossip_object.GetID()]; !ok {
			return false
		}
		return ctx.Gossip_object_storage.STH_INIT[gossip_object.GetID()].Signature == gossip_object.Signature
	case definition.REV_INIT:
		if _, ok := ctx.Gossip_object_storage.REV_INIT[gossip_object.GetID()]; !ok {
			return false
		}
		return ctx.Gossip_object_storage.REV_INIT[gossip_object.GetID()].Signature == gossip_object.Signature
	case definition.ACC_INIT:
		if _, ok := ctx.Gossip_object_storage.ACC_INIT[gossip_object.GetID()]; !ok {
			return false
		}
		return ctx.Gossip_object_storage.ACC_INIT[gossip_object.GetID()].Signature == gossip_object.Signature
	case definition.CON_INIT:
		if _, ok := ctx.Gossip_object_storage.CON_INIT[gossip_object.GetID()]; !ok {
			return false
		}
		return ctx.Gossip_object_storage.CON_INIT[gossip_object.GetID()].Signature == gossip_object.Signature
	case definition.STH_FRAG:
		if len(ctx.Gossip_object_storage.STH_FRAG[gossip_object.GetID()]) == 0 {
			return false
		}
		for _, v := range ctx.Gossip_object_storage.STH_FRAG[gossip_object.GetID()] {
			if v.Signature == gossip_object.Signature {
				return true
			}
		}

	case definition.REV_FRAG:
		if len(ctx.Gossip_object_storage.REV_FRAG[gossip_object.GetID()]) == 0 {
			return false
		}
		for _, v := range ctx.Gossip_object_storage.REV_FRAG[gossip_object.GetID()] {
			if v.Signature == gossip_object.Signature {
				return true
			}
		}
	case definition.ACC_FRAG:
		if len(ctx.Gossip_object_storage.ACC_FRAG[gossip_object.GetID()]) == 0 {
			return false
		}
		for _, v := range ctx.Gossip_object_storage.ACC_FRAG[gossip_object.GetID()] {
			if v.Signature == gossip_object.Signature {
				return true
			}
		}
	case definition.STH_FULL:
		if _, ok := ctx.Gossip_object_storage.STH_FULL[gossip_object.GetID()]; !ok {
			return false
		}
		return ctx.Gossip_object_storage.STH_FULL[gossip_object.GetID()].Signature == gossip_object.Signature
	case definition.REV_FULL:
		if _, ok := ctx.Gossip_object_storage.REV_FULL[gossip_object.GetID()]; !ok {
			return false
		}
		return ctx.Gossip_object_storage.REV_FULL[gossip_object.GetID()].Signature == gossip_object.Signature
	case definition.ACC_FULL:
		if _, ok := ctx.Gossip_object_storage.ACC_FULL[gossip_object.GetID()]; !ok {
			return false
		}
		return ctx.Gossip_object_storage.ACC_FULL[gossip_object.GetID()].Signature == gossip_object.Signature
	}
	return false
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
	}
	return false
}

func (ctx *GossiperContext) Store(obj any) bool {
	switch obj.(type) {
	case definition.Gossip_object:
		gossip_object := obj.(definition.Gossip_object)
		return ctx.Store_gossip_object(gossip_object)
	}
	return false
}

func (ctx *GossiperContext) IsDuplicate(obj any) (bool, error) {
	switch obj.(type) {
	case definition.Gossip_object:
		gossip_object := obj.(definition.Gossip_object)
		return ctx.IsDuplicate_G(gossip_object), nil
	}
	return false, errors.New("Unknown type")
}

func (ctx *GossiperContext) InBlacklist(Entity_URL string) bool {
	return ctx.InBlacklistPerm(Entity_URL)
}

func (ctx *GossiperContext) GetObjectList(GID definition.Gossip_ID, TargetType string) []definition.Gossip_object {
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
	}
	return newlist
}

func (ctx *GossiperContext) GetGossipObjectCount(GID definition.Gossip_ID, TargetType string) int {
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
	}
	return 0
}

func (ctx *GossiperContext) GetObject(GID definition.Gossip_ID, targettype string) definition.Gossip_object {
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
	}
	return definition.Gossip_object{}
}

func (ctx *GossiperContext) GetItemCount(ID any, TargetType string) (int, error) {
	switch ID.(type) {
	case definition.Gossip_ID:
		return ctx.GetGossipObjectCount(ID.(definition.Gossip_ID), TargetType), nil
	}
	return 0, errors.New("Invalid ID Type")
}

func (ctx *GossiperContext) GetItem(ID any, TargetType string) any {
	switch ID.(type) {
	case definition.Gossip_ID:
		return ctx.GetObject(ID.(definition.Gossip_ID), TargetType)

	}
	return nil
}

func (ctx *GossiperContext) IsConvergent() bool {
	ctx.Gossip_object_storage.REV_FULL_LOCK.RLock()
	defer ctx.Gossip_object_storage.REV_FULL_LOCK.RUnlock()
	ctx.Gossip_object_storage.STH_FULL_LOCK.RLock()
	defer ctx.Gossip_object_storage.STH_FULL_LOCK.RUnlock()
	ctx.Gossip_object_storage.ACC_FULL_LOCK.RLock()
	defer ctx.Gossip_object_storage.ACC_FULL_LOCK.RUnlock()
	count1 := len(ctx.Gossip_object_storage.REV_FULL)
	count2 := len(ctx.Gossip_object_storage.STH_FULL)
	count3 := len(ctx.Gossip_object_storage.ACC_FULL)
	count4 := len(ctx.Gossip_object_storage.CON_INIT)
	if count1+count2+count3+count4 == ctx.Total_Logger+ctx.Total_CA {
		return true
	}
	return false
}

func (ctx *GossiperContext) IsInitConvergent() bool {
	ctx.Gossip_object_storage.REV_INIT_LOCK.RLock()
	defer ctx.Gossip_object_storage.REV_INIT_LOCK.RUnlock()
	ctx.Gossip_object_storage.STH_INIT_LOCK.RLock()
	defer ctx.Gossip_object_storage.STH_INIT_LOCK.RUnlock()
	ctx.Gossip_object_storage.ACC_INIT_LOCK.RLock()
	defer ctx.Gossip_object_storage.ACC_INIT_LOCK.RUnlock()
	count1 := len(ctx.Gossip_object_storage.REV_INIT)
	count2 := len(ctx.Gossip_object_storage.STH_INIT)
	count3 := len(ctx.Gossip_object_storage.ACC_INIT)
	if count1+count2+count3 == ctx.Total_Logger+ctx.Total_CA {
		return true
	}
	return false
}

func (ctx *GossiperContext) IsMalicious(obj definition.Gossip_object) bool {
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

func (ctx *GossiperContext) WipeStorage() {
	// clear all storage
	CON_INIT := ctx.Gossip_object_storage.CON_INIT
	*ctx.Gossip_object_storage = *InitializeGossipObjectStorage()
	ctx.Gossip_object_storage.CON_INIT = CON_INIT
	// clear all temperary blacklist
	Blacklistperm := ctx.Gossip_blacklist.BLACKLIST_PERM
	*ctx.Gossip_blacklist = *InitializeGossipBlacklist()
	ctx.Gossip_blacklist.BLACKLIST_PERM = Blacklistperm
	// clear all PoM counter and gossiper log
}

func (ctx *GossiperContext) CleanUpGossiperStorage() {
	//delete all files in storage directory
	err := util.DeleteFilesAndDirectories(ctx.StorageDirectory)
	if err != nil {
		fmt.Println(err)
	}
}
