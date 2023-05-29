package definition

import (
	"CTngV2/crypto"
	"encoding/binary"
)

type Gossip_object struct {
	Application string    `json:"application"`
	Period      string    `json:"period"`
	Type        string    `json:"type"`
	Signer      string    `json:"signer"`
	Signers     []string  `json:"signers,omitempty"`
	Signature   [2]string `json:"signature"`
	// Timestamp is a UTC RFC3339 string
	Timestamp     string    `json:"timestamp"`
	Crypto_Scheme string    `json:"crypto_scheme"`
	Payload       [3]string `json:"payload,omitempty"`
}

type PoM_Counter struct {
	Type             string   `json:"type"`
	ACC_FULL_Counter string   `json:"ACC_FULL_Counter"`
	CON_FULL_Counter string   `json:"CON_FULL_Counter"`
	Period           string   `json:"period"`
	Signer_Monitor   string   `json:"signer_monitor,omitempty"`
	Signer_Gossiper  string   `json:"signer_gossiper,omitempty"`
	Signers          []string `json:"signers,omitempty"`
	Crypto_Scheme    string   `json:"crypto_scheme"`
	Signature        string   `json:"signature,omitempty"`
}

type Revocation struct {
	Period    string
	Delta_CRV []byte
	SRH       string
}

type STH struct {
	Signer    string
	Timestamp string
	RootHash  string
	TreeSize  int
}

// The only valid application type
const CTNG_APPLICATION = "CTng"

// Identifiers for different types of gossip object or PoM counter that can be sent.
const (
	STH_INIT = "http://ctng.uconn.edu/101"
	REV_INIT = "http://ctng.uconn.edu/102"
	ACC_INIT = "http://ctng.uconn.edu/103"
	CON_INIT = "http://ctng.uconn.edu/104"
	NUM_INIT = "http://ctng.uconn.edu/105"
	STH_FRAG = "http://ctng.uconn.edu/201"
	REV_FRAG = "http://ctng.uconn.edu/202"
	ACC_FRAG = "http://ctng.uconn.edu/203"
	CON_FRAG = "http://ctng.uconn.edu/204"
	NUM_FRAG = "http://ctng.uconn.edu/205"
	STH_FULL = "http://ctng.uconn.edu/301"
	REV_FULL = "http://ctng.uconn.edu/302"
	ACC_FULL = "http://ctng.uconn.edu/303"
	CON_FULL = "http://ctng.uconn.edu/304"
	NUM_FULL = "http://ctng.uconn.edu/305"
)

type Gossip_Storage map[Gossip_ID]Gossip_object

type Gossip_ID struct {
	Period     string `json:"period"`
	Type       string `json:"type"`
	Entity_URL string `json:"entity_URL"`
}

func (g Gossip_ID) String() string {
	return g.Period + g.Type + g.Entity_URL
}

func (g Gossip_object) GetID() Gossip_ID {
	new_ID := Gossip_ID{
		Period:     g.Period,
		Type:       g.Type,
		Entity_URL: g.Payload[0],
	}
	return new_ID
}
func (g Gossip_object) GetTargetType() string {
	switch g.Type {
	case STH_INIT:
		return STH_FRAG
	case REV_INIT:
		return REV_FRAG
	case ACC_INIT:
		return ACC_FRAG
	case CON_INIT:
		return CON_FRAG
	case STH_FRAG:
		return STH_FULL
	case REV_FRAG:
		return REV_FULL
	case ACC_FRAG:
		return ACC_FULL
	case CON_FRAG:
		return CON_FULL
	default:
		return ""
	}
}

// This function is used to make sure all gossipers sign on the same
func (g Gossip_object) Get_CON_ID() uint32 {
	hashmsg1 := g.Payload[0] + g.Payload[1] + g.Payload[2]
	hash1, _ := crypto.GenerateSHA256([]byte(hashmsg1))
	int1 := binary.BigEndian.Uint32(hash1)
	return int1
}
func (p PoM_Counter) GetID() string {
	return p.ACC_FULL_Counter + p.CON_FULL_Counter + p.Period
}

//Payload specifications for different types of gossip object

// STH_INIT Payload
// 0: loggerURL
// 1: STH
// 2: empty

// REV_INIT Payload
// 0: CAURL
// 1: Revocation Scheme
// 2: Revocation Struct

// ACC_INIT Payload
// 0: loggerURL/CAURL
// 1: empty
// 2: empty

// CON_INIT Payload
// 0: loggerURL/CAURL
// 1: Conflicting STH/REV 01
// 2: Conflicting STH/REV 02

// This function prints the "name string" of each Gossip object type. It's used when printing this info to console.
func TypeString(t string) string {
	switch t {
	case STH_INIT:
		return "STH_INIT"
	case REV_INIT:
		return "REV_INIT"
	case ACC_INIT:
		return "ACC_INIT"
	case CON_INIT:
		return "CON_INIT"
	case NUM_INIT:
		return "NUM_INIT"
	case STH_FRAG:
		return "STH_FRAG"
	case REV_FRAG:
		return "REV_FRAG"
	case ACC_FRAG:
		return "ACC_FRAG"
	case CON_FRAG:
		return "CON_FRAG"
	case NUM_FRAG:
		return "NUM_FRAG"
	case STH_FULL:
		return "STH_FULL"
	case REV_FULL:
		return "REV_FULL"
	case ACC_FULL:
		return "ACC_FULL"
	case CON_FULL:
		return "CON_FULL"
	case NUM_FULL:
		return "NUM_FULL"
	default:
		return "UNKNOWN"
	}
}
