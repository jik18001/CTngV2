package client

import (
	"CTngV2/definition"
	"CTngV2/monitor"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
)

type MonitorData = []definition.Gossip_object

// Fetch an entity from the given url and parse it as a client update object
func FetchClientUpdate(url string) (monitor.ClientUpdate, error) {
	res, err := fetch(url)
	if err != nil {
		return monitor.ClientUpdate{}, err
	}

	var data monitor.ClientUpdate
	err = json.Unmarshal(res, &data)
	return data, err
}

// Fetch an entity from the given url and parse it as an array of gossip objects
func FetchGossip(url string) (MonitorData, error) {
	res, err := fetch(url)
	if err != nil {
		return MonitorData{}, err
	}

	var data MonitorData
	err = json.Unmarshal(res, &data)
	return data, err
}

// Get the x509 certificate from the given url
func FetchCertificate(url string) (x509.Certificate, error) {
	// CTng certificates, having been created by our own CA, will not pass TLS verification, so we
	// must disable it
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	res, err := client.Get(url)
	if err != nil {
		return x509.Certificate{}, err
	}

	// if res.TLS != nil {
	// 	certificates := res.TLS.PeerCertificates
	// 	if len(certificates) > 0 && certificates[0] != nil {
	// 		return *certificates[0], nil
	// 	}
	// }

	// return x509.Certificate{}, nil

	// Make sure website has a certificate
	if res.TLS == nil {
		return x509.Certificate{}, nil
	}

	// Return the first certificate, if it exists
	certificates := res.TLS.PeerCertificates
	if len(certificates) == 0 && certificates[0] != nil {
		return x509.Certificate{}, fmt.Errorf("no certificate")
	}

	return *certificates[0], nil
}

func fetch(url string) ([]byte, error) {
	res, err := http.Get(url)
	if err != nil {
		return []byte{}, err
	}

	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		return resBody, err
	}

	if res.StatusCode != http.StatusOK {
		return resBody, fmt.Errorf("server returned status code %v: %v", res.StatusCode, string(resBody))
	}

	return resBody, nil
}

func VerifySRH(SRH string) bool {
	//TODO
	return true
}

func (ctx *ClientContext) HandleUpdate(update monitor.ClientUpdate) {
	ctx.CRV_DB_RWLock.Lock()
	for _, rev := range update.REVs {
		SRH, DCRV := Get_SRH_and_DCRV(rev)
		key := rev.Payload[0]
		//verif REV_FULL
		//verify SRH
		if !VerifySRH(SRH) {
			fmt.Println("SRH verification failed")
			return
		}
		//Update CRV
		// look for CRV first
		if _, ok := ctx.CRV_database[key]; !ok {
			ctx.CRV_database[key] = &DCRV
		} else {
			ctx.CRV_database[key].SymmetricDifference(&DCRV)
		}
	}
	ctx.CRV_DB_RWLock.Unlock()
	ctx.STH_DB_RWLock.Lock()
	for _, sth := range update.STHs {
		var STH_def definition.STH
		err := json.Unmarshal([]byte(sth.Payload[1]), &STH_def)
		if err != nil {
			fmt.Println("sth unmarshal failed")
			return
		}
		newrecord := STH_def.RootHash
		key := sth.Payload[0] + "@" + sth.Period
		//verify STH_FULL
		//Update STH
		// look for STH first
		ctx.STH_database[key] = newrecord
	}
	ctx.STH_DB_RWLock.Unlock()
	ctx.D1_Blacklist_DB_RWLock.Lock()
	for _, d1pom := range update.ACCs {
		//verify D1POM_FULL
		//Update D1POM
		// look for D1POM first
		key := d1pom.Payload[0] + "@" + d1pom.Period
		ctx.D1_Blacklist_database[key] = true
	}
	ctx.D1_Blacklist_DB_RWLock.Unlock()
	ctx.D2_Blacklist_DB_RWLock.Lock()
	for _, d2pom := range update.CONs {
		//verify D2POM_FULL
		//Update D2POM
		// look for D2POM first
		key := d2pom.Payload[0]
		if _, ok := ctx.D2_Blacklist_database[key]; !ok {
			ctx.D2_Blacklist_database[key] = d2pom.Period
		}
	}
	ctx.D2_Blacklist_DB_RWLock.Unlock()
	// now verify and store monitor integrity data
	ctx.Monitor_Interity_database[update.Period] = update.NUM.ACC_FULL_Counter + "@" + update.NUM.CON_FULL_Counter
	// verify the Monitor Integrity data for the previous period against the NUM_FULL received in this period
	// if the verification fails, then the monitor is not honest
	period_int, _ := strconv.Atoi(update.Period)
	period_int_prev := strconv.Itoa(period_int - 1)
	key := period_int_prev
	old_data := ctx.Monitor_Interity_database[key]
	if old_data != "" {
		new_data := update.NUM_FULL.ACC_FULL_Counter + "@" + update.NUM_FULL.CON_FULL_Counter
		if old_data != new_data {
			// we should definitely do something else here, but for now we just print
			fmt.Println("Monitor is not honest")
			return
		}
	}
}
