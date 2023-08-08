package main

import (
	"CTngV2/gossiper"
	"CTngV2/util"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"testing"
)

func testgossipobjectnum(entry gossiper.Gossiper_log_entry, Periodoffset int) bool {
	if entry.NUM_STH_INIT != 2 {
		fmt.Println("Number of STH_INIT is ", entry.NUM_STH_INIT, "but should be 1.")
		return false
	}
	if entry.NUM_STH_FRAG != 4 {
		// this could happen, report it but this is not a failure
		fmt.Println("Number of STH_FRAG is ", entry.NUM_STH_FRAG, "but should be 2.")
	}
	if entry.NUM_STH_FULL != 2 {
		fmt.Println("Number of STH_FULL is ", entry.NUM_STH_FULL, "but should be 1.")
		return false
	}
	if entry.NUM_REV_INIT != 2 {
		fmt.Println("Number of REV_INIT is ", entry.NUM_REV_FULL, "but should be 1.")
		return false
	}
	if entry.NUM_REV_FRAG != 4 {
		// this could happen, report it but this is not a failure
		fmt.Println("Number of REV_FRAG is ", entry.NUM_REV_FRAG, "but should be 2.")
	}
	if entry.NUM_REV_FULL != 2 {
		fmt.Println("Number of REV_FULL is ", entry.NUM_ACC_FULL, "but should be 1.")
		return false
	}
	return true
}

func testfirstglogentry(entry gossiper.Gossiper_log_entry) bool {
	return testgossipobjectnum(entry, 0)
}
func testotherglogentry(entry gossiper.Gossiper_log_entry, Periodoffset int) bool {
	return testgossipobjectnum(entry, Periodoffset)
}
func TestGMResult(t *testing.T) {
	var MinConvergeTime float64 = 1000
	var AverageConvergeTime float64 = 0
	var MaxConvergeTime float64 = 0
	var datacount float64 = 0
	//read from /gossiper_testdata/$storage_ID$/gossiper_testdata.json
	var gossiper_log_database [][]gossiper.Gossiper_log_entry
	for i := 1; i <= 4; i++ {
		var gossiper_log_map_1 gossiper.Gossiper_log
		bytedata, _ := util.ReadByte("gossiper_testdata/" + strconv.Itoa(i) + "/gossiper_testdata.json")
		json.Unmarshal(bytedata, &gossiper_log_map_1)
		//iterate through the gossiper_log_map_1, add to a list
		var gossiper_log_map_1_list []gossiper.Gossiper_log_entry
		for _, v := range gossiper_log_map_1 {
			gossiper_log_map_1_list = append(gossiper_log_map_1_list, v)
			// sort the list by GossiperLogEntry.Period
			sort.Slice(gossiper_log_map_1_list, func(i, j int) bool {
				return gossiper_log_map_1_list[i].Period < gossiper_log_map_1_list[j].Period
			})
		}
		gossiper_log_database = append(gossiper_log_database, gossiper_log_map_1_list)
	}
	for i, gossiper_log_map_1_list := range gossiper_log_database {
		fmt.Println("Start testing gossiper ", i+1)
		//fmt.Println(gossiper_log_map_1_list)
		testfirstglogentry(gossiper_log_map_1_list[0])
		//test other entries
		for i := 1; i < len(gossiper_log_map_1_list); i++ {
			newbool := testotherglogentry(gossiper_log_map_1_list[i], i)
			if newbool == false {
				t.Fail()
			}
		}

		for j := 0; j < len(gossiper_log_map_1_list); j++ {
			convergetime, _ := strconv.ParseFloat(gossiper_log_map_1_list[j].Converge_time, 64)
			//fmt.Println("Converge time is ", convergetime)
			//fmt.Println(gossiper_log_map_1_list[j].Converge_time)
			AverageConvergeTime += convergetime
			if convergetime > MaxConvergeTime {
				MaxConvergeTime = convergetime
			} else if convergetime < MinConvergeTime {
				MinConvergeTime = convergetime
			}
			datacount++
		}
	}
	AverageConvergeTime = AverageConvergeTime / datacount
	fmt.Println("Min Converge Time is ", MinConvergeTime)
	fmt.Println("Average Converge Time is ", AverageConvergeTime)
	fmt.Println("Max Converge Time is ", MaxConvergeTime)

}
