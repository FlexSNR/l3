//
//Copyright [2016] [SnapRoute Inc]
//
//Licensed under the Apache License, Version 2.0 (the "License");
//you may not use this file except in compliance with the License.
//You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
//	 Unless required by applicable law or agreed to in writing, software
//	 distributed under the License is distributed on an "AS IS" BASIS,
//	 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//	 See the License for the specific language governing permissions and
//	 limitations under the License.
//
// _______  __       __________   ___      _______.____    __    ____  __  .___________.  ______  __    __
// |   ____||  |     |   ____\  \ /  /     /       |\   \  /  \  /   / |  | |           | /      ||  |  |  |
// |  |__   |  |     |  |__   \  V  /     |   (----` \   \/    \/   /  |  | `---|  |----`|  ,----'|  |__|  |
// |   __|  |  |     |   __|   >   <       \   \      \            /   |  |     |  |     |  |     |   __   |
// |  |     |  `----.|  |____ /  .  \  .----)   |      \    /\    /    |  |     |  |     |  `----.|  |  |  |
// |__|     |_______||_______/__/ \__\ |_______/        \__/  \__/     |__|     |__|      \______||__|  |__|
//

package server

import (
	"asicdServices"
	"fmt"
	"l3/rib/ribdCommonDefs"
	"utils/dmnBase"
)

type DummyServer struct {
	Dmn             dmnBase.L3Daemon
	ServerStartedCh chan bool
}

func (d *DummyServer) GetLogicalIntfInfo() {
	d.Dmn.Logger.Debug("Getting Logical Interfaces from asicd")
	var currMarker asicdServices.Int
	var count asicdServices.Int
	count = 100
	for {
		d.Dmn.Logger.Info(fmt.Sprintln("Getting ", count, "GetBulkLogicalIntf objects from currMarker:", currMarker))
		bulkInfo, err := d.Dmn.Asicdclnt.ClientHdl.GetBulkLogicalIntfState(currMarker, count)
		if err != nil {
			d.Dmn.Logger.Info(fmt.Sprintln("GetBulkLogicalIntfState with err ", err))
			return
		}
		if bulkInfo.Count == 0 {
			d.Dmn.Logger.Info("0 objects returned from GetBulkLogicalIntfState")
			return
		}
		d.Dmn.Logger.Info(fmt.Sprintln("len(bulkInfo.GetBulkLogicalIntfState)  = ", len(bulkInfo.LogicalIntfStateList), " num objects returned = ", bulkInfo.Count))
		for i := 0; i < int(bulkInfo.Count); i++ {
			ifId := (bulkInfo.LogicalIntfStateList[i].IfIndex)
			d.Dmn.Logger.Info(fmt.Sprintln("logical interface = ", bulkInfo.LogicalIntfStateList[i].Name, "ifId = ", ifId))
		}
		if bulkInfo.More == false {
			d.Dmn.Logger.Info("more returned as false, so no more get bulks")
			return
		}
		currMarker = asicdServices.Int(bulkInfo.EndIdx)
	}
}
func NewDummyServer(dmn dmnBase.L3Daemon) *DummyServer {
	dummyServer := &DummyServer{}
	dummyServer.Dmn = dmn
	dummyServer.ServerStartedCh = make(chan bool)
	dummyServer.Dmn.NewServer()
	return dummyServer
}
func (d *DummyServer) InitServer() {
	err := d.Dmn.ConnectToServers()
	if err != nil {
		d.Dmn.Logger.Err("Error connecting to servers")
		return
	}

	//test code
	if d.Dmn.Asicdclnt.IsConnected {
		d.Dmn.Logger.Info("Connected to ASICD")
		d.GetLogicalIntfInfo()
	}
	if d.Dmn.Ribdclnt.IsConnected {
		d.Dmn.Logger.Info("Connected to RIBD")
		nh, _ := d.Dmn.Ribdclnt.ClientHdl.GetRouteReachabilityInfo("40.1.1.2", -1)
		d.Dmn.Logger.Info(fmt.Sprintln("nh: ", nh))
	}

	//read from DB
	//initialize defaults
}
func (d *DummyServer) StartServer() {

	d.InitServer()
	ribdSubscriberList := []string{ribdCommonDefs.PUB_SOCKET_ADDR, ribdCommonDefs.PUB_SOCKET_POLICY_ADDR}
	d.Dmn.InitSubscribers(ribdSubscriberList)

	d.ServerStartedCh <- true

	// Now, wait on below channels to process
	for {
		d.Dmn.Logger.Info("In for loop")
		select {
		case <-d.Dmn.AsicdSubSocketCh:
			d.Dmn.Logger.Info("Received message on AsicdSubSocketCh")
		case <-d.Dmn.AsicdSubSocketErrCh:
		case <-d.Dmn.RibdSubSocketCh:
			d.Dmn.Logger.Info("Received message on RibdSubSocketCh")
		case <-d.Dmn.RibdSubSocketErrCh:
		}
	}
}
