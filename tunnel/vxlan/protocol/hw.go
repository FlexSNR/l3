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

// hw.go
package vxlan

import (
	hwconst "asicd/asicdCommonDefs"
	"asicd/pluginManager/pluginCommon"
	"asicdServices"
	"encoding/json"
	"git.apache.org/thrift.git/lib/go/thrift"
	"io/ioutil"
	"net"
	"strconv"
	"strings"
	"time"
	"utils/commonDefs"
	"utils/ipcutils"
)


type VXLANClientBase struct {
	Address            string
	Transport          thrift.TTransport
	PtrProtocolFactory *thrift.TBinaryProtocolFactory
	IsConnected        bool
}

type AsicdClient struct {
	VXLANClientBase
	ClientHdl *asicdServices.ASICDServicesClient
}

type ClientJson struct {
	Name string `json:Name`
	Port int    `json:Port`
}

var asicdclnt AsicdClient

// look up the various other daemons based on c string
func GetClientPort(paramsFile string, c string) int {
	var clientsList []ClientJson

	bytes, err := ioutil.ReadFile(paramsFile)
	if err != nil {
		//StpLogger("ERROR", fmt.Sprintf("Error in reading configuration file:%s err:%s\n", paramsFile, err))
		return 0
	}

	err = json.Unmarshal(bytes, &clientsList)
	if err != nil {
		//StpLogger("ERROR", "Error in Unmarshalling Json")
		return 0
	}

	for _, client := range clientsList {
		if client.Name == c {
			return client.Port
		}
	}
	return 0
}

func ConstructPortConfigMap() {
	currMarker := asicdServices.Int(hwconst.MIN_SYS_PORTS)
	if asicdclnt.ClientHdl != nil {
		//StpLogger("INFO", "Calling asicd for port config")
		count := asicdServices.Int(hwconst.MAX_SYS_PORTS)
		for {
			bulkInfo, err := asicdclnt.ClientHdl.GetBulkPortState(currMarker, count)
			if err != nil {
				//StpLogger("ERROR", fmt.Sprintf("GetBulkPortState Error: %s", err))
				return
			}
			//StpLogger("INFO", fmt.Sprintf("Length of GetBulkPortState: %d", bulkInfo.Count))

			bulkCfgInfo, err := asicdclnt.ClientHdl.GetBulkPort(currMarker, count)
			if err != nil {
				//StpLogger("ERROR", fmt.Sprintf("Error: %s", err))
				return
			}

			//StpLogger("INFO", fmt.Sprintf("Length of GetBulkPortConfig: %d", bulkCfgInfo.Count))
			objCount := int(bulkInfo.Count)
			more := bool(bulkInfo.More)
			currMarker = asicdServices.Int(bulkInfo.EndIdx)
			for i := 0; i < objCount; i++ {
				ifindex := bulkInfo.PortStateList[i].IfIndex
				ent := PortConfigMap[ifindex]
				ent.IfIndex = ifindex
				ent.Name = bulkInfo.PortStateList[i].Name
				ent.HardwareAddr, _ = net.ParseMAC(bulkCfgInfo.PortList[i].MacAddr)
				PortConfigMap[ifindex] = ent
				//StpLogger("INIT", fmt.Sprintf("Found Port %d IfIndex %d Name %s\n", ent.PortNum, ent.IfIndex, ent.Name))
			}
			if more == false {
				return
			}
		}
	}
}

// connect the the asic d
func ConnectToClients(paramsFile string) {
	port := GetClientPort(paramsFile, "asicd")
	if port != 0 {

		for {
			asicdclnt.Address = "localhost:" + strconv.Itoa(port)
			asicdclnt.Transport, asicdclnt.PtrProtocolFactory, _ = ipcutils.CreateIPCHandles(asicdclnt.Address)
			//StpLogger("INFO", fmt.Sprintf("found asicd at port %d Transport %#v PrtProtocolFactory %#v\n", port, asicdclnt.Transport, asicdclnt.PtrProtocolFactory))
			if asicdclnt.Transport != nil && asicdclnt.PtrProtocolFactory != nil {
				//StpLogger("INFO", "connecting to asicd\n")
				asicdclnt.ClientHdl = asicdServices.NewASICDServicesClientFactory(asicdclnt.Transport, asicdclnt.PtrProtocolFactory)
				asicdclnt.IsConnected = true
				// lets gather all info needed from asicd such as the port
				ConstructPortConfigMap()
				break
			} else {
				time.Sleep(time.Millisecond * 500)
			}
		}
	}
}

func (s *VXLANServer) getLinuxIfName(ifindex int32) string {

	if p, ok := PortConfigMap[ifindex]; ok {
		return p.Name
	}
	return ""
}

func (s *VXLANServer) getLoopbackInfo() (success bool, lbname string, mac net.HardwareAddr, ip net.IP) {
	// TODO this logic only assumes one loopback interface.  More logic is needed
	// to handle multiple  loopbacks configured.  The idea should be
	// that the lowest IP address is used.
	more := true
	for more {
		currMarker := asicdServices.Int(0)
		bulkInfo, err := asicdclnt.ClientHdl.GetBulkLogicalIntfState(currMarker, 5)
		if err == nil {
			objCount := int(bulkInfo.Count)
			more = bool(bulkInfo.More)
			currMarker = asicdServices.Int(bulkInfo.EndIdx)
			for i := 0; i < objCount; i++ {
				ifindex := bulkInfo.LogicalIntfStateList[i].IfIndex
				lbname = bulkInfo.LogicalIntfStateList[i].Name
				if pluginCommon.GetTypeFromIfIndex(ifindex) == commonDefs.IfTypeLoopback {
					mac, _ = net.ParseMAC(bulkInfo.LogicalIntfStateList[i].SrcMac)
					ipV4ObjMore := true
					ipV4ObjCurrMarker := asicdServices.Int(0)
					for ipV4ObjMore {
						ipV4BulkInfo, _ := asicdclnt.ClientHdl.GetBulkIPv4IntfState(ipV4ObjCurrMarker, 20)
						ipV4ObjCount := int(ipV4BulkInfo.Count)
						ipV4ObjCurrMarker = asicdServices.Int(bulkInfo.EndIdx)
						ipV4ObjMore = bool(ipV4BulkInfo.More)
						for j := 0; j < ipV4ObjCount; j++ {
							if ipV4BulkInfo.IPv4IntfStateList[j].IfIndex == ifindex {
								success = true
								ip = net.ParseIP(strings.Split(ipV4BulkInfo.IPv4IntfStateList[j].IpAddr, "/")[0])
								return success, lbname, mac, ip
							}
						}
					}
				}
			}
		}
	}
	return success, lbname, mac, ip
}
