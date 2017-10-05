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

package relayServer

import (
	"dhcprelayd"
	"models/objects"
	"utils/dbutils"
)

func DhcpRelayAgentInitDB() error {
	logger.Debug("DRA: initializing DB")
	var err error
	dhcprelayDbHdl = dbutils.NewDBUtil(logger)
	err = dhcprelayDbHdl.Connect()
	if err != nil {
		logger.Err("DRA: Failed to create db handle", err)
		return err
	}

	logger.Debug("DRA: SQL DB init success")
	return err
}

func DhcpRelayAgentReadDB() {
	logger.Debug("Reading Dhcp Relay Global Config from DB")
	if dhcprelayDbHdl == nil {
		return
	}
	/*  First reading Dhcp Relay Global Config
	 */
	var dbObj objects.DhcpRelayGlobal
	objList, err := dbObj.GetAllObjFromDb(dhcprelayDbHdl)
	if err != nil {
		logger.Warning("DB querry failed for Dhcp Relay Global Config")
		return
	}
	for idx := 0; idx < len(objList); idx++ {
		obj := dhcprelayd.NewDhcpRelayGlobal()
		dbObject := objList[idx].(objects.DhcpRelayGlobal)
		objects.ConvertdhcprelaydDhcpRelayGlobalObjToThrift(&dbObject, obj)
		DhcpRelayGlobalInit(bool(obj.Enable))
	}

	/*  Reading Dhcp Relay Interface Config.
	 *  As we are using redis DB, we will get the server ip list automatically..
	 */
	readIfIndex := make([]int32, 0)
	var intfDbObj objects.DhcpRelayIntf
	objList, err = intfDbObj.GetAllObjFromDb(dhcprelayDbHdl)
	if err != nil {
		logger.Warning("DB querry failed for Dhcp Relay Intf Config")
		return
	}
	for idx := 0; idx < len(objList); idx++ {
		obj := dhcprelayd.NewDhcpRelayIntf()
		dbObject := objList[idx].(objects.DhcpRelayIntf)
		objects.ConvertdhcprelaydDhcpRelayIntfObjToThrift(&dbObject, obj)
		IfIndex := int32(obj.IfIndex)
		Enable := bool(obj.Enable)
		DhcpRelayAgentInitGblHandling(IfIndex, Enable)
		DhcpRelayAgentInitIntfState(IfIndex)
		readIfIndex = append(readIfIndex, IfIndex)
		for _, serverIp := range obj.ServerIp {
			logger.Debug("DRA: ifindex:", IfIndex, "Server Ip:", serverIp)
			DhcpRelayAgentUpdateIntfServerIp(IfIndex, serverIp)
		}
	}
	if len(readIfIndex) > 0 {
		// For all ifIndex recovered from DB.. get ip address from asicd
		go DhcpRelayAgentUpdateIntfIpAddr(readIfIndex)
	}
	dhcprelayDbHdl.Disconnect()
}
