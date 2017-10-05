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

package vrrpServer

import (
	"asicd/asicdCommonDefs"
	"asicdServices"
	"encoding/json"
	"fmt"
	nanomsg "github.com/op/go-nanomsg"
	"utils/commonDefs"
)

func (svr *VrrpServer) VrrpCreateIfIndexEntry(IfIndex int32, IpAddr string) {
	svr.vrrpIfIndexIpAddr[IfIndex] = IpAddr
	svr.logger.Info(fmt.Sprintln("ip address for ifindex", IfIndex,
		"is", IpAddr))
}

func (svr *VrrpServer) VrrpCreateVlanEntry(vlanId int, vlanName string) {
	svr.vrrpVlanId2Name[vlanId] = vlanName
}

func (svr *VrrpServer) VrrpGetIPv4IntfList() {
	svr.logger.Info("Get IPv4 Interface List")
	objCount := 0
	var currMarker int64
	more := false
	count := 10
	for {
		bulkInfo, err := svr.asicdClient.ClientHdl.GetBulkIPv4IntfState(
			asicdServices.Int(currMarker), asicdServices.Int(count))
		if err != nil {
			svr.logger.Err(fmt.Sprintln("getting bulk ipv4 intf config",
				"from asicd failed with reason", err))
			return
		}
		objCount = int(bulkInfo.Count)
		more = bool(bulkInfo.More)
		currMarker = int64(bulkInfo.EndIdx)
		for i := 0; i < objCount; i++ {
			svr.VrrpCreateIfIndexEntry(bulkInfo.IPv4IntfStateList[i].IfIndex,
				bulkInfo.IPv4IntfStateList[i].IpAddr)
			svr.VrrpMapIfIndexToLinuxIfIndex(bulkInfo.IPv4IntfStateList[i].IfIndex)
		}
		if more == false {
			break
		}
	}
}

func (svr *VrrpServer) VrrpGetVlanList() {
	svr.logger.Info("Get Vlans")
	objCount := 0
	var currMarker int64
	more := false
	count := 10
	for {
		bulkInfo, err := svr.asicdClient.ClientHdl.GetBulkVlanState(
			asicdServices.Int(currMarker), asicdServices.Int(count))
		if err != nil {
			svr.logger.Err(fmt.Sprintln("getting bulk vlan config",
				"from asicd failed with reason", err))
			return
		}
		objCount = int(bulkInfo.Count)
		more = bool(bulkInfo.More)
		currMarker = int64(bulkInfo.EndIdx)
		for i := 0; i < objCount; i++ {
			svr.VrrpCreateVlanEntry(int(bulkInfo.VlanStateList[i].VlanId),
				bulkInfo.VlanStateList[i].VlanName)
		}
		if more == false {
			break
		}
	}
}

func (svr *VrrpServer) VrrpUpdateVlanGblInfo(vlanNotifyMsg asicdCommonDefs.VlanNotifyMsg, msgType uint8) {
	svr.logger.Info(fmt.Sprintln("Vlan Update msg for", vlanNotifyMsg))
	switch msgType {
	case asicdCommonDefs.NOTIFY_VLAN_CREATE:
		svr.VrrpCreateVlanEntry(int(vlanNotifyMsg.VlanId), vlanNotifyMsg.VlanName)
	case asicdCommonDefs.NOTIFY_VLAN_DELETE:
		delete(svr.vrrpVlanId2Name, int(vlanNotifyMsg.VlanId))
	}
}

func (svr *VrrpServer) VrrpUpdateIPv4GblInfo(msg asicdCommonDefs.IPv4IntfNotifyMsg, msgType uint8) {
	ifType := asicdCommonDefs.GetIntfTypeFromIfIndex(msg.IfIndex)
	if ifType == commonDefs.IfTypeVirtual || ifType == commonDefs.IfTypeSecondary {
		svr.logger.Info("Ignoring ipv4 interface notifcation for sub interface")
		return
	}
	switch msgType {
	case asicdCommonDefs.NOTIFY_IPV4INTF_CREATE:
		svr.VrrpCreateIfIndexEntry(msg.IfIndex, msg.IpAddr)
		svr.VrrpMapIfIndexToLinuxIfIndex(msg.IfIndex)
		// @TODO: add this call only when we support update of ip addr
		//go svr.VrrpChecknUpdateGblInfo(msg.IfIndex, msg.IpAddr)
	case asicdCommonDefs.NOTIFY_IPV4INTF_DELETE:
		delete(svr.vrrpIfIndexIpAddr, msg.IfIndex)
	}
}

func (svr *VrrpServer) VrrpUpdateL3IntfStateChange(msg asicdCommonDefs.IPv4L3IntfStateNotifyMsg) {
	ifType := asicdCommonDefs.GetIntfTypeFromIfIndex(msg.IfIndex)
	if ifType == commonDefs.IfTypeVirtual || ifType == commonDefs.IfTypeSecondary {
		svr.logger.Info("Ignoring ipv4 interface notifcation for sub interface")
		return
	}
	switch msg.IfState {
	case asicdCommonDefs.INTF_STATE_UP:
		svr.VrrpHandleIntfUpEvent(msg.IfIndex)
		svr.logger.Info("Got Interface state up notification")
	case asicdCommonDefs.INTF_STATE_DOWN:
		svr.VrrpHandleIntfShutdownEvent(msg.IfIndex)
		svr.logger.Info("Got Interface state down notification")
	}
}

func (svr *VrrpServer) VrrpAsicdSubscriber() {
	for {
		svr.logger.Info("Read on Asic Subscriber socket....")
		rxBuf, err := svr.asicdSubSocket.Recv(0)
		if err != nil {
			svr.logger.Err(fmt.Sprintln("Recv on asicd Subscriber",
				"socket failed with error:", err))
			continue
		}
		var msg asicdCommonDefs.AsicdNotification
		err = json.Unmarshal(rxBuf, &msg)
		if err != nil {
			svr.logger.Err(fmt.Sprintln("Unable to Unmarshal",
				"asicd msg:", msg.Msg))
			continue
		}
		if msg.MsgType == asicdCommonDefs.NOTIFY_VLAN_CREATE ||
			msg.MsgType == asicdCommonDefs.NOTIFY_VLAN_DELETE {
			//Vlan Create Msg
			var vlanNotifyMsg asicdCommonDefs.VlanNotifyMsg
			err = json.Unmarshal(msg.Msg, &vlanNotifyMsg)
			if err != nil {
				svr.logger.Err(fmt.Sprintln("Unable to",
					"unmashal vlanNotifyMsg:", msg.Msg))
				return
			}
			svr.VrrpUpdateVlanGblInfo(vlanNotifyMsg, msg.MsgType)
		} else if msg.MsgType == asicdCommonDefs.NOTIFY_IPV4INTF_CREATE ||
			msg.MsgType == asicdCommonDefs.NOTIFY_IPV4INTF_DELETE {
			var ipv4IntfNotifyMsg asicdCommonDefs.IPv4IntfNotifyMsg
			err = json.Unmarshal(msg.Msg, &ipv4IntfNotifyMsg)
			if err != nil {
				svr.logger.Err(fmt.Sprintln("Unable to Unmarshal",
					"ipv4IntfNotifyMsg:", msg.Msg))
				continue
			}
			svr.VrrpUpdateIPv4GblInfo(ipv4IntfNotifyMsg, msg.MsgType)
		} else if msg.MsgType == asicdCommonDefs.NOTIFY_IPV4_L3INTF_STATE_CHANGE {
			//INTF_STATE_CHANGE
			var l3IntfStateNotifyMsg asicdCommonDefs.IPv4L3IntfStateNotifyMsg
			err = json.Unmarshal(msg.Msg, &l3IntfStateNotifyMsg)
			if err != nil {
				svr.logger.Err(fmt.Sprintln("unable to Unmarshal l3 intf",
					"state change:", msg.Msg))
				continue
			}
			svr.VrrpUpdateL3IntfStateChange(l3IntfStateNotifyMsg)
		}
	}
}

func (svr *VrrpServer) VrrpRegisterWithAsicdUpdates(address string) error {
	var err error
	svr.logger.Info("setting up asicd update listener")
	if svr.asicdSubSocket, err = nanomsg.NewSubSocket(); err != nil {
		svr.logger.Err(fmt.Sprintln("Failed to create ASIC subscribe",
			"socket, error:", err))
		return err
	}

	if err = svr.asicdSubSocket.Subscribe(""); err != nil {
		svr.logger.Err(fmt.Sprintln("Failed to subscribe to \"\" on",
			"ASIC subscribe socket, error:",
			err))
		return err
	}

	if _, err = svr.asicdSubSocket.Connect(address); err != nil {
		svr.logger.Err(fmt.Sprintln("Failed to connect to ASIC",
			"publisher socket, address:", address, "error:", err))
		return err
	}

	if err = svr.asicdSubSocket.SetRecvBuffer(1024 * 1024); err != nil {
		svr.logger.Err(fmt.Sprintln("Failed to set the buffer size for ",
			"ASIC publisher socket, error:", err))
		return err
	}
	svr.logger.Info("asicd update listener is set")
	return nil
}

func (svr *VrrpServer) VrrpGetInfoFromAsicd() error {
	svr.logger.Info("Calling Asicd to initialize port properties")
	err := svr.VrrpRegisterWithAsicdUpdates(asicdCommonDefs.PUB_SOCKET_ADDR)
	if err == nil {
		// Asicd subscriber thread
		go svr.VrrpAsicdSubscriber()
	}
	// Get Vlan List
	svr.VrrpGetVlanList()
	// Get IPv4 Interface List
	svr.VrrpGetIPv4IntfList()
	return nil
}
