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
package flexswitch

import (
	"asicd/asicdCommonDefs"
	"asicd/pluginManager/pluginCommon"
	"l3/ndp/api"
	"l3/ndp/config"
	"l3/ndp/debug"
	"sync"
	"utils/commonDefs"
)

var switchInst *commonDefs.AsicdClientStruct = nil
var once sync.Once

func initAsicdNotification() commonDefs.AsicdNotification {
	nMap := make(commonDefs.AsicdNotification)
	nMap = commonDefs.AsicdNotification{
		commonDefs.NOTIFY_L2INTF_STATE_CHANGE:       true,
		commonDefs.NOTIFY_IPV4_L3INTF_STATE_CHANGE:  false,
		commonDefs.NOTIFY_IPV6_L3INTF_STATE_CHANGE:  true,
		commonDefs.NOTIFY_VLAN_CREATE:               true,
		commonDefs.NOTIFY_VLAN_DELETE:               true,
		commonDefs.NOTIFY_VLAN_UPDATE:               true,
		commonDefs.NOTIFY_LOGICAL_INTF_CREATE:       false,
		commonDefs.NOTIFY_LOGICAL_INTF_DELETE:       false,
		commonDefs.NOTIFY_LOGICAL_INTF_UPDATE:       false,
		commonDefs.NOTIFY_IPV4INTF_CREATE:           false,
		commonDefs.NOTIFY_IPV4INTF_DELETE:           false,
		commonDefs.NOTIFY_IPV6INTF_CREATE:           true,
		commonDefs.NOTIFY_IPV6INTF_DELETE:           true,
		commonDefs.NOTIFY_LAG_CREATE:                true,
		commonDefs.NOTIFY_LAG_DELETE:                true,
		commonDefs.NOTIFY_LAG_UPDATE:                true,
		commonDefs.NOTIFY_IPV4NBR_MAC_MOVE:          false,
		commonDefs.NOTIFY_IPV6NBR_MAC_MOVE:          true,
		commonDefs.NOTIFY_IPV4_ROUTE_CREATE_FAILURE: false,
		commonDefs.NOTIFY_IPV4_ROUTE_DELETE_FAILURE: false,
		commonDefs.NOTIFY_IPV6_ROUTE_CREATE_FAILURE: false,
		commonDefs.NOTIFY_IPV6_ROUTE_DELETE_FAILURE: false,
		commonDefs.NOTIFY_VTEP_CREATE:               false,
		commonDefs.NOTIFY_VTEP_DELETE:               false,
		commonDefs.NOTIFY_MPLSINTF_STATE_CHANGE:     false,
		commonDefs.NOTIFY_MPLSINTF_CREATE:           false,
		commonDefs.NOTIFY_MPLSINTF_DELETE:           false,
		commonDefs.NOTIFY_PORT_CONFIG_MODE_CHANGE:   false,
	}
	return nMap
}

func GetSwitchInst() *commonDefs.AsicdClientStruct {
	once.Do(func() {
		notifyMap := initAsicdNotification()
		notifyHdl := &AsicNotificationHdl{}
		switchInst = &commonDefs.AsicdClientStruct{
			NHdl: notifyHdl,
			NMap: notifyMap,
		}
	})
	return switchInst
}

func (notifyHdl *AsicNotificationHdl) ProcessNotification(msg commonDefs.AsicdNotifyMsg) {
	if !api.InitComplete() {
		return
	}
	switch msg.(type) {
	case commonDefs.IPv6IntfNotifyMsg:
		// create/delete ipv6 interface notification case
		ipv6Msg := msg.(commonDefs.IPv6IntfNotifyMsg)
		if pluginCommon.GetTypeFromIfIndex(ipv6Msg.IfIndex) != commonDefs.IfTypeLoopback {
			if ipv6Msg.MsgType == commonDefs.NOTIFY_IPV6INTF_CREATE {
				debug.Logger.Debug("Received Asicd IPV6 INTF Notfication CREATE:", ipv6Msg)
				api.SendIPIntfNotfication(ipv6Msg.IfIndex, ipv6Msg.IpAddr, ipv6Msg.IntfRef, config.CONFIG_CREATE)
			} else {
				debug.Logger.Debug("Received Asicd IPV6 INTF Notfication DELETE:", ipv6Msg)
				api.SendIPIntfNotfication(ipv6Msg.IfIndex, ipv6Msg.IpAddr, ipv6Msg.IntfRef, config.CONFIG_DELETE)
			}
		}
	case commonDefs.IPv6L3IntfStateNotifyMsg:
		// state up/down for ipv6 interface case
		l3Msg := msg.(commonDefs.IPv6L3IntfStateNotifyMsg)
		// only get state notification if ip type is v6 && not loopback
		if pluginCommon.GetTypeFromIfIndex(l3Msg.IfIndex) != commonDefs.IfTypeLoopback {
			if l3Msg.IfState == asicdCommonDefs.INTF_STATE_UP {
				debug.Logger.Debug("Received Asicd L3 State Notfication UP:", l3Msg)
				api.SendL3PortNotification(l3Msg.IfIndex, config.STATE_UP, l3Msg.IpAddr)
			} else {
				debug.Logger.Debug("Received Asicd L3 State Notfication DOWN:", l3Msg)
				api.SendL3PortNotification(l3Msg.IfIndex, config.STATE_DOWN, l3Msg.IpAddr)
			}
		}
	case commonDefs.L2IntfStateNotifyMsg:
		l2Msg := msg.(commonDefs.L2IntfStateNotifyMsg)
		if l2Msg.IfState == asicdCommonDefs.INTF_STATE_UP {
			debug.Logger.Debug("Received Asicd L2 Port Notfication UP:", l2Msg)
			api.SendL3PortNotification(l2Msg.IfIndex, config.STATE_UP, config.L2_NOTIFICATION)
		} else {
			debug.Logger.Debug("Received Asicd L2 Port Notfication DOWN:", l2Msg)
			api.SendL3PortNotification(l2Msg.IfIndex, config.STATE_DOWN, config.L2_NOTIFICATION)
		}
	case commonDefs.VlanNotifyMsg:
		vlanMsg := msg.(commonDefs.VlanNotifyMsg)
		debug.Logger.Debug("Received Asicd Vlan Notfication:", vlanMsg)
		oper := ""
		switch vlanMsg.MsgType {
		case commonDefs.NOTIFY_VLAN_CREATE:
			debug.Logger.Debug("Received Asicd VLAN CREATE")
			oper = config.CONFIG_CREATE
		case commonDefs.NOTIFY_VLAN_DELETE:
			debug.Logger.Debug("Received Asicd VLAN DELETE")
			oper = config.CONFIG_DELETE
		case commonDefs.NOTIFY_VLAN_UPDATE:
			debug.Logger.Debug("Received Asicd VLAN UPDATE")
			oper = config.CONFIG_UPDATE
		}
		api.SendVlanNotification(oper, int32(vlanMsg.VlanId), vlanMsg.VlanIfIndex, vlanMsg.VlanName, vlanMsg.UntagPorts, vlanMsg.TagPorts)
	case commonDefs.IPv6NbrMacMoveNotifyMsg:
		macMoveMsg := msg.(commonDefs.IPv6NbrMacMoveNotifyMsg)
		debug.Logger.Debug("Received Asicd IPv6 Neighbor Mac Move Notification:", macMoveMsg)
		api.SendMacMoveNotification(macMoveMsg.IpAddr, macMoveMsg.IfIndex, macMoveMsg.VlanId)
	}
}
