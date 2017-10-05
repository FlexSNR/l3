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

// ribdEventHandler.go
package server

import (
	"asicd/asicdCommonDefs"
	"encoding/json"
	//"fmt"
	"github.com/op/go-nanomsg"
	"net"
	"ribd"
	"strconv"
	"utils/commonDefs"
)

func (ribdServiceHandler *RIBDServer) ProcessLogicalIntfCreateEvent(logicalIntfNotifyMsg asicdCommonDefs.LogicalIntfNotifyMsg) {
	ifId := logicalIntfNotifyMsg.IfIndex
	if IntfIdNameMap == nil {
		IntfIdNameMap = make(map[int32]IntfEntry)
	}
	intfEntry := IntfEntry{name: logicalIntfNotifyMsg.LogicalIntfName}
	ribdServiceHandler.Logger.Info("Updating IntfIdMap at index ", ifId, " with name ", logicalIntfNotifyMsg.LogicalIntfName)
	IntfIdNameMap[int32(ifId)] = intfEntry
	if IfNameToIfIndex == nil {
		IfNameToIfIndex = make(map[string]int32)
	}
	IfNameToIfIndex[logicalIntfNotifyMsg.LogicalIntfName] = ifId

}
func (ribdServiceHandler *RIBDServer) ProcessVlanCreateEvent(vlanNotifyMsg asicdCommonDefs.VlanNotifyMsg) {
	ifId := asicdCommonDefs.GetIfIndexFromIntfIdAndIntfType(int(vlanNotifyMsg.VlanId), commonDefs.IfTypeVlan)
	ribdServiceHandler.Logger.Info("vlanId ", vlanNotifyMsg.VlanId, " ifId:", ifId)
	if IntfIdNameMap == nil {
		IntfIdNameMap = make(map[int32]IntfEntry)
	}
	intfEntry := IntfEntry{name: vlanNotifyMsg.VlanName}
	IntfIdNameMap[int32(ifId)] = intfEntry
	if IfNameToIfIndex == nil {
		IfNameToIfIndex = make(map[string]int32)
	}
	IfNameToIfIndex[vlanNotifyMsg.VlanName] = ifId
}
func (ribdServiceHandler *RIBDServer) ProcessIPv4IntfCreateEvent(msg asicdCommonDefs.IPv4IntfNotifyMsg) {

	var ipMask net.IP
	ip, ipNet, err := net.ParseCIDR(msg.IpAddr)
	if err != nil {
		return
	}
	ipMask = make(net.IP, 4)
	copy(ipMask, ipNet.Mask)
	ipAddrStr := ip.String()
	ipMaskStr := net.IP(ipMask).String()
	ribdServiceHandler.Logger.Info("Calling createv4Route with ipaddr ", ipAddrStr, " mask ", ipMaskStr, " nextHopIntRef: ", strconv.Itoa(int(msg.IfIndex)))
	//fmt.Println("Calling createv4Route with ipaddr ", ipAddrStr, " mask ", ipMaskStr, " nextHopIntRef: ", strconv.Itoa(int(msg.IfIndex)))
	cfg := ribd.IPv4Route{
		DestinationNw: ipAddrStr,
		Protocol:      "CONNECTED",
		Cost:          0,
		NetworkMask:   ipMaskStr,
	}
	nextHop := ribd.NextHopInfo{
		NextHopIp:     "0.0.0.0",
		NextHopIntRef: strconv.Itoa(int(msg.IfIndex)),
	}
	cfg.NextHop = make([]*ribd.NextHopInfo, 0)
	cfg.NextHop = append(cfg.NextHop, &nextHop)

	ribdServiceHandler.RouteConfCh <- RIBdServerConfig{
		OrigConfigObject: &cfg,
		Op:               "add",
	}
}
func (ribdServiceHandler *RIBDServer) ProcessIPv6IntfCreateEvent(msg asicdCommonDefs.IPv6IntfNotifyMsg) {
	var ipMask net.IP
	ip, ipNet, err := net.ParseCIDR(msg.IpAddr)
	if err != nil {
		return
	}
	ipMask = make(net.IP, 16)
	copy(ipMask, ipNet.Mask)
	ipAddrStr := ip.String()
	ipMaskStr := net.IP(ipMask).String()
	ribdServiceHandler.Logger.Info("Calling createRoute with ipaddr ", ipAddrStr, " mask ", ipMaskStr, " nextHopIntRef: ", strconv.Itoa(int(msg.IfIndex)))
	cfg := ribd.IPv6Route{
		DestinationNw: ipAddrStr,
		Protocol:      "CONNECTED",
		Cost:          0,
		NetworkMask:   ipMaskStr,
	}
	nextHop := ribd.NextHopInfo{
		NextHopIp:     "::",
		NextHopIntRef: strconv.Itoa(int(msg.IfIndex)),
	}
	cfg.NextHop = make([]*ribd.NextHopInfo, 0)
	cfg.NextHop = append(cfg.NextHop, &nextHop)

	ribdServiceHandler.RouteConfCh <- RIBdServerConfig{
		OrigConfigObject: &cfg,
		Op:               "addv6",
	}
}
func (ribdServiceHandler *RIBDServer) ProcessIPv4IntfDeleteEvent(msg asicdCommonDefs.IPv4IntfNotifyMsg) {
	var ipMask net.IP
	ip, ipNet, err := net.ParseCIDR(msg.IpAddr)
	if err != nil {
		return
	}
	ipMask = make(net.IP, 4)
	copy(ipMask, ipNet.Mask)
	ipAddrStr := ip.String()
	ipMaskStr := net.IP(ipMask).String()
	ribdServiceHandler.Logger.Info("Calling deletev4Route with ipaddr ", ipAddrStr, " mask ", ipMaskStr)
	cfg := ribd.IPv4Route{
		DestinationNw: ipAddrStr,
		Protocol:      "CONNECTED",
		Cost:          0,
		NetworkMask:   ipMaskStr,
	}
	nextHop := ribd.NextHopInfo{
		NextHopIp:     "0.0.0.0",
		NextHopIntRef: strconv.Itoa(int(msg.IfIndex)),
	}
	cfg.NextHop = make([]*ribd.NextHopInfo, 0)
	cfg.NextHop = append(cfg.NextHop, &nextHop)
	ribdServiceHandler.RouteConfCh <- RIBdServerConfig{
		OrigConfigObject: &cfg,
		Op:               "del",
	}

}
func (ribdServiceHandler *RIBDServer) ProcessIPv6IntfDeleteEvent(msg asicdCommonDefs.IPv6IntfNotifyMsg) {
	var ipMask net.IP
	ip, ipNet, err := net.ParseCIDR(msg.IpAddr)
	if err != nil {
		return
	}
	ipMask = make(net.IP, 16)
	copy(ipMask, ipNet.Mask)
	ipAddrStr := ip.String()
	ipMaskStr := net.IP(ipMask).String()
	ribdServiceHandler.Logger.Info("Calling deleteRoute with ipaddr ", ipAddrStr, " mask ", ipMaskStr)
	cfg := ribd.IPv6Route{
		DestinationNw: ipAddrStr,
		Protocol:      "CONNECTED",
		Cost:          0,
		NetworkMask:   ipMaskStr,
	}
	nextHop := ribd.NextHopInfo{
		NextHopIp:     "::",
		NextHopIntRef: strconv.Itoa(int(msg.IfIndex)),
	}
	cfg.NextHop = make([]*ribd.NextHopInfo, 0)
	cfg.NextHop = append(cfg.NextHop, &nextHop)
	ribdServiceHandler.RouteConfCh <- RIBdServerConfig{
		OrigConfigObject: &cfg,
		Op:               "delv6",
	}
}
func (ribdServiceHandler *RIBDServer) ProcessAsicdEvents(sub *nanomsg.SubSocket) {

	ribdServiceHandler.Logger.Info("in process Asicd events")
	for {
		rcvdMsg, err := sub.Recv(0)
		if err != nil {
			ribdServiceHandler.Logger.Info("Error in receiving ", err)
			return
		}
		ribdServiceHandler.Logger.Info("After recv rcvdMsg buf", string(rcvdMsg), " getting Notif Info")
		Notif := asicdCommonDefs.AsicdNotification{}
		err = json.Unmarshal(rcvdMsg, &Notif)
		if err != nil {
			ribdServiceHandler.Logger.Info("Error in Unmarshalling rcvdMsg Json")
			return
		}
		ribdServiceHandler.Logger.Debug("Switch msgtype ", Notif.MsgType)
		switch Notif.MsgType {
		case asicdCommonDefs.NOTIFY_LOGICAL_INTF_CREATE:
			ribdServiceHandler.Logger.Info("NOTIFY_LOGICAL_INTF_CREATE received")
			var logicalIntfNotifyMsg asicdCommonDefs.LogicalIntfNotifyMsg
			err = json.Unmarshal(Notif.Msg, &logicalIntfNotifyMsg)
			if err != nil {
				ribdServiceHandler.Logger.Info("Unable to unmashal logicalIntfNotifyMsg:", Notif.Msg)
				return
			}
			ribdServiceHandler.ProcessLogicalIntfCreateEvent(logicalIntfNotifyMsg)
			break
		case asicdCommonDefs.NOTIFY_VLAN_CREATE:
			ribdServiceHandler.Logger.Info("asicdCommonDefs.NOTIFY_VLAN_CREATE")
			var vlanNotifyMsg asicdCommonDefs.VlanNotifyMsg
			err = json.Unmarshal(Notif.Msg, &vlanNotifyMsg)
			if err != nil {
				ribdServiceHandler.Logger.Info("Unable to unmashal vlanNotifyMsg:", Notif.Msg)
				return
			}
			ribdServiceHandler.ProcessVlanCreateEvent(vlanNotifyMsg)
			break
		case asicdCommonDefs.NOTIFY_IPV4_L3INTF_STATE_CHANGE:
			ribdServiceHandler.Logger.Info("NOTIFY_IPV4_L3INTF_STATE_CHANGE event")
			var msg asicdCommonDefs.IPv4L3IntfStateNotifyMsg
			err = json.Unmarshal(Notif.Msg, &msg)
			if err != nil {
				ribdServiceHandler.Logger.Info("Error in reading msg ", err)
				return
			}
			ribdServiceHandler.Logger.Info("Msg linkstatus = ", msg.IfState, " msg  ifId ", msg.IfIndex)
			if msg.IfState == asicdCommonDefs.INTF_STATE_DOWN {
				//processLinkDownEvent(ribd.Int(msg.IfType), ribd.Int(msg.IfId))
				ribdServiceHandler.ProcessIPv4IntfDownEvent(msg.IpAddr, msg.IfIndex)
			} else {
				//processLinkUpEvent(ribd.Int(msg.IfType), ribd.Int(msg.IfId))
				ribdServiceHandler.ProcessIPv4IntfUpEvent(msg.IpAddr, msg.IfIndex)
			}
			break
		case asicdCommonDefs.NOTIFY_IPV6_L3INTF_STATE_CHANGE:
			ribdServiceHandler.Logger.Info("NOTIFY_IPV6_L3INTF_STATE_CHANGE event")
			var msg asicdCommonDefs.IPv6L3IntfStateNotifyMsg
			err = json.Unmarshal(Notif.Msg, &msg)
			if err != nil {
				ribdServiceHandler.Logger.Info("Error in reading msg ", err)
				return
			}
			ribdServiceHandler.Logger.Info("Msg linkstatus = ", msg.IfState, " msg  ifId ", msg.IfIndex)
			if msg.IfState == asicdCommonDefs.INTF_STATE_DOWN {
				//processLinkDownEvent(ribd.Int(msg.IfType), ribd.Int(msg.IfId))
				ribdServiceHandler.ProcessIPv6IntfDownEvent(msg.IpAddr, msg.IfIndex)
			} else {
				//processLinkUpEvent(ribd.Int(msg.IfType), ribd.Int(msg.IfId))
				ribdServiceHandler.ProcessIPv6IntfUpEvent(msg.IpAddr, msg.IfIndex)
			}
			break
		case asicdCommonDefs.NOTIFY_IPV4INTF_CREATE:
			ribdServiceHandler.Logger.Info("NOTIFY_IPV4INTF_CREATE event")
			var msg asicdCommonDefs.IPv4IntfNotifyMsg
			err = json.Unmarshal(Notif.Msg, &msg)
			if err != nil {
				ribdServiceHandler.Logger.Info("Error in reading msg ", err)
				return
			}
			ribdServiceHandler.Logger.Info("Received NOTIFY_IPV4INTF_CREATE ipAddr ", msg.IpAddr, " ifIndex = ", msg.IfIndex, " ifType ", asicdCommonDefs.GetIntfTypeFromIfIndex(msg.IfIndex), " ifId ", asicdCommonDefs.GetIntfIdFromIfIndex(msg.IfIndex))
			ribdServiceHandler.ProcessIPv4IntfCreateEvent(msg)
			break
		case asicdCommonDefs.NOTIFY_IPV6INTF_CREATE:
			ribdServiceHandler.Logger.Info("NOTIFY_IPV6INTF_CREATE event")
			var msg asicdCommonDefs.IPv6IntfNotifyMsg
			err = json.Unmarshal(Notif.Msg, &msg)
			if err != nil {
				ribdServiceHandler.Logger.Info("Error in reading msg ", err)
				return
			}
			ribdServiceHandler.Logger.Info("Received NOTIFY_IPV6INTF_CREATE ipAddr ", msg.IpAddr, " ifIndex = ", msg.IfIndex, " ifType ", asicdCommonDefs.GetIntfTypeFromIfIndex(msg.IfIndex), " ifId ", asicdCommonDefs.GetIntfIdFromIfIndex(msg.IfIndex))
			ribdServiceHandler.ProcessIPv6IntfCreateEvent(msg)
			break
		case asicdCommonDefs.NOTIFY_IPV4INTF_DELETE:
			ribdServiceHandler.Logger.Info("NOTIFY_IPV4INTF_DELETE  event")
			var msg asicdCommonDefs.IPv4IntfNotifyMsg
			err = json.Unmarshal(Notif.Msg, &msg)
			if err != nil {
				ribdServiceHandler.Logger.Info("Error in reading msg ", err)
				return
			}
			ribdServiceHandler.Logger.Info("Received ipv4 intf delete with ipAddr ", msg.IpAddr, " ifIndex = ", msg.IfIndex, " ifType ", asicdCommonDefs.GetIntfTypeFromIfIndex(msg.IfIndex), " ifId ", asicdCommonDefs.GetIntfIdFromIfIndex(msg.IfIndex))
			ribdServiceHandler.ProcessIPv4IntfDeleteEvent(msg)
			break
		case asicdCommonDefs.NOTIFY_IPV6INTF_DELETE:
			ribdServiceHandler.Logger.Info("NOTIFY_IPV6INTF_DELETE  event")
			var msg asicdCommonDefs.IPv6IntfNotifyMsg
			err = json.Unmarshal(Notif.Msg, &msg)
			if err != nil {
				ribdServiceHandler.Logger.Info("Error in reading msg ", err)
				return
			}
			ribdServiceHandler.Logger.Info("Received ipv6 intf delete with ipAddr ", msg.IpAddr, " ifIndex = ", msg.IfIndex, " ifType ", asicdCommonDefs.GetIntfTypeFromIfIndex(msg.IfIndex), " ifId ", asicdCommonDefs.GetIntfIdFromIfIndex(msg.IfIndex))
			ribdServiceHandler.ProcessIPv6IntfDeleteEvent(msg)
			break
		default:
			logger.Debug("Received unknown event ")
		}
	}
}
func (ribdServiceHandler *RIBDServer) ProcessEvents(sub *nanomsg.SubSocket, subType ribd.Int) {
	ribdServiceHandler.Logger.Info("in process events for sub ", subType)
	if subType == SUB_ASICD {
		ribdServiceHandler.Logger.Info("process Asicd events")
		ribdServiceHandler.ProcessAsicdEvents(sub)
	}
}
func (ribdServiceHandler *RIBDServer) SetupEventHandler(sub *nanomsg.SubSocket, address string, subtype ribd.Int) {
	ribdServiceHandler.Logger.Info("Setting up event handlers for sub type ", subtype)
	sub, err := nanomsg.NewSubSocket()
	if err != nil {
		ribdServiceHandler.Logger.Info("Failed to open sub socket")
		return
	}
	ribdServiceHandler.Logger.Info("opened socket")
	ep, err := sub.Connect(address)
	if err != nil {
		ribdServiceHandler.Logger.Info("Failed to connect to pub socket - ", ep)
		return
	}
	ribdServiceHandler.Logger.Info("Connected to ", ep.Address)
	err = sub.Subscribe("")
	if err != nil {
		ribdServiceHandler.Logger.Info("Failed to subscribe to all topics")
		return
	}
	ribdServiceHandler.Logger.Info("Subscribed")
	err = sub.SetRecvBuffer(1024 * 1204)
	if err != nil {
		ribdServiceHandler.Logger.Info("Failed to set recv buffer size")
		return
	}
	//processPortdEvents(sub)
	ribdServiceHandler.ProcessEvents(sub, subtype)
}
