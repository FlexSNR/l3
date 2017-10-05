//
//Copyright [2016] [SnapRoute Inc]
//
//Licensed under the Apache License, Version 2.0 (the "License");
//you may not use this file except in compliance with the License.
//You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
//       Unless required by applicable law or agreed to in writing, software
//       distributed under the License is distributed on an "AS IS" BASIS,
//       WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//       See the License for the specific language governing permissions and
//       limitations under the License.
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
	"asicd/asicdCommonDefs"
	"github.com/google/gopacket/pcap"
	"net"
	"utils/commonDefs"
)

type L3IntfProperty struct {
	Netmask net.IPMask
	IpAddr  string
	IfName  string
}

type PortProperty struct {
	IfName      string
	MacAddr     string
	IpAddr      string
	Netmask     net.IPMask
	L3IfIdx     int
	LagIfIdx    int
	CtrlCh      chan bool
	CtrlReplyCh chan bool
	PcapHdl     *pcap.Handle
	OperState   bool
}

type VlanProperty struct {
	IfName       string
	UntagPortMap map[int]bool
}

type LagProperty struct {
	IfName  string
	PortMap map[int]bool
}

func (server *ARPServer) getL3IntfOnSameSubnet(ip string) int {
	ipAddr := net.ParseIP(ip)
	for l3Idx, l3Ent := range server.l3IntfPropMap {
		if l3Ent.IpAddr == ip {
			return -1
		}

		l3IpAddr := net.ParseIP(l3Ent.IpAddr)
		l3Net := l3IpAddr.Mask(l3Ent.Netmask)
		ipNet := ipAddr.Mask(l3Ent.Netmask)
		if l3Net.Equal(ipNet) {
			return l3Idx
		}
	}
	return -1
}

func (server *ARPServer) processIPv4IntfCreate(msg commonDefs.IPv4IntfNotifyMsg) {
	ip, ipNet, _ := net.ParseCIDR(msg.IpAddr)
	ifType := asicdCommonDefs.GetIntfTypeFromIfIndex(msg.IfIndex)
	ifIdx := int(msg.IfIndex)

	server.logger.Debug("Received IPv4 Create Notification for IP:", ip, "IfIndex:", msg.IfIndex)

	l3IntfEnt, _ := server.l3IntfPropMap[ifIdx]
	l3IntfEnt.IpAddr = ip.String()
	l3IntfEnt.Netmask = ipNet.Mask
	server.l3IntfPropMap[ifIdx] = l3IntfEnt

	if ifType == commonDefs.IfTypeVlan {
		vlanEnt, _ := server.vlanPropMap[ifIdx]

		l3IntfEnt, _ := server.l3IntfPropMap[ifIdx]
		l3IntfEnt.IfName = vlanEnt.IfName
		server.l3IntfPropMap[ifIdx] = l3IntfEnt

		server.logger.Debug("Received IPv4 Create Notification for Untag Port List:", vlanEnt.UntagPortMap)
		for port, _ := range vlanEnt.UntagPortMap {
			portEnt := server.portPropMap[port]
			portEnt.IpAddr = ip.String()
			portEnt.Netmask = ipNet.Mask
			portEnt.L3IfIdx = ifIdx
			operState := portEnt.OperState
			if operState == true {
				server.logger.Debug("Start Rx on port:", port)
				portEnt.PcapHdl, _ = server.StartArpRxTx(portEnt.IfName, portEnt.MacAddr)
			}
			server.portPropMap[port] = portEnt
			if operState == true {
				go server.processRxPkts(port)
				server.logger.Debug("Send Arp Probe on port:", port)
				go server.SendArpProbe(port)
			}
		}
	} else if ifType == commonDefs.IfTypeLag {
		lagEnt, _ := server.lagPropMap[ifIdx]

		l3IntfEnt, _ := server.l3IntfPropMap[ifIdx]
		l3IntfEnt.IfName = lagEnt.IfName
		server.l3IntfPropMap[ifIdx] = l3IntfEnt

		server.logger.Debug("Received IPv4 Create Notification for LagId:", ifIdx, "Port List:", lagEnt.PortMap)
		for port, _ := range lagEnt.PortMap {
			portEnt := server.portPropMap[port]
			portEnt.IpAddr = ip.String()
			portEnt.Netmask = ipNet.Mask
			portEnt.L3IfIdx = ifIdx
			operState := portEnt.OperState
			if operState == true {
				server.logger.Debug("Start Rx on port:", port)
				portEnt.PcapHdl, _ = server.StartArpRxTx(portEnt.IfName, portEnt.MacAddr)
			}
			server.portPropMap[port] = portEnt
			if operState == true {
				go server.processRxPkts(port)
				server.logger.Debug("Send Arp Probe on port:", port)
				go server.SendArpProbe(port)
			}
		}
	} else if ifType == commonDefs.IfTypePort {
		port := ifIdx
		portEnt := server.portPropMap[port]

		l3IntfEnt, _ := server.l3IntfPropMap[ifIdx]
		l3IntfEnt.IfName = portEnt.IfName
		server.l3IntfPropMap[ifIdx] = l3IntfEnt

		portEnt.IpAddr = ip.String()
		portEnt.Netmask = ipNet.Mask
		portEnt.L3IfIdx = ifIdx
		operState := portEnt.OperState
		if operState == true {
			server.logger.Debug("Start Rx on port:", port)
			portEnt.PcapHdl, _ = server.StartArpRxTx(portEnt.IfName, portEnt.MacAddr)
		}
		server.portPropMap[port] = portEnt
		if operState == true {
			go server.processRxPkts(port)
			server.logger.Debug("Send Arp Probe on port:", port)
			go server.SendArpProbe(port)
		}
	}
}

func (server *ARPServer) processIPv4IntfDelete(msg commonDefs.IPv4IntfNotifyMsg) {
	ifType := asicdCommonDefs.GetIntfTypeFromIfIndex(msg.IfIndex)
	ifIdx := int(msg.IfIndex)

	if ifType == commonDefs.IfTypeVlan {
		vlanEnt, _ := server.vlanPropMap[ifIdx]
		for port, _ := range vlanEnt.UntagPortMap {
			portEnt := server.portPropMap[port]
			// Stop Rx Thread
			if portEnt.OperState == true {
				server.logger.Debug("Closing Rx on port:", port)
				portEnt.CtrlCh <- true
				<-portEnt.CtrlReplyCh
				server.logger.Debug("Rx is closed successfully on port:", port)
				portEnt.PcapHdl.Close()
				portEnt.PcapHdl = nil
			}
			//Delete ARP Entry
			server.logger.Debug("Flushing Arp Entry learned on port:", port)
			server.arpEntryDeleteCh <- DeleteArpEntryMsg{
				PortNum: port,
			}
			portEnt.IpAddr = ""
			portEnt.Netmask = nil
			portEnt.L3IfIdx = -1
			server.portPropMap[port] = portEnt
		}
	} else if ifType == commonDefs.IfTypeLag {
		lagEnt, _ := server.lagPropMap[ifIdx]
		for port, _ := range lagEnt.PortMap {
			portEnt := server.portPropMap[port]
			if portEnt.OperState == true {
				// Stop Rx Thread
				server.logger.Debug("Closing Rx on port:", port)
				portEnt.CtrlCh <- true
				<-portEnt.CtrlReplyCh
				server.logger.Debug("Rx is closed successfully on port:", port)
				portEnt.PcapHdl.Close()
				portEnt.PcapHdl = nil
			}
			//Delete ARP Entry
			server.logger.Debug("Flushing Arp Entry learned on port:", port)
			server.arpEntryDeleteCh <- DeleteArpEntryMsg{
				PortNum: port,
			}
			portEnt.IpAddr = ""
			portEnt.Netmask = nil
			portEnt.L3IfIdx = -1
			server.portPropMap[port] = portEnt
		}
	} else if ifType == commonDefs.IfTypePort {
		port := ifIdx
		portEnt := server.portPropMap[port]
		if portEnt.OperState == true {
			// Stop Rx Thread
			server.logger.Debug("Closing Rx on port:", port)
			portEnt.CtrlCh <- true
			<-portEnt.CtrlReplyCh
			server.logger.Debug("Rx is closed successfully on port:", port)
			portEnt.PcapHdl.Close()
			portEnt.PcapHdl = nil
		}
		//Delete ARP Entry
		server.logger.Debug("Flushing Arp Entry learned on port:", port)
		server.arpEntryDeleteCh <- DeleteArpEntryMsg{
			PortNum: port,
		}
		portEnt.IpAddr = ""
		portEnt.Netmask = nil
		portEnt.L3IfIdx = -1
		server.portPropMap[port] = portEnt
	}
	delete(server.l3IntfPropMap, ifIdx)
}

func (server *ARPServer) updateIpv4Infra(msg commonDefs.IPv4IntfNotifyMsg) {
	if msg.MsgType == commonDefs.NOTIFY_IPV4INTF_CREATE {
		server.processIPv4IntfCreate(msg)
	} else {
		server.processIPv4IntfDelete(msg)
	}
}

func (server *ARPServer) processIPv4L3StateChange(msg commonDefs.IPv4L3IntfStateNotifyMsg) {
	ifIdx := int(msg.IfIndex)
	ifType := asicdCommonDefs.GetIntfTypeFromIfIndex(msg.IfIndex)
	if msg.IfState == 0 {
		if ifType == commonDefs.IfTypeVlan {
			vlanEnt := server.vlanPropMap[ifIdx]
			for port, _ := range vlanEnt.UntagPortMap {
				//Delete ARP Entry
				server.logger.Debug("Flushing Arp Entry learned on port:", port)
				server.arpEntryDeleteCh <- DeleteArpEntryMsg{
					PortNum: port,
				}
			}
		} else if ifType == commonDefs.IfTypeLag {
			lagEnt := server.lagPropMap[ifIdx]
			for port, _ := range lagEnt.PortMap {
				//Delete ARP Entry
				server.logger.Debug("Flushing Arp Entry learned on port:", port)
				server.arpEntryDeleteCh <- DeleteArpEntryMsg{
					PortNum: port,
				}
			}
		} else if ifType == commonDefs.IfTypePort {
			port := ifIdx
			//Delete ARP Entry
			server.logger.Debug("Flushing Arp Entry learned on port:", port)
			server.arpEntryDeleteCh <- DeleteArpEntryMsg{
				PortNum: port,
			}
		}
	}
}

func (server *ARPServer) processIPv4NbrMacMove(msg commonDefs.IPv4NbrMacMoveNotifyMsg) {
	server.arpEntryMacMoveCh <- msg
}

func (server *ARPServer) processL2StateChange(msg commonDefs.L2IntfStateNotifyMsg) {
	ifIdx := int(msg.IfIndex)
	ifType := asicdCommonDefs.GetIntfTypeFromIfIndex(msg.IfIndex)
	if msg.IfState == 0 {
		if ifType == commonDefs.IfTypeVlan {
			server.logger.Debug("Vlan Msg: ", ifIdx, msg.IfState)
			vlanEnt := server.vlanPropMap[ifIdx]
			for port, _ := range vlanEnt.UntagPortMap {
				portEnt := server.portPropMap[port]
				if portEnt.L3IfIdx != -1 && portEnt.OperState == true {
					server.logger.Debug("Closing Rx on port:", port)
					portEnt.CtrlCh <- true
					<-portEnt.CtrlReplyCh
					server.logger.Debug("Rx is closed successfully on port:", port)
					portEnt.PcapHdl.Close()
					portEnt.PcapHdl = nil
				}
				portEnt.OperState = false
				server.portPropMap[port] = portEnt
			}
		} else if ifType == commonDefs.IfTypeLag {
			server.logger.Debug("Lag Msg:", ifIdx, msg.IfState)
			lagEnt := server.lagPropMap[ifIdx]
			for port, _ := range lagEnt.PortMap {
				portEnt := server.portPropMap[port]
				if portEnt.L3IfIdx != -1 && portEnt.OperState == true {
					server.logger.Debug("Closing Rx on port:", port)
					portEnt.CtrlCh <- true
					<-portEnt.CtrlReplyCh
					server.logger.Debug("Rx is closed successfully on port:", port)
					portEnt.PcapHdl.Close()
					portEnt.PcapHdl = nil
				}
				portEnt.OperState = false
				server.portPropMap[port] = portEnt
			}
		} else if ifType == commonDefs.IfTypePort {
			server.logger.Debug("Port Msg: ", ifIdx, msg.IfState)
			port := ifIdx
			portEnt := server.portPropMap[port]
			if portEnt.L3IfIdx != -1 && portEnt.OperState == true {
				server.logger.Debug("Closing Rx on port:", port)
				portEnt.CtrlCh <- true
				<-portEnt.CtrlReplyCh
				server.logger.Debug("Rx is closed successfully on port:", port)
				portEnt.PcapHdl.Close()
				portEnt.PcapHdl = nil
			}
			portEnt.OperState = false
			server.portPropMap[port] = portEnt
		}
	} else if msg.IfState == 1 {
		if ifType == commonDefs.IfTypeVlan {
			server.logger.Debug("Vlan Msg: ", ifIdx, msg.IfState)
			vlanEnt := server.vlanPropMap[ifIdx]
			for port, _ := range vlanEnt.UntagPortMap {
				portEnt := server.portPropMap[port]
				if portEnt.L3IfIdx != -1 && portEnt.OperState == false {
					server.logger.Debug("Start Rx on port:", port)
					portEnt.PcapHdl, _ = server.StartArpRxTx(portEnt.IfName, portEnt.MacAddr)
					server.logger.Debug("Rx is started successfully on port:", port)
				}
				portEnt.OperState = true
				server.portPropMap[port] = portEnt
				if portEnt.L3IfIdx != -1 {
					go server.processRxPkts(port)
					server.logger.Debug("Send Arp Probe on port:", port)
					go server.SendArpProbe(port)
				}
			}
		} else if ifType == commonDefs.IfTypeLag {
			server.logger.Debug("Lag Msg: ", ifIdx, msg.IfState)
			lagEnt := server.lagPropMap[ifIdx]
			for port, _ := range lagEnt.PortMap {
				portEnt := server.portPropMap[port]
				if portEnt.L3IfIdx != -1 && portEnt.OperState == false {
					server.logger.Debug("Start Rx on port:", port)
					portEnt.PcapHdl, _ = server.StartArpRxTx(portEnt.IfName, portEnt.MacAddr)
					server.logger.Debug("Rx is started successfully on port:", port)
				}
				portEnt.OperState = true
				server.portPropMap[port] = portEnt
				if portEnt.L3IfIdx != -1 {
					go server.processRxPkts(port)
					server.logger.Debug("Send Arp Probe on port:", port)
					go server.SendArpProbe(port)
				}
			}
		} else if ifType == commonDefs.IfTypePort {
			server.logger.Debug("Port Msg: ", ifIdx, msg.IfState)
			port := ifIdx
			portEnt := server.portPropMap[port]
			if portEnt.L3IfIdx != -1 && portEnt.OperState == false {
				server.logger.Debug("Start Rx on port:", port)
				portEnt.PcapHdl, _ = server.StartArpRxTx(portEnt.IfName, portEnt.MacAddr)
				server.logger.Debug("Rx is started successfully on port:", port)
			}
			portEnt.OperState = true
			server.portPropMap[port] = portEnt
			if portEnt.L3IfIdx != -1 {
				go server.processRxPkts(port)
				server.logger.Debug("Send Arp Probe on port:", port)
				go server.SendArpProbe(port)
			}
		}
	}
}

func (server *ARPServer) processArpInfra() {
	for ifIdx, _ := range server.l3IntfPropMap {
		ifType := asicdCommonDefs.GetIntfTypeFromIfIndex(int32(ifIdx))
		if ifType == commonDefs.IfTypeVlan {
			vlanEnt := server.vlanPropMap[ifIdx]
			for port, _ := range vlanEnt.UntagPortMap {
				portEnt := server.portPropMap[port]
				if portEnt.OperState == true {
					server.logger.Debug("Start Rx on port:", port)
					portEnt.PcapHdl, _ = server.StartArpRxTx(portEnt.IfName, portEnt.MacAddr)
					server.portPropMap[port] = portEnt
				}
				if portEnt.OperState == true {
					go server.processRxPkts(port)
					server.logger.Debug("Send Arp Probe on port:", port)
					go server.SendArpProbe(port)
				}
			}
		} else if ifType == commonDefs.IfTypeLag {
			lagEnt := server.lagPropMap[ifIdx]
			for port, _ := range lagEnt.PortMap {
				portEnt := server.portPropMap[port]
				if portEnt.OperState == true {
					server.logger.Debug("Start Rx on port:", port)
					portEnt.PcapHdl, _ = server.StartArpRxTx(portEnt.IfName, portEnt.MacAddr)
					server.portPropMap[port] = portEnt
					go server.processRxPkts(port)
					server.logger.Debug("Send Arp Probe on port:", port)
					go server.SendArpProbe(port)
				}
			}
		} else if ifType == commonDefs.IfTypePort {
			port := ifIdx
			portEnt := server.portPropMap[port]
			if portEnt.OperState == true {
				server.logger.Debug("Start Rx on port:", port)
				portEnt.PcapHdl, _ = server.StartArpRxTx(portEnt.IfName, portEnt.MacAddr)
				server.portPropMap[port] = portEnt
				go server.processRxPkts(port)
				server.logger.Debug("Send Arp Probe on port:", port)
				go server.SendArpProbe(port)
			}
		}
	}
}

func (server *ARPServer) buildArpInfra() {
	server.constructPortInfra()
	server.constructVlanInfra()
	server.constructL3Infra()
	//server.constructLagInfra()
}

func (server *ARPServer) constructL3Infra() {
	curMark := 0
	server.logger.Debug("Calling Asicd for getting L3 Interfaces")
	count := 100
	var ifName string
	for {
		bulkInfo, _ := server.AsicdPlugin.GetBulkIPv4IntfState(curMark, count)
		if bulkInfo == nil {
			break
		}
		objCnt := int(bulkInfo.Count)
		more := bool(bulkInfo.More)
		curMark = int(bulkInfo.EndIdx)
		for i := 0; i < objCnt; i++ {
			ip, ipNet, _ := net.ParseCIDR(bulkInfo.IPv4IntfStateList[i].IpAddr)
			ifIdx := int(bulkInfo.IPv4IntfStateList[i].IfIndex)
			ifType := asicdCommonDefs.GetIntfTypeFromIfIndex(int32(ifIdx))
			if ifType == commonDefs.IfTypeVlan {
				vlanEnt := server.vlanPropMap[ifIdx]
				ifName = vlanEnt.IfName
				for port, _ := range vlanEnt.UntagPortMap {
					portEnt := server.portPropMap[port]
					portEnt.L3IfIdx = ifIdx
					portEnt.IpAddr = ip.String()
					portEnt.Netmask = ipNet.Mask
					server.portPropMap[port] = portEnt
				}
			} else if ifType == commonDefs.IfTypeLag {
				lagEnt := server.lagPropMap[ifIdx]
				ifName = lagEnt.IfName
				for port, _ := range lagEnt.PortMap {
					portEnt := server.portPropMap[port]
					portEnt.L3IfIdx = ifIdx
					portEnt.IpAddr = ip.String()
					portEnt.Netmask = ipNet.Mask
					server.portPropMap[port] = portEnt
				}
			} else if ifType == commonDefs.IfTypePort {
				port := ifIdx
				portEnt := server.portPropMap[port]
				ifName = portEnt.IfName
				portEnt.L3IfIdx = ifIdx
				portEnt.IpAddr = ip.String()
				portEnt.Netmask = ipNet.Mask
				server.portPropMap[port] = portEnt
			}

			ent := server.l3IntfPropMap[ifIdx]
			ent.Netmask = ipNet.Mask
			ent.IpAddr = ip.String()
			ent.IfName = ifName
			server.l3IntfPropMap[ifIdx] = ent
		}
		if more == false {
			break
		}
	}
}

func (server *ARPServer) constructPortInfra() {
	server.getBulkPortState()
	server.getBulkPortConfig()
}

func (server *ARPServer) getBulkPortConfig() {
	curMark := int(asicdCommonDefs.MIN_SYS_PORTS)
	server.logger.Debug("Calling Asicd for getting Port Property")
	count := 100
	for {
		bulkInfo, _ := server.AsicdPlugin.GetBulkPort(curMark, count)
		if bulkInfo == nil {
			break
		}
		objCnt := int(bulkInfo.Count)
		more := bool(bulkInfo.More)
		curMark = int(bulkInfo.EndIdx)
		for i := 0; i < objCnt; i++ {
			ifIndex := int(bulkInfo.PortList[i].IfIndex)
			ent := server.portPropMap[ifIndex]
			ent.MacAddr = bulkInfo.PortList[i].MacAddr
			ent.CtrlCh = make(chan bool)
			ent.CtrlReplyCh = make(chan bool)
			server.portPropMap[ifIndex] = ent
		}
		if more == false {
			break
		}
	}
}

func (server *ARPServer) getBulkPortState() {
	curMark := int(asicdCommonDefs.MIN_SYS_PORTS)
	server.logger.Debug("Calling Asicd for getting Port Property")
	count := 100
	for {
		bulkInfo, _ := server.AsicdPlugin.GetBulkPortState(curMark, count)
		if bulkInfo == nil {
			break
		}
		objCnt := int(bulkInfo.Count)
		more := bool(bulkInfo.More)
		curMark = int(bulkInfo.EndIdx)
		for i := 0; i < objCnt; i++ {
			ifIndex := int(bulkInfo.PortStateList[i].IfIndex)
			ent := server.portPropMap[ifIndex]
			ent.IfName = bulkInfo.PortStateList[i].Name
			ent.L3IfIdx = -1
			ent.LagIfIdx = -1
			ent.PcapHdl = nil
			switch bulkInfo.PortStateList[i].OperState {
			case "UP":
				ent.OperState = true
			case "DOWN":
				ent.OperState = false
			default:
				server.logger.Err("Invalid OperState for the port", bulkInfo.PortStateList[i].OperState, ent.IfName)
			}
			server.portPropMap[ifIndex] = ent
		}
		if more == false {
			break
		}
	}
}

func (server *ARPServer) constructVlanInfra() {
	curMark := 0
	server.logger.Debug("Calling Asicd for getting Vlan Property")
	count := 100
	for {
		bulkVlanInfo, _ := server.AsicdPlugin.GetBulkVlan(curMark, count)
		if bulkVlanInfo == nil {
			break
		}
		/* Get bulk on vlan state can re-use curMark and count used by get bulk vlan, as there is a 1:1 mapping in terms of cfg/state objs */
		bulkVlanStateInfo, _ := server.AsicdPlugin.GetBulkVlanState(curMark, count)
		if bulkVlanStateInfo == nil {
			break
		}
		objCnt := int(bulkVlanInfo.Count)
		more := bool(bulkVlanInfo.More)
		curMark = int(bulkVlanInfo.EndIdx)
		for i := 0; i < objCnt; i++ {
			ifIndex := int(bulkVlanStateInfo.VlanStateList[i].IfIndex)
			ent := server.vlanPropMap[ifIndex]
			ent.IfName = bulkVlanStateInfo.VlanStateList[i].VlanName
			untaggedIfIndexList := bulkVlanInfo.VlanList[i].UntagIfIndexList
			ent.UntagPortMap = make(map[int]bool)
			for i := 0; i < len(untaggedIfIndexList); i++ {
				ent.UntagPortMap[int(untaggedIfIndexList[i])] = true
			}
			server.vlanPropMap[ifIndex] = ent
		}
		if more == false {
			break
		}
	}
}

func (server *ARPServer) updateVlanInfra(msg commonDefs.VlanNotifyMsg) {
	vlanId := int(msg.VlanId)
	ifIdx := int(asicdCommonDefs.GetIfIndexFromIntfIdAndIntfType(vlanId, commonDefs.IfTypeVlan))
	portList := msg.UntagPorts
	vlanEnt, _ := server.vlanPropMap[ifIdx]
	if msg.MsgType == commonDefs.NOTIFY_VLAN_CREATE { // VLAN CREATE
		server.logger.Debug("Received Vlan Create or Update Notification Vlan:", vlanId, "PortList:", portList)
		vlanEnt.IfName = msg.VlanName
		vlanEnt.UntagPortMap = nil
		vlanEnt.UntagPortMap = make(map[int]bool)
		for i := 0; i < len(portList); i++ {
			port := int(portList[i])
			vlanEnt.UntagPortMap[port] = true
		}
		server.vlanPropMap[ifIdx] = vlanEnt
	} else if msg.MsgType == commonDefs.NOTIFY_VLAN_UPDATE { //VLAN UPDATE
		newPortMap := make(map[int]bool)
		for i := 0; i < len(portList); i++ {
			port := int(portList[i])
			newPortMap[port] = true
		}
		for oldPort, _ := range vlanEnt.UntagPortMap {
			_, exist := newPortMap[oldPort]
			if !exist { // There in Old but Not in New so flush arp cache
				/*
				   server.arpEntryDeleteCh <- DeleteArpEntryMsg {
				           PortNum: oldPort,
				   }
				*/
			} else { //Intersecting Ports (already there in UntagPortMap)
				delete(newPortMap, oldPort)
			}
		}
		for newPort, _ := range newPortMap { // All new ports need to be added
			vlanEnt.UntagPortMap[newPort] = true
		}
		server.vlanPropMap[ifIdx] = vlanEnt
	} else { // VLAN DELETE
		server.logger.Debug("Received Vlan Delete Notification Vlan:", vlanId, "PortList:", portList)
		/*
		   // Note : To be Discussed
		   for portNum, _ := range vlanEnt.UntagPortMap {
		           server.arpEntryDeleteCh <- DeleteArpEntryMsg {
		                   PortNum: portNum,
		           }
		   }
		*/
		vlanEnt.UntagPortMap = nil
		delete(server.vlanPropMap, ifIdx)
	}
}

func (server *ARPServer) updateLagInfra(msg commonDefs.LagNotifyMsg) {
	ifIdx := int(msg.IfIndex)
	portList := msg.IfIndexList
	lagEnt, _ := server.lagPropMap[ifIdx]
	if msg.MsgType == commonDefs.NOTIFY_LAG_CREATE {
		server.logger.Debug("Received Lag Create Notification IfIdx:", ifIdx, "PortList:", portList)
		lagEnt.IfName = msg.LagName
		lagEnt.PortMap = nil
		lagEnt.PortMap = make(map[int]bool)
		for i := 0; i < len(portList); i++ {
			port := int(portList[i])
			portEnt, _ := server.portPropMap[port]
			portEnt.LagIfIdx = ifIdx
			server.portPropMap[port] = portEnt
			lagEnt.PortMap[port] = true
		}
		server.lagPropMap[ifIdx] = lagEnt
	} else if msg.MsgType == commonDefs.NOTIFY_LAG_UPDATE {
		newPortMap := make(map[int]bool)
		for i := 0; i < len(portList); i++ {
			port := int(portList[i])
			newPortMap[port] = true
		}
		for oldPort, _ := range lagEnt.PortMap {
			_, exist := newPortMap[oldPort]
			if !exist { // There in Old but Not in New so flush arp cache
				/*
				   server.arpEntryDeleteCh <- DeleteArpEntryMsg {
				           PortNum: oldPort,
				   }
				*/
				portEnt, _ := server.portPropMap[oldPort]
				portEnt.LagIfIdx = -1
				server.portPropMap[oldPort] = portEnt
			} else { //Intersecting Ports (already there in PortMap)
				delete(newPortMap, oldPort)
			}
		}
		for newPort, _ := range newPortMap { // All new ports need to be added
			portEnt, _ := server.portPropMap[newPort]
			portEnt.LagIfIdx = ifIdx
			server.portPropMap[newPort] = portEnt
			lagEnt.PortMap[newPort] = true
		}
		server.lagPropMap[ifIdx] = lagEnt
	} else {
		server.logger.Debug("Received Lag Delete Notification IfIdx:", ifIdx, "PortList:", portList)
		for i := 0; i < len(portList); i++ {
			port := int(portList[i])
			portEnt, _ := server.portPropMap[port]
			portEnt.LagIfIdx = -1
			server.portPropMap[port] = portEnt
		}
		/*
		   // Do we need to flush
		   for portNum, _ := range lagEnt.PortMap {
		           server.arpEntryDeleteCh <- DeleteArpEntryMsg {
		                   PortNum: portNum,
		           }
		   }
		*/
		lagEnt.PortMap = nil
		delete(server.lagPropMap, ifIdx)
	}
}

/*
func (server *ARPServer)constructLagInfra() {
        curMark := 0
        server.logger.Info("Calling Asicd for getting Lag Property")
        count := 100
        for {
                bulkInfo, _ := server.asicdClient.ClientHdl.GetBulkLag(asicdServices.Int(curMark), asicdServices.Int(count))
                if bulkInfo == nil {
                        break
                }
                objCnt := int(bulkInfo.Count)
                more := bool(bulkInfo.More)
                curMark = asicdServices.Int(bulkInfo.EndIdx)
                for i := 0; i < objCnt; i++ {
                        ifIdx := int(bulkInfo.LagList[i].IfIndex)
                        ent := server.lagPropMap[ifIdx]
                        ifIndexList := ParseUsrPortStrToPortList(bulkInfo.LagList[i].IfIndexList)

                        for i := 0; i < len(ifIndexList); i++ {
                                port := ifIndexList[i]
                                portEnt := server.portPropMap[port]
                                portEnt.LagIfIndex = ifIdx
                                server.portPropMap[port] = portEnt
                                ent.PortMap[port] = true
                        }
                        server.lagPropMap[ifIdx] = ent
                }
                if more == false {
                        break
                }
        }
}
*/
