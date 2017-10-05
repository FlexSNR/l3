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
	"asicd/asicdCommonDefs"
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"net"
	"utils/commonDefs"
)

/*
func (server *ARPServer) StartArpRx(port int) {
        portEnt, _ := server.portPropMap[port]
        //var filter string = "not ether proto 0x8809"
        filter := fmt.Sprintln("not ether src", portEnt.MacAddr, "and not ether proto 0x8809")
        server.logger.Info(fmt.Sprintln("Port: ", port, "filter:", filter))
        pcapHdl, err := pcap.OpenLive(portEnt.IfName, server.snapshotLen, server.promiscuous, server.pcapTimeout)
        if pcapHdl == nil {
                server.logger.Info(fmt.Sprintln("Unable to open pcap handler on:", portEnt.IfName, "error:", err))
                return
        } else {
                err := pcapHdl.SetBPFFilter(filter)
                if err != nil {
                        server.logger.Err(fmt.Sprintln("Unable to set filter on port:", port))
                }
        }

        portEnt.PcapHdl = pcapHdl
        server.portPropMap[port] = portEnt
        server.processRxPkts(port)
}
*/

func (server *ARPServer) StartArpRxTx(ifName string, macAddr string) (*pcap.Handle, error) {
	filter := fmt.Sprintf(`not ether src %s`, macAddr)
	filter = filter + " and not ether proto 0x8809"
	server.logger.Debug(fmt.Sprintln("Port: ", ifName, "Pcap filter:", filter))
	pcapHdl, err := pcap.OpenLive(ifName, server.snapshotLen, server.promiscuous, server.pcapTimeout)
	if pcapHdl == nil {
		return nil, errors.New(fmt.Sprintln("Unable to open pcap handler on", ifName, "error:", err))
	} else {
		err := pcapHdl.SetBPFFilter(filter)
		if err != nil {
			return nil, errors.New(fmt.Sprintln("Unable to set bpf filter to pcap handler on", ifName, "error:", err))
		}
	}

	return pcapHdl, nil
}

func (server *ARPServer) processRxPkts(port int) {
	portEnt, _ := server.portPropMap[port]
	src := gopacket.NewPacketSource(portEnt.PcapHdl, layers.LayerTypeEthernet)
	in := src.Packets()
	for {
		select {
		case packet, ok := <-in:
			if ok {
				arpLayer := packet.Layer(layers.LayerTypeARP)
				if arpLayer != nil {
					server.processArpPkt(arpLayer, port)
				} else {
					server.processIpPkt(packet, port)
				}
			}
		case <-portEnt.CtrlCh:
			server.logger.Info("Recevd shutdown for:", port)
			portEnt.CtrlReplyCh <- true
			return
		}
	}
	return
}

func (server *ARPServer) processArpPkt(arpLayer gopacket.Layer, port int) {
	arp := arpLayer.(*layers.ARP)
	if arp == nil {
		server.logger.Err("Arp layer returns nil")
		return
	}
	portEnt, _ := server.portPropMap[port]
	if portEnt.MacAddr == (net.HardwareAddr(arp.SourceHwAddress)).String() {
		server.logger.Err("Received ARP Packet with our own MAC Address, hence not processing it")
		return
	}

	if arp.Operation == layers.ARPReply {
		server.processArpReply(arp, port)
	} else if arp.Operation == layers.ARPRequest {
		server.processArpRequest(arp, port)
	}
}

func (server *ARPServer) processArpRequest(arp *layers.ARP, port int) {
	srcMac := (net.HardwareAddr(arp.SourceHwAddress)).String()
	//dstMac := (net.HardwareAddr(arp.DstHwAddress)).String()
	srcIp := (net.IP(arp.SourceProtAddress)).String()
	destIp := (net.IP(arp.DstProtAddress)).String()

	/* Check for Local Subnet for SrcIP */
	/* Check for Local Subnet for DestIP */
	if srcIp != "0.0.0.0" {
		portEnt, _ := server.portPropMap[port]
		myIP := net.ParseIP(portEnt.IpAddr)
		mask := portEnt.Netmask
		myNet := myIP.Mask(mask)
		srcIpAddr := net.ParseIP(srcIp)
		srcNet := srcIpAddr.Mask(mask)
		destIpAddr := net.ParseIP(destIp)
		destNet := destIpAddr.Mask(mask)
		if myNet.Equal(srcNet) != true ||
			myNet.Equal(destNet) != true {
			//server.logger.Info(fmt.Sprintln("Received Arp Request but srcIp:", srcIp, " and destIp:", destIp, "are not in same network. Hence, not processing it"))
			//server.logger.Info(fmt.Sprintln("Ip and Netmask on the recvd interface is", myIP, mask))
			//server.logger.Info(fmt.Sprintln("SrcIP:", srcIp, "DstIP:", destIp, "SrcMac:", srcMac, "DstMac:", dstMac, "intfIP:", myIP, "intfPort:", port, "intfMask:", mask, "srcNet:", srcNet, "dstNet:", destNet, "myNet:", myNet))
			return
		}
	} else {
		portEnt, _ := server.portPropMap[port]
		myIP := net.ParseIP(portEnt.IpAddr)
		mask := portEnt.Netmask
		myNet := myIP.Mask(mask)
		destIpAddr := net.ParseIP(destIp)
		destNet := destIpAddr.Mask(mask)
		if myNet.Equal(destNet) != true {
			//server.logger.Info(fmt.Sprintln("Received Arp Probe but destIp:", destIp, "is not in same network. Hence, not processing it"))
			//server.logger.Info(fmt.Sprintln("Ip and Netmask on the recvd interface is", myIP, mask))
			return
		}
	}

	//server.logger.Info(fmt.Sprintln("Received Arp Request SrcIP:", srcIp, "SrcMAC: ", srcMac, "DstIP:", destIp))

	srcExist := false
	destExist := false
	portEnt, _ := server.portPropMap[port]
	if portEnt.L3IfIdx != -1 {
		l3Ent, exist := server.l3IntfPropMap[portEnt.L3IfIdx]
		if exist {
			if srcIp == l3Ent.IpAddr {
				srcExist = true
			}
			if destIp == l3Ent.IpAddr {
				destExist = true
			}
		} else {
			server.logger.Err(fmt.Sprintln("Port:", port, "belong to L3 Interface which doesnot exist"))
			return
		}
	} else {
		server.logger.Err(fmt.Sprintln("Port:", port, "doesnot belong to L3 Interface"))
		return
	}
	if srcExist == true &&
		destExist == true {
		server.logger.Err(fmt.Sprintln("Received our own gratituous ARP with our own SrcIP:", srcIp, "and destIp:", destIp))
		return
	} else if srcExist != true &&
		destExist != true {
		if srcIp == destIp &&
			srcIp != "0.0.0.0" {
			server.logger.Debug(fmt.Sprintln("Received Gratuitous Arp with IP:", srcIp))
			//server.logger.Info(fmt.Sprintln("1 Installing Arp entry IP:", srcIp, "MAC:", srcMac))
			server.arpEntryUpdateCh <- UpdateArpEntryMsg{
				PortNum: port,
				IpAddr:  srcIp,
				MacAddr: srcMac,
				Type:    false,
			}
		} else {
			if srcIp == "0.0.0.0" {
				server.logger.Debug(fmt.Sprintln("Received Arp Probe for IP:", destIp))
				//server.logger.Info(fmt.Sprintln("2 Installing Arp entry IP:", destIp, "MAC: incomplete"))
				server.arpEntryUpdateCh <- UpdateArpEntryMsg{
					PortNum: port,
					IpAddr:  destIp,
					MacAddr: "incomplete",
					Type:    false,
				}
			} else {
				// Arp Request Pkt from neighbor1 for neighbor2 IP
				//server.logger.Info(fmt.Sprintln("Received Arp Request from Neighbor1( IP:", srcIp, "MAC:", srcMac, ") for Neighbor2 (IP:", destIp, "Mac: incomplete)"))

				//server.logger.Info(fmt.Sprintln("3 Installing Arp entry IP:", srcIp, "MAC:", srcMac))
				server.arpEntryUpdateCh <- UpdateArpEntryMsg{
					PortNum: port,
					IpAddr:  srcIp,
					MacAddr: srcMac,
					Type:    false,
				}

				//server.logger.Info(fmt.Sprintln("4 Installing Arp entry IP:", destIp, "MAC: incomplete"))
				server.arpEntryUpdateCh <- UpdateArpEntryMsg{
					PortNum: port,
					IpAddr:  destIp,
					MacAddr: "incomplete",
					Type:    false,
				}
			}
		}
	} else if srcExist == true {
		//server.logger.Info(fmt.Sprintln("Received our own ARP Request with SrcIP:", srcIp, "DestIP:", destIp))
	} else if destExist == true {
		server.logger.Debug(fmt.Sprintln("Received ARP Request for our IP with SrcIP:", srcIp, "DestIP:", destIp, "linux should respond to this request"))
		if srcIp != "0.0.0.0" {
			//server.logger.Info(fmt.Sprintln("5 Installing Arp entry IP:", srcIp, "MAC:", srcMac))
			server.arpEntryUpdateCh <- UpdateArpEntryMsg{
				PortNum: port,
				IpAddr:  srcIp,
				MacAddr: srcMac,
				Type:    false,
			}
		} else {
			server.logger.Debug(fmt.Sprintln("Received Arp Probe for IP:", destIp, "linux should respond to this"))
		}
	}
}

func (server *ARPServer) processArpReply(arp *layers.ARP, port int) {
	srcMac := (net.HardwareAddr(arp.SourceHwAddress)).String()
	srcIp := (net.IP(arp.SourceProtAddress)).String()
	//destMac := (net.HardwareAddr(arp.DstHwAddress)).String()
	destIp := (net.IP(arp.DstProtAddress)).String()

	//server.logger.Info(fmt.Sprintln("Received Arp Response SrcIP:", srcIp, "SrcMAC: ", srcMac, "DstIP:", destIp, "DestMac:", destMac))

	if destIp == "0.0.0.0" {
		server.logger.Err(fmt.Sprintln("Recevied Arp reply for ARP Probe and there is a conflicting IP Address:", srcIp))
		return
	}

	/* Check for Local Subnet for SrcIP */
	/* Check for Local Subnet for DestIP */
	portEnt, _ := server.portPropMap[port]
	myIP := net.ParseIP(portEnt.IpAddr)
	mask := portEnt.Netmask
	myNet := myIP.Mask(mask)
	srcIpAddr := net.ParseIP(srcIp)
	srcNet := srcIpAddr.Mask(mask)
	destIpAddr := net.ParseIP(destIp)
	destNet := destIpAddr.Mask(mask)
	if myNet.Equal(srcNet) != true ||
		myNet.Equal(destNet) != true {
		server.logger.Err(fmt.Sprintln("Received Arp Reply but srcIp:", srcIp, " and destIp:", destIp, "are not in same network. Hence, not processing it"))
		//server.logger.Info(fmt.Sprintln("Netmask on the recvd interface is", mask))
		return
	}
	//server.logger.Info(fmt.Sprintln("6 Installing Arp entry IP:", srcIp, "MAC:", srcMac))
	server.arpEntryUpdateCh <- UpdateArpEntryMsg{
		PortNum: port,
		IpAddr:  srcIp,
		MacAddr: srcMac,
		Type:    false,
	}
}

func (server *ARPServer) processIpPkt(packet gopacket.Packet, port int) {
	if nw := packet.NetworkLayer(); nw != nil {
		sIpAddr, dIpAddr := nw.NetworkFlow().Endpoints()
		dstIp := dIpAddr.String()
		srcIp := sIpAddr.String()

		ethLayer := packet.Layer(layers.LayerTypeEthernet)
		if ethLayer == nil {
			server.logger.Err("Not an Ethernet frame")
			return
		}
		eth := ethLayer.(*layers.Ethernet)
		srcMac := (eth.SrcMAC).String()
		//dstMac := (eth.DstMAC).String()
		// server.logger.Info(fmt.Sprintln("========Hello======= SrcIP:", srcIp, "DstIP:", dstIp, "SrcMac:", srcMac, "DstMac:", dstMac))

		l3IntfIdx := server.getL3IntfOnSameSubnet(srcIp)

		//server.logger.Info(fmt.Sprintln("---Hello---", l3IntfIdx))
		if l3IntfIdx != -1 {
			arpEnt, exist := server.arpCache[srcIp]
			//server.logger.Info(fmt.Sprintln("====Hello2===", arpEnt, exist))
			if exist {
				ifType := asicdCommonDefs.GetIntfTypeFromIfIndex(int32(l3IntfIdx))
				flag := false
				if ifType == commonDefs.IfTypeVlan {
					vlanEnt, exist := server.vlanPropMap[l3IntfIdx]
					if exist {
						vlanId := int(asicdCommonDefs.GetIntfIdFromIfIndex(int32(l3IntfIdx)))
						for p, _ := range vlanEnt.UntagPortMap {
							if p == port &&
								arpEnt.VlanId == vlanId {
								flag = true
							}
						}
					} else {
						flag = false
					}
				} else if ifType == commonDefs.IfTypePort {
					if l3IntfIdx == port &&
						arpEnt.VlanId == asicdCommonDefs.SYS_RSVD_VLAN {
						flag = true
					}
				} else if ifType == commonDefs.IfTypeLag {
					lagEnt, exist := server.lagPropMap[l3IntfIdx]
					if exist {
						for p, _ := range lagEnt.PortMap {
							if p == port &&
								arpEnt.VlanId == asicdCommonDefs.SYS_RSVD_VLAN {
								flag = true
							}
						}
					} else {
						flag = false
					}

				}
				if !(exist && arpEnt.MacAddr == srcMac &&
					port == arpEnt.PortNum && flag == true) {
					server.sendArpReqL3Intf(srcIp, l3IntfIdx)
				}
			} else {
				server.sendArpReqL3Intf(srcIp, l3IntfIdx)
			}
		}

		l3IntfIdx = server.getL3IntfOnSameSubnet(dstIp)
		if l3IntfIdx != -1 {
			server.sendArpReqL3Intf(dstIp, l3IntfIdx)
		}

	}
}

func (server *ARPServer) sendArpReqL3Intf(ip string, l3IfIdx int) {

	ifType := asicdCommonDefs.GetIntfTypeFromIfIndex(int32(l3IfIdx))
	if ifType == commonDefs.IfTypeVlan {
		vlanEnt, _ := server.vlanPropMap[l3IfIdx]
		for port, _ := range vlanEnt.UntagPortMap {
			server.sendArpReq(ip, port)
		}
	} else if ifType == commonDefs.IfTypeLag {
		lagEnt, _ := server.lagPropMap[l3IfIdx]
		for port, _ := range lagEnt.PortMap {
			server.sendArpReq(ip, port)
		}
	} else if ifType == commonDefs.IfTypePort {
		server.sendArpReq(ip, l3IfIdx)
	}
}
