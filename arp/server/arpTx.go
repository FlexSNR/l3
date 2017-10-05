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
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"math/rand"
	"net"
	"time"
)

func getIP(ipAddr string) (ip net.IP) {
	ip = net.ParseIP(ipAddr)
	if ip == nil {
		return ip
	}
	ip = ip.To4()
	return ip
}

func getHWAddr(macAddr string) (mac net.HardwareAddr) {
	mac, err := net.ParseMAC(macAddr)
	if mac == nil || err != nil {
		return nil
	}

	return mac
}

/*
 *@fn sendArpReq
 *  Send the ARP request for ip targetIP
 */
func (server *ARPServer) sendArpReq(targetIp string, port int) {
	server.logger.Debug(fmt.Sprintln("sendArpReq(): sending arp requeust for targetIp ", targetIp, "to port:", port))

	portEnt, _ := server.portPropMap[port]

	if portEnt.OperState == false {
		return
	}
	pcapHdl, err := pcap.OpenLive(portEnt.IfName, server.snapshotLen, server.promiscuous, server.pcapTimeout)
	if pcapHdl == nil {
		server.logger.Err(fmt.Sprintln("Unable to open pcap handle on:", portEnt.IfName, "error:", err))
		return
	}
	defer pcapHdl.Close()
	/*
	   pcapHdl := portEnt.PcapHdl

	*/
	srcIpAddr := getIP(portEnt.IpAddr)
	if srcIpAddr == nil {
		server.logger.Err(fmt.Sprintf("Corrupted source ip :  ", portEnt.IpAddr))
		return
	}

	destIpAddr := getIP(targetIp)
	if destIpAddr == nil {
		server.logger.Err(fmt.Sprintf("Corrupted destination ip :  ", targetIp))
		return
	}

	myMacAddr := getHWAddr(portEnt.MacAddr)
	if myMacAddr == nil {
		server.logger.Err(fmt.Sprintf("corrupted my mac : ", portEnt.MacAddr))
		return
	}
	arp_layer := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   myMacAddr,
		SourceProtAddress: srcIpAddr,
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
	}
	eth_layer := layers.Ethernet{
		SrcMAC:       myMacAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	arp_layer.DstProtAddress = destIpAddr
	gopacket.SerializeLayers(buffer, options, &eth_layer, &arp_layer)

	//logger.Println("Buffer : ", buffer)
	// send arp request and retry after timeout if arp cache is not updated
	if err := pcapHdl.WritePacketData(buffer.Bytes()); err != nil {
		server.logger.Err(fmt.Sprintln("Error writing data to packet buffer for port:", port))
		return
	}
	return
}

/*
 *@fn sendArpProbe
 *  Send the ARP Probe for ip localIP
 */
func (server *ARPServer) sendArpProbe(port int) {
	localIp := server.portPropMap[port].IpAddr
	server.logger.Debug(fmt.Sprintln("sendArpReq(): sending arp requeust for localIp ", localIp, "to port:", port))

	portEnt, _ := server.portPropMap[port]
	if portEnt.OperState == false {
		return
	}

	pcapHdl, err := pcap.OpenLive(portEnt.IfName, server.snapshotLen, server.promiscuous, server.pcapTimeout)
	if pcapHdl == nil {
		server.logger.Err(fmt.Sprintln("Unable to open pcap handle on:", portEnt.IfName, "error:", err))
		return
	}
	defer pcapHdl.Close()

	srcIpAddr := getIP("0.0.0.0")
	if srcIpAddr == nil {
		server.logger.Err(fmt.Sprintf("Corrupted source ip :  ", "0.0.0.0"))
		return
	}

	destIpAddr := getIP(localIp)
	if destIpAddr == nil {
		server.logger.Err(fmt.Sprintf("Corrupted destination ip :  ", localIp))
		return
	}

	myMacAddr := getHWAddr(portEnt.MacAddr)
	if myMacAddr == nil {
		server.logger.Err(fmt.Sprintf("corrupted my mac : ", portEnt.MacAddr))
		return
	}
	arp_layer := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   myMacAddr,
		SourceProtAddress: srcIpAddr,
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
	}
	eth_layer := layers.Ethernet{
		SrcMAC:       myMacAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	arp_layer.DstProtAddress = destIpAddr
	gopacket.SerializeLayers(buffer, options, &eth_layer, &arp_layer)

	//logger.Println("Buffer : ", buffer)
	// send arp request and retry after timeout if arp cache is not updated
	if err := pcapHdl.WritePacketData(buffer.Bytes()); err != nil {
		server.logger.Err(fmt.Sprintln("Error writing data to packet buffer for port:", port))
		return
	}
	return
}

func (server *ARPServer) SendArpProbe(port int) {
	s1 := rand.NewSource(time.Now().UnixNano())
	r1 := rand.New(s1)
	s2 := rand.NewSource(time.Now().UnixNano())
	r2 := rand.New(s2)
	wait := r1.Intn(server.probeWait)
	time.Sleep(time.Duration(wait) * time.Second)
	for i := 0; i < server.probeNum; i++ {
		server.sendArpProbe(port)
		diff := r2.Intn(server.probeMax - server.probeMin)
		diff = diff + server.probeMin
		time.Sleep(time.Duration(diff) * time.Second)
	}
	return
}
