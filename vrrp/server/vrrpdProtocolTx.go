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
	"encoding/binary"
	_ "errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"net"
	"time"
)

/*
 *  VRRP TX INTERFACE
 */
type VrrpTxIntf interface {
	VrrpSendPkt(key string, priority uint16)
	VrrpEncodeHeader(hdr VrrpPktHeader) ([]byte, uint16)
	VrrpCreateVrrpHeader(gblInfo VrrpGlobalInfo) ([]byte, uint16)
	VrrpCreateSendPkt(gblInfo VrrpGlobalInfo, vrrpEncHdr []byte, hdrLen uint16) []byte
	VrrpCreateWriteBuf(eth *layers.Ethernet, arp *layers.ARP, ipv4 *layers.IPv4, payload []byte) []byte
}

/*
Octet Offset--> 0                   1                   2                   3
 |		0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 |		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 V		|                    IPv4 Fields or IPv6 Fields                 |
		...                                                             ...
		|                                                               |
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 0		|Version| Type  | Virtual Rtr ID|   Priority    |Count IPvX Addr|
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 4		|(rsvd) |     Max Adver Int     |          Checksum             |
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 8		|                                                               |
		+                                                               +
12		|                       IPvX Address(es)                        |
		+                                                               +
..		+                                                               +
		+                                                               +
		+                                                               +
		|                                                               |
		+                                                               +
		|                                                               |
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
func (svr *VrrpServer) VrrpEncodeHeader(hdr VrrpPktHeader) ([]byte, uint16) {
	pktLen := VRRP_HEADER_SIZE_EXCLUDING_IPVX + (hdr.CountIPv4Addr * 4)
	if pktLen < VRRP_HEADER_MIN_SIZE {
		pktLen = VRRP_HEADER_MIN_SIZE
	}
	bytes := make([]byte, pktLen)
	bytes[0] = (hdr.Version << 4) | hdr.Type
	bytes[1] = hdr.VirtualRtrId
	bytes[2] = hdr.Priority
	bytes[3] = hdr.CountIPv4Addr
	rsvdAdver := (uint16(hdr.Rsvd) << 13) | hdr.MaxAdverInt
	binary.BigEndian.PutUint16(bytes[4:], rsvdAdver)
	binary.BigEndian.PutUint16(bytes[6:8], hdr.CheckSum)
	baseIpByte := 8
	for i := 0; i < int(hdr.CountIPv4Addr); i++ {
		copy(bytes[baseIpByte:(baseIpByte+4)], hdr.IPv4Addr[i].To4())
		baseIpByte += 4
	}
	// Create Checksum for the header and store it
	binary.BigEndian.PutUint16(bytes[6:8],
		svr.VrrpComputeChecksum(hdr.Version, bytes))
	return bytes, uint16(pktLen)
}

func (svr *VrrpServer) VrrpCreateVrrpHeader(gblInfo VrrpGlobalInfo) ([]byte, uint16) {
	// @TODO: handle v6 packets.....
	vrrpHeader := VrrpPktHeader{
		Version:       VRRP_VERSION2,
		Type:          VRRP_PKT_TYPE_ADVERTISEMENT,
		VirtualRtrId:  uint8(gblInfo.IntfConfig.VRID),
		Priority:      uint8(gblInfo.IntfConfig.Priority),
		CountIPv4Addr: 1, // FIXME for more than 1 vip
		Rsvd:          VRRP_RSVD,
		MaxAdverInt:   uint16(gblInfo.IntfConfig.AdvertisementInterval),
		CheckSum:      VRRP_HDR_CREATE_CHECKSUM,
	}
	var ip net.IP
	//FIXME with Virtual Ip Addr.... and not IfIndex Ip Addr
	// If no virtual ip then use interface/router ip address as virtual ip
	if gblInfo.IntfConfig.VirtualIPv4Addr == "" {
		ip, _, _ = net.ParseCIDR(gblInfo.IpAddr)
	} else {
		ip = net.ParseIP(gblInfo.IntfConfig.VirtualIPv4Addr)
	}
	vrrpHeader.IPv4Addr = append(vrrpHeader.IPv4Addr, ip)
	vrrpEncHdr, hdrLen := svr.VrrpEncodeHeader(vrrpHeader)
	return vrrpEncHdr, hdrLen
}

func (svr *VrrpServer) VrrpWritePacket(gblInfo VrrpGlobalInfo, vrrpTxPkt []byte) {
	gblInfo.PcapHdlLock.Lock()
	err := gblInfo.pHandle.WritePacketData(vrrpTxPkt)
	gblInfo.PcapHdlLock.Unlock()
	if err != nil {
		svr.logger.Info(fmt.Sprintln("Sending Packet failed: ", err))
	}
}

func (svr *VrrpServer) VrrpCreateWriteBuf(eth *layers.Ethernet,
	arp *layers.ARP, ipv4 *layers.IPv4, payload []byte) []byte {

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	if ipv4 != nil {
		gopacket.SerializeLayers(buffer, options, eth, ipv4,
			gopacket.Payload(payload))
	} else {
		gopacket.SerializeLayers(buffer, options, eth, arp)
	}
	return buffer.Bytes()
}

func (svr *VrrpServer) VrrpCreateSendPkt(gblInfo VrrpGlobalInfo, vrrpEncHdr []byte, hdrLen uint16) []byte {
	// Ethernet Layer
	srcMAC, _ := net.ParseMAC(gblInfo.VirtualRouterMACAddress)
	dstMAC, _ := net.ParseMAC(VRRP_PROTOCOL_MAC)
	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}

	// IP Layer
	sip, _, _ := net.ParseCIDR(gblInfo.IpAddr)
	ipv4 := &layers.IPv4{
		Version:  uint8(4),
		IHL:      uint8(VRRP_IPV4_HEADER_MIN_SIZE),
		Protocol: layers.IPProtocol(VRRP_PROTO_ID),
		Length:   uint16(VRRP_IPV4_HEADER_MIN_SIZE + hdrLen),
		TTL:      uint8(VRRP_TTL),
		SrcIP:    sip,
		DstIP:    net.ParseIP(VRRP_GROUP_IP),
	}
	return svr.VrrpCreateWriteBuf(eth, nil, ipv4, vrrpEncHdr)
}

func (svr *VrrpServer) VrrpSendPkt(key string, priority uint16) {
	gblInfo, found := svr.vrrpGblInfo[key]
	if !found {
		svr.logger.Err("No Entry for " + key)
		return
	}
	gblInfo.PcapHdlLock.Lock()
	if gblInfo.pHandle == nil {
		svr.logger.Info("Invalid Pcap Handle")
		gblInfo.PcapHdlLock.Unlock()
		return
	}
	gblInfo.PcapHdlLock.Unlock()
	configuredPriority := gblInfo.IntfConfig.Priority
	// Because we do not update the gblInfo back into the map...
	// we can overwrite the priority value if Master is down..
	if priority == VRRP_MASTER_DOWN_PRIORITY {
		gblInfo.IntfConfig.Priority = int32(priority)
	}
	vrrpEncHdr, hdrLen := svr.VrrpCreateVrrpHeader(gblInfo)
	svr.VrrpWritePacket(gblInfo, svr.VrrpCreateSendPkt(gblInfo, vrrpEncHdr, hdrLen))
	svr.VrrpUpdateMasterTimerStateInfo(&gblInfo)
	gblInfo.IntfConfig.Priority = configuredPriority
	svr.vrrpGblInfo[key] = gblInfo
	// inform the caller that advertisment packet is send out
	svr.vrrpPktSend <- true
}

func (svr *VrrpServer) VrrpUpdateMasterTimerStateInfo(gblInfo *VrrpGlobalInfo) {
	gblInfo.StateInfoLock.Lock()
	gblInfo.StateInfo.LastAdverTx = time.Now().String()
	gblInfo.StateInfo.AdverTx++
	gblInfo.StateInfoLock.Unlock()
}
