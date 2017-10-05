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
	"asicdInt"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	_ "net"
	_ "time"
)

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
func (svr *VrrpServer) VrrpDecodeHeader(data []byte) *VrrpPktHeader {
	var vrrpPkt VrrpPktHeader
	vrrpPkt.Version = uint8(data[0]) >> 4
	vrrpPkt.Type = uint8(data[0]) & 0x0F
	vrrpPkt.VirtualRtrId = data[1]
	vrrpPkt.Priority = data[2]
	vrrpPkt.CountIPv4Addr = data[3]
	rsvdAdver := binary.BigEndian.Uint16(data[4:6])
	vrrpPkt.Rsvd = uint8(rsvdAdver >> 13)
	vrrpPkt.MaxAdverInt = rsvdAdver & 0x1FFF
	vrrpPkt.CheckSum = binary.BigEndian.Uint16(data[6:8])
	baseIpByte := 8
	for i := 0; i < int(vrrpPkt.CountIPv4Addr); i++ {
		vrrpPkt.IPv4Addr = append(vrrpPkt.IPv4Addr, data[baseIpByte:(baseIpByte+4)])
		baseIpByte += 4
	}
	return &vrrpPkt
}

func (svr *VrrpServer) VrrpComputeChecksum(version uint8, content []byte) uint16 {
	var csum uint32
	var rv uint16
	if version == VRRP_VERSION2 {
		for i := 0; i < len(content); i += 2 {
			csum += uint32(content[i]) << 8
			csum += uint32(content[i+1])
		}
		rv = ^uint16((csum >> 16) + csum)
	} else if version == VRRP_VERSION3 {
		//@TODO: .....
	}

	return rv
}

func (svr *VrrpServer) VrrpCheckHeader(hdr *VrrpPktHeader, layerContent []byte, key string) error {
	// @TODO: need to check for version 2 type...RFC requests to drop the packet
	// but cisco uses version 2...
	if hdr.Version != VRRP_VERSION2 && hdr.Version != VRRP_VERSION3 {
		return errors.New(VRRP_INCORRECT_VERSION)
	}
	// Set Checksum to 0 for verifying checksum
	binary.BigEndian.PutUint16(layerContent[6:8], 0)
	// Verify checksum
	chksum := svr.VrrpComputeChecksum(hdr.Version, layerContent)
	if chksum != hdr.CheckSum {
		svr.logger.Err(fmt.Sprintln(chksum, "!=", hdr.CheckSum))
		return errors.New(VRRP_CHECKSUM_ERR)
	}

	// Verify VRRP fields
	if hdr.CountIPv4Addr == 0 ||
		hdr.MaxAdverInt == 0 ||
		hdr.Type == 0 {
		return errors.New(VRRP_INCORRECT_FIELDS)
	}
	gblInfo := svr.vrrpGblInfo[key]
	if gblInfo.IntfConfig.VirtualIPv4Addr == "" {
		for i := 0; i < int(hdr.CountIPv4Addr); i++ {
			/* If Virtual Ip is not configured then check whether the ip
			 * address of router/interface is not same as the received
			 * Virtual Ip Addr
			 */
			if gblInfo.IpAddr == hdr.IPv4Addr[i].String() {
				return errors.New(VRRP_SAME_OWNER)
			}
		}
	}
	if gblInfo.IntfConfig.VRID == 0 {
		return errors.New(VRRP_MISSING_VRID_CONFIG)
	}
	return nil
}

func (svr *VrrpServer) VrrpCheckRcvdPkt(packet gopacket.Packet, key string,
	IfIndex int32) {
	gblInfo := svr.vrrpGblInfo[key]
	gblInfo.StateNameLock.Lock()
	if gblInfo.StateName == VRRP_INITIALIZE_STATE {
		gblInfo.StateNameLock.Unlock()
		return
	}
	gblInfo.StateNameLock.Unlock()
	// Get Entire IP layer Info
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		svr.logger.Err("Not an ip packet?")
		return
	}
	// Get Ip Hdr and start doing basic check according to RFC
	ipHdr := ipLayer.(*layers.IPv4)
	if ipHdr.TTL != VRRP_TTL {
		svr.logger.Err(fmt.Sprintln("ttl should be 255 instead of", ipHdr.TTL,
			"dropping packet from", ipHdr.SrcIP))
		return
	}
	// Get Payload as checks are succesful
	ipPayload := ipLayer.LayerPayload()
	if ipPayload == nil {
		svr.logger.Err("No payload for ip packet")
		return
	}
	// Get VRRP header from IP Payload
	vrrpHeader := svr.VrrpDecodeHeader(ipPayload)
	// Do Basic Vrrp Header Check
	if err := svr.VrrpCheckHeader(vrrpHeader, ipPayload, key); err != nil {
		svr.logger.Err(fmt.Sprintln(err.Error(),
			". Dropping received packet from", ipHdr.SrcIP))
		return
	}
	// Start FSM for VRRP after all the checks are successful
	svr.vrrpFsmCh <- VrrpFsm{
		vrrpHdr: vrrpHeader,
		inPkt:   packet,
		key:     key,
	}
}

func (svr *VrrpServer) VrrpReceivePackets(pHandle *pcap.Handle, key string, IfIndex int32) {
	svr.logger.Info("Listen Vrrp packet for " + key)
	packetSource := gopacket.NewPacketSource(pHandle, pHandle.LinkType())
	for packet := range packetSource.Packets() {
		svr.vrrpRxPktCh <- VrrpPktChannelInfo{
			pkt:     packet,
			key:     key,
			IfIndex: IfIndex,
		}
	}
	svr.logger.Info("Exiting Receive Packets")
}

func (svr *VrrpServer) VrrpInitPacketListener(key string, IfIndex int32) {
	linuxInterface, ok := svr.vrrpLinuxIfIndex2AsicdIfIndex[IfIndex]
	if ok == false {
		svr.logger.Err(fmt.Sprintln("no linux interface for ifindex",
			IfIndex))
		return
	}
	handle, err := pcap.OpenLive(linuxInterface.Name, svr.vrrpSnapshotLen,
		svr.vrrpPromiscuous, svr.vrrpTimeout)
	if err != nil {
		svr.logger.Err(fmt.Sprintln("Creating VRRP listerner failed",
			err))
		return
	}
	err = handle.SetBPFFilter(VRRP_BPF_FILTER)
	if err != nil {
		svr.logger.Err(fmt.Sprintln("Setting filter", VRRP_BPF_FILTER,
			"failed with", "err:", err))
	}
	gblInfo := svr.vrrpGblInfo[key]
	gblInfo.PcapHdlLock.Lock()
	gblInfo.pHandle = handle
	gblInfo.PcapHdlLock.Unlock()
	svr.vrrpGblInfo[key] = gblInfo
	go svr.VrrpReceivePackets(handle, key, IfIndex)
}

func (svr *VrrpServer) VrrpUpdateProtocolMacEntry(add bool) {
	macConfig := asicdInt.RsvdProtocolMacConfig{
		MacAddr:     VRRP_PROTOCOL_MAC,
		MacAddrMask: VRRP_MAC_MASK,
	}
	if add {
		inserted, _ := svr.asicdClient.ClientHdl.EnablePacketReception(&macConfig)
		if !inserted {
			svr.logger.Info("Adding reserved mac failed")
			return
		}
		svr.vrrpMacConfigAdded = true
	} else {
		deleted, _ := svr.asicdClient.ClientHdl.DisablePacketReception(&macConfig)
		if !deleted {
			svr.logger.Info("Deleting reserved mac failed")
			return
		}
		svr.vrrpMacConfigAdded = false
	}
}
