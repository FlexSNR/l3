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
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"l3/ndp/config"
	"l3/ndp/debug"
	"net"
	"utils/commonDefs"
)

func isLinkLocal(ipAddr string) bool {
	ip, _, err := net.ParseCIDR(ipAddr)
	if err != nil {
		ip = net.ParseIP(ipAddr)
	}
	return ip.IsLinkLocalUnicast() && (ip.To4() == nil)
}

func (svr *NDPServer) IsIPv6Addr(ipAddr string) bool {
	ip, _, _ := net.ParseCIDR(ipAddr)
	if ip.To4() == nil {
		return true
	}

	return false
}

/*
 * helper function to create notification msg
 */
func createNotificationMsg(ipAddr string, ifIndex int32) ([]byte, error) {
	msg := commonDefs.Ipv6NeighborNotification{
		IpAddr:  ipAddr,
		IfIndex: ifIndex,
	}
	msgBuf, err := json.Marshal(msg)
	if err != nil {
		debug.Logger.Err("Failed to marshal IPv6 Neighbor Notification message", msg, "error:", err)
		return msgBuf, err
	}

	return msgBuf, nil
}

/*
 * helper function to marshal notification and push it on to the channel
 */
func (svr *NDPServer) pushNotification(notification commonDefs.NdpNotification) {
	notifyBuf, err := json.Marshal(notification)
	if err != nil {
		debug.Logger.Err("Failed to marshal ipv6 notification before pushing it on channel error:", err)
		return
	}
	svr.notifyChan <- notifyBuf
}

/*
 *  Change L2 port state from switch asicd notification
 */
func (svr *NDPServer) updateL2Operstate(ifIndex int32, state string) {
	l2Port, exists := svr.L2Port[ifIndex]
	if !exists {
		debug.Logger.Err("No L2 Port found for ifIndex:", ifIndex, "hence nothing to update on OperState")
		return
	}
	l2Port.Info.OperState = state
	/* HANDLE PORT FLAP SCENARIOS
	 * only l3 CreatePcap should update l2Port.L3 information, so only READ operation on l2Port.L3
	 * no write operations are allowed
	 */
	debug.Logger.Debug("l2 Port l3 information is", l2Port.L3)
	switch state {
	case config.STATE_UP:
		// if l2 port rx is set to nil and l3 ifIndex is not invalid then create pcap
		if l2Port.RX == nil && l2Port.L3.IfIndex != config.L3_INVALID_IFINDEX {
			l2Port.createPortPcap(svr.RxPktCh, l2Port.L3.Name)
			// reverse map updated
			svr.PhyPortToL3PortMap[ifIndex] = l2Port.L3.IfIndex
		}
	case config.STATE_DOWN:
		l2Port.deletePcap()
		delete(svr.PhyPortToL3PortMap, ifIndex)
	}
	svr.L2Port[ifIndex] = l2Port
}

/*
 * internal api for creating pcap handler for l2 untagged/tagged physical port for RX
 */
func (l2Port *PhyPort) createPortPcap(pktCh chan *RxPktInfo, name string) (err error) {
	if l2Port.RX == nil {
		debug.Logger.Debug("creating l2 rx pcap for", name, l2Port.Info.IfIndex)
		l2Port.RX, err = pcap.OpenLive(name, NDP_PCAP_SNAPSHOTlEN, NDP_PCAP_PROMISCUOUS, NDP_PCAP_TIMEOUT)
		if err != nil {
			debug.Logger.Err("Creating Pcap Handler failed for l2 interface:", name, "Error:", err)
			return err
		}
		err = l2Port.RX.SetBPFFilter(NDP_PCAP_FILTER)
		if err != nil {
			debug.Logger.Err("Creating BPF Filter failed Error", err)
			l2Port.RX = nil
			return err
		}
		debug.Logger.Info("Created l2 Pcap handler for port:", name, "now start receiving NdpPkts")
		go l2Port.L2ReceiveNdpPkts(pktCh)
	}
	return nil
}

/*
 * internal api for creating pcap handler for l2 physical port for RX
 */
func (l2Port *PhyPort) deletePcap() {
	if l2Port.RX != nil {
		l2Port.RX.Close()
		l2Port.RX = nil
	}
}

/*
 * Receive Ndp Packet and push it on the pktCh
 */
func (intf *PhyPort) L2ReceiveNdpPkts(pktCh chan *RxPktInfo) error {
	if intf.RX == nil {
		debug.Logger.Err("pcap handler for port:", intf.Info.Name, "is not valid. ABORT!!!!")
		return errors.New(fmt.Sprintln("pcap handler for port:", intf.Info.Name, "is not valid. ABORT!!!!"))
	}
	src := gopacket.NewPacketSource(intf.RX, layers.LayerTypeEthernet)
	in := src.Packets()
	for {
		select {
		case pkt, ok := <-in:
			if ok {
				pktCh <- &RxPktInfo{pkt, intf.Info.IfIndex}
			} else {
				debug.Logger.Debug("Pcap closed as in is invalid exiting go routine for port:", intf.Info.Name)
				return nil
			}
		}
	}
	return nil
}

/*
 *  Creating Pcap handlers for l2 port which are marked as tag/untag for l3 vlan port and are in UP state
 *  only l3 CreatePcap should update l2Port.L3 information
 */
func (svr *NDPServer) CreatePcap(ifIndex int32) error {
	debug.Logger.Info("Creating Physical Port Pcap RX Handlers for L3 Vlan, ifIndex:", ifIndex)
	vlan, exists := svr.VlanInfo[ifIndex]
	if !exists {
		debug.Logger.Err("No matching vlan found for ifIndex:", ifIndex)
		return errors.New(fmt.Sprintln("No matching vlan found for ifIndex:", ifIndex))
	}
	// open rx pcap handler for tagged ports
	for pIfIndex, _ := range vlan.TagPortsMap {
		l2Port, exists := svr.L2Port[pIfIndex]
		if exists {
			name := l2Port.Info.Name + "." + vlan.Name
			if l2Port.Info.OperState == config.STATE_UP {
				l2Port.createPortPcap(svr.RxPktCh, name)
			} else {
				l2Port.RX = nil
			}
			// l3 information store if the port flaps and we need to restart
			l2Port.L3.IfIndex = ifIndex
			l2Port.L3.PortType = config.L2_TAG_TYPE
			l2Port.L3.Name = name
			svr.L2Port[pIfIndex] = l2Port
			// reverse map updated
			svr.PhyPortToL3PortMap[pIfIndex] = ifIndex
		}
	}
	// open rx pcap handler for untagged ports
	for pIfIndex, _ := range vlan.UntagPortsMap {
		l2Port, exists := svr.L2Port[pIfIndex]
		if exists {
			if l2Port.Info.OperState == config.STATE_UP {
				l2Port.createPortPcap(svr.RxPktCh, l2Port.Info.Name)
			} else {
				l2Port.RX = nil
			}
			// l3 information store if the port flaps and we need to restart
			l2Port.L3.IfIndex = ifIndex
			l2Port.L3.PortType = config.L2_UNTAG_TYPE
			l2Port.L3.Name = l2Port.Info.Name
			svr.L2Port[pIfIndex] = l2Port
			// reverse map updated
			svr.PhyPortToL3PortMap[pIfIndex] = ifIndex
		}
	}
	return nil
}

/*
 *  Deleting Pcap handlers for l2 port which are marked as tag/untag for l3 vlan port and are in UP state
 *  only l3 CreatePcap should update l2Port.L3 information
 */
func (svr *NDPServer) DeletePcap(ifIndex int32) {
	debug.Logger.Info("Deleting Physical Port Pcap RX Handlers for L3 Vlan, ifIndex:", ifIndex)
	vlan, exists := svr.VlanInfo[ifIndex]
	if !exists {
		debug.Logger.Err("No matching vlan found for ifIndex:", ifIndex)
		return //errors.New(fmt.Sprintln("No matching vlan found for ifIndex:", ifIndex))
	}
	l3 := L3Info{
		IfIndex: config.L3_INVALID_IFINDEX,
	}
	// open rx pcap handler for tagged ports
	for pIfIndex, _ := range vlan.TagPortsMap {
		l2Port, exists := svr.L2Port[pIfIndex]
		if exists {
			l2Port.deletePcap()
			// cleanup l3 port information from phy port only when L3 is calling delete
			l2Port.L3 = l3
			svr.L2Port[pIfIndex] = l2Port
			delete(svr.PhyPortToL3PortMap, pIfIndex)
		}
	}
	// open rx pcap handler for untagged ports
	for pIfIndex, _ := range vlan.UntagPortsMap {
		l2Port, exists := svr.L2Port[pIfIndex]
		if exists {
			l2Port.deletePcap()
			// cleanup l3 port information from phy port only when L3 is calling delete
			l2Port.L3 = l3
			svr.L2Port[pIfIndex] = l2Port
			delete(svr.PhyPortToL3PortMap, pIfIndex)
		}
	}
}

/*
 *  Utility Action function to delete ndp entries by L3 Port interface name
 */
func (svr *NDPServer) ActionDeleteByIntf(intfRef string) {
	ifIndex, exists := svr.L3IfIntfRefToIfIndex[intfRef]
	if !exists {
		debug.Logger.Err("Refresh Action by Interface Name:", intfRef,
			"cannot be performed as no ifIndex found for L3 interface")
		return
	}
	l3Port, exists := svr.L3Port[ifIndex]
	if !exists {
		debug.Logger.Err("Delete Action by Interface Name:", intfRef,
			"cannot be performed as no such L3 interface exists")
		return
	}
	deleteEntries, err := l3Port.FlushNeighbors()
	if len(deleteEntries) > 0 && err == nil {
		debug.Logger.Info("Server Action Delete by Intf:", l3Port.IntfRef, "Neighbors:", deleteEntries)
		svr.DeleteNeighborInfo(deleteEntries, ifIndex)
	}
	svr.L3Port[ifIndex] = l3Port
}

/*
 *  Utility Action function to refreshndp entries by L3 Port interface name
 */
func (svr *NDPServer) ActionRefreshByIntf(intfRef string) {
	ifIndex, exists := svr.L3IfIntfRefToIfIndex[intfRef]
	if !exists {
		debug.Logger.Err("Refresh Action by Interface Name:", intfRef,
			"cannot be performed as no ifIndex found for L3 interface")
		return
	}
	l3Port, exists := svr.L3Port[ifIndex]
	if !exists {
		debug.Logger.Err("Refresh Action by Interface Name:", intfRef,
			"cannot be performed as no such L3 interface exists")
		return
	}

	l3Port.RefreshAllNeighbors(svr.SwitchMac)
	svr.L3Port[ifIndex] = l3Port
}

/*
 *  Utility Action function to delete ndp entries by Neighbor Ip Address
 */
func (svr *NDPServer) ActionDeleteByNbrIp(ipAddr string) {
	var nbrKey string
	found := false
	for _, nbrKey = range svr.neighborKey {
		splitString := splitNeighborKey(nbrKey)
		if splitString[1] == ipAddr {
			found = true
		}
	}
	if !found {
		debug.Logger.Err("Delete Action by Ip Address:", ipAddr, "as no such neighbor is learned")
		return
	}
	nbrEntry, exists := svr.NeighborInfo[nbrKey]
	if !exists {
		debug.Logger.Err("Delete Action by Ip Address:", ipAddr, "as no such neighbor is learned")
		return
	}
	l3IfIndex := nbrEntry.IfIndex
	// if valid vlan then get l3 ifIndex from PhyPortToL3PortMap
	if nbrEntry.VlanId != config.INTERNAL_VLAN {
		l3IfIndex, exists = svr.PhyPortToL3PortMap[nbrEntry.IfIndex]
		if !exists {
			debug.Logger.Err("Delete Action by Ip Address:", ipAddr,
				"cannot be performed as no l3IfIndex mapping found for", nbrEntry.IfIndex,
				"vlan:", nbrEntry.VlanId)
			return
		}
	}

	l3Port, exists := svr.L3Port[l3IfIndex]
	if !exists {
		debug.Logger.Err("Delete Action by Ip Address:", ipAddr, "as no L3 Port found where this neighbor is learned")
		return
	}
	deleteEntries, err := l3Port.DeleteNeighbor(nbrEntry)
	if err == nil {
		debug.Logger.Info("Server Action Delete by NbrIp:", ipAddr, "L3 Port:", l3Port.IntfRef,
			"Neighbors:", deleteEntries)
		svr.deleteNeighbor(deleteEntries[0], l3Port.IfIndex)
	}

	svr.L3Port[l3IfIndex] = l3Port
}

/*
 *  Utility Action function to refresh ndp entries by Neighbor Ip Address
 */
func (svr *NDPServer) ActionRefreshByNbrIp(ipAddr string) {
	var nbrKey string
	found := false
	for _, nbrKey = range svr.neighborKey {
		splitString := splitNeighborKey(nbrKey)
		if splitString[1] == ipAddr {
			found = true
		}
	}
	if !found {
		debug.Logger.Err("Delete Action by Ip Address:", ipAddr, "as no such neighbor is learned")
		return
	}
	nbrEntry, exists := svr.NeighborInfo[nbrKey]
	if !exists {
		debug.Logger.Err("Refresh Action by Ip Address:", ipAddr, "as no such neighbor is learned")
		return
	}
	l3IfIndex := nbrEntry.IfIndex
	// if valid vlan then get l3 ifIndex from PhyPortToL3PortMap
	if nbrEntry.VlanId != config.INTERNAL_VLAN {
		l3IfIndex, exists = svr.PhyPortToL3PortMap[nbrEntry.IfIndex]
		if !exists {
			debug.Logger.Err("Refresh Action by Ip Address:", ipAddr,
				"cannot be performed as no l3IfIndex mapping found for", nbrEntry.IfIndex,
				"vlan:", nbrEntry.VlanId)
			return
		}
	}

	l3Port, exists := svr.L3Port[l3IfIndex]
	if !exists {
		debug.Logger.Err("Delete Action by Ip Address:", ipAddr, "as no L3 Port found where this neighbor is learned")
		return
	}
	l3Port.SendNS(svr.SwitchMac, nbrEntry.MacAddr, nbrEntry.IpAddr, false /*isFastProbe*/)
	svr.L3Port[l3IfIndex] = l3Port
}
