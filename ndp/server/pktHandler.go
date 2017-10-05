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
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"l3/ndp/config"
	"l3/ndp/debug"
	"net"
	"reflect"
	"utils/commonDefs"
)

/*
 *	StartRxTx      a) Check if entry is present in the map
 *		       b) If no entry create one do the initialization for the entry
 *		       c) Create Pcap Handler & add the entry to up interface slice
 *		       d) Start receiving Packets
 */
func (svr *NDPServer) StartRxTx(ifIndex int32) {
	l3Port, exists := svr.L3Port[ifIndex]
	if !exists {
		// This will copy msg (intRef, ifIndex, ipAddr) into l3Port
		// And also create an entry into the ndpL3IntfStateSlice
		debug.Logger.Err("Failed starting RX/TX for interface which was not created, ifIndex:",
			ifIndex, "is not allowed")
		return
	}
	var err error
	switch l3Port.IfType {
	case commonDefs.IfTypePort:
		// create pcap handler if there is none created right now
		err = l3Port.CreatePcap()
		if err != nil {
			debug.Logger.Err("Failed Creating Pcap Handler, err:", err, "for interface:", l3Port.IntfRef)
			return
		}
	case commonDefs.IfTypeVlan:
		if l3Port.PcapBase.PcapUsers == 0 {
			// for all the ports in tag/untag list create pcap for RX channel, only if there are no
			// pcap users created right now
			err = svr.CreatePcap(ifIndex)
			// @TODO: jgheewala help me fixing pcap users here
			if err != nil {
				debug.Logger.Err("Failed Creating Pcap Handler, err:", err, "for interface:", l3Port.IntfRef)
				return
			}
		}
		l3Port.addPcapUser()
	}
	debug.Logger.Info("Started rx/tx for port:", l3Port.IntfRef, "ifIndex:",
		l3Port.IfIndex, "ip GS:", l3Port.IpAddr, "LS:", l3Port.LinkLocalIp, "pcap users are:", l3Port.PcapBase.PcapUsers)
	// go routine will be spawned only on first pcap user
	// @FIX for WD-190 NDP HIGH CPU usage on WM Clos
	if l3Port.PcapBase.PcapUsers == 1 {
		// create TX pcap only one time without any filter
		err = l3Port.CreateTXPcap()
		if err != nil {
			debug.Logger.Err("Failed Creating TX Pcap Handler, err:", err, "for interface:", l3Port.IntfRef)
			// cleanup rx pcap handlers
			if l3Port.IfType == commonDefs.IfTypeVlan {
				svr.DeletePcap(ifIndex)
			}
			return
		}
		// Spawn go routines for rx only if iftype is port because rx is done via l2 ports
		if l3Port.IfType == commonDefs.IfTypePort {
			go l3Port.ReceiveNdpPkts(svr.RxPktCh)
		}
		svr.ndpUpL3IntfStateSlice = append(svr.ndpUpL3IntfStateSlice, ifIndex)
	}
	// On Port Up Send RA packets
	pktData := config.PacketData{
		SendPktType: layers.ICMPv6TypeRouterAdvertisement,
	}
	l3Port.SendND(pktData, svr.SwitchMac)
	svr.L3Port[ifIndex] = l3Port
}

/*
 *	StopRxTx       a) Check if entry is present in the map
 *		       b) If present then send a ctrl signal to stop receiving packets
 *		       c) block until cleanup is going on
 *		       c) delete the entry from up interface slice
 * delete interface will delete pcap if needed and return the deleteEntries
 * The below check is based on following assumptions:
 *	1) fpPort1 has one ip address, bypass the check and delete pcap
 *	2) fpPort1 has two ip address
 *		a) 2003::2/64 	- Global Scope
 *		b) fe80::123/64 - Link Scope
 *		In this case we will get two Notification for port down from the chip, one is for
 *		Global Scope Ip and second is for Link Scope..
 *		On first Notification NDP will update pcap users and move on. Only when second delete
 *		notification comes then NDP will delete pcap
 */
func (svr *NDPServer) StopRxTx(ifIndex int32, ipAddr string) {
	l3Port, exists := svr.L3Port[ifIndex]
	if !exists {
		debug.Logger.Err("No entry found for ifIndex:", ifIndex)
		return
	}

	var deleteEntries []string
	var err error
	switch l3Port.IfType {
	case commonDefs.IfTypePort:
		switch ipAddr {
		case "ALL":
			debug.Logger.Debug("Deleting all entries during stop rx/tx")
			deleteEntries, err = l3Port.DeleteAll()
		default:
			debug.Logger.Debug("Deleing interface:", ipAddr, "during stop rx/tx")
			deleteEntries, err = l3Port.DeleteIntf(ipAddr)
		}
	case commonDefs.IfTypeVlan:
		switch ipAddr {
		case "ALL":
			l3Port.PcapBase.PcapUsers = 0
			deleteEntries, err = l3Port.DeleteAll()
		default:
			if l3Port.PcapBase.Tx != nil {
				l3Port.deletePcapUser()
				deleteEntries, err = l3Port.DeleteIntf(ipAddr)
			}
		}
	}
	if len(deleteEntries) > 0 && err == nil {
		//debug.Logger.Info("Server Got Neigbor Delete for interface:", l3Port.IntfRef)
		svr.DeleteNeighborInfo(deleteEntries, ifIndex)
	}
	// if rx pcap handler is closed then close TX Pcap handler also
	l3Port.DeleteTXPcap()
	// if rx && tx both are closed then delete pcap from l2 ports if ifType is Vlan
	if l3Port.PcapBase.Tx == nil && l3Port.PcapBase.PcapHandle == nil && l3Port.IfType == commonDefs.IfTypeVlan {
		svr.DeletePcap(ifIndex)
	}

	svr.L3Port[ifIndex] = l3Port
	if len(deleteEntries) == 0 {
		return // only one ip address got deleted
	}
	debug.Logger.Info("Stop rx/tx for port:", l3Port.IntfRef, "ifIndex:",
		l3Port.IfIndex, "ip GS:", l3Port.IpAddr, "LS:", l3Port.LinkLocalIp, "is done")
	// Delete Entry from Slice only after all the ip's are deleted
	svr.DeleteL3IntfFromUpState(l3Port.IfIndex)
}

/*
 *	CheckSrcMac
 *		        a) Check for packet src mac and validate it against ifIndex mac addr
 *			    if it is same then discard the packet
 */
func (svr *NDPServer) CheckSrcMac(macAddr string) bool {
	_, exists := svr.SwitchMacMapEntries[macAddr]
	return exists
}

/*
 *	insertNeighborInfo: Helper API to update list of neighbor keys that are created by ndp
 */
func (svr *NDPServer) insertNeigborInfo(nbrInfo *config.NeighborConfig) {
	svr.NeigborEntryLock.Lock()
	nbrKey := createNeighborKey(nbrInfo.MacAddr, nbrInfo.IpAddr, nbrInfo.Intf)
	svr.NeighborInfo[nbrKey] = *nbrInfo
	svr.neighborKey = append(svr.neighborKey, nbrKey)
	svr.NeigborEntryLock.Unlock()
}

func (svr *NDPServer) updateNeighborInfo(nbrInfo *config.NeighborConfig) {
	svr.NeigborEntryLock.Lock()
	nbrKey := createNeighborKey(nbrInfo.MacAddr, nbrInfo.IpAddr, nbrInfo.Intf)
	svr.NeighborInfo[nbrKey] = *nbrInfo
	svr.NeigborEntryLock.Unlock()
}

/*
 *	deleteSvrStateNbrInfo: Helper API to update list of neighbor keys that are deleted by ndp
 *	@NOTE: caller is responsible for acquiring the lock to access slice
 */
func (svr *NDPServer) deleteSvrStateNbrInfo(nbrKey string) {
	// delete the entry from neighbor map
	delete(svr.NeighborInfo, nbrKey)

	for idx, _ := range svr.neighborKey {
		if svr.neighborKey[idx] == nbrKey {
			svr.neighborKey = append(svr.neighborKey[:idx], svr.neighborKey[idx+1:]...)
			break
		}
	}
}

/*
 *	 CreateNeighborInfo
 *			a) It will first check whether a neighbor exists in the neighbor cache
 *			b) If it doesn't exists then we create neighbor in the platform
 *		        a) It will update ndp server neighbor info cache with the latest information
 */
func (svr *NDPServer) CreateNeighborInfo(nbrInfo *config.NeighborConfig) {
	debug.Logger.Debug("Calling create ipv6 neighgor for global nbrinfo is", nbrInfo.IpAddr, nbrInfo.MacAddr,
		nbrInfo.VlanId, nbrInfo.IfIndex)
	if net.ParseIP(nbrInfo.IpAddr).IsLinkLocalUnicast() == false {
		_, err := svr.SwitchPlugin.CreateIPv6Neighbor(nbrInfo.IpAddr, nbrInfo.MacAddr, nbrInfo.VlanId, nbrInfo.IfIndex)
		if err != nil {
			debug.Logger.Err("create ipv6 global neigbor failed for", nbrInfo, "error is", err)
			// do not enter that neighbor in our neigbor map
			return
		}
	}
	svr.SendIPv6CreateNotification(nbrInfo.IpAddr, nbrInfo.IfIndex)
	svr.insertNeigborInfo(nbrInfo)
}

func (svr *NDPServer) deleteNeighbor(nbrKey string, ifIndex int32) {
	debug.Logger.Debug("deleteNeighbor called for nbrKey:", nbrKey)
	// Inform clients that neighbor is gonna be deleted
	splitString := splitNeighborKey(nbrKey)
	nbrIp := splitString[1]
	svr.SendIPv6DeleteNotification(nbrIp, ifIndex)
	// Request asicd to delete the neighbor
	if net.ParseIP(nbrIp).IsLinkLocalUnicast() == false {
		_, err := svr.SwitchPlugin.DeleteIPv6Neighbor(nbrIp)
		if err != nil {
			debug.Logger.Err("delete ipv6 neigbor failed for", nbrIp, "error is", err)
		}
	}
	svr.deleteSvrStateNbrInfo(nbrKey)
}

func (svr *NDPServer) UpdateNeighborInfo(nbrInfo *config.NeighborConfig, oldNbrEntry config.NeighborConfig) {
	//svr.SendIPv6DeleteNotification(oldNbrEntry.IpAddr, oldNbrEntry.IfIndex)
	debug.Logger.Debug("Calling update ipv6 neighgor for global nbrinfo is", nbrInfo.IpAddr, nbrInfo.MacAddr,
		nbrInfo.VlanId, nbrInfo.IfIndex)
	if net.ParseIP(nbrInfo.IpAddr).IsLinkLocalUnicast() == false {
		_, err := svr.SwitchPlugin.UpdateIPv6Neighbor(nbrInfo.IpAddr, nbrInfo.MacAddr, nbrInfo.VlanId, nbrInfo.IfIndex)
		if err != nil {
			debug.Logger.Err("update ipv6 global neigbor failed for", nbrInfo, "error is", err)
			// do not enter that neighbor in our neigbor map
			return
		}
	}
	//svr.SendIPv6CreateNotification(nbrInfo.IpAddr, nbrInfo.IfIndex)
	svr.updateNeighborInfo(nbrInfo)
}

/*
 *	 DeleteNeighborInfo
 *			a) It will first check whether a neighbor exists in the neighbor cache
 *			b) If it doesn't exists then we will move on to next neighbor
 *		        c) If exists then we will call DeleteIPV6Neighbor for that entry and remove
 *			   the entry from our runtime information
 */
func (svr *NDPServer) DeleteNeighborInfo(deleteEntries []string, ifIndex int32) {
	svr.NeigborEntryLock.Lock()
	for _, nbrKey := range deleteEntries {
		debug.Logger.Debug("Calling delete ipv6 neighbor for nbr:", nbrKey)
		svr.deleteNeighbor(nbrKey, ifIndex)
	}
	svr.NeigborEntryLock.Unlock()
}

/*
 *	ProcessRxPkt
 *		        a) Check for runtime information
 *			b) Validate & Parse Pkt, which gives ipAddr, MacAddr
 *			c) PopulateVlanInfo will check if the port is untagged port or not and based of that
 *			   vlan id will be selected
 *			c) CreateIPv6 Neighbor entry
 */
func (svr *NDPServer) ProcessRxPkt(ifIndex int32, pkt gopacket.Packet) error {
	var l3Port Interface
	var l2Port PhyPort
	var exists bool
	var nbrKey string
	// if we receive packet on L2 Physical interface then the we need get l3 port via cross referencing PhyPortToL3PortMap
	l3IfIndex, l3exists := svr.PhyPortToL3PortMap[ifIndex]
	if l3exists {
		// Vlan is the l3 port
		l3Port, exists = svr.L3Port[l3IfIndex]
		if !exists {
			return errors.New(fmt.Sprintln("Entry for ifIndex:", l3IfIndex, "doesn't exists"))
		}
		l2Port = svr.L2Port[ifIndex]
	} else {
		// Physical Port itself is the l3 port
		l3Port, exists = svr.L3Port[ifIndex]
		if !exists {
			return errors.New(fmt.Sprintln("Entry for ifIndex:", ifIndex, "doesn't exists"))
		}
	}
	// Step1 : decode packet
	ndInfo, err := svr.Packet.DecodeND(pkt)
	if err != nil || ndInfo == nil {
		return errors.New(fmt.Sprintln("Failed decoding ND packet, error:", err))
	}
	// Step2: process decode neighbor information
	// update ifIndex to l2 ifIndex if iftype is not ifTypePort
	switch l3Port.IfType {
	case commonDefs.IfTypeVlan:
		ndInfo.LearnedIfIndex = ifIndex
		// if vlan type then updating the name to original port where the packet was received
		ndInfo.LearnedIntfRef = l2Port.Info.Name
	case commonDefs.IfTypePort:
		ndInfo.LearnedIfIndex = l3Port.IfIndex
		ndInfo.LearnedIntfRef = l3Port.IntfRef
	}
	// Step2: process decoded packet
	nbrInfo, operation := l3Port.ProcessND(ndInfo)
	if nbrInfo == nil && operation == IGNORE { //|| (operation != CREATE && operation != DELETE) {
		//return nil
		goto early_exit
	}
	// Step3: process decode neighbor information
	// update ifIndex to l2 ifIndex if iftype is not ifTypePort
	switch l3Port.IfType {
	case commonDefs.IfTypeVlan:
		nbrInfo.IfIndex = ifIndex
		// if vlan type then updating the name to original port where the packet was received
		nbrInfo.Intf = l2Port.Info.Name
	}
	svr.PopulateVlanInfo(nbrInfo, l3Port.IntfRef)
	nbrKey = createNeighborKey(nbrInfo.MacAddr, nbrInfo.IpAddr, nbrInfo.Intf)
	// based on operation program hardware, update sw & send notifications
	switch operation {
	case CREATE:
		svr.CreateNeighborInfo(nbrInfo)
	case UPDATE:
		nbrEntry, exists := svr.NeighborInfo[nbrKey]
		if !exists { //entry does not exists and hence creating new
			debug.Logger.Info("!!!!!!ALERT!!!!!! NDP Server does not have nbrInfo for ipaddr:",
				nbrInfo.IpAddr, "hence on UPDATE doing CREATE")
			svr.CreateNeighborInfo(nbrInfo)
		} else {
			// @TODO: check Process Neighbor Information with Server Neighbor Information
			if !reflect.DeepEqual(nbrEntry, *nbrInfo) {
				debug.Logger.Debug("Updating neighbor Info as oldEntry:", nbrEntry,
					"is not equal to new entry", *nbrInfo)
				svr.UpdateNeighborInfo(nbrInfo, nbrEntry)
			}
		}
	case DELETE:
		svr.deleteNeighbor(nbrKey, l3Port.IfIndex) // used mostly by RA
	}

early_exit:
	if l3exists {
		svr.L3Port[l3IfIndex] = l3Port
	} else {
		svr.L3Port[ifIndex] = l3Port
	}
	return nil
}

func (svr *NDPServer) ProcessTimerExpiry(pktData config.PacketData) error {
	var l3Port Interface
	var exists bool
	var intfName string
	// if we receive packet on L2 Physical interface then the we need get l3 port via cross referencing PhyPortToL3PortMap
	l3IfIndex, l3exists := svr.PhyPortToL3PortMap[pktData.IfIndex]
	if l3exists {
		// Vlan is the l3 port
		l3Port, exists = svr.L3Port[l3IfIndex]
		if !exists {
			return errors.New(fmt.Sprintln("Entry for ifIndex:", l3IfIndex, "doesn't exists"))
		}
		l2Port := svr.L2Port[pktData.IfIndex]
		intfName = l2Port.Info.Name
	} else {
		// Port is the l3 port
		l3Port, exists = svr.L3Port[pktData.IfIndex]
		if !exists {
			return errors.New(fmt.Sprintln("Entry for ifIndex:", pktData.IfIndex, "doesn't exists"))
		}
		intfName = l3Port.IntfRef
	}
	nbrKey := createNeighborKey(pktData.NeighborMac, pktData.NeighborIp, intfName)
	// fix this when we have per port mac addresses
	operation := l3Port.SendND(pktData, svr.SwitchMac)
	if operation == DELETE {
		//svr.deleteNeighbor(pktData.NeighborIp, pktData.IfIndex)
		svr.deleteNeighbor(nbrKey, l3Port.IfIndex)
	}
	if l3exists {
		svr.L3Port[l3IfIndex] = l3Port
	} else {
		svr.L3Port[pktData.IfIndex] = l3Port
	}
	//nbrInfo := svr.NeighborInfo[nbrKey]
	//svr.NeighborInfo[nbrKey] = nbrInfo
	svr.counter.Send++
	return nil
}
