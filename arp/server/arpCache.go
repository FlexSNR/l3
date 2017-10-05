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
	"errors"
	"fmt"
	"models/events"
	"time"
	"utils/commonDefs"
	"utils/eventUtils"
)

type UpdateArpEntryMsg struct {
	PortNum int
	IpAddr  string
	MacAddr string
	Type    bool // True: RIB False: Rx
}

/*
type CreateArpEntryMsg struct {
        PortNum         int
        IpAddr          string
        MacAddr         string
}
*/

type AsicdMsgType uint8

const (
	Create AsicdMsgType = 1
	Delete AsicdMsgType = 2
	Update AsicdMsgType = 3
)

type AsicdMsg struct {
	MsgType AsicdMsgType
	IpAddr  string
	MacAddr string
	VlanId  int32
	IfIdx   int32
}

type DeleteArpEntryMsg struct {
	PortNum int
}

type EventData struct {
	IpAddr  string
	MacAddr string
	IfName  string
}

func (server *ARPServer) updateArpCache() {
	for {
		select {
		/*
		   case msg := <-server.arpEntryCreateCh:
		           server.processArpEntryCreateMsg(msg)
		*/
		case msg := <-server.arpEntryUpdateCh:
			server.processArpEntryUpdateMsg(msg)
		case msg := <-server.arpEntryDeleteCh:
			server.processArpEntryDeleteMsg(msg)
		case <-server.arpSliceRefreshStartCh:
			server.processArpSliceRefreshMsg()
		case <-server.arpCounterUpdateCh:
			server.processArpCounterUpdateMsg()
		case cnt := <-server.arpEntryCntUpdateCh:
			server.processArpEntryCntUpdateMsg(cnt)
		case msg := <-server.arpEntryMacMoveCh:
			server.processArpEntryMacMoveMsg(msg)
		case msg := <-server.arpDeleteArpEntryFromRibCh:
			server.processArpEntryDeleteMsgFromRib(msg)
		case msg := <-server.arpActionProcessCh:
			server.processArpActionMsg(msg)
		}
	}
}

func (server *ARPServer) processArpEntryDeleteMsgFromRib(ipAddr string) {
	arpEnt, exist := server.arpCache[ipAddr]
	if !exist {
		server.logger.Warning(fmt.Sprintln("Cannot perform Arp delete action as Arp Entry does exist for ipAddr:", ipAddr))
		return
	}

	if arpEnt.Type == false {
		server.logger.Debug(fmt.Sprintln("Arp Entry for IpAddr:", ipAddr, "was no installed by RIB, hence cannot be delete"))
		return
	}

	if arpEnt.MacAddr != "incomplete" {
		server.logger.Debug(fmt.Sprintln("4 Calling Asicd Delete Ip:", ipAddr))
		asicdMsg := AsicdMsg{
			MsgType: Delete,
			IpAddr:  ipAddr,
		}
		err := server.processAsicdMsg(asicdMsg)
		if err != nil {
			return
		}
	}
	delete(server.arpCache, ipAddr)
	server.deleteLinuxArp(ipAddr)
}

func (server *ARPServer) processDeleteByIPAddr(ipAddr string) {
	server.logger.Info(fmt.Sprintln("Delete Arp entry by IpAddr:", ipAddr))
	arpEnt, exist := server.arpCache[ipAddr]
	if !exist {
		server.logger.Warning(fmt.Sprintln("Cannot perform Arp delete action as Arp Entry does exist for ipAddr:", ipAddr))
		return
	}

	if arpEnt.Type == true {
		server.logger.Warning(fmt.Sprintln("Cannot perform Arp delete action as Arp Entry for", ipAddr, "belong to nexthop of some route, can only be deleted by RIB"))
		return
	}

	if arpEnt.MacAddr != "incomplete" {
		server.logger.Debug(fmt.Sprintln("4 Calling Asicd Delete Ip:", ipAddr))
		asicdMsg := AsicdMsg{
			MsgType: Delete,
			IpAddr:  ipAddr,
		}
		err := server.processAsicdMsg(asicdMsg)
		if err != nil {
			return
		}
	}
	delete(server.arpCache, ipAddr)
	server.deleteLinuxArp(ipAddr)
}

func (server *ARPServer) processDeleteByIfName(ifName string) {
	server.logger.Info(fmt.Sprintln("Delete Arp entry by IfName:", ifName))
	for l3IfIdx, l3Ent := range server.l3IntfPropMap {
		if l3Ent.IfName == ifName {
			for ip, arpEnt := range server.arpCache {
				if arpEnt.L3IfIdx == l3IfIdx {
					server.processDeleteByIPAddr(ip)
				}
			}
		}
	}
}

func (server *ARPServer) processRefreshByIPAddr(ipAddr string) {
	server.logger.Info(fmt.Sprintln("Refresh Arp entry by IpAddr:", ipAddr))
	arpEnt, exist := server.arpCache[ipAddr]
	if !exist {
		server.logger.Warning(fmt.Sprintln("Cannot perform Arp refresh action as Arp Entry does exist for ipAddr:", ipAddr))
		return
	}

	if arpEnt.MacAddr != "incomplete" {
		server.logger.Debug(fmt.Sprintln("4 Calling Asicd Delete Ip:", ipAddr))
		asicdMsg := AsicdMsg{
			MsgType: Delete,
			IpAddr:  ipAddr,
		}
		err := server.processAsicdMsg(asicdMsg)
		if err != nil {
			return
		}
	}
	arpEnt.MacAddr = "incomplete"
	arpEnt.Counter = server.timeoutCounter
	server.arpCache[ipAddr] = arpEnt
	server.deleteLinuxArp(ipAddr)
}

func (server *ARPServer) processRefreshByIfName(ifName string) {
	server.logger.Info(fmt.Sprintln("Refresh Arp entry by IfName:", ifName))
	for l3IfIdx, l3Ent := range server.l3IntfPropMap {
		if l3Ent.IfName == ifName {
			for ip, arpEnt := range server.arpCache {
				if arpEnt.L3IfIdx == l3IfIdx {
					server.processRefreshByIPAddr(ip)
				}
			}
		}
	}
}

func (server *ARPServer) processArpActionMsg(msg ArpActionMsg) {
	switch msg.Type {
	case DeleteByIPAddr:
		server.processDeleteByIPAddr(msg.Obj)
	case DeleteByIfName:
		server.processDeleteByIfName(msg.Obj)
	case RefreshByIPAddr:
		server.processRefreshByIPAddr(msg.Obj)
	case RefreshByIfName:
		server.processRefreshByIfName(msg.Obj)
	}

}

func (server *ARPServer) processAsicdMsg(msg AsicdMsg) error {
	switch msg.MsgType {
	case Create:
		_, err := server.AsicdPlugin.CreateIPv4Neighbor(msg.IpAddr, msg.MacAddr, msg.VlanId, msg.IfIdx)
		if err != nil {
			server.logger.Err(fmt.Sprintln("Asicd Create IPv4 Neighbor failed for IpAddr:", msg.IpAddr, "VlanId:", msg.VlanId, "IfIdx:", msg.IfIdx, "err:", err))
			return err
		}
	case Delete:
		_, err := server.AsicdPlugin.DeleteIPv4Neighbor(msg.IpAddr)
		if err != nil {
			server.logger.Err(fmt.Sprintln("Asicd was unable to delete neigbhor entry for", msg.IpAddr, "err:", err))
			return err
		}
	case Update:
		_, err := server.AsicdPlugin.UpdateIPv4Neighbor(msg.IpAddr, msg.MacAddr, msg.VlanId, msg.IfIdx)
		if err != nil {
			server.logger.Err(fmt.Sprintln("Asicd Update IPv4 Neighbor failed for IpAddr:", msg.IpAddr, "MacAddr:", msg.MacAddr, "VlanId:", msg.VlanId, "IfIdx:", msg.IfIdx, "err:", err))
			return err
		}
	default:
		err := errors.New("Invalid Asicd Msg Type")
		return err
	}
	return nil
}

func (server *ARPServer) processArpEntryCntUpdateMsg(cnt int) {
	for key, ent := range server.arpCache {
		if ent.Counter > cnt {
			ent.Counter = cnt
			server.arpCache[key] = ent
		}
	}
}

func (server *ARPServer) processArpEntryMacMoveMsg(msg commonDefs.IPv4NbrMacMoveNotifyMsg) {
	if entry, ok := server.arpCache[msg.IpAddr]; ok {
		entry.PortNum = int(msg.IfIndex)
		server.arpCache[msg.IpAddr] = entry
		evtKey := events.ArpEntryKey{
			IpAddr: msg.IpAddr,
		}
		evtData := EventData{
			IpAddr:  msg.IpAddr,
			MacAddr: entry.MacAddr,
			IfName:  entry.IfName,
		}
		txEvent := eventUtils.TxEvent{
			EventId:        events.ArpEntryUpdated,
			Key:            evtKey,
			AdditionalInfo: "",
			AdditionalData: evtData,
		}
		err := eventUtils.PublishEvents(&txEvent)
		if err != nil {
			server.logger.Err("Error in publishing ArpEntryUpdated Event")
		}
	} else {
		server.logger.Debug(fmt.Sprintf("Mac move message received. Neighbor IP does not exist in arp cache - %x", msg.IpAddr))
	}
}

/*
func (server *ARPServer)processArpEntryCreateMsg(msg CreateArpEntryMsg) {

}
*/

func (server *ARPServer) processArpEntryDeleteMsg(msg DeleteArpEntryMsg) {
	for key, ent := range server.arpCache {
		if msg.PortNum == ent.PortNum {
			server.logger.Debug(fmt.Sprintln("1 Calling Asicd Delete Ip:", key))
			asicdMsg := AsicdMsg{
				MsgType: Delete,
				IpAddr:  key,
			}
			err := server.processAsicdMsg(asicdMsg)
			if err != nil {
				return
			}
			delete(server.arpCache, key)
			server.deleteArpEntryInDB(key)
		}
	}

}

func (server *ARPServer) processArpEntryUpdateMsg(msg UpdateArpEntryMsg) {
	portEnt, _ := server.portPropMap[msg.PortNum]
	l3IfIdx := portEnt.L3IfIdx
	ifType := asicdCommonDefs.GetIntfTypeFromIfIndex(int32(l3IfIdx))
	ifId := asicdCommonDefs.GetIntfIdFromIfIndex(int32(l3IfIdx))
	var vlanId int
	if l3IfIdx == -1 {
		vlanId = asicdCommonDefs.SYS_RSVD_VLAN
	} else {
		_, exist := server.l3IntfPropMap[l3IfIdx]
		if !exist {
			server.logger.Err(fmt.Sprintln("Port", msg.PortNum, "doesnot belong to L3 Interface"))
			return
		}
		if ifType == commonDefs.IfTypeVlan {
			vlanId = ifId
		} else {
			vlanId = asicdCommonDefs.SYS_RSVD_VLAN
		}
	}
	arpEnt, exist := server.arpCache[msg.IpAddr]
	if exist {
		if arpEnt.MacAddr == msg.MacAddr &&
			arpEnt.PortNum == msg.PortNum &&
			arpEnt.VlanId == vlanId &&
			arpEnt.L3IfIdx == portEnt.L3IfIdx {
			arpEnt.Counter = server.timeoutCounter
			if arpEnt.MacAddr != "incomplete" {
				arpEnt.TimeStamp = time.Now()
			}
			server.arpCache[msg.IpAddr] = arpEnt
			return
		}

		if arpEnt.MacAddr != "incomplete" &&
			msg.MacAddr == "incomplete" {
			server.logger.Err(fmt.Sprintln("Neighbor", msg.IpAddr, "is already resolved at port:", arpEnt.IfName, "with MacAddr:", arpEnt.MacAddr, "vlanId:", arpEnt.VlanId))
			if msg.Type == true && arpEnt.Type != true {
				arpEnt.Type = true
				server.arpCache[msg.IpAddr] = arpEnt
			}
			return
		}
	}

	var ifIdx int32
	if portEnt.LagIfIdx == -1 {
		ifIdx = int32(msg.PortNum)
	} else {
		ifIdx = int32(portEnt.LagIfIdx)
	}
	if msg.MacAddr != "incomplete" {
		server.logger.Debug(fmt.Sprintln("3 Calling Asicd Create Ip:", msg.IpAddr, "mac:", msg.MacAddr, "vlanId:", vlanId, "IfIndex:", ifIdx))
		asicdMsg := AsicdMsg{
			MsgType: Create,
			IpAddr:  msg.IpAddr,
			MacAddr: msg.MacAddr,
			VlanId:  int32(vlanId),
			IfIdx:   ifIdx,
		}
		err := server.processAsicdMsg(asicdMsg)
		if err != nil {
			return
		}
		evtKey := events.ArpEntryKey{
			IpAddr: msg.IpAddr,
		}
		evtData := EventData{
			IpAddr:  msg.IpAddr,
			MacAddr: msg.MacAddr,
			IfName:  portEnt.IfName,
		}
		txEvent := eventUtils.TxEvent{
			EventId:        events.ArpEntryLearned,
			Key:            evtKey,
			AdditionalInfo: "",
			AdditionalData: evtData,
		}
		err = eventUtils.PublishEvents(&txEvent)
		if err != nil {
			server.logger.Err("Error in publishing ArpEntryLearned Event")
		}
	}
	if !exist {
		server.storeArpEntryInDB(msg.IpAddr, portEnt.L3IfIdx)
	}
	arpEnt.MacAddr = msg.MacAddr
	arpEnt.PortNum = msg.PortNum
	arpEnt.VlanId = vlanId
	arpEnt.IfName = portEnt.IfName
	arpEnt.L3IfIdx = portEnt.L3IfIdx
	arpEnt.Counter = server.timeoutCounter
	if arpEnt.Type == false {
		arpEnt.Type = msg.Type
	}
	if arpEnt.MacAddr != "incomplete" {
		arpEnt.TimeStamp = time.Now()
	}
	server.arpCache[msg.IpAddr] = arpEnt
	for i := 0; i < len(server.arpSlice); i++ {
		if server.arpSlice[i] == msg.IpAddr {
			return
		}
	}
	server.arpSlice = append(server.arpSlice, msg.IpAddr)
}

func (server *ARPServer) processArpCounterUpdateMsg() {
	oneMinCnt := (60 / server.timerGranularity)
	thirtySecCnt := (30 / server.timerGranularity)
	for ip, arpEnt := range server.arpCache {
		if arpEnt.Counter <= server.minCnt {
			if arpEnt.Type == false {
				server.deleteArpEntryInDB(ip)
				delete(server.arpCache, ip)
				if arpEnt.MacAddr != "incomplete" {
					server.logger.Debug(fmt.Sprintln("5 Calling Asicd Delete Ip:", ip))
					asicdMsg := AsicdMsg{
						MsgType: Delete,
						IpAddr:  ip,
					}
					err := server.processAsicdMsg(asicdMsg)
					if err != nil {
						continue
					}
					evtKey := events.ArpEntryKey{
						IpAddr: ip,
					}
					evtData := EventData{
						IpAddr:  ip,
						MacAddr: arpEnt.MacAddr,
						IfName:  arpEnt.IfName,
					}
					txEvent := eventUtils.TxEvent{
						EventId:        events.ArpEntryDeleted,
						Key:            evtKey,
						AdditionalInfo: "",
						AdditionalData: evtData,
					}
					err = eventUtils.PublishEvents(&txEvent)
					if err != nil {
						server.logger.Err("Error in publishing ArpEntryDeleted Event")
					}
				}
				server.printArpEntries()
			} else {
				server.logger.Debug(fmt.Sprintln("Nexthop", ip, " installed by Rib hence not deleting it"))
				if arpEnt.MacAddr != "incomplete" {
					server.logger.Debug(fmt.Sprintln("5 Calling Asicd Delete Ip:", ip))
					asicdMsg := AsicdMsg{
						MsgType: Delete,
						IpAddr:  ip,
					}
					err := server.processAsicdMsg(asicdMsg)
					if err != nil {
						continue
					}
				}
				server.logger.Debug(fmt.Sprintln("Reseting the counter to max", ip))
				arpEnt.MacAddr = "incomplete"
				arpEnt.Counter = server.timeoutCounter
				server.arpCache[ip] = arpEnt
			}
		} else {
			arpEnt.Counter--
			server.arpCache[ip] = arpEnt
			if arpEnt.Counter <= (server.minCnt+server.retryCnt+1) ||
				arpEnt.Counter == (server.timeoutCounter/2) ||
				arpEnt.Counter == (server.timeoutCounter/4) ||
				arpEnt.Counter == oneMinCnt ||
				arpEnt.Counter == thirtySecCnt {
				if arpEnt.MacAddr == "incomplete" {
					server.retryForArpEntry(ip, arpEnt.L3IfIdx)
				} else {
					server.refreshArpEntry(ip, arpEnt.PortNum)
				}
			} else if arpEnt.Counter <= server.timeoutCounter &&
				arpEnt.Counter > (server.timeoutCounter-server.retryCnt) &&
				arpEnt.MacAddr == "incomplete" {
				server.retryForArpEntry(ip, arpEnt.L3IfIdx)
			} else if arpEnt.Counter > (server.minCnt+server.retryCnt+1) &&
				arpEnt.MacAddr != "incomplete" {
				continue
			} else {
				if arpEnt.Type == false {
					server.deleteArpEntryInDB(ip)
					delete(server.arpCache, ip)
					server.printArpEntries()
				} else {
					server.logger.Debug(fmt.Sprintln("Nexthop", ip, " installed by Rib hence not deleting it"))
				}
			}
		}
	}
}

func (server *ARPServer) refreshArpEntry(ipAddr string, port int) {
	// TimeoutCounter set to retryCnt
	server.logger.Debug(fmt.Sprintln("Refreshing Arp entry for IP:", ipAddr, "on port:", port))
	server.sendArpReq(ipAddr, port)
}

func (server *ARPServer) retryForArpEntry(ipAddr string, l3IfIdx int) {
	ifType := asicdCommonDefs.GetIntfTypeFromIfIndex(int32(l3IfIdx))
	if ifType == commonDefs.IfTypeVlan {
		vlanEnt, _ := server.vlanPropMap[l3IfIdx]
		for port, _ := range vlanEnt.UntagPortMap {
			server.logger.Debug(fmt.Sprintln("Retry Arp entry for IP:", ipAddr, "on port:", port))
			server.sendArpReq(ipAddr, port)

		}
	} else if ifType == commonDefs.IfTypeLag {
		lagEnt, _ := server.lagPropMap[l3IfIdx]
		for port, _ := range lagEnt.PortMap {
			server.logger.Debug(fmt.Sprintln("Retry Arp entry for IP:", ipAddr, "on port:", port))
			server.sendArpReq(ipAddr, port)

		}

	} else {
		server.logger.Debug(fmt.Sprintln("Retry Arp entry for IP:", ipAddr, "on port:", l3IfIdx))
		server.sendArpReq(ipAddr, l3IfIdx)

	}
}

func (server *ARPServer) processArpSliceRefreshMsg() {
	server.logger.Debug("Refresh Arp Slice used for Getbulk")
	server.arpSlice = server.arpSlice[:0]
	server.arpSlice = nil
	server.arpSlice = make([]string, 0)
	for ip, _ := range server.arpCache {
		server.arpSlice = append(server.arpSlice, ip)
	}
	server.arpSliceRefreshDoneCh <- true
}

func (server *ARPServer) refreshArpSlice() {
	refreshArpSlicefunc := func() {
		server.arpSliceRefreshStartCh <- true
		msg := <-server.arpSliceRefreshDoneCh
		if msg == true {
			server.logger.Debug("ARP Entry refresh done")
		} else {
			server.logger.Err("ARP Entry refresh not done")
		}

		server.arpSliceRefreshTimer.Reset(server.arpSliceRefreshDuration)
	}

	server.arpSliceRefreshTimer = time.AfterFunc(server.arpSliceRefreshDuration, refreshArpSlicefunc)
}

func (server *ARPServer) arpCacheTimeout() {
	var count int
	for {
		time.Sleep(server.timeout)
		count++
		if server.dumpArpTable == true &&
			(count%60) == 0 {
			server.logger.Debug("===============Message from ARP Timeout Thread==============")
			server.printArpEntries()
			server.logger.Debug("========================================================")
			server.logger.Debug(fmt.Sprintln("Arp Slice: ", server.arpSlice))
		}
		server.arpCounterUpdateCh <- true
	}
}
