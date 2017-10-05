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
	"asicdServices"
	"bytes"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"net"
	"strconv"
	"strings"
	"time"
)

type VrrpFsmIntf interface {
	VrrpFsmStart(fsmObj VrrpFsm)
	VrrpCreateObject(gblInfo VrrpGlobalInfo) (fsmObj VrrpFsm)
	VrrpInitState(key string)
	VrrpBackupState(inPkt gopacket.Packet, vrrpHdr *VrrpPktHeader, key string)
	VrrpMasterState(inPkt gopacket.Packet, vrrpHdr *VrrpPktHeader, key string)
	VrrpTransitionToMaster(key string, reason string)
	VrrpTransitionToBackup(key string, AdvertisementInterval int32, reason string)
	VrrpHandleIntfUpEvent(IfIndex int32)
	VrrpHandleIntfShutdownEvent(IfIndex int32)
}

/*
			   +---------------+
		+--------->|               |<-------------+
		|          |  Initialize   |              |
		|   +------|               |----------+   |
		|   |      +---------------+          |   |
		|   |                                 |   |
		|   V                                 V   |
	+---------------+                       +---------------+
	|               |---------------------->|               |
	|    Master     |                       |    Backup     |
	|               |<----------------------|               |
	+---------------+                       +---------------+

*/

func (svr *VrrpServer) VrrpCreateObject(gblInfo VrrpGlobalInfo) (fsmObj VrrpFsm) {
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

	return VrrpFsm{
		vrrpHdr: &vrrpHeader,
	}
}

/*
 * This API will create config object with MacAddr and configure....
 * Configure will enable/disable the link...
 */
func (svr *VrrpServer) VrrpUpdateSubIntf(gblInfo VrrpGlobalInfo, configure bool) {
	vip := gblInfo.IntfConfig.VirtualIPv4Addr
	if !strings.Contains(vip, "/") {
		vip = vip + "/32"
	}
	config := asicdServices.SubIPv4Intf{
		IpAddr:  vip,
		IntfRef: strconv.Itoa(int(gblInfo.IntfConfig.IfIndex)),
		Enable:  configure,
		MacAddr: gblInfo.VirtualRouterMACAddress,
	}
	svr.logger.Info(fmt.Sprintln("updating sub interface config obj is", config))
	/*
		struct SubIPv4Intf {
			0 1 : string IpAddr
			1 2 : i32 IfIndex
			2 3 : string Type
			3 4 : string MacAddr
			4 5 : bool Enable
		}
	*/
	var attrset []bool
	// The len of attrset is set to 5 for 5 elements in the object...
	// if no.of elements changes then index for mac address and enable needs
	// to change..
	attrset = make([]bool, 5)
	elems := len(attrset)
	attrset[elems-1] = true
	if configure {
		attrset[elems-2] = true
	}
	_, err := svr.asicdClient.ClientHdl.UpdateSubIPv4Intf(&config, &config,
		attrset, nil)
	if err != nil {
		svr.logger.Err(fmt.Sprintln("updating sub interface config failed",
			"Error:", err))
	}
	return
}

func (svr *VrrpServer) VrrpUpdateStateInfo(key string, reason string,
	currentSt string) {
	gblInfo, exists := svr.vrrpGblInfo[key]
	if !exists {
		svr.logger.Err("No entry found ending fsm")
		return
	}
	gblInfo.StateInfoLock.Lock()
	gblInfo.StateInfo.CurrentFsmState = currentSt
	gblInfo.StateNameLock.Lock()
	gblInfo.StateInfo.PreviousFsmState = gblInfo.StateName
	gblInfo.StateNameLock.Unlock()
	gblInfo.StateInfo.ReasonForTransition = reason
	gblInfo.StateInfoLock.Unlock()
	svr.vrrpGblInfo[key] = gblInfo
}

func (svr *VrrpServer) VrrpHandleMasterAdverTimer(key string) {
	var timerCheck_func func()
	timerCheck_func = func() {
		// Send advertisment every time interval expiration
		svr.vrrpTxPktCh <- VrrpTxChannelInfo{
			key:      key,
			priority: VRRP_IGNORE_PRIORITY,
		}
		<-svr.vrrpPktSend
		gblInfo, exists := svr.vrrpGblInfo[key]
		if !exists {
			svr.logger.Err("Gbl Config for " + key + " doesn't exists")
			return
		}
		gblInfo.AdverTimer.Reset(
			time.Duration(gblInfo.IntfConfig.AdvertisementInterval) *
				time.Second)
		svr.vrrpGblInfo[key] = gblInfo
	}
	gblInfo, exists := svr.vrrpGblInfo[key]
	if exists {
		svr.logger.Info(fmt.Sprintln("setting adver timer to",
			gblInfo.IntfConfig.AdvertisementInterval))
		// Set Timer expire func...
		gblInfo.AdverTimer = time.AfterFunc(
			time.Duration(gblInfo.IntfConfig.AdvertisementInterval)*time.Second,
			timerCheck_func)
		// (145) + Transition to the {Master} state
		gblInfo.StateNameLock.Lock()
		gblInfo.StateName = VRRP_MASTER_STATE
		gblInfo.StateNameLock.Unlock()
		svr.vrrpGblInfo[key] = gblInfo
	}
}

func (svr *VrrpServer) VrrpTransitionToMaster(key string, reason string) {
	// (110) + Send an ADVERTISEMENT
	svr.vrrpTxPktCh <- VrrpTxChannelInfo{
		key:      key,
		priority: VRRP_IGNORE_PRIORITY,
	}
	// Wait for the packet to be send out
	<-svr.vrrpPktSend
	// After Advertisment update fsm state info
	svr.VrrpUpdateStateInfo(key, reason, VRRP_MASTER_STATE)

	gblInfo, exists := svr.vrrpGblInfo[key]
	if !exists {
		svr.logger.Err("No entry found ending fsm")
		return
	}
	// Set Sub-intf state up and send out garp via linux stack
	svr.VrrpUpdateSubIntf(gblInfo, true /*configure or set*/)
	// (140) + Set the Adver_Timer to Advertisement_Interval
	// Start Advertisement Timer
	svr.VrrpHandleMasterAdverTimer(key)
}

func (svr *VrrpServer) VrrpHandleMasterDownTimer(key string) {
	gblInfo, exists := svr.vrrpGblInfo[key]
	if !exists {
		svr.logger.Err("No object for " + key)
		return
	}
	if gblInfo.MasterDownTimer != nil {
		gblInfo.MasterDownLock.Lock()
		gblInfo.MasterDownTimer.Reset(time.Duration(gblInfo.MasterDownValue) *
			time.Second)
		gblInfo.MasterDownLock.Unlock()
	} else {
		var timerCheck_func func()
		// On Timer expiration we will transition to master
		timerCheck_func = func() {
			svr.logger.Info(fmt.Sprintln("master down timer",
				"expired..transition to Master"))
			// do timer expiry handling here
			svr.VrrpTransitionToMaster(key, "Master Down Timer expired")
		}
		svr.logger.Info("initiating master down timer")
		svr.logger.Info(fmt.Sprintln("setting down timer to",
			gblInfo.MasterDownValue))
		// Set Timer expire func...
		gblInfo.MasterDownLock.Lock()
		gblInfo.MasterDownTimer = time.AfterFunc(
			time.Duration(gblInfo.MasterDownValue)*time.Second,
			timerCheck_func)
		gblInfo.MasterDownLock.Unlock()
	}
	//(165) + Transition to the {Backup} state
	gblInfo.StateNameLock.Lock()
	gblInfo.StateName = VRRP_BACKUP_STATE
	gblInfo.StateNameLock.Unlock()
	svr.vrrpGblInfo[key] = gblInfo
}

func (svr *VrrpServer) VrrpCalculateDownValue(AdvertisementInterval int32,
	gblInfo *VrrpGlobalInfo) {
	//(155) + Set Master_Adver_Interval to Advertisement_Interval
	gblInfo.MasterAdverInterval = AdvertisementInterval
	//(160) + Set the Master_Down_Timer to Master_Down_Interval
	if gblInfo.IntfConfig.Priority != 0 && gblInfo.MasterAdverInterval != 0 {
		gblInfo.SkewTime = ((256 - gblInfo.IntfConfig.Priority) *
			gblInfo.MasterAdverInterval) / 256
	}
	gblInfo.MasterDownValue = (3 * gblInfo.MasterAdverInterval) + gblInfo.SkewTime
}

func (svr *VrrpServer) VrrpTransitionToBackup(key string, AdvertisementInterval int32,
	reason string) {
	svr.logger.Info(fmt.Sprintln("advertisement timer to be used in backup state for",
		"calculating master down timer is ", AdvertisementInterval))
	gblInfo, exists := svr.vrrpGblInfo[key]
	if !exists {
		svr.logger.Err("No entry found ending fsm")
		return
	}
	// Bring Down Sub-Interface
	svr.VrrpUpdateSubIntf(gblInfo, false /*configure or set*/)
	// Re-Calculate Down timer value
	gblInfo.MasterDownLock.Lock()
	svr.VrrpCalculateDownValue(AdvertisementInterval, &gblInfo)
	gblInfo.MasterDownLock.Unlock()
	svr.vrrpGblInfo[key] = gblInfo
	svr.VrrpUpdateStateInfo(key, reason, VRRP_BACKUP_STATE)
	svr.VrrpHandleMasterDownTimer(key)
}

func (svr *VrrpServer) VrrpInitState(key string) {
	svr.logger.Info("in init state decide next state")
	gblInfo, found := svr.vrrpGblInfo[key]
	if !found {
		svr.logger.Err("running info not found, bailing fsm")
		return
	}
	if gblInfo.IntfConfig.Priority == VRRP_MASTER_PRIORITY {
		svr.logger.Info("Transitioning to Master State")
		svr.VrrpTransitionToMaster(key, "Priority is 255")
	} else {
		svr.logger.Info("Transitioning to Backup State")
		// Transition to backup state first
		svr.VrrpTransitionToBackup(key,
			gblInfo.IntfConfig.AdvertisementInterval,
			"Priority is not 255")
	}
}

func (svr *VrrpServer) VrrpBackupState(inPkt gopacket.Packet, vrrpHdr *VrrpPktHeader,
	key string) {
	// @TODO: Handle arp drop...
	// Check dmac address from the inPacket and if it is same discard the packet
	ethLayer := inPkt.Layer(layers.LayerTypeEthernet)
	if ethLayer == nil {
		svr.logger.Err("Not an eth packet?")
		return
	}
	eth := ethLayer.(*layers.Ethernet)
	gblInfo, exists := svr.vrrpGblInfo[key]
	if !exists {
		svr.logger.Err("No entry found ending fsm")
		return
	}
	if (eth.DstMAC).String() == gblInfo.VirtualRouterMACAddress {
		svr.logger.Err("Dmac is equal to VMac and hence fsm is aborted")
		return
	}
	// MUST NOT accept packets addressed to the IPvX address(es)
	// associated with the virtual router. @TODO: check with Hari
	ipLayer := inPkt.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		svr.logger.Err("Not an ip packet?")
		return
	}
	ipHdr := ipLayer.(*layers.IPv4)
	if (ipHdr.DstIP).String() == gblInfo.IpAddr {
		svr.logger.Err("dst ip is equal to interface ip, drop the packet")
		return
	}

	if vrrpHdr.Type == VRRP_PKT_TYPE_ADVERTISEMENT {
		gblInfo.StateInfoLock.Lock()
		gblInfo.StateInfo.MasterIp = ipHdr.SrcIP.String()
		gblInfo.StateInfo.AdverRx++
		gblInfo.StateInfo.LastAdverRx = time.Now().String()
		gblInfo.StateInfo.CurrentFsmState = gblInfo.StateName
		gblInfo.StateInfoLock.Unlock()
		svr.vrrpGblInfo[key] = gblInfo
		if vrrpHdr.Priority == 0 {
			// Change down Value to Skew time
			gblInfo.MasterDownLock.Lock()
			gblInfo.MasterDownValue = gblInfo.SkewTime
			gblInfo.MasterDownLock.Unlock()
			svr.vrrpGblInfo[key] = gblInfo
			svr.VrrpHandleMasterDownTimer(key)
		} else {
			// local preempt is false
			if gblInfo.IntfConfig.PreemptMode == false {
				// if remote priority is higher update master down
				// timer and move on
				if vrrpHdr.Priority >= uint8(gblInfo.IntfConfig.Priority) {
					gblInfo.MasterDownLock.Lock()
					svr.VrrpCalculateDownValue(int32(vrrpHdr.MaxAdverInt),
						&gblInfo)
					gblInfo.MasterDownLock.Unlock()
					svr.vrrpGblInfo[key] = gblInfo
					svr.VrrpHandleMasterDownTimer(key)
				} else {
					// Do nothing.... same as discarding packet
					svr.logger.Info("Discarding advertisment")
					return
				}
			} else { // local preempt is true
				if vrrpHdr.Priority >= uint8(gblInfo.IntfConfig.Priority) {
					// Do nothing..... same as discarding packet
					svr.logger.Info("Discarding advertisment")
					return
				} else { // Preempt is true... need to take over
					// as master
					svr.VrrpTransitionToMaster(key,
						"Preempt is true and local Priority is higher than remote")
				}
			} // endif preempt test
		} // endif was priority zero
	} // endif was advertisement received
	// end BACKUP STATE
}

func (svr *VrrpServer) VrrpMasterState(inPkt gopacket.Packet, vrrpHdr *VrrpPktHeader,
	key string) {
	/* // @TODO:
	   (645) - MUST forward packets with a destination link-layer MAC
	   address equal to the virtual router MAC address.

	   (650) - MUST accept packets addressed to the IPvX address(es)
	   associated with the virtual router if it is the IPvX address owner
	   or if Accept_Mode is True.  Otherwise, MUST NOT accept these
	   packets.
	*/
	if vrrpHdr.Priority == VRRP_MASTER_DOWN_PRIORITY {
		svr.vrrpTxPktCh <- VrrpTxChannelInfo{
			key:      key,
			priority: VRRP_IGNORE_PRIORITY,
		}
		<-svr.vrrpPktSend
		svr.VrrpHandleMasterAdverTimer(key)
	} else {
		ipLayer := inPkt.Layer(layers.LayerTypeIPv4)
		if ipLayer == nil {
			svr.logger.Err("Not an ip packet?")
			return
		}
		ipHdr := ipLayer.(*layers.IPv4)
		gblInfo, exists := svr.vrrpGblInfo[key]
		if !exists {
			svr.logger.Err("No entry found ending fsm")
			return
		}
		if int32(vrrpHdr.Priority) > gblInfo.IntfConfig.Priority ||
			(int32(vrrpHdr.Priority) == gblInfo.IntfConfig.Priority &&
				bytes.Compare(ipHdr.SrcIP,
					net.ParseIP(gblInfo.IpAddr)) > 0) {
			if gblInfo.AdverTimer != nil {
				gblInfo.AdverTimer.Stop()
			}
			svr.vrrpGblInfo[key] = gblInfo
			svr.VrrpTransitionToBackup(key, int32(vrrpHdr.MaxAdverInt),
				"Remote Priority is higher OR (priority are equal AND remote ip is higher than local ip)")
		} else { // new Master logic
			// Discard Advertisement
			return
		} // endif new Master Detected
	} // end if was priority zero
	// end for Advertisemtn received over the channel
	// end MASTER STATE
}

func (svr *VrrpServer) VrrpFsmStart(fsmObj VrrpFsm) {
	key := fsmObj.key
	pktInfo := fsmObj.inPkt
	pktHdr := fsmObj.vrrpHdr
	gblInfo, exists := svr.vrrpGblInfo[key]
	if !exists {
		svr.logger.Err("No entry found ending fsm")
		return
	}
	gblInfo.StateNameLock.Lock()
	currentState := gblInfo.StateName
	gblInfo.StateNameLock.Unlock()
	switch currentState {
	case VRRP_INITIALIZE_STATE:
		svr.VrrpInitState(key)
	case VRRP_BACKUP_STATE:
		svr.VrrpBackupState(pktInfo, pktHdr, key)
	case VRRP_MASTER_STATE:
		svr.VrrpMasterState(pktInfo, pktHdr, key)
	default: // VRRP_UNINTIALIZE_STATE
		svr.logger.Info("No Ip address and hence no need for fsm")
	}
}

/*
 * During a shutdown event stop timers will be called and we will cancel master
 * down timer and transition to initialize state
 */
func (svr *VrrpServer) VrrpStopTimers(IfIndex int32) {
	for _, key := range svr.vrrpIntfStateSlice {
		splitString := strings.Split(key, "_")
		// splitString = { IfIndex, VRID }
		ifindex, _ := strconv.Atoi(splitString[0])
		if int32(ifindex) != IfIndex {
			// Key doesn't match
			continue
		}
		// If IfIndex matches then use that key and stop the timer for
		// that VRID
		gblInfo, found := svr.vrrpGblInfo[key]
		if !found {
			svr.logger.Err("No entry found for Ifindex:" +
				splitString[0] + " VRID:" + splitString[1])
			return
		}
		svr.logger.Info("Stopping Master Down Timer for Ifindex:" +
			splitString[0] + " VRID:" + splitString[1])
		if gblInfo.MasterDownTimer != nil {
			gblInfo.MasterDownTimer.Stop()
		}
		svr.logger.Info("Stopping Master Advertisemen Timer for Ifindex:" +
			splitString[0] + " VRID:" + splitString[1])
		if gblInfo.AdverTimer != nil {
			gblInfo.AdverTimer.Stop()
		}
		// If state is Master then we need to send an advertisement with
		// priority as 0
		gblInfo.StateNameLock.RLock()
		state := gblInfo.StateName
		gblInfo.StateNameLock.RUnlock()
		if state == VRRP_MASTER_STATE {
			svr.vrrpTxPktCh <- VrrpTxChannelInfo{
				key:      key,
				priority: VRRP_MASTER_DOWN_PRIORITY,
			}
			<-svr.vrrpPktSend
		}
		// Transition to Init State
		gblInfo.StateNameLock.Lock()
		gblInfo.StateName = VRRP_INITIALIZE_STATE
		gblInfo.StateNameLock.Unlock()
		svr.vrrpGblInfo[key] = gblInfo
		svr.logger.Info(fmt.Sprintln("VRID:", gblInfo.IntfConfig.VRID,
			" transitioned to INIT State"))
	}
}

func (svr *VrrpServer) VrrpHandleIntfShutdownEvent(IfIndex int32) {
	svr.VrrpStopTimers(IfIndex)
}

func (svr *VrrpServer) VrrpHandleIntfUpEvent(IfIndex int32) {
	for _, key := range svr.vrrpIntfStateSlice {
		splitString := strings.Split(key, "_")
		// splitString = { IfIndex, VRID }
		ifindex, _ := strconv.Atoi(splitString[0])
		if int32(ifindex) != IfIndex {
			// Key doesn't match
			continue
		}
		// If IfIndex matches then use that key and stop the timer for
		// that VRID
		gblInfo, found := svr.vrrpGblInfo[key]
		if !found {
			svr.logger.Err("No entry found for Ifindex:" +
				splitString[0] + " VRID:" + splitString[1])
			return
		}

		svr.logger.Info(fmt.Sprintln("Intf State Up Notification",
			" restarting the fsm event for VRID:", gblInfo.IntfConfig.VRID))
		svr.vrrpFsmCh <- VrrpFsm{
			key: key,
		}
	}
}
