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
	"utils/commonDefs"
)

func (server *ARPServer) processResolveIPv4(conf ResolveIPv4) {
	server.logger.Debug(fmt.Sprintln("Received ResolveIPv4 call for TargetIP:", conf.TargetIP, "ifIndex:", conf.IfId))
	if conf.TargetIP == "0.0.0.0" {
		return
	}
	IfIndex := conf.IfId
	ifType := asicdCommonDefs.GetIntfTypeFromIfIndex(int32(IfIndex))
	if ifType == commonDefs.IfTypeVlan {
		server.logger.Debug("Calling UpdateArpEntryMsg ... Vlan for IfIndex", IfIndex)
		vlanEnt := server.vlanPropMap[IfIndex]
		for port, _ := range vlanEnt.UntagPortMap {
			server.arpEntryUpdateCh <- UpdateArpEntryMsg{
				PortNum: port,
				IpAddr:  conf.TargetIP,
				MacAddr: "incomplete",
				Type:    true,
			}
			server.sendArpReq(conf.TargetIP, port)
		}
	} else if ifType == commonDefs.IfTypeLag {
		server.logger.Debug("Calling UpdateArpEntryMsg ... Lag for IfIndex", IfIndex)
		lagEnt := server.lagPropMap[IfIndex]
		for port, _ := range lagEnt.PortMap {
			server.arpEntryUpdateCh <- UpdateArpEntryMsg{
				PortNum: port,
				IpAddr:  conf.TargetIP,
				MacAddr: "incomplete",
				Type:    true,
			}
			server.sendArpReq(conf.TargetIP, port)
		}
	} else if ifType == commonDefs.IfTypePort {
		server.logger.Debug("Calling UpdateArpEntryMsg ... Port for IfIndex", IfIndex)
		server.arpEntryUpdateCh <- UpdateArpEntryMsg{
			PortNum: IfIndex,
			IpAddr:  conf.TargetIP,
			MacAddr: "incomplete",
			Type:    true,
		}
		server.sendArpReq(conf.TargetIP, IfIndex)
	} else {
		server.logger.Err("Invalid ifType:", ifType)
	}
}

func (server *ARPServer) processDeleteResolvedIPv4(ipAddr string) {
	server.logger.Info(fmt.Sprintln("Delete Resolved IPv4 for ipAddr:", ipAddr))
	server.arpDeleteArpEntryFromRibCh <- ipAddr
}

func (server *ARPServer) processArpConf(conf ArpConf) (int, error) {
	server.logger.Debug(fmt.Sprintln("Received ARP Timeout Value via Configuration:", conf.RefTimeout))
	if conf.RefTimeout < server.MinRefreshTimeout {
		server.logger.Err(fmt.Sprintln("Refresh Timeout is below minimum allowed refresh timeout value of:", server.MinRefreshTimeout))
		err := errors.New("Invalid Timeout Value")
		return 0, err
	} else if conf.RefTimeout == server.ConfRefreshTimeout {
		server.logger.Err(fmt.Sprintln("Arp is already configured with Refresh Timeout Value of:", server.ConfRefreshTimeout, "(seconds)"))
		return 0, nil
	}

	server.timeoutCounter = conf.RefTimeout / server.timerGranularity
	server.arpEntryCntUpdateCh <- server.timeoutCounter
	return 0, nil
}

func (server *ARPServer) processArpAction(msg ArpActionMsg) {
	server.logger.Info(fmt.Sprintln("Processing Arp Action msg", msg))
	server.arpActionProcessCh <- msg
}
