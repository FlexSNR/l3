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
	"utils/commonDefs"
)

func (server *ARPServer) processAsicdNotification(msg commonDefs.AsicdNotifyMsg) {
	switch msg.(type) {
	case commonDefs.L2IntfStateNotifyMsg:
		l2Msg := msg.(commonDefs.L2IntfStateNotifyMsg)
		server.processL2StateChange(l2Msg)
	case commonDefs.IPv4L3IntfStateNotifyMsg:
		l3Msg := msg.(commonDefs.IPv4L3IntfStateNotifyMsg)
		server.processIPv4L3StateChange(l3Msg)
	case commonDefs.VlanNotifyMsg:
		vlanMsg := msg.(commonDefs.VlanNotifyMsg)
		server.updateVlanInfra(vlanMsg)
	case commonDefs.LagNotifyMsg:
		lagMsg := msg.(commonDefs.LagNotifyMsg)
		server.updateLagInfra(lagMsg)
	case commonDefs.IPv4IntfNotifyMsg:
		ipv4Msg := msg.(commonDefs.IPv4IntfNotifyMsg)
		server.updateIpv4Infra(ipv4Msg)
	case commonDefs.IPv4NbrMacMoveNotifyMsg:
		macMoveMsg := msg.(commonDefs.IPv4NbrMacMoveNotifyMsg)
		server.processIPv4NbrMacMove(macMoveMsg)
	}
}
