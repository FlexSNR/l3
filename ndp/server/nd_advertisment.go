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
	"l3/ndp/config"
	"l3/ndp/packet"
)

/*
 * When we get advertisement packet we need to update the mac address of peer and move the state to
 * REACHABLE
 *
 * If srcIP is my own IP then linux is responding for earlier solicitation message and hence we need to update
 * our cache entry with reachable
 * If srcIP is peer ip then we need to use dst ip to get link information and then update cache entry to be
 * reachable and also update peer mac address into the cache
 * @TODO: handle un-solicited Neighbor Advertisemtn
 */
func (intf *Interface) processNA(ndInfo *packet.NDInfo) (nbrInfo *config.NeighborConfig, oper NDP_OPERATION) {
	if ndInfo.SrcIp == intf.linkScope || ndInfo.SrcIp == intf.globalScope {
		// NA was generated locally or it is multicast-solicitation message
		return nil, IGNORE
	}
	nbrKey := intf.createNbrKey(ndInfo)
	if !intf.validNbrKey(nbrKey) {
		return nil, IGNORE
	}
	nbr, exists := intf.Neighbor[nbrKey]
	if exists {
		// update existing neighbor timers and move
		nbr.UpdateProbe()
		nbr.RchTimer()
		oper = UPDATE
	} else {
		// create new neighbor
		nbr.InitCache(intf.reachableTime, intf.retransTime, nbrKey, intf.PktDataCh, intf.IfIndex)
		oper = CREATE
	}
	nbr.State = REACHABLE
	nbrInfo = nbr.populateNbrInfo(intf.IfIndex, intf.IntfRef)
	nbr.updatePktRxStateInfo()
	intf.Neighbor[nbrKey] = nbr
	return nbrInfo, oper
}
