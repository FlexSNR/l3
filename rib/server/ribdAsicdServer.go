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

// ribdAsicdServer.go
package server

import (
	"asicdInt"
	"asicdServices"
	//"fmt"
	"l3/rib/ribdCommonDefs"
)

var asicdBulkCount = 30000
var asicdv4RouteCount = 0
var asicdv4Routes []*asicdInt.IPv4Route
var asicdv4Route []asicdInt.IPv4Route
var asicdv6Route []asicdInt.IPv6Route

type Linklocaldata struct{}

var V6linklocalIPMap = make(map[string]Linklocaldata)

func addAsicdRouteBulk(routeInfoRecord RouteInfoRecord, bulkEnd bool) {
	logger.Info("addAsicdRouteBulk, bulkEnd:", bulkEnd)
	if asicdclnt.IsConnected == false {
		return
	}
	ipType := ""
	if routeInfoRecord.ipType == ribdCommonDefs.IPv4 {
		ipType = "IPv4"
	} else if routeInfoRecord.ipType == ribdCommonDefs.IPv6 {
		ipType = "IPv6"
	}
	logger.Info("addAsicdRoute, weight = ", routeInfoRecord.weight+1, " ipType:", ipType)
	if routeInfoRecord.ipType == ribdCommonDefs.IPv4 {
		if asicdv4RouteCount == 0 {
			asicdv4Routes = make([]*asicdInt.IPv4Route, 0)
		}
		asicdv4Routes = append(asicdv4Routes,
			&asicdInt.IPv4Route{
				routeInfoRecord.destNetIp.String(),
				routeInfoRecord.networkMask.String(),
				[]*asicdInt.IPv4NextHop{
					&asicdInt.IPv4NextHop{
						NextHopIp: routeInfoRecord.resolvedNextHopIpIntf.NextHopIp,
						Weight:    int32(routeInfoRecord.weight + 1),
					},
				},
			})
		asicdv4RouteCount++
		if asicdv4RouteCount == asicdBulkCount || bulkEnd {
			asicdclnt.ClientHdl.OnewayCreateIPv4Route(asicdv4Routes)
			asicdv4Routes = nil
			asicdv4RouteCount = 0
		}
	} else if routeInfoRecord.ipType == ribdCommonDefs.IPv6 {
	}
}
func addAsicdRoute(routeInfoRecord RouteInfoRecord) {
	if asicdclnt.IsConnected == false {
		return
	}
	/*	ipType := ""
		if routeInfoRecord.ipType == ribdCommonDefs.IPv4 {
			ipType = "IPv4"
		} else if routeInfoRecord.ipType == ribdCommonDefs.IPv6 {
			ipType = "IPv6"
		}
		logger.Info("addAsicdRoute, weight = ", routeInfoRecord.weight+1, " ipType:", ipType)*/
	if routeInfoRecord.ipType == ribdCommonDefs.IPv4 {
		//logger.Info("ipv4 route, calling onewaycreateipv4 route")
		/*	asicdRoute = make([]asicdInt.IPv4Route, asicdBulkCount)
			if asicdRouteCount == 0 {
				asicdRoutes = make([]*asicdInt.IPv4Route, 0)
			}
			asicdRoute[asicdRouteCount] = asicdInt.IPv4Route{
				routeInfoRecord.destNetIp.String(),
				routeInfoRecord.networkMask.String(),
				[]*asicdInt.IPv4NextHop{
					&asicdInt.IPv4NextHop{
						NextHopIp: routeInfoRecord.resolvedNextHopIpIntf.NextHopIp,
						Weight:    int32(routeInfoRecord.weight + 1),
					},
				},
			}
			asicdRoutes = append(asicdRoutes, &asicdRoute[asicdRouteCount])
			asicdRouteCount++
			if asicdRouteCount == asicdBulkCount {
				asicdclnt.ClientHdl.OnewayCreateIPv4Route(asicdRoutes)
				asicdRoutes = nil
				asicdRouteCount = 0
			}*/
		asicdclnt.ClientHdl.OnewayCreateIPv4Route([]*asicdInt.IPv4Route{
			&asicdInt.IPv4Route{
				routeInfoRecord.destNetIp.String(),
				routeInfoRecord.networkMask.String(),
				[]*asicdInt.IPv4NextHop{
					&asicdInt.IPv4NextHop{
						NextHopIp: routeInfoRecord.resolvedNextHopIpIntf.NextHopIp,
						Weight:    int32(routeInfoRecord.weight + 1),
					},
				},
			},
		})
	} else if routeInfoRecord.ipType == ribdCommonDefs.IPv6 {
		add := true
		//fmt.Println("RIBD addAsicdRoute: ipv6 address add for ", routeInfoRecord.destNetIp.String())
		if routeInfoRecord.destNetIp.IsLinkLocalUnicast() {
			//fmt.Println("RIBD addAsicdRoute: link local unicast ipv6 during add in asicdaddroute for ", routeInfoRecord.destNetIp.String())
			if len(V6linklocalIPMap) > 0 {
				//fmt.Println("RIBD addAsicdRoute ", routeInfoRecord.destNetIp.String(), " is not the first link local ip, there are already ", len(V6linklocalIPMap), " addresses ")
				add = false
			}
			empty := Linklocaldata{}
			V6linklocalIPMap[routeInfoRecord.destNetIp.String()] = empty
		}
		if add {
			//fmt.Println("RIBD addAsicdRoute: add set to true, send add address to asicd for ", routeInfoRecord.destNetIp.String())
			asicdclnt.ClientHdl.OnewayCreateIPv6Route([]*asicdInt.IPv6Route{
				&asicdInt.IPv6Route{
					routeInfoRecord.destNetIp.String(),
					routeInfoRecord.networkMask.String(),
					[]*asicdInt.IPv6NextHop{
						&asicdInt.IPv6NextHop{
							NextHopIp: routeInfoRecord.resolvedNextHopIpIntf.NextHopIp,
							Weight:    int32(routeInfoRecord.weight + 1),
						},
					},
				},
			})
		}
	}
}
func delAsicdRoute(routeInfoRecord RouteInfoRecord) {
	if asicdclnt.IsConnected == false {
		return
	}
	logger.Info("delAsicdRoute with ipType ", routeInfoRecord.ipType)
	if routeInfoRecord.ipType == ribdCommonDefs.IPv4 {
		asicdclnt.ClientHdl.OnewayDeleteIPv4Route([]*asicdInt.IPv4Route{
			&asicdInt.IPv4Route{
				routeInfoRecord.destNetIp.String(),
				routeInfoRecord.networkMask.String(),
				[]*asicdInt.IPv4NextHop{
					&asicdInt.IPv4NextHop{
						NextHopIp: routeInfoRecord.resolvedNextHopIpIntf.NextHopIp,
						Weight:    int32(routeInfoRecord.weight + 1),
						//NextHopIfType: int32(routeInfoRecord.resolvedNextHopIpIntf.NextHopIfType),
					},
				},
			},
		})
	} else if routeInfoRecord.ipType == ribdCommonDefs.IPv6 {
		del := true
		//fmt.Println("RIBD delAsicdRoute: delete asicd address:", routeInfoRecord.destNetIp.String())
		if routeInfoRecord.destNetIp.IsLinkLocalUnicast() {
			//fmt.Println("RIBD delAsicdRoute:link local unicast ipv6:", routeInfoRecord.destNetIp.String())
			delete(V6linklocalIPMap, routeInfoRecord.destNetIp.String())
			//fmt.Println("RIBD delAsicdRoute: deleted map entry for ", routeInfoRecord.destNetIp.String(), " len of v6linklocalmap:", len(V6linklocalIPMap))
			if len(V6linklocalIPMap) > 0 {
				//fmt.Println("RIBD delAsicdRoute:link local routes still configured, so do not delete this route: ", routeInfoRecord.destNetIp.String(), "from ASICd")
				del = false
			}
		}
		if del {
			//fmt.Sprintln("RIBD delAsicdRoute:del is true, calling delasicdroute for ", routeInfoRecord.destNetIp.String())
			asicdclnt.ClientHdl.OnewayDeleteIPv6Route([]*asicdInt.IPv6Route{
				&asicdInt.IPv6Route{
					routeInfoRecord.destNetIp.String(),
					routeInfoRecord.networkMask.String(),
					[]*asicdInt.IPv6NextHop{
						&asicdInt.IPv6NextHop{
							NextHopIp: routeInfoRecord.resolvedNextHopIpIntf.NextHopIp,
							Weight:    int32(routeInfoRecord.weight + 1),
							//NextHopIfType: int32(routeInfoRecord.resolvedNextHopIpIntf.NextHopIfType),
						},
					},
				},
			})
		}
	}
}
func (m RIBDServer) GetV4ConnectedRoutes() {
	logger.Info("Getting v4 Intfs from asicd")
	var currMarker asicdServices.Int
	var count asicdServices.Int
	ipv4IntfList := make([]*asicdServices.IPv4IntfState, 0)
	count = 100
	ret_count := 0
	for {
		IPIntfBulk, err := asicdclnt.ClientHdl.GetBulkIPv4IntfState(currMarker, count)
		if err != nil {
			logger.Debug("GetBulkIPv4IntfState with err ", err)
			break
		}
		if IPIntfBulk.Count == 0 {
			logger.Info("0 objects returned from GetBulkIPv4IntfState")
			break
		}
		//logger.Info("len(IPIntfBulk.IPv4IntfStateList)  = ", len(IPIntfBulk.IPv4IntfStateList), " num objects returned = ", IPIntfBulk.Count)
		ret_count = ret_count + int(IPIntfBulk.Count)
		ipv4IntfList = append(ipv4IntfList, IPIntfBulk.IPv4IntfStateList...)
		if IPIntfBulk.More == false {
			logger.Debug("more returned as false, so no more get bulks")
			break
		}
		currMarker = asicdServices.Int(IPIntfBulk.EndIdx)
	}
	m.V4IntfsGetDone <- V4IntfGetInfo{ret_count, ipv4IntfList}
}

func (m RIBDServer) GetV6ConnectedRoutes() {
	logger.Info("Getting v6  intfs from asicd")
	var currMarker asicdServices.Int
	var count asicdServices.Int
	ipv6IntfList := make([]*asicdServices.IPv6IntfState, 0)
	count = 100
	ret_count := 0
	for {
		IPIntfBulk, err := asicdclnt.ClientHdl.GetBulkIPv6IntfState(currMarker, count)
		if err != nil {
			logger.Debug("GetBulkIPv6IntfState with err ", err)
			break
		}
		if IPIntfBulk.Count == 0 {
			logger.Info("0 objects returned from GetBulkIPv6IntfState")
			break
		}
		logger.Info("len(IPIntfBulk.IPv6IntfStateList)  = ", len(IPIntfBulk.IPv6IntfStateList), " num objects returned = ", IPIntfBulk.Count)
		ret_count = ret_count + int(IPIntfBulk.Count)
		ipv6IntfList = append(ipv6IntfList, IPIntfBulk.IPv6IntfStateList...)
		if IPIntfBulk.More == false {
			logger.Debug("more returned as false, so no more get bulks")
			break
		}
		currMarker = asicdServices.Int(IPIntfBulk.EndIdx)
	}
	m.V6IntfsGetDone <- V6IntfGetInfo{ret_count, ipv6IntfList}
}

func (ribdServiceHandler *RIBDServer) StartAsicdServer() {
	logger.Info("Starting the asicdserver loop")
	asicdv4Route = make([]asicdInt.IPv4Route, asicdBulkCount)
	asicdv6Route = make([]asicdInt.IPv6Route, asicdBulkCount)
	for {
		select {
		case route := <-ribdServiceHandler.AsicdRouteCh:
			logger.Info(" received message on AsicdRouteCh, op:", route.Op)
			if route.Op == "add" {
				if route.Bulk {
					addAsicdRouteBulk(route.OrigConfigObject.(RouteInfoRecord), route.BulkEnd)
				} else {
					addAsicdRoute(route.OrigConfigObject.(RouteInfoRecord))
				}
			} else if route.Op == "del" {
				delAsicdRoute(route.OrigConfigObject.(RouteInfoRecord))
			} else if route.Op == "fetchv4" {
				logger.Info("AsicdServer loop fetchv4, call getv4connectedroutes")
				ribdServiceHandler.GetV4ConnectedRoutes()
			} else if route.Op == "fetchv6" {
				logger.Info("AsicdServer loop fetchv6, call getv6connectedroutes")
				ribdServiceHandler.GetV6ConnectedRoutes()
			}
		}
	}
}
