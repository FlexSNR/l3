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

// route.go
package rib

import (
	"l3/bgp/packet"
	"net"
)

type AdjRIBDir int

const (
	AdjRIBDirIn AdjRIBDir = iota
	AdjRIBDirOut
)

type AdjRIBRoute struct {
	Neighbor         net.IP
	ProtocolFamily   uint32
	NLRI             packet.NLRI
	PathMap          map[uint32]*Path
	PolicyList       []string
	PolicyHitCounter int
	Accept           bool
}

func NewAdjRIBRoute(neighbor net.IP, protoFamily uint32, nlri packet.NLRI) *AdjRIBRoute {
	return &AdjRIBRoute{
		Neighbor:         neighbor,
		ProtocolFamily:   protoFamily,
		NLRI:             nlri,
		PathMap:          make(map[uint32]*Path),
		PolicyList:       make([]string, 0),
		PolicyHitCounter: 0,
		Accept:           false,
	}
}

func (a *AdjRIBRoute) AddPath(pathId uint32, path *Path) {
	a.PathMap[pathId] = path
}

func (a *AdjRIBRoute) RemovePath(pathId uint32) {
	delete(a.PathMap, pathId)
}

func (a *AdjRIBRoute) GetPath(pathId uint32) *Path {
	return a.PathMap[pathId]
}

func (a *AdjRIBRoute) DoesPathsExist() bool {
	return len(a.PathMap) != 0
}

func (a *AdjRIBRoute) GetPathMap() map[uint32]*Path {
	return a.PathMap
}

func (a *AdjRIBRoute) RemoveAllPaths() {
	a.PathMap = nil
	a.PathMap = make(map[uint32]*Path)
}

type FilteredRoutes struct {
	Add    []packet.NLRI
	Remove []packet.NLRI
}

func NewFilteredRoutes() *FilteredRoutes {
	f := FilteredRoutes{
		Add:    make([]packet.NLRI, 0),
		Remove: make([]packet.NLRI, 0),
	}

	return &f
}
