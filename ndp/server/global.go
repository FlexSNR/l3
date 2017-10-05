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
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"l3/ndp/config"
	"l3/ndp/packet"
	"sync"
	"time"
	"utils/asicdClient" // this is switch plugin need to change the name
	"utils/dmnBase"
)

type RxPktInfo struct {
	pkt     gopacket.Packet
	ifIndex int32
}

type NdpConfig struct {
	Vrf               string
	ReachableTime     uint32
	RetransTime       uint32
	RaRestransmitTime uint8
}

type L3Info struct {
	Name     string
	IfIndex  int32
	PortType string // tag or untag
}

type PhyPort struct {
	RX   *pcap.Handle
	Info config.PortInfo
	L3   L3Info
}

type NDPServer struct {
	NdpConfig                                // base config
	dmnBase      *dmnBase.FSBaseDmn          // base Daemon
	SwitchPlugin asicdClient.AsicdClientIntf // asicd plugin

	// System Ports information, key is IntfRef
	L2Port              map[int32]PhyPort                //config.PortInfo        // key is l2 ifIndex
	L3Port              map[int32]Interface              // key is l3 ifIndex
	VlanInfo            map[int32]config.VlanInfo        // key is vlanId
	VlanIfIdxVlanIdMap  map[string]int32                 //reverse map for vlanName ----> vlanId, used during ipv6 neig create
	SwitchMacMapEntries map[string]struct{}              // cache entry for all mac addresses on a switch
	NeighborInfo        map[string]config.NeighborConfig // neighbor created by NDP used for STATE
	neighborKey         []string                         // keys for all neighbor entries is stored here for GET calls
	PhyPortToL3PortMap  map[int32]int32                  // reverse map for l2IfIndex ----> l3IfIndex, used during vlan RX Pcap

	//Configuration Channels
	GlobalCfg chan NdpConfig
	// Lock for reading/writing NeighorInfo
	// We need this lock because getbulk/getentry is not requested on the main entry point channel, rather it's a
	// direct call to server. So to avoid updating the Neighbor Runtime Info during read
	// it's better to use lock
	NeigborEntryLock *sync.RWMutex

	//IPV6 Create/Delete State Up/Down Notification Channel
	IpIntfCh chan *config.IPIntfNotification
	// Vlan Create/Delete/Update Notification Channel
	VlanCh chan *config.VlanNotification
	// Mac Move Notification Channel
	MacMoveCh chan *config.MacMoveNotification
	//Received Pkt Channel
	RxPktCh chan *RxPktInfo
	//Package packet informs server over PktDataCh saying that send this packet..
	PktDataCh chan config.PacketData
	//Action Channel for NDP
	ActionCh chan *config.ActionData

	ndpL3IntfStateSlice   []int32
	ndpUpL3IntfStateSlice []int32
	L3IfIntfRefToIfIndex  map[string]int32

	//Pcap Default config values
	SnapShotLen int32
	Promiscuous bool
	Timeout     time.Duration

	// Neighbor Cache Information
	Packet *packet.Packet

	// @HACK: Need to find better way of getting Switch Mac Address
	SwitchMac string

	// Notification Channel for Publisher
	notifyChan chan<- []byte

	// counter for packets send and received
	counter PktCounter
}

const (
	NDP_CPU_PROFILE_FILE                  = "/var/log/ndpd.prof"
	NDP_SERVER_MAP_INITIAL_CAP            = 30
	NDP_SERVER_ASICD_NOTIFICATION_CH_SIZE = 1
	NDP_SERVER_INITIAL_CHANNEL_SIZE       = 1
	INTF_REF_NOT_FOUND                    = "Not Found"
)
