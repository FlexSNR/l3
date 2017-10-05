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
	"fmt"
	"l3/ospf/config"
	"sync"
	"time"
	//"l3/ospf/rpc"
	//    "l3/rib/ribdCommonDefs"
	"errors"
	"github.com/google/gopacket/pcap"
	"net"
	"utils/commonDefs"
)

type IntfConfKey struct {
	IPAddr  config.IpAddress
	IntfIdx config.InterfaceIndexOrZero
}

type NeighborData struct {
	TwoWayStatus bool
	RtrPrio      uint8
	DRtr         []byte
	BDRtr        []byte
	NbrIP        uint32
	FullState    bool
}

/*
type NeighborKey struct {
	RouterId uint32
} */

type BackupSeenMsg struct {
	RouterId uint32
	BDRId    []byte
	DRId     []byte
}

type NeighCreateMsg struct {
	RouterId     uint32
	NbrIP        uint32
	TwoWayStatus bool
	RtrPrio      uint8
	DRtr         []byte
	BDRtr        []byte
}

type NeighChangeMsg struct {
	RouterId     uint32
	NbrIP        uint32
	TwoWayStatus bool
	RtrPrio      uint8
	DRtr         []byte
	BDRtr        []byte
}

type IntfConf struct {
	IfAreaId              []byte
	IfType                config.IfType
	IfAdminStat           config.Status
	IfRtrPriority         uint8
	IfTransitDelay        config.UpToMaxAge
	IfRetransInterval     config.UpToMaxAge
	IfHelloInterval       uint16
	IfRtrDeadInterval     uint32
	IfPollInterval        config.PositiveInteger
	IfAuthKey             []byte
	IfMulticastForwarding config.MulticastForwarding
	IfDemand              bool
	IfAuthType            uint16
	FSMCtrlCh             chan bool
	FSMCtrlStatusCh       chan bool
	HelloIntervalTicker   *time.Ticker
	BackupSeenCh          chan BackupSeenMsg
	NeighborMap           map[NeighborConfKey]NeighborData
	NeighCreateCh         chan NeighCreateMsg
	NeighChangeCh         chan NeighChangeMsg
	NbrStateChangeCh      chan NbrStateChangeMsg
	NbrFullStateCh        chan NbrFullStateMsg
	WaitTimer             *time.Timer
	/* IntefaceState: Start */
	IfDRIp        []byte
	IfBDRIp       []byte
	IfFSMState    config.IfState
	IfEvents      int32
	IfLsaCount    int32
	IfLsaCksumSum int32
	IfDRtrId      uint32
	IfBDRtrId     uint32
	/* IntefaceState: End */
	IfName         string
	IfIpAddr       net.IP
	IfMacAddr      net.HardwareAddr
	IfNetmask      []byte
	IfMtu          int32
	IfCost         uint32
	IfMetricTOSMap map[uint8]uint32 // Key: TOS Value, Value: TOS Metric
}

func (server *OSPFServer) initDefaultIntfConf(key IntfConfKey, ipIntfProp IPIntfProperty, ifType int) {
	var intfType config.IfType
	switch ifType {
	case numberedP2P:
		intfType = config.NumberedP2P
		server.logger.Info("Creating numbered point2point")
	case unnumberedP2P:
		intfType = config.UnnumberedP2P
		server.logger.Info("Creating unnumbered point2point")
	default:
		intfType = config.Broadcast
		server.logger.Info("Creating broadcast")
	}
	/*
		if ifType == numberedP2P ||
			ifType == unnumberedP2P {
			intfType = config.PointToPoint
			server.logger.Info("Creating point2point")
		} else {
			intfType = config.Broadcast
			server.logger.Info("Creating broadcast")
		} */
	ent, exist := server.IntfConfMap[key]
	if !exist {
		areaId := convertAreaOrRouterId("0.0.0.0")
		if areaId == nil {
			return
		}
		server.updateIntfToAreaMap(key, "none", "0.0.0.0")
		ent.IfAreaId = areaId
		ent.IfType = intfType
		ent.IfAdminStat = config.Disabled
		ent.IfRtrPriority = uint8(config.DesignatedRouterPriority(1))
		ent.IfTransitDelay = config.UpToMaxAge(1)
		ent.IfRetransInterval = config.UpToMaxAge(5)
		ent.IfHelloInterval = uint16(config.HelloRange(10))
		ent.IfRtrDeadInterval = uint32(config.PositiveInteger(40))
		ent.IfPollInterval = config.PositiveInteger(120)
		authKey := convertAuthKey("0.0.0.0.0.0.0.0")
		if authKey == nil {
			return
		}
		ent.IfAuthKey = authKey
		ent.IfMulticastForwarding = config.Blocked
		ent.IfDemand = false
		ent.IfAuthType = uint16(config.NoAuth)
		ent.FSMCtrlCh = make(chan bool)
		ent.FSMCtrlStatusCh = make(chan bool)
		ent.BackupSeenCh = make(chan BackupSeenMsg)
		ent.NeighCreateCh = make(chan NeighCreateMsg)
		ent.NeighChangeCh = make(chan NeighChangeMsg)
		ent.NbrStateChangeCh = make(chan NbrStateChangeMsg)
		ent.NbrFullStateCh = make(chan NbrFullStateMsg)
		//ent.WaitTimerExpired = make(chan bool)
		ent.WaitTimer = nil
		ent.HelloIntervalTicker = nil
		ent.NeighborMap = make(map[NeighborConfKey]NeighborData)
		if ifType == broadcast {
			ent.IfNetmask = ipIntfProp.NetMask
			ent.IfIpAddr = ipIntfProp.IpAddr
		} else if ifType == unnumberedP2P {
			ent.IfNetmask = []byte{0, 0, 0, 0}
			// IP address of a loopback interface
			ent.IfIpAddr = net.ParseIP("20.0.1.141")
		} else if ifType == numberedP2P {
			ent.IfNetmask = []byte{0, 0, 0, 0}
			ent.IfIpAddr = ipIntfProp.IpAddr
		} else {
			server.logger.Err("Invalid Interface type.")
			return
		}
		ent.IfName = ipIntfProp.IfName
		ent.IfMtu = ipIntfProp.Mtu
		ent.IfCost = ipIntfProp.Cost
		ent.IfMacAddr = ipIntfProp.MacAddr
		ent.IfDRIp = []byte{0, 0, 0, 0}
		ent.IfBDRIp = []byte{0, 0, 0, 0}
		ent.IfDRtrId = 0
		ent.IfBDRtrId = 0
		ent.IfEvents = 0
		ent.IfLsaCount = 0
		ent.IfLsaCksumSum = 0
		ent.IfMetricTOSMap = make(map[uint8]uint32)
		txEntry, exist := server.IntfTxMap[key]
		if !exist {
			sendHdl, err := pcap.OpenLive(ent.IfName, snapshot_len, promiscuous, timeout_pcap)
			if sendHdl == nil {
				server.logger.Err(fmt.Sprintln("SendHdl: No device found.", ent.IfName, err))
				return
			}
			txEntry.SendPcapHdl = sendHdl
			txEntry.SendMutex = &sync.Mutex{}
			server.IntfTxMap[key] = txEntry
		}
		rxEntry, exist := server.IntfRxMap[key]
		if !exist {
			recvHdl, err := pcap.OpenLive(ent.IfName, snapshot_len, promiscuous, timeout_pcap)
			if recvHdl == nil {
				server.logger.Err(fmt.Sprintln("RecvHdl: No device found.", ent.IfName, err))
				return
			}

			filter := fmt.Sprintln("proto ospf and not src host", ipIntfProp.IpAddr.String())
			server.logger.Info(fmt.Sprintln("Filter is : ", filter))
			// Setting Pcap filter for Ospf Pkt
			err = recvHdl.SetBPFFilter(filter)
			if err != nil {
				server.logger.Err(fmt.Sprintln("Unable to set filter on", ent.IfName))
				return
			}

			rxEntry.RecvPcapHdl = recvHdl
			rxEntry.PktRecvCh = make(chan bool)
			rxEntry.PktRecvStatusCh = make(chan bool)
			server.IntfRxMap[key] = rxEntry
		}
		server.IntfConfMap[key] = ent
		server.logger.Info(fmt.Sprintln("Intf Conf initialized", key))
	} else {
		server.logger.Info(fmt.Sprintln("Intf Conf is not initialized", key))
	}
}

func (server *OSPFServer) createIPIntfConfMap(msg IPv4IntfNotifyMsg, mtu int32, ifIndex int32, ifType int) {
	var ifIdx int32
	ip, ipNet, err := net.ParseCIDR(msg.IpAddr)
	if err != nil {
		server.logger.Err(fmt.Sprintln("Unable to parse IP address", msg.IpAddr))
		return
	}
	if ip.String() == "0.0.0.0" {
		ifIdx = ifIndex
	} else {
		ifIdx = 0
	}
	ifName, err := server.getLinuxIntfName(int32(msg.IfId), msg.IfType)
	if err != nil {
		server.logger.Err("CreateIpIntf: No Such Interface exists ", msg.IfId)
		return
	}

	ifCost, err := server.getIntfCost(msg.IfId, msg.IfType)
	if err != nil {
		server.logger.Err("Unable to get the cost")
		return
	}

	// Set ifIdx = 0 for time being --- Need to be revisited
	intfConfKey := IntfConfKey{
		IPAddr:  config.IpAddress(ip.String()),
		IntfIdx: config.InterfaceIndexOrZero(ifIdx),
	}
	var macAddr net.HardwareAddr
	if msg.IfType == commonDefs.IfTypeLoopback {
		macAddr, err = server.getMacAddrLogicalIntf(ifName)
	} else {
		macAddr, err = getMacAddrIntfName(ifName)
	}
	if err != nil {
		server.logger.Err(fmt.Sprintln("Unable to get MacAddress of Interface exists", ifName))
		return
	}
	ipIntfProp := IPIntfProperty{
		IfName:  ifName,
		IpAddr:  ip,
		MacAddr: macAddr,
		NetMask: ipNet.Mask,
		Mtu:     mtu,
		Cost:    ifCost,
	}

	server.initDefaultIntfConf(intfConfKey, ipIntfProp, ifType)
	_, exist := server.IntfConfMap[intfConfKey]
	if !exist {
		server.logger.Err("No such inteface exists")
		return
	}

	server.IntfKeySlice = append(server.IntfKeySlice, intfConfKey)
	server.IntfKeyToSliceIdxMap[intfConfKey] = true

	/*
		if server.ospfGlobalConf.AdminStat == config.Enabled {
			server.StartSendRecvPkts(intfConfKey)
		}
	*/
}

func (server *OSPFServer) deleteIPIntfConfMap(msg IPv4IntfNotifyMsg, ifIndex int32) {
	var flag bool = false
	var ifIdx int32
	server.logger.Info(fmt.Sprintln("calling deleteIPIntfConfMap for....:", msg))
	ip, _, err := net.ParseCIDR(msg.IpAddr)
	if err != nil {
		server.logger.Err(fmt.Sprintln("Unable to parse IP address", msg.IpAddr))
		return
	}

	if ip.String() == "0.0.0.0" {
		ifIdx = ifIndex
	} else {
		ifIdx = 0
	}
	server.logger.Info(fmt.Sprintln("delete IPIntfConfMap for ", msg, "ifIndex:", ifIdx))

	// Set ifIdx = 0 for time being --- Need to be revisited
	intfConfKey := IntfConfKey{
		IPAddr:  config.IpAddress(ip.String()),
		IntfIdx: config.InterfaceIndexOrZero(ifIdx),
	}
	ent, exist := server.IntfConfMap[intfConfKey]
	if !exist {
		server.logger.Err("No such inteface exists")
		return
	}
	areaId := convertIPv4ToUint32(ent.IfAreaId)
	oldAreaId := convertIPInByteToString(ent.IfAreaId)
	server.updateIntfToAreaMap(intfConfKey, oldAreaId, "none")

	if server.ospfGlobalConf.AdminStat == config.Enabled &&
		ent.IfAdminStat == config.Enabled {
		server.StopSendRecvPkts(intfConfKey)
		flag = true
	}
	server.logger.Info(fmt.Sprintln("1:delete IPIntfConfMap for ", intfConfKey))
	server.IntfKeyToSliceIdxMap[intfConfKey] = false
	delete(server.IntfConfMap, intfConfKey)
	if flag == true {
		msg := NetworkLSAChangeMsg{
			areaId:  areaId,
			intfKey: intfConfKey,
		}
		server.IntfStateChangeCh <- msg
	}
}

func (server *OSPFServer) updateIPIntfConfMap(ifConf config.InterfaceConf) {
	intfConfKey := IntfConfKey{
		IPAddr:  ifConf.IfIpAddress,
		IntfIdx: config.InterfaceIndexOrZero(ifConf.AddressLessIf),
	}

	ent, exist := server.IntfConfMap[intfConfKey]
	//  we can update only when we already have entry
	if exist {
		oldAreaId := convertIPInByteToString(ent.IfAreaId)
		newAreaId := string(ifConf.IfAreaId)
		if oldAreaId != newAreaId {
			server.updateIntfToAreaMap(intfConfKey, oldAreaId, newAreaId)
		}
		ent.IfAreaId = convertAreaOrRouterId(newAreaId)
		/*
		   		areaId := convertAreaOrRouterId(string(ifConf.IfAreaId))
		   		if areaId == nil {
		   			server.logger.Err("Invalid areaId")
		   			return
		   		}
		                   if bytesEqual(ent.IfAreaId, areaId) == false {
		                           oldAreaId := config.AreaId(convertIPInByteToString(ent.IfAreaId))
		                           areaId := server.updateIntfToAreaMap(intfConfKey, ifConf.IfAreaId, oldAreaId)
		                           ent.IfAreaId =  convertAreaOrRouterId(string(areaId))
		                   }
		*/
		ent.IfType = ifConf.IfType
		ent.IfAdminStat = ifConf.IfAdminStat
		ent.IfRtrPriority = uint8(ifConf.IfRtrPriority)
		ent.IfTransitDelay = ifConf.IfTransitDelay
		ent.IfRetransInterval = ifConf.IfRetransInterval
		ent.IfHelloInterval = uint16(ifConf.IfHelloInterval)
		ent.IfRtrDeadInterval = uint32(ifConf.IfRtrDeadInterval)
		ent.IfPollInterval = ifConf.IfPollInterval
		//authKey := convertAuthKey(string(ifConf.IfAuthKey))
		//if authKey == nil {
		//	server.logger.Err("Invalid authKey")
		//	return
		//}
		//ent.IfAuthKey = authKey
		ent.IfAuthType = uint16(ifConf.IfAuthType)
		/* Re initiate the Interface State */
		ent.IfDRIp = []byte{0, 0, 0, 0}
		ent.IfBDRIp = []byte{0, 0, 0, 0}
		ent.IfDRtrId = 0
		ent.IfBDRtrId = 0
		ent.IfEvents = 0
		ent.IfLsaCount = 0
		ent.IfLsaCksumSum = 0
		server.IntfConfMap[intfConfKey] = ent
		server.logger.Info(fmt.Sprintln("1:Update IPIntfConfMap for ", intfConfKey))
	}
}

func (server *OSPFServer) processIntfConfig(ifConf config.InterfaceConf) error {
	intfConfKey := IntfConfKey{
		IPAddr:  ifConf.IfIpAddress,
		IntfIdx: config.InterfaceIndexOrZero(ifConf.AddressLessIf),
	}
	ent, exist := server.IntfConfMap[intfConfKey]
	if !exist {
		server.logger.Err(fmt.Sprintln("No such L3 interface exists ", intfConfKey.IPAddr, intfConfKey.IntfIdx))
		err := errors.New("No such L3 interface exists")
		return err
	}
	if intfConfKey.IPAddr == "0.0.0.0" &&
		ifConf.IfType == config.NumberedP2P || ifConf.IfType == config.UnnumberedP2P {
		flag := false
		for key, _ := range server.IntfConfMap {
			if key.IPAddr != "0.0.0.0" {
				flag = true
				break
			}
		}

		if flag == false {
			server.logger.Err("Invalid Configuration")
			server.logger.Err("Unnumbered PointToPoint Interface cannot be configured without having any other IP interface")
			err := errors.New("Invalid Configuration")
			return err
		}
	}

	if ent.IfAdminStat == config.Enabled &&
		server.ospfGlobalConf.AdminStat == config.Enabled {
		server.StopSendRecvPkts(intfConfKey)
	}

	server.updateIPIntfConfMap(ifConf)

	server.logger.Info(fmt.Sprintln("InterfaceConf:", server.IntfConfMap))
	ent, _ = server.IntfConfMap[intfConfKey]
	if ent.IfAdminStat == config.Enabled &&
		server.ospfGlobalConf.AdminStat == config.Enabled {
		server.StartSendRecvPkts(intfConfKey)
	}
	return nil
}

func (server *OSPFServer) StopSendRecvPkts(intfConfKey IntfConfKey) {
	server.logger.Info("Stop Sending Hello Pkt")
	server.StopOspfIntfFSM(intfConfKey)
	server.logger.Info("Stop Receiving Hello Pkt")
	server.StopOspfRecvPkts(intfConfKey)
	ent, _ := server.IntfConfMap[intfConfKey]
	ent.NeighborMap = nil
	ent.IfEvents = ent.IfEvents + 1
	ent.IfFSMState = config.Down
	server.IntfConfMap[intfConfKey] = ent
}

func (server *OSPFServer) StartSendRecvPkts(intfConfKey IntfConfKey) {
	ent, _ := server.IntfConfMap[intfConfKey]
	helloInterval := time.Duration(ent.IfHelloInterval) * time.Second
	ent.HelloIntervalTicker = time.NewTicker(helloInterval)
	if ent.IfType == config.Broadcast {
		waitTime := time.Duration(ent.IfRtrDeadInterval) * time.Second
		ent.WaitTimer = time.NewTimer(waitTime)
	}
	// rtrDeadInterval := time.Duration(ent.IfRtrDeadInterval * time.Second)
	ent.NeighborMap = make(map[NeighborConfKey]NeighborData)
	ent.IfEvents = ent.IfEvents + 1
	if ent.IfType == config.Broadcast {
		ent.IfFSMState = config.Waiting
	} else if ent.IfType == config.NumberedP2P || ent.IfType == config.UnnumberedP2P {
		ent.IfFSMState = config.P2P
	}
	server.IntfConfMap[intfConfKey] = ent
	server.logger.Info("Start Sending Hello Pkt")
	go server.StartOspfIntfFSM(intfConfKey)
	server.logger.Info("Start Receiving Hello Pkt")
	go server.StartOspfRecvPkts(intfConfKey)
}

func (server *OSPFServer) initIntfStateSlice() {
	var intfStateRefFunc func()
	intfStateRefFunc = func() {
		server.IntfKeySlice = []IntfConfKey{}
		server.IntfKeyToSliceIdxMap = nil
		server.IntfKeyToSliceIdxMap = make(map[IntfConfKey]bool)
		server.IntfSliceRefreshCh <- true
		msg := <-server.IntfSliceRefreshDoneCh
		if msg == true {
			server.logger.Debug("Interface slice got refreshed")
		}
		server.IntfStateTimer.Reset(server.RefreshDuration)
	}
	server.IntfStateTimer = time.AfterFunc(server.RefreshDuration, intfStateRefFunc)
}

func (server *OSPFServer) refreshIntfKeySlice() {
	for key, _ := range server.IntfConfMap {
		server.IntfKeySlice = append(server.IntfKeySlice, key)
		server.IntfKeyToSliceIdxMap[key] = true
	}
}
