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

package FSMgr

import (
	"asicd/asicdCommonDefs"
	"asicdServices"
	"encoding/json"
	"errors"
	"l3/bgp/api"
	"l3/bgp/config"
	"l3/bgp/rpc"
	"ndpd"
	"strconv"
	"utils/commonDefs"
	"utils/logging"

	nanomsg "github.com/op/go-nanomsg"
)

/*  Interface manager is responsible for handling asicd notifications and hence
 *  we are creating asicd client
 */
func NewFSIntfMgr(logger *logging.Writer, fileName string) (*FSIntfMgr, error) {
	var asicdClient *asicdServices.ASICDServicesClient = nil
	asicdClientChan := make(chan *asicdServices.ASICDServicesClient)

	var ndpdClient *ndpd.NDPDServicesClient = nil
	ndpdClientChan := make(chan *ndpd.NDPDServicesClient)

	logger.Info("Connecting to ASICd")
	go rpc.StartAsicdClient(logger, fileName, asicdClientChan)
	asicdClient = <-asicdClientChan
	if asicdClient == nil {
		logger.Err("Failed to connect to ASICd")
		return nil, errors.New("Failed to connect to ASICd")
	} else {
		logger.Info("Connected to ASICd")
	}
	logger.Info("Connecting to NDPd")
	go rpc.StartNdpdClient(logger, fileName, ndpdClientChan)
	ndpdClient = <-ndpdClientChan
	if ndpdClient == nil {
		logger.Err("Failed to connect to NDPd")
		return nil, errors.New("Failed to connect to NDPd")
	} else {
		logger.Info("Connected to NDPd")
	}
	mgr := &FSIntfMgr{
		plugin:      "ovsdb",
		AsicdClient: asicdClient,
		NdpdClient:  ndpdClient,
		logger:      logger,
	}
	return mgr, nil
}

/*  Do any necessary init. Called from server..
 */
func (mgr *FSIntfMgr) Start() {
	mgr.asicdL3IntfSubSocket, _ = mgr.setupSubSocket(asicdCommonDefs.PUB_SOCKET_ADDR)
	mgr.ndpIntfSubSocket, _ = mgr.setupSubSocket("ipc:///tmp/ndpd_all.ipc")
	mgr.logger.Err("ndp socket set up")
	go mgr.listenForAsicdEvents()
	go mgr.listenForNDPEvents()
}

/*  Create One way communication asicd sub-socket
 */
func (mgr *FSIntfMgr) setupSubSocket(address string) (*nanomsg.SubSocket, error) {
	var err error
	mgr.logger.Info("setupSubSocket for address:", address)
	var socket *nanomsg.SubSocket
	if socket, err = nanomsg.NewSubSocket(); err != nil {
		mgr.logger.Err("Failed to create subscribe socket %s, error:%s", address, err)
		return nil, err
	}

	if err = socket.Subscribe(""); err != nil {
		mgr.logger.Err("Failed to subscribe to \"\" on subscribe socket %s, address", " error:", err)
		return nil, err
	}

	if _, err = socket.Connect(address); err != nil {
		mgr.logger.Err("Failed to connect to publisher socket %s, error:%s", address, err)
		return nil, err
	}

	mgr.logger.Info("Connected to publisher socket %s", address)
	if err = socket.SetRecvBuffer(1024 * 1024); err != nil {
		mgr.logger.Err("Failed to set the buffer size for subsriber socket %s, error:", address, err)
		return nil, err
	}
	return socket, nil
}

/*  listen for ndp events mainly ipv6 neighbor events
 */

func (mgr *FSIntfMgr) listenForNDPEvents() {
	for {
		mgr.logger.Info("Read on NDP subscriber socket...")
		rxBuf, err := mgr.ndpIntfSubSocket.Recv(0)
		if err != nil {
			mgr.logger.Info("Error in receiving NDP events", err)
			return
		}

		mgr.logger.Info("NDP subscriber recv returned", rxBuf)
		event := commonDefs.NdpNotification{}
		err = json.Unmarshal(rxBuf, &event)
		if err != nil {
			mgr.logger.Errf("Unmarshal NDP event failed with err %s", err)
			return
		}

		switch event.MsgType {
		case commonDefs.NOTIFY_IPV6_NEIGHBOR_CREATE, commonDefs.NOTIFY_IPV6_NEIGHBOR_DELETE:
			var msg commonDefs.Ipv6NeighborNotification
			err = json.Unmarshal(event.Msg, &msg)
			if err != nil {
				mgr.logger.Errf("Unmarshal NDP IPV6 neighbor event failed with err %s", err)
				return
			}

			mgr.logger.Info("NDP IPV6 neighbor event idx ", msg.IfIndex, " ip ", msg.IpAddr)
			if event.MsgType == commonDefs.NOTIFY_IPV6_NEIGHBOR_CREATE {
				api.SendIntfNotification(msg.IfIndex, "", msg.IpAddr, config.IPV6_NEIGHBOR_CREATED)
			} else {
				api.SendIntfNotification(msg.IfIndex, "", msg.IpAddr, config.IPV6_NEIGHBOR_DELETED)
			}
		}
	}
}

/*  listen for asicd events mainly L3 interface state change
 */
func (mgr *FSIntfMgr) listenForAsicdEvents() {
	for {
		mgr.logger.Info("Read on Asicd subscriber socket...")
		rxBuf, err := mgr.asicdL3IntfSubSocket.Recv(0)
		if err != nil {
			mgr.logger.Info("Error in receiving Asicd events", err)
			return
		}

		mgr.logger.Info("Asicd subscriber recv returned", rxBuf)
		event := asicdCommonDefs.AsicdNotification{}
		err = json.Unmarshal(rxBuf, &event)
		if err != nil {
			mgr.logger.Errf("Unmarshal Asicd event failed with err %s", err)
			return
		}

		switch event.MsgType {
		case asicdCommonDefs.NOTIFY_LOGICAL_INTF_CREATE:
			mgr.logger.Info("asicdCommonDefs.NOTIFY_LOGICAL_INTF_CREATE")
			var logicalIntfNotifyMsg asicdCommonDefs.LogicalIntfNotifyMsg
			err = json.Unmarshal(event.Msg, &logicalIntfNotifyMsg)
			if err != nil {
				mgr.logger.Err("Unable to unmarshal logicalIntfNotifyMsg:", event.Msg)
				return
			}
			api.SendIntfMapNotification(logicalIntfNotifyMsg.IfIndex, logicalIntfNotifyMsg.LogicalIntfName)
			break
		case asicdCommonDefs.NOTIFY_VLAN_CREATE:
			mgr.logger.Info("asicdCommonDefs.NOTIFY_VLAN_CREATE")
			var vlanNotifyMsg asicdCommonDefs.VlanNotifyMsg
			err = json.Unmarshal(event.Msg, &vlanNotifyMsg)
			if err != nil {
				mgr.logger.Info("Unable to unmarshal vlanNotifyMsg:", event.Msg)
				return
			}
			api.SendIntfMapNotification(asicdCommonDefs.GetIfIndexFromIntfIdAndIntfType(int(vlanNotifyMsg.VlanId), commonDefs.IfTypeVlan), vlanNotifyMsg.VlanName)
			break
		case asicdCommonDefs.NOTIFY_IPV4_L3INTF_STATE_CHANGE:
			var msg asicdCommonDefs.IPv4L3IntfStateNotifyMsg
			err = json.Unmarshal(event.Msg, &msg)
			if err != nil {
				mgr.logger.Errf("Unmarshal Asicd IPV4L3INTF event failed with err %s", err)
				return
			}

			mgr.logger.Infof("Asicd IPv4L3INTF event idx %d ip %s state %d", msg.IfIndex, msg.IpAddr, msg.IfState)
			if msg.IfState == asicdCommonDefs.INTF_STATE_DOWN {
				api.SendIntfNotification(msg.IfIndex, msg.IpAddr, "", config.INTF_STATE_DOWN)
			} else {
				api.SendIntfNotification(msg.IfIndex, msg.IpAddr, "", config.INTF_STATE_UP)
			}

		case asicdCommonDefs.NOTIFY_IPV6_L3INTF_STATE_CHANGE:
			var msg asicdCommonDefs.IPv6L3IntfStateNotifyMsg
			err = json.Unmarshal(event.Msg, &msg)
			if err != nil {
				mgr.logger.Errf("Unmarshal Asicd IPV6L3INTF event failed with err %s", err)
				return
			}

			mgr.logger.Infof("Asicd IPV6L3INTF event idx %d ip %s state %d", msg.IfIndex, msg.IpAddr, msg.IfState)
			if msg.IfState == asicdCommonDefs.INTF_STATE_DOWN {
				api.SendIntfNotification(msg.IfIndex, msg.IpAddr, "", config.INTF_STATE_DOWN)
			} else {
				api.SendIntfNotification(msg.IfIndex, msg.IpAddr, "", config.INTF_STATE_UP)
			}

		case asicdCommonDefs.NOTIFY_IPV6INTF_CREATE, asicdCommonDefs.NOTIFY_IPV6INTF_DELETE:
			var msg asicdCommonDefs.IPv6IntfNotifyMsg
			err = json.Unmarshal(event.Msg, &msg)
			if err != nil {
				mgr.logger.Errf("Unmarshal Asicd IPV6INTF event failed with err %s", err)
				return
			}

			mgr.logger.Info("Asicd IPV6INTF event idx %d ip %s", msg.IfIndex, msg.IpAddr)
			if event.MsgType == asicdCommonDefs.NOTIFY_IPV6INTF_CREATE {
				api.SendIntfNotification(msg.IfIndex, msg.IpAddr, "", config.INTFV6_CREATED)
			} else {
				api.SendIntfNotification(msg.IfIndex, msg.IpAddr, "", config.INTFV6_DELETED)
			}
		case asicdCommonDefs.NOTIFY_IPV4INTF_CREATE, asicdCommonDefs.NOTIFY_IPV4INTF_DELETE:
			var msg asicdCommonDefs.IPv4IntfNotifyMsg
			err = json.Unmarshal(event.Msg, &msg)
			if err != nil {
				mgr.logger.Errf("Unmarshal Asicd IPV4INTF event failed with err %s", err)
				return
			}

			mgr.logger.Info("Asicd IPV4INTF event idx %d ip %s", msg.IfIndex, msg.IpAddr)
			if event.MsgType == asicdCommonDefs.NOTIFY_IPV4INTF_CREATE {
				api.SendIntfNotification(msg.IfIndex, msg.IpAddr, "", config.INTF_CREATED)
			} else {
				api.SendIntfNotification(msg.IfIndex, msg.IpAddr, "", config.INTF_DELETED)
			}
		}
	}
}

func (mgr *FSIntfMgr) GetIPv4Intfs() []*config.IntfStateInfo {
	var currMarker asicdServices.Int
	var count asicdServices.Int
	intfs := make([]*config.IntfStateInfo, 0)
	count = 100
	for {
		mgr.logger.Info("Getting ", count, "IPv4IntfState objects from currMarker", currMarker)
		getBulkInfo, err := mgr.AsicdClient.GetBulkIPv4IntfState(currMarker, count)
		if err != nil {
			mgr.logger.Info("GetBulkIPv4IntfState failed with error", err)
			break
		}
		if getBulkInfo.Count == 0 {
			mgr.logger.Info("0 objects returned from GetBulkIPv4IntfState")
			break
		}
		mgr.logger.Info("len(getBulkInfo.IPv4IntfStateList)  =", len(getBulkInfo.IPv4IntfStateList),
			"num objects returned =", getBulkInfo.Count)
		for _, intfState := range getBulkInfo.IPv4IntfStateList {
			intf := config.NewIntfStateInfo(intfState.IfIndex, intfState.IpAddr, "", config.INTF_CREATED)
			intfs = append(intfs, intf)
		}
		if getBulkInfo.More == false {
			mgr.logger.Info("more returned as false, so no more get bulks")
			break
		}
		currMarker = getBulkInfo.EndIdx
	}

	return intfs
}

func (mgr *FSIntfMgr) GetIPv6Neighbors() []*config.IntfStateInfo {
	var currMarker ndpd.Int
	var count ndpd.Int
	intfs := make([]*config.IntfStateInfo, 0)
	count = 100
	for {
		mgr.logger.Info("Getting ", count, "NDPEntryState objects from currMarker", currMarker)
		getBulkInfo, err := mgr.NdpdClient.GetBulkNDPEntryState(currMarker, count)
		if err != nil {
			mgr.logger.Info("GetBulkNDPEntryState failed with error", err)
			break
		}
		if getBulkInfo.Count == 0 {
			mgr.logger.Info("0 objects returned from GetBulkNDPEntryState")
			break
		}
		mgr.logger.Info("len(getBulkInfo.NDPEntryStateList)  =", len(getBulkInfo.NDPEntryStateList),
			"num objects returned =", getBulkInfo.Count)
		for _, intfState := range getBulkInfo.NDPEntryStateList {
			intf := config.NewIntfStateInfo(intfState.IfIndex, "", intfState.IpAddr, config.IPV6_NEIGHBOR_CREATED)
			intfs = append(intfs, intf)
		}
		if getBulkInfo.More == false {
			mgr.logger.Info("more returned as false, so no more get bulks")
			break
		}
		currMarker = getBulkInfo.EndIdx
	}

	return intfs
}
func (mgr *FSIntfMgr) GetIPv6Intfs() []*config.IntfStateInfo {
	var currMarker asicdServices.Int
	var count asicdServices.Int
	intfs := make([]*config.IntfStateInfo, 0)
	count = 100
	for {
		mgr.logger.Info("Getting ", count, "IPv6IntfState objects from currMarker", currMarker)
		getBulkInfo, err := mgr.AsicdClient.GetBulkIPv6IntfState(currMarker, count)
		if err != nil {
			mgr.logger.Info("GetBulkIPv6IntfState failed with error", err)
			break
		}
		if getBulkInfo.Count == 0 {
			mgr.logger.Info("0 objects returned from GetBulkIPv6IntfState")
			break
		}
		mgr.logger.Info("len(getBulkInfo.IPv6IntfStateList)  =", len(getBulkInfo.IPv6IntfStateList),
			"num objects returned =", getBulkInfo.Count)
		for _, intfState := range getBulkInfo.IPv6IntfStateList {
			intf := config.NewIntfStateInfo(intfState.IfIndex, intfState.IpAddr, "", config.INTFV6_CREATED)
			intfs = append(intfs, intf)
		}
		if getBulkInfo.More == false {
			mgr.logger.Info("more returned as false, so no more get bulks")
			break
		}
		currMarker = getBulkInfo.EndIdx
	}

	return intfs
}

func (mgr *FSIntfMgr) GetIPv4Information(ifIndex int32) (string, error) {
	ipv4IntfState, err := mgr.AsicdClient.GetIPv4IntfState(strconv.Itoa(int(ifIndex)))
	if err != nil {
		return "", nil
	}
	return ipv4IntfState.IpAddr, err
}
func (mgr *FSIntfMgr) GetIPv6Information(ifIndex int32) (string, error) {
	ipv6IntfState, err := mgr.AsicdClient.GetIPv6IntfState(strconv.Itoa(int(ifIndex)))
	if err != nil {
		return "", nil
	}
	return ipv6IntfState.IpAddr, err
}

func (mgr *FSIntfMgr) GetIfIndex(ifIndex, ifType int) int32 {
	return asicdCommonDefs.GetIfIndexFromIntfIdAndIntfType(ifIndex, ifType)
}

func (m *FSIntfMgr) GetLogicalIntfInfo() []config.IntfMapInfo {
	m.logger.Info("Getting Logical Interfaces from asicd")
	intfMaps := make([]config.IntfMapInfo, 0)
	var currMarker asicdServices.Int
	var count asicdServices.Int
	count = 100
	for {
		m.logger.Info("Getting ", count, "GetBulkLogicalIntf objects from currMarker:", currMarker)
		bulkInfo, err := m.AsicdClient.GetBulkLogicalIntfState(currMarker, count)
		if err != nil {
			m.logger.Err("GetBulkLogicalIntfState with err ", err)
			return intfMaps
		}
		if bulkInfo.Count == 0 {
			m.logger.Err("0 objects returned from GetBulkLogicalIntfState")
			return intfMaps
		}
		m.logger.Info("len(bulkInfo.GetBulkLogicalIntfState)  = ", len(bulkInfo.LogicalIntfStateList), " num objects returned = ", bulkInfo.Count)
		for i := 0; i < int(bulkInfo.Count); i++ {
			ifId := (bulkInfo.LogicalIntfStateList[i].IfIndex)
			intfMap := config.IntfMapInfo{Idx: ifId, IfName: bulkInfo.LogicalIntfStateList[i].Name}
			intfMaps = append(intfMaps, intfMap)
		}
		if bulkInfo.More == false {
			return intfMaps
		}
		currMarker = asicdServices.Int(bulkInfo.EndIdx)
	}
	return intfMaps
}
func (m *FSIntfMgr) GetVlanInfo() []config.IntfMapInfo {
	m.logger.Info("Getting vlans from asicd")
	intfMaps := make([]config.IntfMapInfo, 0)
	var currMarker asicdServices.Int
	var count asicdServices.Int
	count = 100
	for {
		m.logger.Info("Getting ", count, "GetBulkVlan objects from currMarker:", currMarker)
		bulkInfo, err := m.AsicdClient.GetBulkVlanState(currMarker, count)
		if err != nil {
			m.logger.Err("GetBulkVlan with err ", err)
			return intfMaps
		}
		if bulkInfo.Count == 0 {
			m.logger.Err("0 objects returned from GetBulkVlan")
			return intfMaps
		}
		m.logger.Info("len(bulkInfo.GetBulkVlan)  = ", len(bulkInfo.VlanStateList), " num objects returned = ", bulkInfo.Count)
		for i := 0; i < int(bulkInfo.Count); i++ {
			ifId := (bulkInfo.VlanStateList[i].IfIndex)
			intfMap := config.IntfMapInfo{Idx: ifId, IfName: bulkInfo.VlanStateList[i].VlanName}
			intfMaps = append(intfMaps, intfMap)
		}
		if bulkInfo.More == false {
			return intfMaps
		}
		currMarker = asicdServices.Int(bulkInfo.EndIdx)
	}
	return intfMaps
}
func (m *FSIntfMgr) GetPortInfo() []config.IntfMapInfo {
	m.logger.Info("Getting ports from asicd")
	intfMaps := make([]config.IntfMapInfo, 0)
	var currMarker asicdServices.Int
	var count asicdServices.Int
	count = 100
	for {
		m.logger.Info(" Getting ", count, "objects from currMarker:", currMarker)
		bulkInfo, err := m.AsicdClient.GetBulkPortState(currMarker, count)
		if err != nil {
			m.logger.Err("GetBulkPortState with err ", err)
			return intfMaps
		}
		if bulkInfo.Count == 0 {
			m.logger.Err("0 objects returned from GetBulkPortState")
			return intfMaps
		}
		m.logger.Info("len(bulkInfo.PortStateList)  = ", len(bulkInfo.PortStateList), " num objects returned = ", bulkInfo.Count)
		for i := 0; i < int(bulkInfo.Count); i++ {
			ifId := bulkInfo.PortStateList[i].IfIndex
			intfMap := config.IntfMapInfo{Idx: ifId, IfName: bulkInfo.PortStateList[i].Name}
			intfMaps = append(intfMaps, intfMap)
		}
		if bulkInfo.More == false {
			return intfMaps
		}
		currMarker = asicdServices.Int(bulkInfo.EndIdx)
	}
	return intfMaps
}
