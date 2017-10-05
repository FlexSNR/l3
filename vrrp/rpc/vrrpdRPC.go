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

package vrrpRpc

import (
	"encoding/json"
	"errors"
	"fmt"
	"git.apache.org/thrift.git/lib/go/thrift"
	"io/ioutil"
	"l3/vrrp/server"
	"strconv"
	"utils/logging"
	"vrrpd"
)

type VrrpHandler struct {
	server *vrrpServer.VrrpServer
	logger *logging.Writer
}
type VrrpClientJson struct {
	Name string `json:Name`
	Port int    `json:Port`
}

const (
	VRRP_RPC_NO_PORT      = "could not find port and hence not starting rpc"
	VRRP_NEED_UNIQUE_INFO = "Original IfIndex & new IfIndex have different ifindex or VRID, hence cannot do an update"
	VRRP_SVR_NO_ENTRY     = "Cannot find entry in db"
)

func VrrpCheckConfig(config *vrrpd.VrrpIntf, h *VrrpHandler) (bool, error) {
	if config.VRID == 0 {
		h.logger.Info("VRRP: Invalid VRID")
		return false, errors.New(vrrpServer.VRRP_INVALID_VRID)
	}

	err := h.server.VrrpValidateIntfConfig(config.IfIndex)
	if err != nil {
		return false, err
	}

	return true, nil
}

func VrrpNewHandler(vrrpSvr *vrrpServer.VrrpServer, logger *logging.Writer) *VrrpHandler {
	hdl := new(VrrpHandler)
	hdl.server = vrrpSvr
	hdl.logger = logger
	return hdl
}

func VrrpRpcGetClient(logger *logging.Writer, fileName string, process string) (*VrrpClientJson, error) {
	var allClients []VrrpClientJson

	data, err := ioutil.ReadFile(fileName)
	if err != nil {
		logger.Err(fmt.Sprintf("Failed to open VRRPd config file:%s, err:%s", fileName, err))
		return nil, err
	}

	json.Unmarshal(data, &allClients)
	for _, client := range allClients {
		if client.Name == process {
			return &client, nil
		}
	}

	logger.Err(fmt.Sprintf("Did not find port for %s in config file:%s", process, fileName))
	return nil, errors.New(VRRP_RPC_NO_PORT)

}

func VrrpRpcStartServer(log *logging.Writer, handler *VrrpHandler, paramsDir string) error {
	logger := log
	fileName := paramsDir

	if fileName[len(fileName)-1] != '/' {
		fileName = fileName + "/"
	}
	fileName = fileName + "clients.json"

	clientJson, err := VrrpRpcGetClient(logger, fileName, "vrrpd")
	if err != nil || clientJson == nil {
		return err
	}
	logger.Info(fmt.Sprintln("Got Client Info for", clientJson.Name, " port",
		clientJson.Port))
	// create processor, transport and protocol for server
	processor := vrrpd.NewVRRPDServicesProcessor(handler)
	transportFactory := thrift.NewTBufferedTransportFactory(8192)
	protocolFactory := thrift.NewTBinaryProtocolFactoryDefault()
	transport, err := thrift.NewTServerSocket("localhost:" + strconv.Itoa(clientJson.Port))
	if err != nil {
		logger.Info(fmt.Sprintln("StartServer: NewTServerSocket "+
			"failed with error:", err))
		return err
	}
	server := thrift.NewTSimpleServer4(processor, transport,
		transportFactory, protocolFactory)
	err = server.Serve()
	if err != nil {
		logger.Err(fmt.Sprintln("Failed to start the listener, err:", err))
		return err
	}
	return nil
}

func (h *VrrpHandler) CreateVrrpIntf(config *vrrpd.VrrpIntf) (r bool, err error) {
	h.logger.Info(fmt.Sprintln("VRRP: Interface config create for ifindex ",
		config.IfIndex))
	r, err = VrrpCheckConfig(config, h)
	if err != nil {
		return r, err
	}
	h.server.VrrpCreateIntfConfigCh <- *config
	return true, err
}
func (h *VrrpHandler) UpdateVrrpIntf(origconfig *vrrpd.VrrpIntf,
	newconfig *vrrpd.VrrpIntf, attrset []bool, op []*vrrpd.PatchOpInfo) (r bool, err error) {
	// Verify orig config
	if (origconfig.IfIndex != newconfig.IfIndex) ||
		(origconfig.VRID != newconfig.VRID) {
		return false, errors.New(VRRP_NEED_UNIQUE_INFO)
	}
	r, err = VrrpCheckConfig(origconfig, h)
	if err != nil {
		return r, err
	}
	// Verify new config
	r, err = VrrpCheckConfig(newconfig, h)
	if err != nil {
		return r, err
	}
	updConfg := vrrpServer.VrrpUpdateConfig{
		OldConfig: *origconfig,
		NewConfig: *newconfig,
		AttrSet:   attrset,
	}
	h.server.VrrpUpdateIntfConfigCh <- updConfg

	return true, nil
}

func (h *VrrpHandler) DeleteVrrpIntf(config *vrrpd.VrrpIntf) (r bool, err error) {
	h.server.VrrpDeleteIntfConfigCh <- *config
	return true, nil
}

func (h *VrrpHandler) convertVrrpIntfEntryToThriftEntry(state vrrpd.VrrpIntfState) *vrrpd.VrrpIntfState {
	entry := vrrpd.NewVrrpIntfState()
	entry.VirtualRouterMACAddress = state.VirtualRouterMACAddress
	entry.PreemptMode = bool(state.PreemptMode)
	entry.AdvertisementInterval = int32(state.AdvertisementInterval)
	entry.VRID = int32(state.VRID)
	entry.Priority = int32(state.Priority)
	entry.SkewTime = int32(state.SkewTime)
	entry.VirtualIPv4Addr = state.VirtualIPv4Addr
	entry.IfIndex = int32(state.IfIndex)
	entry.MasterDownTimer = int32(state.MasterDownTimer)
	entry.IntfIpAddr = state.IntfIpAddr
	entry.VrrpState = state.VrrpState
	return entry
}

func (h *VrrpHandler) GetBulkVrrpIntfState(fromIndex vrrpd.Int,
	count vrrpd.Int) (*vrrpd.VrrpIntfStateGetInfo, error) {
	nextIdx, currCount, vrrpIntfStateEntries := h.server.VrrpGetBulkVrrpIntfStates(
		int(fromIndex), int(count))
	if vrrpIntfStateEntries == nil {
		return nil, errors.New("Interface Slice is not initialized")
	}
	vrrpEntryResponse := make([]*vrrpd.VrrpIntfState, len(vrrpIntfStateEntries))
	for idx, item := range vrrpIntfStateEntries {
		vrrpEntryResponse[idx] = h.convertVrrpIntfEntryToThriftEntry(item)
	}
	intfEntryBulk := vrrpd.NewVrrpIntfStateGetInfo()
	intfEntryBulk.VrrpIntfStateList = vrrpEntryResponse
	intfEntryBulk.StartIdx = fromIndex
	intfEntryBulk.EndIdx = vrrpd.Int(nextIdx)
	intfEntryBulk.Count = vrrpd.Int(currCount)
	intfEntryBulk.More = (nextIdx != 0)
	return intfEntryBulk, nil
}

func (h *VrrpHandler) convertVrrpVridEntryToThriftEntry(state vrrpd.VrrpVridState) *vrrpd.VrrpVridState {
	entry := vrrpd.NewVrrpVridState()
	entry.IfIndex = state.IfIndex
	entry.VRID = state.VRID
	entry.AdverRx = int32(state.AdverRx)
	entry.AdverTx = int32(state.AdverTx)
	entry.CurrentState = state.CurrentState
	entry.PreviousState = state.PreviousState
	entry.LastAdverRx = state.LastAdverRx
	entry.LastAdverTx = state.LastAdverTx
	entry.MasterIp = state.MasterIp
	entry.TransitionReason = state.TransitionReason
	return entry
}

func (h *VrrpHandler) GetBulkVrrpVridState(fromIndex vrrpd.Int,
	count vrrpd.Int) (*vrrpd.VrrpVridStateGetInfo, error) {
	nextIdx, currCount, vrrpVridStateEntries := h.server.VrrpGetBulkVrrpVridStates(
		int(fromIndex), int(count))
	if vrrpVridStateEntries == nil {
		return nil, errors.New("Interface Slice is not initialized")
	}
	vrrpEntryResponse := make([]*vrrpd.VrrpVridState, len(vrrpVridStateEntries))
	for idx, item := range vrrpVridStateEntries {
		vrrpEntryResponse[idx] = h.convertVrrpVridEntryToThriftEntry(item)
	}
	vridEntryBulk := vrrpd.NewVrrpVridStateGetInfo()
	vridEntryBulk.VrrpVridStateList = vrrpEntryResponse
	vridEntryBulk.StartIdx = fromIndex
	vridEntryBulk.EndIdx = vrrpd.Int(nextIdx)
	vridEntryBulk.Count = vrrpd.Int(currCount)
	vridEntryBulk.More = (nextIdx != 0)
	return vridEntryBulk, nil
}

func (h *VrrpHandler) GetVrrpIntfState(ifIndex int32, vrId int32) (*vrrpd.VrrpIntfState, error) {
	response := vrrpd.NewVrrpIntfState()
	key := strconv.Itoa(int(ifIndex)) + "_" + strconv.Itoa(int(vrId))
	rv := h.server.VrrpPopulateIntfState(key, response)
	if !rv {
		return nil, errors.New(VRRP_SVR_NO_ENTRY + strconv.Itoa(int(ifIndex)) +
			" and Virtual Router Id:" + strconv.Itoa(int(vrId)))
	}
	return response, nil
}

func (h *VrrpHandler) GetVrrpVridState(ifIndex int32, vrId int32) (*vrrpd.VrrpVridState, error) {
	response := vrrpd.NewVrrpVridState()
	key := strconv.Itoa(int(ifIndex)) + "_" + strconv.Itoa(int(vrId))
	rv := h.server.VrrpPopulateVridState(key, response)
	if !rv {
		return nil, errors.New(VRRP_SVR_NO_ENTRY + strconv.Itoa(int(ifIndex)) +
			" and Virtual Router Id:" + strconv.Itoa(int(vrId)))
	}
	return response, nil
}
