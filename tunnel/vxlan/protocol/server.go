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

// server.go
package vxlan

import (
	"fmt"
	"infra/sysd/sysdCommonDefs"
	"net"
	"utils/keepalive"
	"utils/logging"
)

var SwitchMac [6]uint8
var NetSwitchMac net.HardwareAddr
var logger *logging.Writer
var ClientIntf []VXLANClientIntf
var Serverclients ServerClients
var VxlanServer *VXLANServer

// vtep vlan membership
var PortConfigMap map[int32]*PortConfig

type VXLANServer struct {
	logger         *logging.Writer
	Configchans    *VxLanConfigChannels
	DaemonStatusCh chan sysdCommonDefs.DaemonStatus
	Paramspath     string // location of params path
}

type cfgFileJson struct {
	SwitchMac        string            `json:"SwitchMac"`
	PluginList       []string          `json:"PluginList"`
	IfNameMap        map[string]string `json:"IfNameMap"`
	IfNamePrefix     map[string]string `json:"IfNamePrefix"`
	SysRsvdVlanRange string            `json:"SysRsvdVlanRange"`
}

type ServerClients struct {
}

// SetIntf:
// The user may implement mulitple interfaces for uses
// by the server.  This was created to avoid import cycle
func RegisterClients(intf VXLANClientIntf) {
	logger.Info(fmt.Sprintf("VXLAN Registering client interface %#v", intf))
	if ClientIntf == nil {
		ClientIntf = make([]VXLANClientIntf, 0)
	}
	ClientIntf = append(ClientIntf, intf)
}

func DeRegisterClients() {
	ClientIntf = nil
}

// set the global logger instance
func SetLogger(l *logging.Writer) {
	logger = l
}

func GetLogger() *logging.Writer {
	return logger
}

func GetConfigChannels() *VxLanConfigChannels {
	return VxlanServer.Configchans
}

func NewVXLANServer(l *logging.Writer, paramspath string) *VXLANServer {

	if VxlanServer == nil {

		logger.Info(fmt.Sprintf("Params path: %s", paramspath))

		// setup server to monitor the daemons vxlan have a depenance on
		go keepalive.InitKeepAlive("vxland", paramspath)

		VxlanServer = &VXLANServer{
			Paramspath: paramspath,
			logger:     l,
			Configchans: &VxLanConfigChannels{
				Vxlancreate:               make(chan VxlanConfig, 0),
				Vxlandelete:               make(chan VxlanConfig, 0),
				Vxlanupdate:               make(chan VxlanUpdate, 0),
				Vtepcreate:                make(chan VtepConfig, 0),
				Vtepdelete:                make(chan VtepConfig, 0),
				Vtepupdate:                make(chan VtepUpdate, 0),
				VxlanAccessPortVlanUpdate: make(chan VxlanAccessPortVlan, 0),
				VxlanNextHopUpdate:        make(chan VxlanNextHopIp, 0),
				VxlanPortCreate:           make(chan PortConfig, 0),
			},
		}

		// listen for config messages from intf and server listener (thrift)
		VxlanServer.ConfigListener()

		// connect to the various servers in order to get additional information
		// such as connecting to RIB for next hop ip of the vtep dst ip, and
		// resolve the mac for the next hop ip
		for _, client := range ClientIntf {
			client.SetServerChannels(VxlanServer.Configchans)
			client.ConnectToClients(paramspath + "clients.json")
		}
	}
	return VxlanServer
}

//HandleNextHopChange:
// Handle notifications from RIB that the next hop reachabilty has changed
func (s *VXLANServer) HandleNextHopChange(dip net.IP, nexthopip net.IP, nexthopIfIndex int32, nexthopIfName string, reachable bool) {
	// TOOD do some work to find all VTEP's and deprovision the entries
	for _, vtep := range GetVtepDB() {
		if reachable &&
			vtep.DstIp.String() == dip.String() {
			if vtep.VxlanVtepMachineFsm.Machine.Curr.CurrentState() == VxlanVtepStateInterface {

				nexthopinfo := VtepNextHopInfo{
					Ip:      nexthopip,
					IfIndex: nexthopIfIndex,
					IfName:  nexthopIfName,
				}
				event := MachineEvent{
					E:    VxlanVtepEventNextHopInfoResolved,
					Src:  VxlanVtepMachineModuleStr,
					Data: nexthopinfo,
				}

				vtep.VxlanVtepMachineFsm.VxlanVtepEvents <- event

			}
		} else if !reachable &&
			vtep.DstIp.String() == dip.String() {
			// set state
			// tearing down the connection appropriately
			if vtep.VxlanVtepMachineFsm.Machine.Curr.CurrentState() >= VxlanVtepStateNextHopInfo {
				// deprovision the vtep
				DeProvisionVtep(vtep, false)
			}
		}
	}
}
