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

// config.go
// Config entry is based on thrift data structures.
package vxlan

import (
	"fmt"
	"net"
	"reflect"
	//"strings"
	"errors"
	"vxland"
)

const (
	VxlanCommandCreate = iota + 1
	VxlanCommandDelete
	VxlanCommandUpdate
)

type VxLanConfigChannels struct {
	Vxlancreate               chan VxlanConfig
	Vxlandelete               chan VxlanConfig
	Vxlanupdate               chan VxlanUpdate
	Vtepcreate                chan VtepConfig
	Vtepdelete                chan VtepConfig
	Vtepupdate                chan VtepUpdate
	VxlanAccessPortVlanUpdate chan VxlanAccessPortVlan
	VxlanNextHopUpdate        chan VxlanNextHopIp
	VxlanPortCreate           chan PortConfig
	Vxlanintfinfo             chan VxlanIntfInfo
}

type VxlanIntfInfo struct {
	Command  int
	IntfName string
	IfIndex  int32
	Mac      net.HardwareAddr
	Ip       net.IP
}

type VxlanNextHopIp struct {
	Command   int
	Ip        net.IP
	Intf      int32
	IntfName  string
	NextHopIp net.IP
}

type VxlanAccessPortVlan struct {
	Command  int
	VlanId   uint16
	IntfList []int32
}

type VxlanUpdate struct {
	Oldconfig VxlanConfig
	Newconfig VxlanConfig
	Attr      []bool
}

type VtepUpdate struct {
	Oldconfig VtepConfig
	Newconfig VtepConfig
	Attr      []bool
}

// bridge for the VNI
type VxlanConfig struct {
	VNI    uint32
	VlanId uint16 // used to tag inner ethernet frame when egressing
	Group  net.IP // multicast group IP
	MTU    uint32 // MTU size for each VTEP
}

type PortConfig struct {
	Name         string
	HardwareAddr net.HardwareAddr
	Speed        int32
	PortNum      int32
	IfIndex      int32
}

// tunnel endpoint for the VxLAN
type VtepConfig struct {
	Vni                   uint32           `SNAPROUTE: KEY` //VxLAN ID.
	VtepName              string           //VTEP instance name.
	SrcIfName             string           //Source interface ifIndex.
	UDP                   uint16           //vxlan udp port.  Deafult is the iana default udp port
	TTL                   uint16           //TTL of the Vxlan tunnel
	TOS                   uint16           //Type of Service
	InnerVlanHandlingMode int32            //The inner vlan tag handling mode.
	Learning              bool             //specifies if unknown source link layer  addresses and IP addresses are entered into the VXLAN  device forwarding database.
	Rsc                   bool             //specifies if route short circuit is turned on.
	L2miss                bool             //specifies if netlink LLADDR miss notifications are generated.
	L3miss                bool             //specifies if netlink IP ADDR miss notifications are generated.
	TunnelSrcIp           net.IP           //Source IP address for the static VxLAN tunnel
	TunnelDstIp           net.IP           //Destination IP address for the static VxLAN tunnel
	VlanId                uint16           //Vlan Id to encapsulate with the vtep tunnel ethernet header
	TunnelSrcMac          net.HardwareAddr //Src Mac assigned to the VTEP within this VxLAN. If an address is not assigned the the local switch address will be used.
	TunnelDstMac          net.HardwareAddr // Optional - may be looked up based on TunnelNextHopIp
	TunnelNextHopIP       net.IP           // NextHopIP is used to find the DMAC for the tunnel within Asicd
}

func ConvertInt32ToBool(val int32) bool {
	if val == 0 {
		return false
	}
	return true
}

// VxlanConfigCheck
// Validate the VXLAN provisioning
func VxlanConfigCheck(c *VxlanConfig) error {
	if GetVxlanDBEntry(c.VNI) != nil {
		return errors.New(fmt.Sprintln("Error VxlanInstance Exists vni is not unique", c))
	}
	return nil
}

// VtepConfigCheck
// Validate the VTEP provisioning
func VtepConfigCheck(c *VtepConfig) error {
	key := VtepDbKey{
		name: c.VtepName,
	}
	if GetVtepDBEntry(&key) != nil {
		return errors.New(fmt.Sprintln("Error VtepInstance Exists name is not unique", c))
	}
	return nil
}

// ConvertVxlanInstanceToVxlanConfig:
// Convert thrift struct to vxlan config and check that db entry exists already
func ConvertVxlanInstanceToVxlanConfig(c *vxland.VxlanInstance) (*VxlanConfig, error) {

	if GetVxlanDBEntry(uint32(c.Vni)) != nil {
		return nil, errors.New(fmt.Sprintln("Error VxlanInstance Exists", c))
	}

	return &VxlanConfig{
		VNI:    uint32(c.Vni),
		VlanId: uint16(c.VlanId),
	}, nil
}

func getVtepName(intf string) string {
	vtepName := intf
	//if !strings.Contains("vtep", intf) {
	//	vtepName = "vtep" + intf
	//}
	return vtepName
}

// ConvertVxlanVtepInstanceToVtepConfig:
// Convert thrift struct to vxlan config
func ConvertVxlanVtepInstanceToVtepConfig(c *vxland.VxlanVtepInstance) (*VtepConfig, error) {

	var mac net.HardwareAddr
	var ip net.IP
	var name string
	//var ok bool
	vtepName := getVtepName(c.Intf)
	name = c.IntfRef
	ip = net.ParseIP(c.SrcIp)

	/* TODO need to create a generic way to get an interface name, mac, ip
	if c.SrcIp == "0.0.0.0" && c.IntfRef != "" {
		// need to get the appropriate IntfRef type
		ok, name, mac, ip = snapclient.asicDGetLoopbackInfo()
		if !ok {
			errorstr := "VTEP: Src Tunnel Info not provisioned yet, loopback intf needed"
			logger.Info(errorstr)
			return &VtepConfig{}, errors.New(errorstr)
		}
		fmt.Println("loopback info:", name, mac, ip)
		if c.SrcIp != "0.0.0.0" {
			ip = net.ParseIP(c.SrcIp)
		}
		logger.Info(fmt.Sprintf("Forcing Vtep %s to use Lb %s SrcMac %s Ip %s", vtepName, name, mac, ip))
	}
	*/

	return &VtepConfig{
		Vni:       uint32(c.Vni),
		VtepName:  vtepName,
		SrcIfName: name,
		UDP:       uint16(c.DstUDP),
		TTL:       uint16(c.TTL),
		TOS:       uint16(c.TOS),
		InnerVlanHandlingMode: c.InnerVlanHandlingMode,
		TunnelSrcIp:           ip,
		TunnelDstIp:           net.ParseIP(c.DstIp),
		VlanId:                uint16(c.VlanId),
		TunnelSrcMac:          mac,
	}, nil
}

func (s *VXLANServer) updateThriftVxLAN(c *VxlanUpdate) {
	objTyp := reflect.TypeOf(c.Oldconfig)

	// important to note that the attrset starts at index 0 which is the BaseObj
	// which is not the first element on the thrift obj, thus we need to skip
	// this attribute
	for i := 0; i < objTyp.NumField(); i++ {
		objName := objTyp.Field(i).Name
		if c.Attr[i] {

			if objName == "VxlanId" {
				// TODO
			}
			if objName == "McDestIp" {
				// TODO
			}
			if objName == "VlanId" {
				// TODO
			}
			if objName == "Mtu" {
				// TODO
			}
		}
	}
}

func (s *VXLANServer) updateThriftVtep(c *VtepUpdate) {
	objTyp := reflect.TypeOf(c.Oldconfig)

	// important to note that the attrset starts at index 0 which is the BaseObj
	// which is not the first element on the thrift obj, thus we need to skip
	// this attribute
	for i := 0; i < objTyp.NumField(); i++ {
		objName := objTyp.Field(i).Name
		if c.Attr[i] {

			if objName == "InnerVlanHandlingMode" {
				// TODO
			}
			if objName == "UDP" {
				// TODO
			}
			if objName == "TunnelSourceIp" {
				// TODO
			}
			if objName == "SrcMac" {
				// TODO
			}
			if objName == "L2miss" {
				// TODO
			}
			if objName == "TOS" {
				// TODO
			}
			if objName == "VxlanId" {
				// TODO
			}
			if objName == "VtepName" {
				// TODO
			}
			if objName == "VlanId" {
				// TODO
			}
			if objName == "Rsc" {
				// TODO
			}
			if objName == "VtepId" {
				// TODO
			}
			if objName == "SrcIfIndex" {
				// TODO
			}
			if objName == "L3miss" {
				// TODO
			}
			if objName == "Learning" {
				// TODO
			}
			if objName == "TTL" {
				// TODO
			}
			if objName == "TunnelDestinationIp" {
				// TODO
			}
		}
	}
}

func (s *VXLANServer) ConfigListener() {

	go func(cc *VxLanConfigChannels) {
		for {
			select {

			case daemonstatus := <-s.DaemonStatusCh:
				if daemonstatus.Name == "asicd" {
					// TODO do something
				} else if daemonstatus.Name == "ribd" {
					// TODO do something
				} else if daemonstatus.Name == "arpd" {
					// TODO do something
				}
			case vxlan := <-cc.Vxlancreate:
				CreateVxLAN(&vxlan)

			case vxlan := <-cc.Vxlandelete:
				DeleteVxLAN(&vxlan)

			case <-cc.Vxlanupdate:
				//s.UpdateThriftVxLAN(&vxlan)

			case vtep := <-cc.Vtepcreate:
				CreateVtep(&vtep)

			case vtep := <-cc.Vtepdelete:
				DeleteVtep(&vtep)

			case <-cc.Vtepupdate:
				//s.UpdateThriftVtep(&vtep)

			case <-cc.VxlanAccessPortVlanUpdate:
				// updates from client which are post create of vxlan

			case ipinfo := <-cc.VxlanNextHopUpdate:
				// updates from client which are triggered post create of vtep
				reachable := false
				if ipinfo.Command == VxlanCommandCreate {
					reachable = true
				}
				//ip := net.ParseIP(fmt.Sprintf("%s.%s.%s.%s", uint8(ipinfo.Ip>>24&0xff), uint8(ipinfo.Ip>>16&0xff), uint8(ipinfo.Ip>>8&0xff), uint8(ipinfo.Ip>>0&0xff)))
				s.HandleNextHopChange(ipinfo.Ip, ipinfo.NextHopIp, ipinfo.Intf, ipinfo.IntfName, reachable)

			case port := <-cc.VxlanPortCreate:
				// store all the valid physical ports
				if _, ok := PortConfigMap[port.IfIndex]; !ok {
					var portcfg = &PortConfig{
						Name:         port.Name,
						HardwareAddr: port.HardwareAddr,
						Speed:        port.Speed,
						PortNum:      port.PortNum,
						IfIndex:      port.IfIndex,
					}					
                                        logger.Info("Saving Port Config to db", *portcfg)
					PortConfigMap[port.IfIndex] = portcfg
				}
			case intfinfo := <-cc.Vxlanintfinfo:
				for _, vtep := range GetVtepDB() {
					logger.Info(fmt.Sprintln("received intf info", intfinfo, vtep))
					if vtep.SrcIfName == intfinfo.IntfName {

						vtep.VxlanVtepMachineFsm.VxlanVtepEvents <- MachineEvent{
							E:    VxlanVtepEventSrcInterfaceResolved,
							Src:  VxlanVtepMachineModuleStr,
							Data: intfinfo,
						}
					}
				}
			}
		}
	}(s.Configchans)
}
