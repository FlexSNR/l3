// hw.go
package snapclient

import (
	"arpd"
	"asicd/pluginManager/pluginCommon"
	"asicdServices"
	"encoding/json"
	//"fmt"
	"git.apache.org/thrift.git/lib/go/thrift"
	"io/ioutil"
	"net"
	"ribd"
	"strconv"
	"strings"
	"time"
	"utils/commonDefs"
	"utils/ipcutils"
)

//var softswitch *vxlan_linux.VxlanLinux

type VXLANClientBase struct {
	Address            string
	Transport          thrift.TTransport
	PtrProtocolFactory *thrift.TBinaryProtocolFactory
	IsConnected        bool
}

type ClientJson struct {
	Name string `json:Name`
	Port int    `json:Port`
}

/*
func ConvertVxlanConfigToVxlanLinuxConfig(c *VxlanConfig) *vxlan_linux.VxlanConfig {

	return &vxlan_linux.VxlanConfig{
		VNI:    c.VNI,
		VlanId: c.VlanId,
		Group:  c.Group,
		MTU:    c.MTU,
	}
}


func ConvertVtepToVxlanLinuxConfig(vtep *VtepDbEntry) *vxlan_linux.VtepConfig {
	return &vxlan_linux.VtepConfig{
		Vni:          vtep.Vni,
		VtepName:     vtep.VtepName,
		SrcIfName:    vtep.SrcIfName,
		UDP:          vtep.UDP,
		TTL:          vtep.TTL,
		TunnelSrcIp:  vtep.SrcIp,
		TunnelDstIp:  vtep.DstIp,
		VlanId:       vtep.VlanId,
		TunnelSrcMac: vtep.SrcMac,
		TunnelDstMac: vtep.DstMac,
	}
}
*/

// look up the various other daemons based on c string
func GetClientPort(paramsFile string, c string) int {
	var clientsList []ClientJson

	bytes, err := ioutil.ReadFile(paramsFile)
	if err != nil {
		return 0
	}

	err = json.Unmarshal(bytes, &clientsList)
	if err != nil {
		return 0
	}

	for _, client := range clientsList {
		if client.Name == c {
			return client.Port
		}
	}
	return 0
}

// ConnectToClients:
// connect the clients to which vxland will need send/receive information
// For this client we will need to connect to asicd, ribd, and arpd
// 1) asicd - provision: vtep/vxlan,
//           notifications: vlan port membership, link up/down
// 2) ribd - provision: next hop ip retreival
//           notifications: next hop reachability changes
// 3) arpd - provision: resolve next hop ip
func (intf VXLANSnapClient) ConnectToClients(clientFile string) {
	allclientsconnect := 0
	clientList := [3]string{"asicd", "ribd", "arpd"}
	for allclientsconnect < len(clientList) {
		for _, client := range clientList {
			port := GetClientPort(clientFile, client)
			//logger.Info(fmt.Sprintf("VXLAN -> looking to connect %s isconnected asicd[%t] ribd[%t] arpd[%t] numconnected[%d]",
			//	client, asicdclnt.IsConnected, ribdclnt.IsConnected, arpdclnt.IsConnected, allclientsconnect))

			if !asicdclnt.IsConnected && client == "asicd" {
				asicdclnt.Address = "localhost:" + strconv.Itoa(port)
				asicdclnt.Transport, asicdclnt.PtrProtocolFactory, _ = ipcutils.CreateIPCHandles(asicdclnt.Address)
				if asicdclnt.Transport != nil && asicdclnt.PtrProtocolFactory != nil {
					asicdclnt.ClientHdl = asicdServices.NewASICDServicesClientFactory(asicdclnt.Transport, asicdclnt.PtrProtocolFactory)
					asicdclnt.IsConnected = true
					// lets gather all info needed from asicd such as the port
					logger.Info("VXLAN -> ASICD connected")
					allclientsconnect++
				}
			} else if !ribdclnt.IsConnected && client == "ribd" {
				ribdclnt.Address = "localhost:" + strconv.Itoa(port)
				ribdclnt.Transport, ribdclnt.PtrProtocolFactory, _ = ipcutils.CreateIPCHandles(ribdclnt.Address)
				if ribdclnt.Transport != nil && asicdclnt.PtrProtocolFactory != nil {
					ribdclnt.ClientHdl = ribd.NewRIBDServicesClientFactory(ribdclnt.Transport, ribdclnt.PtrProtocolFactory)
					ribdclnt.IsConnected = true
					logger.Info("VXLAN -> RIBD connected")
					allclientsconnect++
				}
			} else if !arpdclnt.IsConnected && client == "arpd" {
				arpdclnt.Address = "localhost:" + strconv.Itoa(port)
				arpdclnt.Transport, arpdclnt.PtrProtocolFactory, _ = ipcutils.CreateIPCHandles(arpdclnt.Address)
				if arpdclnt.Transport != nil && arpdclnt.PtrProtocolFactory != nil {
					arpdclnt.ClientHdl = arpd.NewARPDServicesClientFactory(arpdclnt.Transport, arpdclnt.PtrProtocolFactory)
					arpdclnt.IsConnected = true
					logger.Info("VXLAN -> ARPD connected")
					allclientsconnect++
				}
			}
		}
		// lets delay to allow time for other processes to come up
		if allclientsconnect < len(clientList) {
			time.Sleep(time.Millisecond * 500)
		}
	}
	// lets call any client init configuration needed here
	intf.ConstructPortConfigMap()

	// need to listen for next hop notifications
	go intf.createRIBdSubscriber()
	// need to listen for por vlan membership notifications
	go intf.createASICdSubscriber()
}

func asicDGetLoopbackInfo() (success bool, lbname string, mac net.HardwareAddr, ip net.IP) {
	// TODO this logic only assumes one loopback interface.  More logic is needed
	// to handle multiple  loopbacks configured.  The idea should be
	// that the lowest IP address is used.
	if asicdclnt.ClientHdl != nil {
		more := true
		for more {
			currMarker := asicdServices.Int(0)
			bulkInfo, err := asicdclnt.ClientHdl.GetBulkLogicalIntfState(currMarker, 5)
			if err == nil {
				objCount := int(bulkInfo.Count)
				more = bool(bulkInfo.More)
				currMarker = asicdServices.Int(bulkInfo.EndIdx)
				for i := 0; i < objCount; i++ {
					ifindex := bulkInfo.LogicalIntfStateList[i].IfIndex
					lbname = bulkInfo.LogicalIntfStateList[i].Name
					if pluginCommon.GetTypeFromIfIndex(ifindex) == commonDefs.IfTypeLoopback {
						mac, _ = net.ParseMAC(bulkInfo.LogicalIntfStateList[i].SrcMac)
						ipV4ObjMore := true
						ipV4ObjCurrMarker := asicdServices.Int(0)
						for ipV4ObjMore {
							ipV4BulkInfo, _ := asicdclnt.ClientHdl.GetBulkIPv4IntfState(ipV4ObjCurrMarker, 20)
							ipV4ObjCount := int(ipV4BulkInfo.Count)
							ipV4ObjCurrMarker = asicdServices.Int(bulkInfo.EndIdx)
							ipV4ObjMore = bool(ipV4BulkInfo.More)
							for j := 0; j < ipV4ObjCount; j++ {
								if ipV4BulkInfo.IPv4IntfStateList[j].IfIndex == ifindex {
									success = true
									ip = net.ParseIP(strings.Split(ipV4BulkInfo.IPv4IntfStateList[j].IpAddr, "/")[0])
									return success, lbname, mac, ip
								}
							}
						}
					}
				}
			}
		}
	}
	return success, lbname, mac, ip
}

func asicDLearnFwdDbEntry(mac net.HardwareAddr, vtepName string, ifindex int32) {
	//macstr := mac.String()
	// convert a vxland config to hw config
	//if asicdclnt.ClientHdl != nil {
	//asicdclnt.ClientHdl.DeleteVxlanVtep(ConvertVtepConfigToVxlanAsicdConfig(vtep))
	//}
	/* Add as another interface
	else {
		// run standalone
		if softswitch != nil {
			softswitch.LearnFdbVtep(macstr, vtepName, ifindex)
		}
	}
	*/
}
