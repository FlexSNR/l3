package snapclient

import (
//	"asicd/asicdCommonDefs"
	"encoding/json"
	"fmt"
	nanomsg "github.com/op/go-nanomsg"
	"l3/rib/ribdCommonDefs"
	vxlan "l3/tunnel/vxlan/protocol"
	"net"
	"ribd"
)

type RibdClient struct {
	VXLANClientBase
	ClientHdl *ribd.RIBDServicesClient
}

var ribdclnt RibdClient

func (intf VXLANSnapClient) createRIBdSubscriber() error {
	logger.Info("Listen for RIBd updates")
	address := ribdCommonDefs.PUB_SOCKET_VXLAND_ADDR
	var err error
	if intf.ribdSubSocket, err = nanomsg.NewSubSocket(); err != nil {
		logger.Err(fmt.Sprintln("Failed to create RIBd subscribe socket, error:", err))
		return err
	}

	if _, err = intf.ribdSubSocket.Connect(address); err != nil {
		logger.Err(fmt.Sprintln("Failed to connect to RIBd publisher socket, address:", address, "error:", err))
		return err
	}

	if err = intf.ribdSubSocket.Subscribe(""); err != nil {
		logger.Err(fmt.Sprintln("Failed to subscribe to \"\" on RIBd subscribe socket, error:", err))
		return err
	}

	logger.Info(fmt.Sprintln("Connected to RIBd publisher at address:", address))
	if err = intf.ribdSubSocket.SetRecvBuffer(1024 * 1024); err != nil {
		logger.Err(fmt.Sprintln("Failed to set the buffer size for RIBd publisher socket, error:", err))
		return err
	}
	//intf.listenForRIBdUpdates(ribdCommonDefs.PUB_SOCKET_VXLAND_ADDR)
	for {
		logger.Info("Read on RIBd subscriber socket...")
		rxBuf, err := intf.ribdSubSocket.Recv(0)
		if err != nil {
			logger.Err(fmt.Sprintln("Recv on RIBd subscriber socket failed with error:", err))
			intf.ribdSubSocketErrCh <- err
			continue
		}
		logger.Info(fmt.Sprintln("RIB subscriber recv returned:", rxBuf))
		intf.ribdSubSocketCh <- rxBuf
	}
	return nil
}

func (intf VXLANSnapClient) listenForRIBdUpdates(address string) error {
	var err error
	if intf.ribdSubSocket, err = nanomsg.NewSubSocket(); err != nil {
		logger.Err(fmt.Sprintln("Failed to create RIBd subscribe socket, error:", err))
		return err
	}

	if _, err = intf.ribdSubSocket.Connect(address); err != nil {
		logger.Err(fmt.Sprintln("Failed to connect to RIBd publisher socket, address:", address, "error:", err))
		return err
	}

	if err = intf.ribdSubSocket.Subscribe(""); err != nil {
		logger.Err(fmt.Sprintln("Failed to subscribe to \"\" on RIBd subscribe socket, error:", err))
		return err
	}

	logger.Info(fmt.Sprintln("Connected to RIBd publisher at address:", address))
	if err = intf.ribdSubSocket.SetRecvBuffer(1024 * 1024); err != nil {
		logger.Err(fmt.Sprintln("Failed to set the buffer size for RIBd publisher socket, error:", err))
		return err
	}
	return nil
}

func (intf VXLANSnapClient) processRibdNotification(rxBuf []byte) error {
	var msg ribdCommonDefs.RibdNotifyMsg
	err := json.Unmarshal(rxBuf, &msg)
	if err != nil {
		logger.Err(fmt.Sprintln("Unable to unmarshal rxBuf:", rxBuf))
		return err
	}
	switch msg.MsgType {
	case ribdCommonDefs.NOTIFY_ROUTE_REACHABILITY_STATUS_UPDATE:
		logger.Info(fmt.Sprintln("Received NOTIFY_ROUTE_REACHABILITY_STATUS_UPDATE"))
		var msgInfo ribdCommonDefs.RouteReachabilityStatusMsgInfo
		err = json.Unmarshal(msg.MsgBuf, &msgInfo)
		if err != nil {
			logger.Err(fmt.Sprintln("Unable to unmarshal msg:", msg.MsgBuf))
			return err
		}
		logger.Info(fmt.Sprintln(" IP ", msgInfo.Network, " reachabilityStatus: ", msgInfo.IsReachable))
		if msgInfo.IsReachable {
			//logger.Info(fmt.Sprintln(" NextHop IP:", msgInfo.NextHopIntf.NextHopIp, " IntfType:IntfId ", msgInfo.NextHopIntf.NextHopIfType, ":", msgInfo.NextHopIntf.NextHopIfIndex))
			//ifIndex := asicdCommonDefs.GetIfIndexFromIntfIdAndIntfType(int(msgInfo.NextHopIntf.NextHopIfType), int(msgInfo.NextHopIntf.NextHopIfIndex))
			serverchannels.VxlanNextHopUpdate <- vxlan.VxlanNextHopIp{
				Command:   vxlan.VxlanCommandCreate,
				Intf:      int32(msgInfo.NextHopIntf.NextHopIfIndex),
				NextHopIp: net.ParseIP(msgInfo.NextHopIntf.NextHopIp),
			}
		} else {
			logger.Info(fmt.Sprintln(" NextHop IP:", msgInfo.NextHopIntf.NextHopIp, " is not reachable "))
			serverchannels.VxlanNextHopUpdate <- vxlan.VxlanNextHopIp{
				Command:   vxlan.VxlanCommandDelete,
				Intf:      int32(msgInfo.NextHopIntf.NextHopIfIndex),
				NextHopIp: net.ParseIP(msgInfo.NextHopIntf.NextHopIp),
			}
		}
		break
	default:
		break
	}
	return nil
}

// GetNextHopInfo:
// rib holds the next hop info so lets quiery the for the next hop
// then notify the vtep channel of that ip
func (intf VXLANSnapClient) GetNextHopInfo(ip net.IP, vtepnexthopchan chan<- vxlan.MachineEvent) {
	if ribdclnt.ClientHdl != nil {
		nexthopinfo, err := ribdclnt.ClientHdl.GetRouteReachabilityInfo(ip.String(), -1)
		if err == nil {
                        fmt.Println("GetNextHopInfo", ip, nexthopinfo, vxlan.PortConfigMap[3].Name)

			nexthopip := net.ParseIP(nexthopinfo.NextHopIp)
			if nexthopinfo.IsReachable &&
				nexthopinfo.NextHopIp == "0.0.0.0" {
				nexthopip = ip
			}
			// lets let RIB notify us if there is a change in next hop
			ribdclnt.ClientHdl.TrackReachabilityStatus(ip.String(), "VXLAND", "add")
			// TODO at this point assuming the next hop is a physical interface
			nexthopdata := vxlan.VtepNextHopInfo{
				Ip:      nexthopip,
				IfIndex: int32(nexthopinfo.NextHopIfIndex),
				IfName:  vxlan.PortConfigMap[int32(nexthopinfo.NextHopIfIndex)].Name,
			}

			event := vxlan.MachineEvent{
				E:    vxlan.VxlanVtepEventNextHopInfoResolved,
				Src:  vxlan.VXLANSnapClientStr,
				Data: nexthopdata,
			}
			vtepnexthopchan <- event
		}
	}
}
