// vxlanArpd.go
package snapclient

import (
	"arpd"
	"arpdInt"
	"fmt"
	vxlan "l3/tunnel/vxlan/protocol"
	"net"
	"strings"
)

type ArpdClient struct {
	VXLANClientBase
	ClientHdl *arpd.ARPDServicesClient
}

var arpdclnt ArpdClient

func (intf VXLANSnapClient) ResolveNextHopMac(nexthopip net.IP, macchan chan<- vxlan.MachineEvent) {
	if arpdclnt.ClientHdl != nil {
		arpentrystate, err := arpdclnt.ClientHdl.GetArpEntryState(nexthopip.String())
		logger.Info(fmt.Sprintln("calling GetArpEntryState", nexthopip, nexthopip.String(), arpentrystate, err))
		if err == nil && !strings.Contains(arpentrystate.MacAddr, "incomplete") && arpentrystate.MacAddr != "" {
			nexthopmac, _ := net.ParseMAC(arpentrystate.MacAddr)
			event := vxlan.MachineEvent{
				E:    vxlan.VxlanVtepEventNextHopInfoMacResolved,
				Src:  vxlan.VXLANSnapClientStr,
				Data: nexthopmac,
			}
			macchan <- event
		} else {
			logger.Info(fmt.Sprintln("calling ResolveArpIPV4", nexthopip))
			portstate, _ := asicdclnt.ClientHdl.GetPortState("em4")
			//arpdclnt.ClientHdl.ResolveArpIPV4(nexthopip.String(), arpdInt.Int(portstate.Pvid))
			arpdclnt.ClientHdl.ResolveArpIPV4(nexthopip.String(), arpdInt.Int(portstate.IfIndex))
		}
	}
}
