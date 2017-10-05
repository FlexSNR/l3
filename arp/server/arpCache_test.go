package server

import (
	"net"
	"testing"
)

func (server *ARPServer) SetPortPropertyMap() {
	portEnt, _ := server.portPropMap[20]
	portEnt.IfName = "fpPort20"
	portEnt.MacAddr = "11:22:33:44:55:66"
	portEnt.IpAddr = "10.10.10.20"
	portEnt.Netmask = net.IPMask([]byte{0xff, 0xff, 0xff, 0})
	portEnt.L3IfIdx = 20
	portEnt.LagIfIdx = -1
	server.portPropMap[20] = portEnt
}

func (server *ARPServer) SetVlanPropertyMap() {

}

func (server *ARPServer) SetLagPropertyMap() {

}

func (server *ARPServer) SetL3PropertyMap() {
	l3Ent, _ := server.l3IntfPropMap[20]
	l3Ent.Netmask = net.IPMask([]byte{0xff, 0xff, 0xff, 0})
	l3Ent.IpAddr = "10.10.10.20"
	l3Ent.IfName = "fpPort20"
	server.l3IntfPropMap[20] = l3Ent
}

func TestProcessArpEntryUpdateMsg(t *testing.T) {
	t.Log("Testing initArpParams()")
	logger, err := NewLogger("arpdTest", "ARPTest", true)
	if err != nil {
		t.Errorf("Unable to initialize logger")
		return
	}
	ser := NewARPServer(logger)

	msg := UpdateArpEntryMsg{
		PortNum: 10,
		IpAddr:  "10.10.10.10",
		MacAddr: "00:11:22:33:44:55",
		Type:    false,
	}

	ser.processArpEntryUpdateMsg(msg)
	_, exist := ser.arpCache["10.10.10.10"]
	if !exist {
		t.Log("Successfully test processArpEntryUpdateMsg() with invalid port")
	} else {
		t.Errorf("Successfully test processArpEntryUpdateMsg() with invalid port")
	}
	ser.SetPortPropertyMap()
	msg = UpdateArpEntryMsg{
		PortNum: 20,
		IpAddr:  "10.10.10.10",
		MacAddr: "00:11:22:33:44:55",
		Type:    false,
	}

	ser.processArpEntryUpdateMsg(msg)
	_, exist = ser.arpCache["10.10.10.10"]
	if !exist {
		t.Log("Successfully test processArpEntryUpdateMsg() with valid port but no l3 interface")
	} else {
		t.Errorf("Successfully test processArpEntryUpdateMsg() with valid port and no l3 interface")
	}

	ser.SetL3PropertyMap()
	msg = UpdateArpEntryMsg{
		PortNum: 10,
		IpAddr:  "10.10.10.10",
		MacAddr: "00:11:22:33:44:55",
		Type:    false,
	}

	ser.processArpEntryUpdateMsg(msg)
	_, exist = ser.arpCache["10.10.10.10"]
	if !exist {
		t.Log("Successfully test processArpEntryUpdateMsg() with valid port and invalid l3 interface")
	} else {
		t.Errorf("Successfully test processArpEntryUpdateMsg() with invalid port and invalid l3 interface")
	}
}
