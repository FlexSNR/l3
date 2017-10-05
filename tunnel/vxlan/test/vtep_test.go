package vxlan_test

import (
	"fmt"
	vxlan_linux "l3/tunnel/vxlan/clients/testlinux"
	vxlan "l3/tunnel/vxlan/protocol"
	"net"
	"testing"
	"time"
	"utils/logging"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/vishvananda/netlink"
)

var logger *logging.Writer

func Setup() {
	logger, _ = logging.NewLogger("./", "vxland", true)
	vxlan.SetLogger(logger)
	// options "linux", "proxy"
	// as of 4/11/16 linux does not work getting error counts (carrier)
	vxlan_linux.VxlanConfigMode = "proxy"
}

var UDP_PORT layers.UDPPort = 4789

//var UDP_PORT layers.UDPPort = 8472

func CreateTestLbPort(name string) error {

	var linkAttrs netlink.LinkAttrs
	//create loopbacki/f
	liLink, err := netlink.LinkByName(name)
	if err != nil {

		linkAttrs.Name = name
		linkAttrs.Flags = net.FlagLoopback
		linkAttrs.HardwareAddr = net.HardwareAddr{
			0x00, 0x00, 0x64, 0x01, 0x01, 0x01,
		}
		//liLink = &netlink.Dummy{linkAttrs} //,"loopback"}
		liLink = &netlink.Veth{linkAttrs, "tap2"}

		err = netlink.LinkAdd(liLink)
		if err != nil {
			logger.Err(fmt.Sprintf("SS: LinkAdd call failed during CreateTestLbPort() ", err))
			return err
		}
		time.Sleep(5 * time.Second)
		link, err2 := netlink.LinkByName(name)
		if err2 != nil {
			logger.Err(fmt.Sprintf("SS: 2 LinkByName call failed during CreateTestLbPort()", err2))
			return err2
		}
		err = netlink.LinkSetUp(link)
		if err != nil {
			logger.Err(fmt.Sprintf("SS: LinkSetUp call failed during CreateTestLbPort()", err))
			return err
		}
	}
	// need to delay some time to let the interface create to happen
	time.Sleep(5 * time.Second)
	return nil
}

func CreateTestTxHandle(ifname string) *pcap.Handle {
	handle, err := pcap.OpenLive(ifname, 65536, false, 50*time.Millisecond)
	if err != nil {
		logger.Err(fmt.Sprintf("SS: FAiled during OpenLive()", err))
		return nil
	}
	return handle
}

func CreateVxlanArpFrame(vni [3]uint8) gopacket.SerializeBuffer {
	// send an ARP frame
	// Set up all the layers' fields we can.
	tunnelsrcmac, _ := net.ParseMAC("00:00:64:01:01:02")
	tunneldstmac, _ := net.ParseMAC("00:00:64:01:01:01")
	tunnelsrcip := net.ParseIP("100.1.1.2")
	tunneldstip := net.ParseIP("100.1.1.1")
	// outer ethernet header
	eth := layers.Ethernet{
		SrcMAC:       tunnelsrcmac,
		DstMAC:       tunneldstmac,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := layers.IPv4{
		Version:    4,
		IHL:        20,
		TOS:        0,
		Length:     120,
		Id:         0xd2c0,
		Flags:      layers.IPv4DontFragment, //IPv4Flag
		FragOffset: 0,                       //uint16
		TTL:        255,
		Protocol:   layers.IPProtocolUDP, //IPProtocol
		SrcIP:      tunnelsrcip,
		DstIP:      tunneldstip,
	}

	udp := layers.UDP{
		SrcPort: UDP_PORT,
		DstPort: UDP_PORT,
		Length:  100,
	}
	udp.SetNetworkLayerForChecksum(&ip)

	vxlan := layers.VXLAN{
		Flags: 0x08,
		VNI:   vni,
	}

	dstmac, _ := net.ParseMAC("FF:FF:FF:FF:FF:FF")
	srcmac, _ := net.ParseMAC("00:01:02:03:04:05")

	// inner ethernet header
	ieth := layers.Ethernet{
		SrcMAC:       srcmac,
		DstMAC:       dstmac,
		EthernetType: layers.EthernetTypeARP,
	}

	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeARP,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         1,
		SourceHwAddress:   []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05},
		SourceProtAddress: []byte{0xA, 0x01, 0x01, 0x01},
		DstHwAddress:      []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		DstProtAddress:    []byte{0x14, 0x01, 0x01, 0x011},
	}

	// Set up buffer and options for serialization.
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	// Send one packet for every address.
	gopacket.SerializeLayers(buf, opts, &eth, &ip, &udp, &vxlan, &ieth, &arp)

	p := gopacket.NewPacket(buf.Bytes(), layers.LinkTypeEthernet, gopacket.Default)
	fmt.Println("created packet", p)
	return buf
}

func SendPacket(handle *pcap.Handle, buf gopacket.SerializeBuffer, t *testing.T) {
	if err := handle.WritePacketData(buf.Bytes()); err != nil {
		t.Error("Error writing packet to interface")
		t.FailNow()
	}
}

func CreateTestVtepRxHandle(ifname string) *pcap.Handle {
	handle, err := pcap.OpenLive(ifname, 65536, false, 50*time.Millisecond)
	if err != nil {
		logger.Err(fmt.Sprintf("SS: FAiled during OpenLive()", err))
		return nil
	}
	return handle
}

func WaitForRxPacket(handle *pcap.Handle) chan bool {
	waitdone := make(chan bool)
	src := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	in := src.Packets()
	timeout := time.NewTimer(10 * time.Second)
	go func() {
		for {
			select {
			case packet, ok := <-in:
				if ok {
					fmt.Println("TEST: Rx packet", packet)
					timeout.Stop()
					waitdone <- true
					return
				} else {
					// channel closed
					return
				}
			case <-timeout.C:
				waitdone <- false
				return
			}
		}
	}()

	return waitdone
}

func waitTillVtepIsUp(ifname string) {
	/* need to get stp if state??? can take up to 15 seconds
	for {
		link, _ := netlink.LinkByName(ifname)
		if link != nil {
			if link.Attrs().Flags&net.FlagUp != 0 {
				break
			} else {
				fmt.Println("Link is not up yet")
			}
		} else {
			fmt.Println("Link has not been created yet")
		}
	}
	*/
	time.Sleep(15 * time.Second)

}

func _TestRxArpPacket(t *testing.T) {

	Setup()

	// setup
	vteplbnametx := "eth0" // test will send to this port
	vteplbnamerx := "eth2" // vxland will rx/tx on this port
	srcip := net.IP{0x64, 0x01, 0x01, 0x01}
	srcmac, _ := net.ParseMAC("00:00:64:01:01:01")
	dstip := net.IP{0x64, 0x01, 0x01, 0x02}
	dstmac, _ := net.ParseMAC("00:00:64:01:01:02")

	vxlanconfig := &vxlan.VxlanConfig{
		VNI:    500,
		VlanId: 100, // used to tag inner ethernet frame when egressing
		MTU:    1550,
	}

	vxlan.CreateVxLAN(vxlanconfig)

	fmt.Printf("src/dst ip %#v %#v \n", srcip, dstip)
	vtepconfig := &vxlan.VtepConfig{
		Vni:       500,
		VtepName:  "vtep10",
		SrcIfName: vteplbnamerx,
		UDP:       uint16(UDP_PORT),
		TTL:       255,
		TOS:       0,
		InnerVlanHandlingMode: 0,
		Learning:              false,
		Rsc:                   false,
		L2miss:                false,
		L3miss:                false,
		TunnelSrcIp:           srcip,
		TunnelDstIp:           dstip,
		VlanId:                100,
		TunnelSrcMac:          srcmac,
		TunnelDstMac:          dstmac,
	}
	/*
		if vteplbnametx != "tap1" {
			// create linux loopback interface to which the vtep will be associated with
			err := CreateTestLbPort(vteplbnametx)
			if err != nil {
				t.Error("Failed to Create test looopback interface")
				t.FailNow()
			}
		}
	*/

	handle := CreateTestTxHandle(vteplbnametx)
	if handle == nil {
		t.Error("Failed to Create pcap handle")
		t.FailNow()
	}
	var rxhandle *pcap.Handle
	if vxlan_linux.VxlanConfigMode == "proxy" {
		rxhandle = CreateTestVtepRxHandle(vtepconfig.VtepName)
	}
	// create vtep interface and which will listen on vtep interface
	vxlan.CreateVtep(vtepconfig)
	// delay to allow for resources to be created in linux
	waitTillVtepIsUp(vtepconfig.VtepName)
	// send an ARP frame
	// Set up all the layers' fields we can.
	arppktbuf := CreateVxlanArpFrame([3]uint8{uint8(vtepconfig.Vni >> 16 & 0xff), uint8(vtepconfig.Vni >> 8 & 0xff), uint8(vtepconfig.Vni >> 0 & 0xff)})
	fmt.Println("Sending packet to ", vteplbnametx)
	if vxlan_linux.VxlanConfigMode == "proxy" {

		// create a listener for the packet that should be received
		donechan := WaitForRxPacket(rxhandle)
		// send packet
		SendPacket(handle, arppktbuf, t)
		done := <-donechan
		if !done {
			t.Error("Failed to Receive packet")
			t.FailNow()
		}
		// lets close the listner channel
		rxhandle.Close()
	}

	// cleanup the resources
	vxlan.DeleteVtep(vtepconfig)
	vxlan.DeleteVxLAN(vxlanconfig)

	if len(vxlan.GetVxlanDB()) != 0 {
		t.Error("Failed to Delete Vxlan entry")
		t.FailNow()
	}

	if len(vxlan.GetVtepDB()) != 0 {
		t.Error("Failed to Delete Vtep entry")
		t.FailNow()
	}
	// Linux needs time to clean up all its resources
	time.Sleep(3 * time.Second)
	link, err := netlink.LinkByName(fmt.Sprintf("br%d", vxlanconfig.VNI))
	if link != nil {
		t.Error(fmt.Sprintf("Failed to delete bridge", err))
		t.FailNow()
	}
	link, err = netlink.LinkByName(vtepconfig.VtepName)
	if link != nil {
		t.Error("Failed to delete vtep (vEth) interfaces")
		t.FailNow()
	}

}
