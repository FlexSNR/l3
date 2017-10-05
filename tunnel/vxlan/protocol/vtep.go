// vtepdb.go
// File contains db and struct which holds the vtep db.  Also it contains the logic
// for a small FSM which will wait till Next Hop and Next Hop MAC are resolved.
// The VTEP Encap and Decap functions are defined
// The pcap listener/sender for the VTEP is also defined
package vxlan

import (
	"encoding/json"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"io/ioutil"
	"net"
	"strings"
	"sync"
	"time"
)

// constants for the status of the VTEP based on FSM and provisioning
const (
	VtepStatusUp             vtepStatus = "UP"
	VtepStatusDown                      = "DOWN"
	VtepStatusAdminDown                 = "ADMIN DOWN"
	VtepStatusIncomplete                = "INCOMPLETE VTEP PROV"
	VtepStatusDetached                  = "ICOMPLETE VTEP VXLAN NOT PROV"
	VtepStatusIntfUnknown               = "SRC INTF UNKNOWN"
	VtepStatusNextHopUnknown            = "NEXT HOP UKNOWN"
	VtepStatusArpUnresolved             = "ARP UNRESOLVED"
	VtepStatusConfigPending             = "CONFIG PENDING"
)

// VtepDbKey
// Holds the key for the VtepDB
type VtepDbKey struct {
	name string
}

// vtepStatus
// defines the type for the status
type vtepStatus string

type VtepDbEntry struct {
	// reference to the vxlan db, and value used in encap/decap
	Vni uint32
	// name of this vtep interface
	VtepName string
	// interface name which vtep will get src ip/mac info from
	SrcIfName string
	// interface id which vtep will get src ip/mac info from
	SrcIfIndex int32
	// dst UDP port
	UDP uint16
	// TTL used in the ip header in the vxlan header
	TTL uint16
	// Source Ip used in ip header in the vxlan header
	SrcIp net.IP
	// Destination Ip used in ip header in the vxlan header
	DstIp net.IP
	// Vlan to be used to in the ethernet header in the vxlan header
	VlanId uint16
	// Source MAC to be used to in the ethernet header in the vxlan header
	SrcMac net.HardwareAddr
	// Destination MAC to be used to in the ethernet header in the vxlan header
	DstMac net.HardwareAddr
	// interface id for which packets vxlan packets should rx/tx for this vtep
	VtepIfIndex int32
	// Next Hop Ip used to find the next hop MAC which will be used as the DstMac of the vxlan header
	NextHop VtepNextHopInfo

	// Enable/Disable state
	Enable bool

	// handle name used to rx/tx packets to linux if
	VtepHandleName string
	// handle used to rx/tx packets to linux if
	handle *pcap.Handle

	// Reference to the vxlan server
	server *VXLANServer

	rxpkts uint64
	txpkts uint64

	VxlanVtepMachineFsm *VxlanVtepMachine

	/*
		nexthopchan      chan VtepNextHopInfo
		macchan          chan net.HardwareAddr
		hwconfig         chan bool
		killroutine      chan bool
		intfinfochan     chan VxlanIntfInfo
		vteplistenerchan chan string
	*/
	// number of ticks before hw was able to come up
	ticksTillConfig int
	ticksToPollArp  int

	retrytimer *time.Timer

	// wait group used to help sync on cleanup of FSM
	wg sync.WaitGroup
}

type VtepNextHopInfo struct {
	Ip      net.IP
	IfIndex int32
	IfName  string
}

// pcap handle (vtep) per source ip defined
type VtepVniSrcIpEntry struct {
	// handle used to rx/tx packets from other applications
	handle *pcap.Handle
}

type SrcIfIndexEntry struct {
	IfIndex int32
	// handle used to rx/tx packets from/to linux if
	handle *pcap.Handle
}

// vtep id to vtep data
var vtepDB map[VtepDbKey]*VtepDbEntry

// vni + customer mac to vtepId
//var fdbDb map[vtepVniCMACToVtepKey]VtepDbKey

// db to hold vni ip to pcap handle
var vtepAppPcap []VtepVniSrcIpEntry

var VxlanVtepSrcIp net.IP
var VxlanVtepSrcNetMac net.HardwareAddr
var VxlanVtepSrcMac [6]uint8
var VxlanVtepRxTx = CreateVtepRxTx

func (vtep *VtepDbEntry) GetRxStats() uint64 {
	return vtep.rxpkts
}

func (vtep *VtepDbEntry) GetTxStats() uint64 {
	return vtep.txpkts
}

func GetVtepDB() map[VtepDbKey]*VtepDbEntry {
	return vtepDB
}

func GetVtepDBEntry(key *VtepDbKey) *VtepDbEntry {
	if vtep, ok := vtepDB[*key]; ok {
		return vtep
	}
	return nil
}

/* TODO may need to keep a table to map customer macs to vtep
type srcMacVtepMap struct {
	SrcMac      net.HardwareAddr
	VtepIfIndex int32
}
*/

func NewVtepDbEntry(c *VtepConfig) *VtepDbEntry {
	vtep := &VtepDbEntry{
		Vni: c.Vni,
		// TODO if we are running in hw linux vs proxy then this should not be + Int
		VtepName:       c.VtepName,
		VtepHandleName: c.VtepName + "Int",
		//VtepName:  c.VtepName,
		SrcIfName: c.SrcIfName,
		UDP:       c.UDP,
		TTL:       c.TTL,
		DstIp:     c.TunnelDstIp,
		SrcIp:     c.TunnelSrcIp,
		SrcMac:    c.TunnelSrcMac,
		DstMac:    c.TunnelDstMac,
		VlanId:    c.VlanId,
		Enable:    true,
	}

	return vtep
}

func CreateVtep(c *VtepConfig) *VtepDbEntry {

	vtep := saveVtepConfigData(c)
	logger.Info(fmt.Sprintln("Vtep CreateVtep Start", vtep))
	// lets start the FSM
	vtep.VxlanVtepMachineMain()
	vtep.VxlanVtepMachineFsm.BEGIN()

	return vtep
}

func DeProvisionVtep(vtep *VtepDbEntry, del bool) {
	logger.Info("Calling DeprovisionVtep")
	// delete vtep resources in hw
	if vtep.VxlanVtepMachineFsm != nil &&
		(vtep.VxlanVtepMachineFsm.Machine.Curr.CurrentState() == VxlanVtepStateStart ||
			vtep.VxlanVtepMachineFsm.Machine.Curr.CurrentState() == VxlanVtepStateHwConfig) {
		for _, client := range ClientIntf {
			client.DeleteVtep(vtep)
		}
		if vtep.handle != nil {
			vtep.handle.Close()
		}
		// need to check the ref count on the port
		VxlanDelPortRxTx(vtep.NextHop.IfName, vtep.UDP)
	}

	// clear out the information which was discovered for this VTEP
	vtep.NextHop.Ip = nil
	vtep.NextHop.IfIndex = 0
	vtep.NextHop.IfName = ""
	if vtep.SrcIfName != "" {
		vtep.SrcIp = nil
	}
	vtep.DstMac, _ = net.ParseMAC("00:00:00:00:00:00")

	if !del {
		// restart the state machine
		vtep.VxlanVtepMachineFsm.VxlanVtepEvents <- MachineEvent{
			E:   VxlanVtepEventBegin,
			Src: VxlanVtepMachineModuleStr,
		}

		// restart the timer on deprovisioning as we will retry each of the
		// state transitions again
		vtep.retrytimer.Reset(retrytime)
	}
}

func DeleteVtep(c *VtepConfig) {

	key := &VtepDbKey{
		name: c.VtepName,
	}

	vtep := GetVtepDBEntry(key)
	if vtep != nil {
		DeProvisionVtep(vtep, true)
		if vtep.VxlanVtepMachineFsm != nil {
			vtep.VxlanVtepMachineFsm.Stop()
			vtep.VxlanVtepMachineFsm = nil
		}
		if vtep.retrytimer != nil {
			vtep.retrytimer.Stop()
			vtep.retrytimer = nil
		}

		delete(vtepDB, *key)
	}
}

func saveVtepConfigData(c *VtepConfig) *VtepDbEntry {
	key := &VtepDbKey{
		name: c.VtepName,
	}
	vtep := GetVtepDBEntry(key)
	if vtep == nil {
		vtep = NewVtepDbEntry(c)
		vtepDB[*key] = vtep
	}
	return vtep
}

func SaveVtepSrcMacSrcIp(paramspath string) {
	var cfgFile cfgFileJson
	asicdconffilename := paramspath + "asicdConf.json"
	cfgFileData, err := ioutil.ReadFile(asicdconffilename)
	if err != nil {
		logger.Info("Error reading config file - asicdConf.json")
		return
	}
	err = json.Unmarshal(cfgFileData, &cfgFile)
	if err != nil {
		logger.Info("Error parsing config file")
		return
	}

	VxlanVtepSrcNetMac, _ := net.ParseMAC(cfgFile.SwitchMac)
	VxlanVtepSrcMac = [6]uint8{VxlanVtepSrcNetMac[0], VxlanVtepSrcNetMac[1], VxlanVtepSrcNetMac[2], VxlanVtepSrcNetMac[3], VxlanVtepSrcNetMac[4], VxlanVtepSrcNetMac[5]}

}

func CreateVtepRxTx(vtep *VtepDbEntry) {
	vtep.createVtepSenderListener()
}

// createVtepSenderListener:
// This will listen for packets from the linux stack on the VtepHandleName
// Similarly if the MAC was learned against this VTEP traffic will be transmited
// back to the linux stack from this interface.
func (vtep *VtepDbEntry) createVtepSenderListener() error {

	// TODO need to revisit the timeout interval in case of processing lots of
	// data frames
	handle, err := pcap.OpenLive(vtep.VtepHandleName, 65536, true, 50*time.Millisecond)
	if err != nil {
		logger.Err(fmt.Sprintf("%s: Error opening pcap.OpenLive for %s err=%s", vtep.VtepName, vtep.VtepHandleName, err))
		return err
	}
	logger.Info(fmt.Sprintf("Creating VXLAN Listener for intf ", vtep.VtepName))
	vtep.handle = handle
	src := gopacket.NewPacketSource(vtep.handle, layers.LayerTypeEthernet)
	in := src.Packets()

	go func(rxchan chan gopacket.Packet) {
		for {
			select {
			// packets received from applications which should be sent out
			case packet, ok := <-rxchan:
				if ok {
					if !vtep.filterPacket(packet) {
						go vtep.encapAndDispatchPkt(packet)
					}
				} else {
					// channel closed
					return
				}
			}
		}
	}(in)

	return nil
}

// do not process packets which contain the vtep src mac
func (vtep *VtepDbEntry) filterPacket(packet gopacket.Packet) bool {

	ethernetL := packet.Layer(layers.LayerTypeEthernet)
	if ethernetL != nil {
		ethernet := ethernetL.(*layers.Ethernet)
		//logger.Info("filterPacket pkt:", ethernet.SrcMAC, "vtep:", vtep.SrcMac)
		if ethernet.SrcMAC[0] == vtep.SrcMac[0] &&
			ethernet.SrcMAC[1] == vtep.SrcMac[1] &&
			ethernet.SrcMAC[2] == vtep.SrcMac[2] &&
			ethernet.SrcMAC[3] == vtep.SrcMac[3] &&
			ethernet.SrcMAC[4] == vtep.SrcMac[4] &&
			ethernet.SrcMAC[5] == vtep.SrcMac[5] {
			return true
		}
	}
	return false
}

func (vtep *VtepDbEntry) snoop(data []byte) {
	p2 := gopacket.NewPacket(data, layers.LinkTypeEthernet, gopacket.Default)
	ethernetL := p2.Layer(layers.LayerTypeEthernet)
	if ethernetL != nil {
		ethernet, _ := ethernetL.(*layers.Ethernet)
		learnmac := ethernet.SrcMAC
		// fdb entry mac -> vtep ip interface
		logger.Debug(fmt.Sprintln("Learning mac", learnmac, "against", strings.TrimRight(vtep.VtepName, "Int")))
		//asicDLearnFwdDbEntry(learnmac, vtep.VtepName, vtep.VtepIfIndex)
	}

}

func (vtep *VtepDbEntry) decapAndDispatchPkt(packet gopacket.Packet) {

	vxlanLayer := packet.Layer(layers.LayerTypeVxlan)
	if vxlanLayer != nil {
		vxlan := vxlanLayer.(*layers.VXLAN)
		buf := vxlan.LayerPayload()
		//logger.Info(fmt.Sprintf("Sending Packet to %s %#v", vtep.VtepName, buf))
		vtep.snoop(buf)
		if err := vtep.handle.WritePacketData(buf); err != nil {
			logger.Err("Error writing packet to interface")
		}
	}
}

func (vtep *VtepDbEntry) encapAndDispatchPkt(packet gopacket.Packet) {
	// every vtep is tied to a port
	if p, ok := portDB[vtep.SrcIfName]; ok {
		phandle := p.handle
                if phandle != nil {

		// outer ethernet header
		eth := layers.VxlanEthernet{
			layers.Ethernet{SrcMAC:       vtep.SrcMac,
			DstMAC:       vtep.DstMac,
			EthernetType: layers.EthernetTypeIPv4,
			},
		}
		ip := layers.IPv4{
			Version:    4,
			IHL:        20,
			TOS:        0,
			//Length:     20 + uint16(origpktlen),
			Id:         0xd2c0,
			Flags:      layers.IPv4DontFragment, //IPv4Flag
			FragOffset: 0,                       //uint16
			TTL:        255,
			Protocol:   layers.IPProtocolUDP, //IPProtocol
			SrcIP:      vtep.SrcIp,
			DstIP:      vtep.DstIp,
		}

		udp := layers.UDP{
			SrcPort: layers.UDPPort(vtep.UDP), // TODO need a src port
			DstPort: layers.UDPPort(vtep.UDP),
			//Length:  8 + uint16(origpktlen),
		}
		udp.SetNetworkLayerForChecksum(&ip)

		vxlan := layers.VXLAN{
			Flags: 0x08,
		}
		vxlan.SetVNI(vtep.Vni)

		// Set up buffer and options for serialization.
		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		}
		// Send one packet for every address.
		gopacket.SerializeLayers(buf, opts, &eth, &ip, &udp, &vxlan, gopacket.Payload(packet.Data()))
		//logger.Info(fmt.Sprintf("Rx Packet now encapsulating and sending packet to if", vtep.SrcIfName, buf.Bytes()))
		if err := phandle.WritePacketData(buf.Bytes()); err != nil {
			logger.Err("Error writing packet to interface")
			return
		}
		vtep.txpkts++
                }
	}
}
