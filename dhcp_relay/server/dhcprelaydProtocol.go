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

package relayServer

import (
	"dhcprelayd"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"golang.org/x/net/ipv4"
	"net"
	"strconv"
	"time"
)

/* ========================HELPER FUNCTIONS FOR DHCP =========================*/
/*
   0               1               2               3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     op (1)    |   htype (1)   |   hlen (1)    |   hops (1)    |
   +---------------+---------------+---------------+---------------+
   |                            xid (4)                            |
   +-------------------------------+-------------------------------+
   |           secs (2)            |           flags (2)           |
   +-------------------------------+-------------------------------+
   |                          ciaddr  (4)                          |
   +---------------------------------------------------------------+
   |                          yiaddr  (4)                          |
   +---------------------------------------------------------------+
   |                          siaddr  (4)                          |
   +---------------------------------------------------------------+
   |                          giaddr  (4)                          |
   +---------------------------------------------------------------+
   |                                                               |
   |                          chaddr  (16)                         |
   |                                                               |
   |                                                               |
   +---------------------------------------------------------------+
   |                                                               |
   |                          sname   (64)                         |
   +---------------------------------------------------------------+
   |                                                               |
   |                          file    (128)                        |
   +---------------------------------------------------------------+
   |                                                               |
   |                          options (variable)                   |
   +---------------------------------------------------------------+
*/
/*
 * ========================GET API's FOR ABOVE MESSAGE FORMAT==================
 */
func (p DhcpRelayAgentPacket) GetHeaderLen() byte {
	return p[2]
}

func (p DhcpRelayAgentPacket) GetOpCode() OpCode {
	return OpCode(p[0])
}
func (p DhcpRelayAgentPacket) GetHeaderType() byte {
	return p[1]
}
func (p DhcpRelayAgentPacket) GetHops() byte {
	return p[3]
}
func (p DhcpRelayAgentPacket) GetXId() []byte {
	return p[4:8]
}
func (p DhcpRelayAgentPacket) GetSecs() []byte {
	return p[8:10]
}
func (p DhcpRelayAgentPacket) GetFlags() []byte {
	return p[10:12]
}
func (p DhcpRelayAgentPacket) GetCIAddr() net.IP {
	return net.IP(p[12:16])
}
func (p DhcpRelayAgentPacket) GetYIAddr() net.IP {
	return net.IP(p[16:20])
}
func (p DhcpRelayAgentPacket) GetSIAddr() net.IP {
	return net.IP(p[20:24])
}
func (p DhcpRelayAgentPacket) GetGIAddr() net.IP {
	return net.IP(p[24:28])
}
func (p DhcpRelayAgentPacket) GetCHAddr() net.HardwareAddr {
	hLen := p.GetHeaderLen()
	if hLen > DHCP_PACKET_HEADER_SIZE { // Prevent chaddr exceeding p boundary
		hLen = DHCP_PACKET_HEADER_SIZE
	}
	return net.HardwareAddr(p[28 : 28+hLen]) // max endPos 44
}

func UtiltrimNull(d []byte) []byte {
	for i, v := range d {
		if v == 0 {
			return d[:i]
		}
	}
	return d
}
func (p DhcpRelayAgentPacket) GetCookie() []byte {
	return p[236:240]
}

// BOOTP legacy
func (p DhcpRelayAgentPacket) GetSName() []byte {
	return UtiltrimNull(p[44:108])
}

// BOOTP legacy
func (p DhcpRelayAgentPacket) GetFile() []byte {
	return UtiltrimNull(p[108:236])
}

func ParseMessageTypeToString(mtype MessageType) string {
	switch mtype {
	case 1:
		logger.Debug("DRA: Message Type: DhcpDiscover")
		return "DHCPDISCOVER"
	case 2:
		logger.Debug("DRA: Message Type: DhcpOffer")
		return "DHCPOFFER"
	case 3:
		logger.Debug("DRA: Message Type: DhcpRequest")
		return "DHCPREQUEST"
	case 4:
		logger.Debug("DRA: Message Type: DhcpDecline")
		return "DHCPDECLINE"
	case 5:
		logger.Debug("DRA: Message Type: DhcpACK")
		return "DHCPACK"
	case 6:
		logger.Debug("DRA: Message Type: DhcpNAK")
		return "DHCPNAK"
	case 7:
		logger.Debug("DRA: Message Type: DhcpRelease")
		return "DHCPRELEASE"
	case 8:
		logger.Debug("DRA: Message Type: DhcpInform")
		return "DHCPINFORM"
	default:
		logger.Debug("DRA: Message Type: UnKnown...Discard the Packet")
		return "UNKNOWN REQUEST TYPE"
	}
}

/*
 * ========================SET API's FOR ABOVE MESSAGE FORMAT==================
 */
func (p DhcpRelayAgentPacket) SetOpCode(c OpCode) {
	p[0] = byte(c)
}

func (p DhcpRelayAgentPacket) SetCHAddr(a net.HardwareAddr) {
	copy(p[28:44], a)
	p[2] = byte(len(a))
}

func (p DhcpRelayAgentPacket) SetHeaderType(hType byte) {
	p[1] = hType
}

func (p DhcpRelayAgentPacket) SetCookie(cookie []byte) {
	copy(p.GetCookie(), cookie)
}

func (p DhcpRelayAgentPacket) SetHops(hops byte) {
	p[3] = hops
}

func (p DhcpRelayAgentPacket) SetXId(xId []byte) {
	copy(p.GetXId(), xId)
}

func (p DhcpRelayAgentPacket) SetSecs(secs []byte) {
	copy(p.GetSecs(), secs)
}

func (p DhcpRelayAgentPacket) SetFlags(flags []byte) {
	copy(p.GetFlags(), flags)
}

func (p DhcpRelayAgentPacket) SetCIAddr(ip net.IP) {
	copy(p.GetCIAddr(), ip.To4())
}

func (p DhcpRelayAgentPacket) SetYIAddr(ip net.IP) {
	copy(p.GetYIAddr(), ip.To4())
}

func (p DhcpRelayAgentPacket) SetSIAddr(ip net.IP) {
	copy(p.GetSIAddr(), ip.To4())
}

func (p DhcpRelayAgentPacket) SetGIAddr(ip net.IP) {
	copy(p.GetGIAddr(), ip.To4())
}

// BOOTP legacy
func (p DhcpRelayAgentPacket) SetSName(sName []byte) {
	copy(p[44:108], sName)
	if len(sName) < 64 {
		p[44+len(sName)] = 0
	}
}

// BOOTP legacy
func (p DhcpRelayAgentPacket) SetFile(file []byte) {
	copy(p[108:236], file)
	if len(file) < 128 {
		p[108+len(file)] = 0
	}
}

func (p DhcpRelayAgentPacket) AllocateOptions() []byte {
	if len(p) > DHCP_PACKET_MIN_BYTES {
		return p[DHCP_PACKET_MIN_BYTES:]
	}
	return nil
}

func (p *DhcpRelayAgentPacket) PadToMinSize() {
	sizeofPacket := len(*p)
	if sizeofPacket < DHCP_PACKET_MIN_SIZE {
		// adding whatever is left out to the padder
		*p = append(*p, dhcprelayPadder[:DHCP_PACKET_MIN_SIZE-sizeofPacket]...)
	}
}

// Parses the packet's options into an Options map
func (p DhcpRelayAgentPacket) ParseDhcpOptions() DhcpRelayAgentOptions {
	opts := p.AllocateOptions()
	// create basic dhcp options...
	doptions := make(DhcpRelayAgentOptions, 15)
	for len(opts) >= 2 && DhcpOptionCode(opts[0]) != End {
		if DhcpOptionCode(opts[0]) == Pad {
			opts = opts[1:]
			continue
		}
		size := int(opts[1])
		if len(opts) < 2+size {
			break
		}
		doptions[DhcpOptionCode(opts[0])] = opts[2 : 2+size]
		opts = opts[2+size:]
	}
	return doptions
}

// Appends a DHCP option to the end of a packet
func (p *DhcpRelayAgentPacket) AddDhcpOptions(op DhcpOptionCode, value []byte) {
	// Strip off End, Add OptionCode and Length
	*p = append((*p)[:len(*p)-1], []byte{byte(op), byte(len(value))}...)
	*p = append(*p, value...)  // Add Option Value
	*p = append(*p, byte(End)) // Add on new End
}

// SelectOrder returns a slice of options ordered and selected by a byte array
// usually defined by OptionParameterRequestList.  This result is expected to be
// used in ReplyPacket()'s []Option parameter.
func (o DhcpRelayAgentOptions) SelectOrder(order []byte) []Option {
	opts := make([]Option, 0, len(order))
	for _, v := range order {
		if data, ok := o[DhcpOptionCode(v)]; ok {
			opts = append(opts, Option{Code: DhcpOptionCode(v),
				Value: data})
		}
	}
	return opts
}

// SelectOrderOrAll has same functionality as SelectOrder, except if the order
// param is nil, whereby all options are added (in arbitary order).
func (o DhcpRelayAgentOptions) SelectOrderOrAll(order []byte) []Option {
	if order == nil {
		opts := make([]Option, 0, len(o))
		for i, v := range o {
			opts = append(opts, Option{Code: i, Value: v})
		}
		return opts
	}
	return o.SelectOrder(order)
}

/*========================= END OF HELPER FUNCTION ===========================*/
/*
 * APT to decode incoming Packet by converting the byte into DHCP packet format
 */
func DhcpRelayAgentDecodeInPkt(data []byte, bytesRead int) (DhcpRelayAgentPacket,
	DhcpRelayAgentOptions, MessageType) {
	inRequest := DhcpRelayAgentPacket(data[:bytesRead])
	if inRequest.GetHeaderLen() > DHCP_PACKET_HEADER_SIZE {
		logger.Warning("Header Lenght is invalid... don't do anything")
		return nil, nil, 0
	}
	reqOptions := inRequest.ParseDhcpOptions()
	/*
		logger.Debug("DRA: CIAddr is " + inRequest.GetCIAddr().String())
		logger.Debug("DRA: CHaddr is " + inRequest.GetCHAddr().String())
		logger.Debug("DRA: YIAddr is " + inRequest.GetYIAddr().String())
		logger.Debug("DRA: GIAddr is " + inRequest.GetGIAddr().String())

		logger.Debug("DRA: Cookie is ", inRequest.GetCookie())
	*/
	mType := reqOptions[OptionDHCPMessageType]
	return inRequest, reqOptions, MessageType(mType[0])
}

/*
 * API to create a new Dhcp packet with Relay Agent information in it
 */
func DhcpRelayAgentCreateNewPacket(opCode OpCode, inReq DhcpRelayAgentPacket) DhcpRelayAgentPacket {
	p := make(DhcpRelayAgentPacket, DHCP_PACKET_MIN_BYTES+1) //241
	p.SetHeaderType(inReq.GetHeaderType())                   // Ethernet
	p.SetCookie(inReq.GetCookie())                           // copy cookie from original pkt
	p.SetOpCode(opCode)                                      // opcode can be request or reply
	p.SetXId(inReq.GetXId())                                 // copy from org pkt
	p.SetFlags(inReq.GetFlags())                             // copy from org pkt
	p.SetYIAddr(inReq.GetYIAddr())                           // copy from org pkt
	p.SetCHAddr(inReq.GetCHAddr())                           // copy from org pkt
	p.SetSecs(inReq.GetSecs())                               // copy from org pkt
	p.SetSName(inReq.GetSName())                             // copy from org pkt
	p.SetFile(inReq.GetFile())                               // copy from org pkt
	p[DHCP_PACKET_MIN_BYTES] = byte(End)                     // set opcode END at the very last
	return p
}

func DhcpRelayAgentAddOptionsToPacket(reqOptions DhcpRelayAgentOptions, mt MessageType,
	outPacket *DhcpRelayAgentPacket) (string, string) {
	outPacket.AddDhcpOptions(OptionDHCPMessageType, []byte{byte(mt)})
	var dummyDup map[DhcpOptionCode]int
	var reqIp string
	var serverIp = ""
	dummyDup = make(map[DhcpOptionCode]int, len(reqOptions))
	for i := 0; i < len(reqOptions); i++ {
		opt := reqOptions.SelectOrderOrAll(reqOptions[DhcpOptionCode(i)])
		for _, option := range opt {
			_, ok := dummyDup[option.Code]
			if ok {
				continue
			}
			switch option.Code {
			case OptionRequestedIPAddress:
				reqIp = net.IPv4(option.Value[0], option.Value[1],
					option.Value[2], option.Value[3]).String()
				break
			case OptionServerIdentifier:
				serverIp = net.IPv4(option.Value[0], option.Value[1],
					option.Value[2], option.Value[3]).String()
				break
			}
			outPacket.AddDhcpOptions(option.Code, option.Value)
			dummyDup[option.Code] = 9999
		}
	}
	return reqIp, serverIp
}

func DhcpRelayAgentSendDiscoverPacket(ch *net.UDPConn, gblEntry DhcpRelayAgentGlobalInfo,
	inReq DhcpRelayAgentPacket, reqOptions DhcpRelayAgentOptions,
	mt MessageType, intfStateEntry *dhcprelayd.DhcpRelayIntfState) {
	logger.Debug("DRA: Sending Discover Request")
	for i := 0; i < len(gblEntry.IntfConfig.ServerIp); i++ {
		hostServerStateKey := inReq.GetCHAddr().String() + "_" +
			gblEntry.IntfConfig.ServerIp[i]
		// get host + server state entry for updating the state
		hostServerStateEntry, ok := dhcprelayHostServerStateMap[hostServerStateKey]
		if !ok {
			hostServerStateEntry.MacAddr = inReq.GetCHAddr().String()
			hostServerStateEntry.ServerIp = gblEntry.IntfConfig.ServerIp[i]
			dhcprelayHostServerStateSlice = append(dhcprelayHostServerStateSlice,
				hostServerStateKey)
		}
		hostServerStateEntry.ClientRequests++
		hostServerStateEntry.ClientDiscover = time.Now().String()
		// Create server ip address + port number
		serverIpPort := gblEntry.IntfConfig.ServerIp[i] + ":" +
			strconv.Itoa(DHCP_SERVER_PORT)
		logger.Debug("DRA: Sending DHCP PACKET to server: " + serverIpPort)
		serverAddr, err := net.ResolveUDPAddr("udp", serverIpPort)
		if err != nil {
			logger.Err("DRA: couldn't resolved udp addr for and err is", err)
			intfStateEntry.TotalDrops++
			dhcprelayHostServerStateMap[hostServerStateKey] = hostServerStateEntry
			continue
		}

		outPacket := DhcpRelayAgentCreateNewPacket(Request, inReq)
		if inReq.GetGIAddr().String() == DHCP_NO_IP {
			outPacket.SetGIAddr(net.ParseIP(gblEntry.IpAddr))
		} else {
			logger.Debug("DRA: Relay Agent " + inReq.GetGIAddr().String() +
				" requested for DHCP for HOST " + inReq.GetCHAddr().String())
			outPacket.SetGIAddr(inReq.GetGIAddr())
		}

		DhcpRelayAgentAddOptionsToPacket(reqOptions, mt, &outPacket)
		// Pad to minimum size of dhcp packet
		outPacket.PadToMinSize()
		// send out the packet...
		_, err = ch.WriteToUDP(outPacket, serverAddr)
		if err != nil {
			logger.Debug("DRA: WriteToUDP failed with error:", err)
			intfStateEntry.TotalDrops++
			dhcprelayHostServerStateMap[hostServerStateKey] = hostServerStateEntry
			continue
		}
		intfkey := strconv.Itoa(int(gblEntry.IntfConfig.IfIndex)) + "_" +
			gblEntry.IntfConfig.ServerIp[i]
		intfStateServerEntry, ok := dhcprelayIntfServerStateMap[intfkey]
		if !ok {
			logger.Debug("DRA: Why don't we have entry for " + intfkey)
		}
		intfStateServerEntry.Request++
		dhcprelayIntfServerStateMap[intfkey] = intfStateServerEntry
		intfStateEntry.TotalDhcpServerTx++
		hostServerStateEntry.ServerRequests++
		logger.Debug("DRA: Create & Send of PKT successfully to server", gblEntry.IntfConfig.ServerIp[i])
		dhcprelayHostServerStateMap[hostServerStateKey] = hostServerStateEntry
	}

}

func DhcpRelayAgentSendClientOptPacket(ch *net.UDPConn, gblEntry DhcpRelayAgentGlobalInfo,
	inReq DhcpRelayAgentPacket, reqOptions DhcpRelayAgentOptions,
	mt MessageType, intfStateEntry *dhcprelayd.DhcpRelayIntfState) {

	reqTime := time.Now().String()
	// Create Packet
	outPacket := DhcpRelayAgentCreateNewPacket(Request, inReq)
	if inReq.GetGIAddr().String() == DHCP_NO_IP {
		outPacket.SetGIAddr(net.ParseIP(gblEntry.IpAddr))
	} else {
		logger.Debug("DRA: Relay Agent " + inReq.GetGIAddr().String() +
			" requested for DHCP for HOST " + inReq.GetCHAddr().String())
		outPacket.SetGIAddr(inReq.GetGIAddr())
	}

	requestedIp, serverIp := DhcpRelayAgentAddOptionsToPacket(reqOptions,
		mt, &outPacket)
	if serverIp == "" {
		logger.Warning("DRA: no server ip.. dropping the request")
		intfStateEntry.TotalDrops++
		return
	}
	hostServerStateKey := inReq.GetCHAddr().String() + "_" + serverIp
	// get host + server state entry for updating the state
	hostServerStateEntry, ok := dhcprelayHostServerStateMap[hostServerStateKey]
	hostServerStateEntry.ClientRequests++
	hostServerStateEntry.RequestedIp = requestedIp
	hostServerStateEntry.ClientRequest = reqTime
	// Create server ip address + port number
	serverIpPort := serverIp + ":" + strconv.Itoa(DHCP_SERVER_PORT)
	logger.Debug("DRA: Sending " + ParseMessageTypeToString(mt) +
		" packet to " + serverIpPort)
	serverAddr, err := net.ResolveUDPAddr("udp", serverIpPort)
	if err != nil {
		logger.Err("DRA: couldn't resolved udp addr for and err is", err)
		intfStateEntry.TotalDrops++
		dhcprelayHostServerStateMap[hostServerStateKey] = hostServerStateEntry
		return
	}
	// Pad to minimum size of dhcp packet
	outPacket.PadToMinSize()
	// send out the packet...
	_, err = ch.WriteToUDP(outPacket, serverAddr)
	if err != nil {
		logger.Debug("DRA: WriteToUDP failed with error:", err)
		intfStateEntry.TotalDrops++
		dhcprelayHostServerStateMap[hostServerStateKey] = hostServerStateEntry
		return
	}
	intfkey := strconv.Itoa(int(intfStateEntry.IfIndex)) + "_" + serverIp
	intfStateServerEntry, ok := dhcprelayIntfServerStateMap[intfkey]
	if !ok {
		logger.Debug("DRA: Why don't we have entry for " + intfkey)
	}
	intfStateServerEntry.Request++
	dhcprelayIntfServerStateMap[intfkey] = intfStateServerEntry
	intfStateEntry.TotalDhcpServerTx++
	hostServerStateEntry.ServerRequests++
	logger.Debug("DRA: Create & Send of PKT successfully to server", serverIp)
	dhcprelayHostServerStateMap[hostServerStateKey] = hostServerStateEntry

}

/*
	DhcpDiscover MessageType = 1 // From Client - Can I have an IP?
	DhcpOffer    MessageType = 2 // From Server - Here's an IP
	DhcpRequest  MessageType = 3 // From Client - I'll take that IP (Also start for renewals)
	DhcpDecline  MessageType = 4 // From Client - Sorry I can't use that IP
	DhcpACK      MessageType = 5 // From Server, Yes you can have that IP
	DhcpNAK      MessageType = 6 // From Server, No you cannot have that IP
	DhcpRelease  MessageType = 7 // From Client, I don't need that IP anymore
	DhcpInform   MessageType = 8 // From Client, I have this IP and there's nothing you can do about it
*/
func DhcpRelayAgentSendPacketToDhcpServer(ch *net.UDPConn,
	gblEntry DhcpRelayAgentGlobalInfo,
	inReq DhcpRelayAgentPacket, reqOptions DhcpRelayAgentOptions,
	mt MessageType, intfStateEntry *dhcprelayd.DhcpRelayIntfState) {

	switch mt {
	case DhcpDiscover:
		DhcpRelayAgentSendDiscoverPacket(ch, gblEntry, inReq, reqOptions,
			mt, intfStateEntry)
		break
	case DhcpRequest, DhcpDecline, DhcpRelease, DhcpInform:
		DhcpRelayAgentSendClientOptPacket(ch, gblEntry, inReq, reqOptions,
			mt, intfStateEntry)
		break
	}
}

func DhcpRelayAgentSendPacketToDhcpClient(gblEntry DhcpRelayAgentGlobalInfo,
	logicalId int32, inReq DhcpRelayAgentPacket, linuxInterface *net.Interface,
	reqOptions DhcpRelayAgentOptions, mt MessageType, server net.IP,
	intfStateEntry *dhcprelayd.DhcpRelayIntfState) {

	var outPacket DhcpRelayAgentPacket
	var intfkey string
	hostServerStateKey := inReq.GetCHAddr().String() + "_" + server.String()
	// get host + server state entry for updating the state
	hostServerStateEntry, ok := dhcprelayHostServerStateMap[hostServerStateKey]
	if !ok {
		logger.Warning("DRA: missed updating state during client " +
			"request for " + inReq.GetCHAddr().String())
	} else {
		hostServerStateEntry.ServerResponses++
		hostServerStateEntry.GatewayIp = inReq.GetGIAddr().String()
		switch mt {
		case DhcpOffer:
			//Offer
			hostServerStateEntry.ServerOffer = time.Now().String()
			hostServerStateEntry.OfferedIp = inReq.GetYIAddr().String()
			break
		case DhcpACK:
			//Ack
			hostServerStateEntry.AcceptedIp = inReq.GetYIAddr().String()
			hostServerStateEntry.ServerAck = time.Now().String()
			break
		}

	}
	outPacket = DhcpRelayAgentCreateNewPacket(Reply, inReq)
	DhcpRelayAgentAddOptionsToPacket(reqOptions, mt, &outPacket)
	// Pad to minimum size of dhcp packet
	outPacket.PadToMinSize()

	eth := &layers.Ethernet{
		SrcMAC:       linuxInterface.HardwareAddr,
		DstMAC:       outPacket.GetCHAddr(),
		EthernetType: layers.EthernetTypeIPv4,
	}
	ipv4 := &layers.IPv4{
		SrcIP:    net.ParseIP(gblEntry.IpAddr),
		DstIP:    outPacket.GetYIAddr(),
		Version:  4,
		Protocol: layers.IPProtocolUDP,
		TTL:      64,
	}
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(DHCP_SERVER_PORT),
		DstPort: layers.UDPPort(DHCP_CLIENT_PORT),
	}
	udp.SetNetworkLayerForChecksum(ipv4)

	goOpts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	buffer := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buffer, goOpts, eth, ipv4, udp,
		gopacket.Payload(outPacket))
	var pHandle *pcap.Handle
	var err error
	var intfStateServerEntry dhcprelayd.DhcpRelayIntfServerState
	if gblEntry.PcapHandle == nil {
		logger.Debug("DRA: opening pcap handle for", linuxInterface.Name)
		pHandle, err = pcap.OpenLive(linuxInterface.Name, snapshot_len,
			promiscuous, timeout)
		if err != nil {
			logger.Err("DRA: opening pcap for", linuxInterface.Name, "failed with Error:", err)
			intfStateEntry.TotalDrops++
			goto early_exit
		}
		gblEntry.PcapHandle = pHandle
		dhcprelayGblInfo[logicalId] = gblEntry
	} else {
		pHandle = gblEntry.PcapHandle
	}

	if gblEntry.PcapHandle == nil {
		logger.Debug("DRA: pcap handler is nul....")
		intfStateEntry.TotalDrops++
		goto early_exit
	}
	err = pHandle.WritePacketData(buffer.Bytes())
	if err != nil {
		logger.Debug("DRA: WritePacketData failed with error:", err)
		intfStateEntry.TotalDrops++
		goto early_exit
	}

	if ok {
		hostServerStateEntry.ClientResponses++
	}
	intfkey = strconv.Itoa(int(gblEntry.IntfConfig.IfIndex)) + "_" + server.String()
	intfStateServerEntry, ok = dhcprelayIntfServerStateMap[intfkey]
	if !ok {
	} else {
		intfStateServerEntry.Responses++
		dhcprelayIntfServerStateMap[intfkey] = intfStateServerEntry
	}
	intfStateEntry.TotalDhcpClientTx++

	logger.Debug("DRA: Create & Send of PKT successfully to client")
early_exit:
	if ok {
		dhcprelayHostServerStateMap[hostServerStateKey] =
			hostServerStateEntry
	}
}

func DhcpRelayAgentSendPacket(clientHandler *net.UDPConn, cm *ipv4.ControlMessage,
	inReq DhcpRelayAgentPacket, reqOptions DhcpRelayAgentOptions, mType MessageType,
	intfStateEntry *dhcprelayd.DhcpRelayIntfState) {
	switch mType {
	case DhcpDiscover, DhcpRequest, DhcpDecline, DhcpRelease, DhcpInform:
		intfStateEntry.TotalDhcpClientRx++
		// Updating reverse mapping with logical interface id
		logicalId, ok := dhcprelayLogicalIntf2IfIndex[dhcprelayLogicalIntfId2LinuxIntId[cm.IfIndex]]
		if !ok {
			intfStateEntry.TotalDrops++
			return
		}
		// Use obtained logical id to find the global interface object
		gblEntry, ok := dhcprelayGblInfo[logicalId]
		if !ok {
			logger.Err("DRA: is dra enabled on if_index?", logicalId, " dropping packet")
			intfStateEntry.TotalDrops++
			return
		}
		if gblEntry.IntfConfig.Enable == false {
			logger.Warning("DRA: Relay Agent is not enabled")
			intfStateEntry.TotalDrops++
			return
		}
		linuxInterface, err := net.InterfaceByIndex(cm.IfIndex)
		if err != nil {
			logger.Err("DRA: getting interface by id failed", err, "drop packet")
			intfStateEntry.TotalDrops++
			return
		}
		dhcprelayReverseMap[inReq.GetCHAddr().String()] = linuxInterface
		logger.Debug("DRA: cached linux interface is", linuxInterface)
		// Send Packet
		DhcpRelayAgentSendPacketToDhcpServer(clientHandler, gblEntry,
			inReq, reqOptions, mType, intfStateEntry)
		break
	case DhcpOffer, DhcpACK, DhcpNAK:
		intfStateEntry.TotalDhcpServerRx++
		// Get the interface from reverse mapping to send the unicast
		// packet...
		linuxInterface, ok := dhcprelayReverseMap[inReq.GetCHAddr().String()]
		if !ok {
			logger.Err("DRA: cache for linux interface for " +
				inReq.GetCHAddr().String() + " not present")
			intfStateEntry.TotalDrops++
			return
		}
		// Getting logical ID from reverse mapping
		logicalId, ok :=
			dhcprelayLogicalIntf2IfIndex[dhcprelayLogicalIntfId2LinuxIntId[linuxInterface.Index]]
		if !ok {
			logger.Err("DRA: linux id", cm.IfIndex, " has no mapping...drop packet")
			intfStateEntry.TotalDrops++
			return
		}
		// Use obtained logical id to find the global interface object
		gblEntry, ok := dhcprelayGblInfo[logicalId]
		if !ok {
			logger.Err("DRA: is dra enabled on if_index", logicalId, "? not sending packet")
			intfStateEntry.TotalDrops++
			return
		}
		if gblEntry.IntfConfig.Enable == false {
			logger.Warning("DRA: Relay Agent is not enabled")
			intfStateEntry.TotalDrops++
			return
		}
		DhcpRelayAgentSendPacketToDhcpClient(gblEntry, logicalId, inReq,
			linuxInterface, reqOptions, mType, cm.Src, intfStateEntry)
		break
	default:
		logger.Debug("DRA: any new message type")
		intfStateEntry.TotalDrops++
	}

}

func DhcpRelayProcessReceivedBuf(rcvdCh <-chan DhcpRelayPktChannel) {
	for {
		pktChannel := <-rcvdCh
		cm := pktChannel.cm
		buf := pktChannel.buf
		bytesRead := pktChannel.bytesRead
		clientHandler := dhcprelayClientHandler
		var intfState dhcprelayd.DhcpRelayIntfState
		intfId := dhcprelayLogicalIntf2IfIndex[dhcprelayLogicalIntfId2LinuxIntId[cm.IfIndex]]
		// from control message ---> Linux Intf ----> IntfStateObj
		intfState = dhcprelayIntfStateMap[intfId]
		if bytesRead < DHCP_PACKET_MIN_BYTES {
			// This is not dhcp packet as the minimum size is 240
			intfState.TotalDrops++
			dhcprelayIntfStateMap[intfId] = intfState
			continue
		}

		//Decode the packet...
		inReq, reqOptions, mType := DhcpRelayAgentDecodeInPkt(buf, bytesRead)
		if inReq == nil || reqOptions == nil {
			logger.Warning("DRA: Couldn't decode dhcp packet...continue")
			intfState.TotalDrops++
			dhcprelayIntfStateMap[intfId] = intfState
			continue
		}
		// Based on Packet type decide whether to send packet to server
		// or to client
		DhcpRelayAgentSendPacket(clientHandler, cm, inReq, reqOptions,
			mType, &intfState)
		dhcprelayIntfStateMap[intfId] = intfState
	}
}

func DhcpRelayAgentReceiveDhcpPkt(clientHandler *net.UDPConn) {
	var buf []byte = make([]byte, 1500)
	count := 0
	for {
		if dhcprelayEnable == false {
			logger.Warning("DRA: Enable DHCP RELAY AGENT GLOBALLY")
			continue
		}
		dhcprelayRefCountMutex.Lock()
		if dhcprelayEnabledIntfRefCount == 0 {
			if count%10000 == 0 {
				logger.Debug("No Relay Agent Enabled")
			}
			dhcprelayRefCountMutex.Unlock()
			continue
		}
		dhcprelayRefCountMutex.Unlock()
		bytesRead, cm, srcAddr, err := dhcprelayClientConn.ReadFrom(buf)
		if err != nil {
			logger.Err("DRA: reading buffer failed")
			continue
		}
		logger.Debug("DRA: Received Packet from ", srcAddr)
		pktChannel <- DhcpRelayPktChannel{
			cm:        cm,
			buf:       buf,
			bytesRead: bytesRead,
		}
	}
}

func DhcpRelayAgentCreateClientServerConn() {
	// Client send dhcp packet from port 68 to server port 67
	// So create a filter for udp:67 for messages send out by client to
	// server
	saddr := net.UDPAddr{
		Port: DHCP_SERVER_PORT,
		IP:   net.ParseIP(""),
	}
	var err error
	dhcprelayClientHandler, err = net.ListenUDP("udp", &saddr)
	if err != nil {
		logger.Err("DRA: Opening udp port for client --> server failed", err)
		return
	}
	dhcprelayClientConn = ipv4.NewPacketConn(dhcprelayClientHandler)
	controlFlag := ipv4.FlagTTL | ipv4.FlagSrc | ipv4.FlagDst | ipv4.FlagInterface
	err = dhcprelayClientConn.SetControlMessage(controlFlag, true)
	if err != nil {
		logger.Err("DRA: Setting control flag for client failed..", err)
		return
	}
	dhcprelayReverseMap = make(map[string]*net.Interface, 30)
	// State information
	dhcprelayHostServerStateMap = make(map[string]dhcprelayd.DhcpRelayHostDhcpState, 150)
	dhcprelayHostServerStateSlice = []string{}
	pktChannel = make(chan DhcpRelayPktChannel, 1)
	go DhcpRelayProcessReceivedBuf(pktChannel)
	go DhcpRelayAgentReceiveDhcpPkt(dhcprelayClientHandler)

	logger.Debug("DRA: Client Connection opened successfully")
}
