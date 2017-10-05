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

// Main entry point for DHCP_RELAY
package relayServer

import (
	"asicd/asicdCommonDefs"
	"asicdServices"
	"dhcprelayd"
	"encoding/json"
	"errors"
	_ "flag"
	"git.apache.org/thrift.git/lib/go/thrift"
	"io/ioutil"
	"net"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"
	"utils/ipcutils"
	"utils/logging"
)

/******* Local API Calls. *******/

func NewDhcpRelayServer() *DhcpRelayServiceHandler {
	return &DhcpRelayServiceHandler{}
}

/*
 * DhcpRelaySignalHandler:
 *	This API will catch any os signals for DRA and if the signal is of
 *	SIGHUP type then it exit the process
 */
func DhcpRelaySignalHandler(sigChannel <-chan os.Signal) {
	signal := <-sigChannel // receive from sigChannel and assign it to signal
	switch signal {
	case syscall.SIGHUP:
		logger.Alert("DRA: Received SIGHUP SIGNAL")
		os.Exit(0)
	default:
		logger.Info("DRA: Unhandled Signal : ", signal)
	}

}

func DhcpRelayAgentOSSignalHandle() {
	// Set up channel on which to send signal notifications.
	// We must use a buffered channel or risk missing the signal
	// if we're not ready to receive when the signal is sent.
	sigChannel := make(chan os.Signal, 1)
	// SIGHUP is a signal sent to a process when its controlling terminal is
	// closed and we need to handle that signal
	signalList := []os.Signal{syscall.SIGHUP}
	signal.Notify(sigChannel, signalList...)
	// start a light weighted thread goroutine for signal handler
	go DhcpRelaySignalHandler(sigChannel)
}

func DhcpRelayConnectToAsicd(client ClientJson) error {
	var err error
	asicdClient.Address = "localhost:" + strconv.Itoa(client.Port)
	asicdClient.Transport, asicdClient.PtrProtocolFactory, err =
		ipcutils.CreateIPCHandles(asicdClient.Address)
	if asicdClient.Transport == nil ||
		asicdClient.PtrProtocolFactory == nil ||
		err != nil {
		return err
	}
	asicdClient.ClientHdl =
		asicdServices.NewASICDServicesClientFactory(
			asicdClient.Transport,
			asicdClient.PtrProtocolFactory)
	asicdClient.IsConnected = true
	return nil
}

/*
 *  ConnectToClients:
 *	    This API will accept configFile location and from that it will
 *	    connect to clients like asicd, etc..
 */
func DhcpRelayAgentConnectToClients(client ClientJson) error {
	switch client.Name {
	case "asicd":
		return DhcpRelayConnectToAsicd(client)
	default:
		return errors.New(CLIENT_CONNECTION_NOT_REQUIRED)
	}
}

/*
 *  InitDhcpRelayPktHandler:
 *	    This API is used to initialize all the data structures varialbe that
 *	    is needed by relay agent to perform its operation
 */
func InitDhcpRelayPortPktHandler() error {
	// connecting to asicd
	configFile := paramsDir + "/clients.json"
	logger.Debug("DRA: configFile is ", configFile)
	bytes, err := ioutil.ReadFile(configFile)
	if err != nil {
		logger.Err("DRA:Error while reading configuration file", configFile)
		return err
	}
	var unConnectedClients []ClientJson
	err = json.Unmarshal(bytes, &unConnectedClients)
	if err != nil {
		logger.Err("DRA: Error in Unmarshalling Json")
		return err
	}

	logger.Debug("DRA: Connecting to Clients")
	re_connect := 25
	count := 0
	// connect to client
	for {
		time.Sleep(time.Millisecond * 500)
		for i := 0; i < len(unConnectedClients); i++ {
			err := DhcpRelayAgentConnectToClients(
				unConnectedClients[i])
			if err == nil {
				logger.Debug("DRA: Connected to " +
					unConnectedClients[i].Name)
				unConnectedClients = append(
					unConnectedClients[:i],
					unConnectedClients[i+1:]...)

			} else if err.Error() == CLIENT_CONNECTION_NOT_REQUIRED {
				unConnectedClients = append(
					unConnectedClients[:i],
					unConnectedClients[i+1:]...)
			} else {
				count++
				if count == re_connect {
					logger.Err("Connecting to", unConnectedClients[i].Name, "failed ", err)
					count = 0
				}
			}
		}
		if len(unConnectedClients) == 0 {
			break
		}
	}
	// Initialize port parameters after client is connected
	err = DhcpRelayInitPortParams()
	if err != nil {
		logger.Err("DRA: initializing port paramters failed")
		return err
	}
	// OS signal channel listener thread
	DhcpRelayAgentOSSignalHandle()

	return nil
}

func DhcpRelayAgentInitIntfServerState(serverIp string, id int32) {
	IntfId := int(id)
	key := strconv.Itoa(IntfId) + "_" + serverIp
	intfServerEntry := dhcprelayIntfServerStateMap[key]
	intfServerEntry.IntfId = id
	intfServerEntry.ServerIp = serverIp
	intfServerEntry.Request = 0
	intfServerEntry.Responses = 0
	dhcprelayIntfServerStateMap[key] = intfServerEntry
	dhcprelayIntfServerStateSlice = append(dhcprelayIntfServerStateSlice, key)
}

func DhcpRelayAgentInitIntfState(IntfId int32) {
	intfEntry := dhcprelayIntfStateMap[IntfId]
	intfEntry.IfIndex = IntfId
	intfEntry.TotalDrops = 0
	intfEntry.TotalDhcpClientRx = 0
	intfEntry.TotalDhcpClientTx = 0
	intfEntry.TotalDhcpServerRx = 0
	intfEntry.TotalDhcpServerTx = 0
	dhcprelayIntfStateMap[IntfId] = intfEntry
	dhcprelayIntfStateSlice = append(dhcprelayIntfStateSlice, IntfId)
}

func DhcpRelayAgentInitGblHandling(ifNum int32, enable bool) {
	//logger.Debug("DRA: Initializaing Global Info for " + strconv.Itoa(int(ifNum)))
	// Created a global Entry for Interface
	gblEntry := dhcprelayGblInfo[ifNum]
	// Setting up default values for globalEntry
	gblEntry.IpAddr = ""
	gblEntry.Netmask = ""
	gblEntry.IntfConfig.IfIndex = ifNum
	gblEntry.IntfConfig.Enable = enable
	dhcprelayGblInfo[ifNum] = gblEntry
}

func DhcpRelayAgentUpdateIntfServerIp(ifNum int32, serverIp string) {
	logger.Debug("DRA: Updating Interface", ifNum, "with server ip", serverIp)
	gblEntry, ok := dhcprelayGblInfo[ifNum]
	if !ok {
		logger.Err("No entry found in database")
		return
	}
	gblEntry.IntfConfig.ServerIp = append(gblEntry.IntfConfig.ServerIp, serverIp)
	dhcprelayGblInfo[ifNum] = gblEntry
}

func DhcpRelayAgentUpdateIntfIpAddr(ifIndexList []int32) {
	logger.Debug("DRA: updating address for ", ifIndexList)
	DhcpRelayAgentGetIpv4IntfList()
	//@TODO: Once asicd supports Get then replace GetBulk with Get

	for i := 0; i < len(ifIndexList); i++ {
		obj, ok := dhcprelayIntfIpv4Map[ifIndexList[i]]
		if !ok {
			logger.Err("DRA: Get bulkd didn't return any info for", ifIndexList[i])
			continue
		}
		logicalId := int32(asicdCommonDefs.GetIntfIdFromIfIndex(obj.IfIndex))
		dhcprelayLogicalIntf2IfIndex[logicalId] = obj.IfIndex
		gblEntry := dhcprelayGblInfo[ifIndexList[i]]
		ip, ipnet, err := net.ParseCIDR(obj.IpAddr)
		if err != nil {
			logger.Err("DRA: Parsing ipadd and netmask failed:", err)
			continue
		}
		gblEntry.IpAddr = ip.String()
		gblEntry.Netmask = ipnet.IP.String()
		dhcprelayGblInfo[ifIndexList[i]] = gblEntry
		logger.Debug("DRA: Updated interface:", obj.IfIndex, " Ip address:", gblEntry.IpAddr, " netmask:", gblEntry.Netmask)
	}
}

func DhcpRelayAgentInitVlanInfo(VlanName string, VlanId int32) {
	logger.Debug("DRA: Vlan update message for ", VlanName, "vlan id is ", VlanId)
	var linuxInterface *net.Interface
	var err error
	linuxInterface, err = net.InterfaceByName(VlanName)
	if err != nil {
		logger.Err("DRA: getting interface by name failed", err)
		return
	}
	dhcprelayLogicalIntfId2LinuxIntId[linuxInterface.Index] = VlanId
}

func DhcpRelayGetClient(logger *logging.Writer, fileName string,
	process string) (*DhcpRelayClientJson, error) {
	var allClients []DhcpRelayClientJson

	data, err := ioutil.ReadFile(fileName)
	if err != nil {
		logger.Err("Failed to open dhcpd config file", err, fileName)
		return nil, err
	}
	json.Unmarshal(data, &allClients)
	for _, client := range allClients {
		if client.Name == process {
			return &client, nil
		}
	}
	return nil, errors.New("couldn't find dhcprelay port info")
}

func DhcpRelayGlobalInit(enable bool) {
	if enable {
		if dhcprelayRefCountMutex == nil {
			dhcprelayRefCountMutex = &sync.RWMutex{}
			dhcprelayEnabledIntfRefCount = 0
		}
		dhcprelayEnable = enable
		if dhcprelayClientConn != nil {
			logger.Debug("DRA: no need to create pcap as its already created")
			return
		} else {
			DhcpRelayAgentCreateClientServerConn()
		}
	} else {
		dhcprelayEnable = enable
	}
}

func StartServer(log *logging.Writer, handler *DhcpRelayServiceHandler, params string) error {
	logger = log
	paramsDir = params
	// Allocate Memory for Global DS
	DhcpRelayAgentAllocateMemory()
	// Initialize DB
	err := DhcpRelayAgentInitDB()
	if err != nil {
		logger.Err("DRA: Init of DB failed")
	} else {
		DhcpRelayAgentReadDB()
	}
	logger.Debug("DRA: Continuining with port init")
	// Initialize port information and packet handler for dhcp
	go InitDhcpRelayPortPktHandler()
	dhcprelayEnable = false
	fileName := params + "/clients.json"
	clientJson, err := DhcpRelayGetClient(logger, fileName, "dhcprelayd")
	if err != nil || clientJson == nil {
		return err
	}

	logger.Debug("Got Client info for", clientJson.Name, "port", clientJson.Port)

	// create transport and protocol for server
	transportFactory := thrift.NewTBufferedTransportFactory(8192)
	protocolFactory := thrift.NewTBinaryProtocolFactoryDefault()
	transport, err := thrift.NewTServerSocket("localhost:" +
		strconv.Itoa(clientJson.Port))
	if err != nil {
		logger.Err("DRA: StartServer: NewTServerSocket failed with error:", err)
		return err
	}
	processor := dhcprelayd.NewDHCPRELAYDServicesProcessor(handler)
	server := thrift.NewTSimpleServer4(processor, transport,
		transportFactory, protocolFactory)
	err = server.Serve()
	if err != nil {
		logger.Err("DRA: Failed to start the listener, err:", err)
		return err
	}

	return nil
}
