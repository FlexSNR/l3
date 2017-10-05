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

package main

import (
	"fmt"
	"git.apache.org/thrift.git/lib/go/thrift"
	"vrrpd"
)

const (
	IP   = "localhost"
	PORT = "10009"
)

func main() {
	fmt.Println("Starting VRRP Thrift client for Testing")
	var clientTransport thrift.TTransport

	protocolFactory := thrift.NewTBinaryProtocolFactoryDefault()
	transportFactory := thrift.NewTBufferedTransportFactory(8192)
	clientTransport, err := thrift.NewTSocket(IP + ":" + PORT)
	if err != nil {
		fmt.Println("NewTSocket failed with error:", err)
		return
	}

	clientTransport = transportFactory.GetTransport(clientTransport)
	if err = clientTransport.Open(); err != nil {
		fmt.Println("Failed to open the socket, error:", err)
	}

	client := vrrpd.NewVRRPDServicesClientFactory(clientTransport, protocolFactory)

	vrrpIntfConfig := vrrpd.NewVrrpIntf()
	vrrpIntfConfig.IfIndex = 123
	vrrpIntfConfig.VRID = 1
	vrrpIntfConfig.VirtualIPv4Addr = "172.16.0.1"
	vrrpIntfConfig.Priority = 100
	vrrpIntfConfig.PreemptMode = false
	vrrpIntfConfig.AcceptMode = false
	ret, err := client.CreateVrrpIntf(vrrpIntfConfig)
	if !ret {
		fmt.Println("Create Vrrp Intf Config Failed", err)
	} else {
		fmt.Println("Create Vrrp Intf Config Success")
	}
}
