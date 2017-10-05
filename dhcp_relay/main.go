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
package main

import (
	"flag"
	"fmt"
	"l3/dhcp_relay/server"
	"utils/keepalive"
	"utils/logging"
)

func main() {
	fmt.Println("Starting dhcprelay daemon")
	paramsDir := flag.String("params", "./params", "Params directory")
	flag.Parse()
	fileName := *paramsDir
	if fileName[len(fileName)-1] != '/' {
		fileName = fileName + "/"
	}
	fmt.Println("Start logger")
	logger, err := logging.NewLogger("dhcprelayd", "DRA", true)
	if err != nil {
		fmt.Println("Failed to start the logger. Nothing will be logged...")
	}
	logger.Info("Started the logger successfully.")

	// Start keepalive routine
	go keepalive.InitKeepAlive("dhcprelayd", fileName)

	logger.Info("Starting DHCP RELAY....")
	// Create a handler
	handler := relayServer.NewDhcpRelayServer()
	err = relayServer.StartServer(logger, handler, *paramsDir)
	if err != nil {
		logger.Err("DRA: Cannot start dhcp server", err)
		return
	}
}
