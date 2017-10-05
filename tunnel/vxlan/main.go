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

// main
package main

import (
	"flag"
	"fmt"
	"l3/tunnel/vxlan/clients/snapclient"
	vxlan "l3/tunnel/vxlan/protocol"
	"l3/tunnel/vxlan/rpc"
	"utils/keepalive"
	"utils/logging"
)

func main() {

	// lookup port
	paramsDir := flag.String("params", "./params", "Params directory")
	flag.Parse()
	path := *paramsDir
	if path[len(path)-1] != '/' {
		path = path + "/"
	}

	fmt.Println("Start logger")
	logger, err := logging.NewLogger("vxland", "VXLAN", true)
	if err != nil {
		fmt.Println("Failed to start the logger. Nothing will be logged...")
	}
	logger.Info("Started the logger successfully.")

	// Order of calls here matters as the logger
	// needs to exist before clients are registerd
	// and before the server is created.  Similarly
	// the clients need to exist before the server
	// is created as they are connected at time
	// of server creation
	vxlan.SetLogger(logger)

	// register all appropriate clients for use by server
	// TODO add logic to read a param file which contains
	// which client interface to use
	client := snapclient.NewVXLANSnapClient(logger)
	vxlan.RegisterClients(*client)

	// create a new vxlan server
	server := vxlan.NewVXLANServer(logger, path)
	handler := rpc.NewVXLANDServiceHandler(server, logger)

	// Start keepalive routine
	go keepalive.InitKeepAlive("vxland", path)

	// blocking call
	handler.StartThriftServer()
}
