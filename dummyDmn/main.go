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
	"l3/dummyDmn/server"
	"utils/dmnBase"
)

var DummyDmn dmnBase.L3Daemon

func main() {
	status := DummyDmn.Init("dmnd", "DUMMY")
	DummyDmn.Logger.Info(fmt.Sprintln("Init done with status", status))
	if status == false {
		fmt.Println("Init failed")
		return
	}
	dummyServer := server.NewDummyServer(DummyDmn)

	go dummyServer.StartServer()
	<-dummyServer.ServerStartedCh

	DummyDmn.Logger.Info("Dummy server started")

	// Start keepalive routine
	DummyDmn.Logger.Println("Starting KeepAlive")
	DummyDmn.StartKeepAlive()

	//simulate rpc.StartServer()
	for {
	}
}
