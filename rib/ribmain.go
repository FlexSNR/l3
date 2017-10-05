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
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	//"github.com/davecheney/profile"
	"l3/rib/rpc"
	"l3/rib/server"
	//	"os"
	//	"runtime/pprof"
	"utils/dbutils"
	"utils/keepalive"
	"utils/logging"
)

//var cpuprofile = flag.String("cpuprofile", "cpu.prof", "write cpu profile to file")
//var cpuprofile = "cpu.prof"
func SigHandler(logger *logging.Writer, dbHdl *dbutils.DBUtil, routeServer *server.RIBDServer) {
	logger.Info("Inside sigHandler....")
	sigChan := make(chan os.Signal, 1)
	signalList := []os.Signal{syscall.SIGHUP}
	signal.Notify(sigChan, signalList...)

	signal := <-sigChan
	switch signal {
	case syscall.SIGHUP:
		logger.Info("Received SIGHUP signal")
		routeServer.StopServer()
		if dbHdl != nil {
			logger.Info("Closing DB handler")
			dbHdl.Disconnect()
		}
		os.Exit(0)
	default:
		//logger.Err(fmt.Sprintln("Unhandled signal : ", signal))
	}
}

func main() {
	//defer profile.Start(profile.CPUProfile).Stop()
	/*if cpuprofile != "" {
		fmt.Println("cpuprofile not empty, start profiling")
		f, err := os.Create(cpuprofile)
		if err != nil {
			fmt.Println("Error: ", err)
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}*/
	var err error
	paramsDir := flag.String("params", "./params", "Params directory")
	flag.Parse()
	fileName := *paramsDir
	if fileName[len(fileName)-1] != '/' {
		fileName = fileName + "/"
	}

	fmt.Println("RIBD Start logger")
	logger, err := logging.NewLogger("ribd", "RIB", true)
	if err != nil {
		fmt.Println("Failed to start the logger. Nothing will be logged...")
	}
	logger.Info("Started the logger successfully.")

	dbHdl := dbutils.NewDBUtil(logger)
	err = dbHdl.Connect()
	if err != nil {
		logger.Err("Failed to dial out to Redis server")
		return
	}
	routeServer := server.NewRIBDServicesHandler(dbHdl, logger)
	if routeServer == nil {
		logger.Println("routeServer nil")
		return
	}
	go routeServer.StartServer(*paramsDir)
	up := <-routeServer.ServerUpCh
	//dbHdl.Close()
	logger.Info(fmt.Sprintln("RIBD server is up: ", up))
	if !up {
		logger.Err(fmt.Sprintln("Exiting!!"))
		return
	}

	// Start keepalive routine
	go keepalive.InitKeepAlive("ribd", fileName)
	go SigHandler(logger, dbHdl, routeServer)
	ribdServicesHandler := rpc.NewRIBdHandler(logger, routeServer)
	rpc.NewRIBdRPCServer(logger, ribdServicesHandler, fileName)
}
