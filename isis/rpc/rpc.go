//Copyright [2016] [SnapRoute Inc]
//
//Licensed under the Apache License, Version 2.0 (the "License");
//you may not use this file except in compliance with the License.
//You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
//       Unless required by applicable law or agreed to in writing, software
//       distributed under the License is distributed on an "AS IS" BASIS,
//       WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//       See the License for the specific language governing permissions and
//       limitations under the License.
//
//   This is a auto-generated file, please do not edit!
// _______   __       __________   ___      _______.____    __    ____  __  .___________.  ______  __    __ 
// |   ____||  |     |   ____\  \ /  /     /       |\   \  /  \  /   / |  | |           | /      ||  |  |  |
// |  |__   |  |     |  |__   \  V  /     |   (----  \   \/    \/   /  |  |  ---|  |----    ,---- |  |__|  |
// |   __|  |  |     |   __|   >   <       \   \      \            /   |  |     |  |        |     |   __   |
// |  |     |  `----.|  |____ /  .  \  .----)   |      \    /\    /    |  |     |  |        `----.|  |  |  |
// |__|     |_______||_______/__/ \__\ |_______/        \__/  \__/     |__|     |__|      \______||__|  |__|
//

package rpc

import (
    "isisd"
    "git.apache.org/thrift.git/lib/go/thrift"
    "utils/logging"
)

type rpcServiceHandler struct {
    logger logging.LoggerIntf
}

func newRPCServiceHandler(logger logging.LoggerIntf) *rpcServiceHandler {
    return &rpcServiceHandler{
        logger: logger,
    }
}

type RPCServer struct {
    *thrift.TSimpleServer
}

func NewRPCServer(rpcAddr string, logger logging.LoggerIntf) *RPCServer {
        transport, err := thrift.NewTServerSocket(rpcAddr)
        if err != nil {
                panic(err)
        }
        handler := newRPCServiceHandler(logger)
        processor := isisd.NewISISDServicesProcessor(handler)
        transportFactory := thrift.NewTBufferedTransportFactory(8192)
        protocolFactory := thrift.NewTBinaryProtocolFactoryDefault()
        server := thrift.NewTSimpleServer4(processor, transport, transportFactory, protocolFactory)
        return &RPCServer{
                TSimpleServer: server,
        }
}
