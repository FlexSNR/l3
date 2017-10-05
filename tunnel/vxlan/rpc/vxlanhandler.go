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

// lahandler
package rpc

import (
	"encoding/json"
	"errors"
	"fmt"
	"git.apache.org/thrift.git/lib/go/thrift"
	"github.com/garyburd/redigo/redis"
	"io/ioutil"
	vxlan "l3/tunnel/vxlan/protocol"
	"models/objects"
	"utils/dbutils"
	"utils/logging"
	"vxland"
)

const DBName string = "UsrConfDb.db"

type ClientJson struct {
	Name string `json:Name`
	Port int    `json:Port`
}

type VXLANDServiceHandler struct {
	server *vxlan.VXLANServer
	logger *logging.Writer
}

// look up the various other daemons based on c string
func GetClientPort(paramsFile string, c string) int {
	var clientsList []ClientJson

	bytes, err := ioutil.ReadFile(paramsFile)
	if err != nil {
		return 0
	}

	err = json.Unmarshal(bytes, &clientsList)
	if err != nil {
		return 0
	}

	for _, client := range clientsList {
		if client.Name == c {
			return client.Port
		}
	}
	return 0
}

func NewVXLANDServiceHandler(server *vxlan.VXLANServer, logger *logging.Writer) *VXLANDServiceHandler {
	//lacp.LacpStartTime = time.Now()
	// link up/down events for now
	//startEvtHandler()
	handler := &VXLANDServiceHandler{
		server: server,
		logger: logger,
	}

	// lets read the current config and re-play the config
	handler.ReadConfigFromDB()

	return handler
}

func (v *VXLANDServiceHandler) StartThriftServer() {

	var transport thrift.TServerTransport
	var err error

	fileName := v.server.Paramspath + "clients.json"
	port := GetClientPort(fileName, "vxland")
	if port != 0 {
		addr := fmt.Sprintf("localhost:%d", port)
		transport, err = thrift.NewTServerSocket(addr)
		if err != nil {
			panic(fmt.Sprintf("Failed to create Socket with:", addr))
		}

		processor := vxland.NewVXLANDServicesProcessor(v)
		transportFactory := thrift.NewTBufferedTransportFactory(8192)
		protocolFactory := thrift.NewTBinaryProtocolFactoryDefault()
		thriftserver := thrift.NewTSimpleServer4(processor, transport, transportFactory, protocolFactory)

		err = thriftserver.Serve()
		panic(err)
	}
	panic(errors.New("Unable to find vxland port"))
}

func (v *VXLANDServiceHandler) CreateVxlanInstance(config *vxland.VxlanInstance) (bool, error) {
	v.logger.Info(fmt.Sprintf("CreateVxlanConfigInstance %#v", config))

	c, err := vxlan.ConvertVxlanInstanceToVxlanConfig(config)
	if err == nil {
		err = vxlan.VxlanConfigCheck(c)
		if err == nil {
			v.server.Configchans.Vxlancreate <- *c
			return true, nil
		}
	}
	return false, err
}

func (v *VXLANDServiceHandler) DeleteVxlanInstance(config *vxland.VxlanInstance) (bool, error) {
	v.logger.Info(fmt.Sprintf("DeleteVxlanConfigInstance %#v", config))
	c, err := vxlan.ConvertVxlanInstanceToVxlanConfig(config)
	if err == nil {
		v.server.Configchans.Vxlandelete <- *c
		return true, nil
	}
	return false, err
}

func (v *VXLANDServiceHandler) UpdateVxlanInstance(origconfig *vxland.VxlanInstance, newconfig *vxland.VxlanInstance, attrset []bool, op []*vxland.PatchOpInfo) (bool, error) {
	v.logger.Info(fmt.Sprintf("UpdateVxlanConfigInstance orig[%#v] new[%#v]", origconfig, newconfig))
	oc, _ := vxlan.ConvertVxlanInstanceToVxlanConfig(origconfig)
	nc, err := vxlan.ConvertVxlanInstanceToVxlanConfig(newconfig)
	if err == nil {
		err = vxlan.VxlanConfigCheck(nc)
		if err == nil {
			update := vxlan.VxlanUpdate{
				Oldconfig: *oc,
				Newconfig: *nc,
				Attr:      attrset,
			}
			v.server.Configchans.Vxlanupdate <- update
			return true, nil
		}
	}
	return false, err
}

func (v *VXLANDServiceHandler) CreateVxlanVtepInstance(config *vxland.VxlanVtepInstance) (bool, error) {
	v.logger.Info(fmt.Sprintf("CreateVxlanVtepInstance %#v", config))
	c, err := vxlan.ConvertVxlanVtepInstanceToVtepConfig(config)
	if err == nil {
		err = vxlan.VtepConfigCheck(c)
		if err == nil {
			v.server.Configchans.Vtepcreate <- *c
			return true, err
		}
	}
	return false, err
}

func (v *VXLANDServiceHandler) DeleteVxlanVtepInstance(config *vxland.VxlanVtepInstance) (bool, error) {
	v.logger.Info(fmt.Sprintf("DeleteVxlanVtepInstance %#v", config))
	c, err := vxlan.ConvertVxlanVtepInstanceToVtepConfig(config)
	if err == nil {
		v.server.Configchans.Vtepdelete <- *c
		return true, nil
	}
	return false, err
}

func (v *VXLANDServiceHandler) UpdateVxlanVtepInstance(origconfig *vxland.VxlanVtepInstance, newconfig *vxland.VxlanVtepInstance, attrset []bool, op []*vxland.PatchOpInfo) (bool, error) {
	v.logger.Info(fmt.Sprintf("UpdateVxlanVtepInstances orig[%#v] new[%#v]", origconfig, newconfig))
	oc, _ := vxlan.ConvertVxlanVtepInstanceToVtepConfig(origconfig)
	nc, err := vxlan.ConvertVxlanVtepInstanceToVtepConfig(newconfig)
	if err == nil {
		err = vxlan.VtepConfigCheck(nc)
		if err == nil {
			update := vxlan.VtepUpdate{
				Oldconfig: *oc,
				Newconfig: *nc,
				Attr:      attrset,
			}
			v.server.Configchans.Vtepupdate <- update
			return true, nil
		}
	}

	return false, err
}

func (v *VXLANDServiceHandler) HandleDbReadVxlanInstance(dbHdl redis.Conn) error {
	if dbHdl != nil {
		var dbObj objects.VxlanInstance
		objList, err := dbObj.GetAllObjFromDb(dbHdl)
		if err != nil {
			v.logger.Warning("DB Query failed when retrieving VxlanInstance objects")
			return err
		}
		for idx := 0; idx < len(objList); idx++ {
			obj := vxland.NewVxlanInstance()
			dbObject := objList[idx].(objects.VxlanInstance)
			objects.ConvertvxlandVxlanInstanceObjToThrift(&dbObject, obj)
			_, err = v.CreateVxlanInstance(obj)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (v *VXLANDServiceHandler) HandleDbReadVxlanVtepInstance(dbHdl redis.Conn) error {
	if dbHdl != nil {
		var dbObj objects.VxlanVtepInstance
		objList, err := dbObj.GetAllObjFromDb(dbHdl)
		if err != nil {
			v.logger.Warning("DB Query failed when retrieving VxlanVtepInstance objects")
			return err
		}
		for idx := 0; idx < len(objList); idx++ {
			obj := vxland.NewVxlanVtepInstance()
			dbObject := objList[idx].(objects.VxlanVtepInstance)
			objects.ConvertvxlandVxlanVtepInstanceObjToThrift(&dbObject, obj)
			_, err = v.CreateVxlanVtepInstance(obj)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (v *VXLANDServiceHandler) ReadConfigFromDB() error {

	dbHdl := dbutils.NewDBUtil(v.logger)
	err := dbHdl.Connect()
	if err != nil {
		v.logger.Err("Unable to connect to db")
		return err
	}
	defer dbHdl.Disconnect()

	if err := v.HandleDbReadVxlanInstance(dbHdl); err != nil {
		//stp.StpLogger("ERROR", "Error getting All VxlanInstance objects")
		return err
	}

	if err := v.HandleDbReadVxlanVtepInstance(dbHdl); err != nil {
		//stp.StpLogger("ERROR", "Error getting All VxlanVtepInstance objects")
		return err
	}

	return nil
}
