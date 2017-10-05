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

package vrrpServer

import (
	"fmt"
	"models/objects"
	"utils/dbutils"
	"vrrpd"
)

func (svr *VrrpServer) VrrpInitDB() error {
	svr.logger.Info("Initializing DB")
	var err error
	svr.vrrpDbHdl = dbutils.NewDBUtil(svr.logger)
	err = svr.vrrpDbHdl.Connect()
	if err != nil {
		svr.logger.Err(fmt.Sprintln("Failed to Create DB Handle", err))
		return err
	}

	svr.logger.Info("DB connection is established")
	return err
}

func (svr *VrrpServer) VrrpCloseDB() {
	svr.logger.Info("Closed vrrp db")
	svr.vrrpDbHdl.Disconnect()
}

func (svr *VrrpServer) VrrpReadDB() error {
	svr.logger.Info("Reading VrrpIntf Config from DB")
	if svr.vrrpDbHdl == nil {
		return nil
	}
	var dbObj objects.VrrpIntf
	objList, err := dbObj.GetAllObjFromDb(svr.vrrpDbHdl)
	if err != nil {
		svr.logger.Warning("DB querry failed for VrrpIntf Config")
		return err
	}
	for idx := 0; idx < len(objList); idx++ {
		obj := vrrpd.NewVrrpIntf()
		dbObject := objList[idx].(objects.VrrpIntf)
		objects.ConvertvrrpdVrrpIntfObjToThrift(&dbObject, obj)
		svr.VrrpCreateGblInfo(*obj)
	}
	svr.logger.Info("Done reading from DB")
	return err
}
