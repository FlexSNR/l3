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

// policyApis.go
package rpc

import (
	"fmt"
	"l3/rib/server"
	"ribd"
	"ribdInt"
	//"utils/policy"
)

func (m RIBDServicesHandler) CreatePolicyStmt(cfg *ribd.PolicyStmt) (val bool, err error) {
	logger.Debug("CreatePolicyStatement")
	m.server.PolicyConfCh <- server.RIBdServerConfig{
		OrigConfigObject: cfg,
		Op:               "addPolicyStmt",
	}
	err = <-m.server.PolicyConfDone
	if err == nil {
		val = true
	}
	return val, err
}

func (m RIBDServicesHandler) DeletePolicyStmt(cfg *ribd.PolicyStmt) (val bool, err error) {
	logger.Debug(fmt.Sprintln("DeletePolicyStatement for name ", cfg.Name))
	m.server.PolicyConfCh <- server.RIBdServerConfig{
		OrigConfigObject: cfg,
		Op:               "delPolicyStmt",
	}
	err = <-m.server.PolicyConfDone
	if err == nil {
		val = true
	}
	return val, err
}

func (m RIBDServicesHandler) UpdatePolicyStmt(origconfig *ribd.PolicyStmt, newconfig *ribd.PolicyStmt, attrset []bool, op []*ribd.PatchOpInfo) (val bool, err error) {
	if op == nil || len(op) == 0 {
		//update op
		logger.Info("Update op for policy stmt definition")

	} else {
		//patch op
		logger.Info("patch op:", op, " for policy stmt definition")
	}
	m.server.PolicyConfCh <- server.RIBdServerConfig{
		OrigConfigObject: origconfig,
		NewConfigObject:  newconfig,
		AttrSet:          attrset,
		PatchOp:          op,
		Op:               "updatePolicyStmt",
	}
	err = <-m.server.PolicyConfDone
	if err == nil {
		val = true
	}
	logger.Debug("updatepolicystmt ,err:", err, " val:", val)
	return val, err
}
func (m RIBDServicesHandler) GetPolicyStmtState(name string) (*ribd.PolicyStmtState, error) {
	logger.Debug("Get state for Policy Stmt")
	retState := ribd.NewPolicyStmtState()
	return retState, nil
}
func (m RIBDServicesHandler) GetBulkPolicyStmtState(fromIndex ribd.Int, rcount ribd.Int) (policyStmts *ribd.PolicyStmtStateGetInfo, err error) { //(routes []*ribd.Routes, err error) {
	logger.Debug(fmt.Sprintln("GetBulkPolicyStmtState"))
	policyStmts, err = m.server.GetBulkPolicyStmtState(fromIndex, rcount, m.server.GlobalPolicyEngineDB)
	return policyStmts, err
}

func (m RIBDServicesHandler) CreatePolicyDefinition(cfg *ribd.PolicyDefinition) (val bool, err error) {
	logger.Debug(fmt.Sprintln("CreatePolicyDefinition"))
	m.server.PolicyConfCh <- server.RIBdServerConfig{
		OrigConfigObject: cfg,
		Op:               "addPolicyDefinition",
	}
	err = <-m.server.PolicyConfDone
	if err == nil {
		val = true
	}
	return val, err
}

func (m RIBDServicesHandler) DeletePolicyDefinition(cfg *ribd.PolicyDefinition) (val bool, err error) {
	logger.Debug(fmt.Sprintln("DeletePolicyDefinition for name ", cfg.Name))
	m.server.PolicyConfCh <- server.RIBdServerConfig{
		OrigConfigObject: cfg,
		Op:               "delPolicyDefinition",
	}
	err = <-m.server.PolicyConfDone
	if err == nil {
		val = true
	}
	return val, err
}

func (m RIBDServicesHandler) UpdatePolicyDefinition(origconfig *ribd.PolicyDefinition, newconfig *ribd.PolicyDefinition, attrset []bool, op []*ribd.PatchOpInfo) (val bool, err error) {
	logger.Debug(fmt.Sprintln("UpdatePolicyDefinition for name ", origconfig.Name))
	if op == nil || len(op) == 0 {
		//update op
		logger.Info("Update op for policy definition")

	} else {
		//patch op
		logger.Info("patch op:", op, " for policy definition")
	}
	m.server.PolicyConfCh <- server.RIBdServerConfig{
		OrigConfigObject: origconfig,
		NewConfigObject:  newconfig,
		AttrSet:          attrset,
		PatchOp:          op,
		Op:               "updatePolicyDefinition",
	}
	err = <-m.server.PolicyConfDone
	if err == nil {
		val = true
	}
	return val, err
}
func (m RIBDServicesHandler) GetPolicyDefinitionState(name string) (*ribd.PolicyDefinitionState, error) {
	logger.Debug("Get state for Policy Definition")
	retState := ribd.NewPolicyDefinitionState()
	return retState, nil
}
func (m RIBDServicesHandler) GetBulkPolicyDefinitionState(fromIndex ribd.Int, rcount ribd.Int) (policyStmts *ribd.PolicyDefinitionStateGetInfo, err error) { //(routes []*ribd.Routes, err error) {
	logger.Debug(fmt.Sprintln("GetBulkPolicyDefinitionState"))
	policyStmts, err = m.server.GetBulkPolicyDefinitionState(fromIndex, rcount, m.server.GlobalPolicyEngineDB)
	return policyStmts, err
}

//this API is called by applications when user applies a policy to a entity and RIBD applies the policy/runs the policyEngine
func (m RIBDServicesHandler) ApplyPolicy(applyList []*ribdInt.ApplyPolicyInfo, undoList []*ribdInt.ApplyPolicyInfo) (err error) {
	logger.Debug(fmt.Sprintln("RIB handler ApplyPolicy applyList:", applyList, " undoList:", undoList))
	m.server.PolicyConfCh <- server.RIBdServerConfig{
		PolicyList: server.ApplyPolicyList{applyList, undoList},
		Op:         "applyPolicy",
	}
	err = <-m.server.PolicyConfDone
	//m.server.PolicyApplyCh <- server.ApplyPolicyList{applyList, undoList} //source, policy, action, conditions}
	return nil
}

//this API is called when an external application has applied a policy and wants to update the application map for the policy in the global policy DB
func (m RIBDServicesHandler) UpdateApplyPolicy(applyList []*ribdInt.ApplyPolicyInfo, undoList []*ribdInt.ApplyPolicyInfo) (err error) {
	//logger.Debug(fmt.Sprintln("RIB handler UpdateApplyPolicy applyList:applyList," undoList:",undoList))
	m.server.PolicyUpdateApplyCh <- server.ApplyPolicyList{applyList, undoList}
	return nil
}
