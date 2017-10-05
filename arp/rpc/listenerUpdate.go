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

package rpc

import (
	"arpd"
	"errors"
	"fmt"
	"l3/arp/server"
)

func (h *ARPHandler) sanityCheckArpGlobalConfig(timeout int) error {
	if timeout < h.server.MinRefreshTimeout {
		err := errors.New(fmt.Sprintln("Arp refresh timeout value is below allowed refresh timeout value of:", h.server.MinRefreshTimeout))
		return err
	} else if timeout == h.server.ConfRefreshTimeout {
		h.logger.Info(fmt.Sprintln("Arp refresh timeout is already configured with value of:", h.server.ConfRefreshTimeout))
		return nil
	}
	return nil
}

func (h *ARPHandler) SendUpdateArpGlobalConfig(timeout int) error {
	err := h.sanityCheckArpGlobalConfig(timeout)
	if err != nil {
		return err
	}
	arpConf := server.ArpConf{
		RefTimeout: timeout,
	}
	h.server.ArpConfCh <- arpConf
	return err
}

func (h *ARPHandler) UpdateArpGlobal(origConf *arpd.ArpGlobal, newConf *arpd.ArpGlobal, attrset []bool, op []*arpd.PatchOpInfo) (bool, error) {
	h.logger.Info(fmt.Sprintln("Original Arp config attrs:", origConf))
	h.logger.Info(fmt.Sprintln("New Arp config attrs:", newConf))
	err := h.SendUpdateArpGlobalConfig(int(newConf.Timeout))
	if err != nil {
		return false, err
	}
	return true, nil
}
