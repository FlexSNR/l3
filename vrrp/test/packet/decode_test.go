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

package packettest

import (
	"l3/vrrp/server"
	"net"
	"reflect"
	"testing"
)

func TestVRRPDDecode(t *testing.T) {
	data := []byte{0x21, 0x01, 0x64, 0x01, 0x00, 0x01, 0xba, 0x52, 0xc0, 0xa8,
		0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	server := &vrrpServer.VrrpServer{}
	decodeInfo := server.VrrpDecodeHeader(data)

	vrrpHeader := vrrpServer.VrrpPktHeader{
		Version:       vrrpServer.VRRP_VERSION2,
		Type:          vrrpServer.VRRP_PKT_TYPE_ADVERTISEMENT,
		VirtualRtrId:  1,
		Priority:      100,
		CountIPv4Addr: 1,
		Rsvd:          vrrpServer.VRRP_RSVD,
		MaxAdverInt:   1,
		CheckSum:      47698,
	}
	ip := net.ParseIP("192.168.0.1")
	vrrpHeader.IPv4Addr = append(vrrpHeader.IPv4Addr, ip.To4())

	if !reflect.DeepEqual(decodeInfo.Version, vrrpHeader.Version) {
		t.Error("Version mismatch")
	}
	if !reflect.DeepEqual(decodeInfo.Type, vrrpHeader.Type) {
		t.Error("Type Mismatch")
	}
	if !reflect.DeepEqual(decodeInfo.VirtualRtrId, vrrpHeader.VirtualRtrId) {
		t.Error("VRID mismatch")

	}
	if !reflect.DeepEqual(decodeInfo.Priority, vrrpHeader.Priority) {
		t.Error("Priority mismatch")
	}

	if !reflect.DeepEqual(decodeInfo.CountIPv4Addr, vrrpHeader.CountIPv4Addr) {
		t.Error("Count ipv4 addr mismatch")
	}

	if !reflect.DeepEqual(decodeInfo.Rsvd, vrrpHeader.Rsvd) {
		t.Error("rsvd mismatch")
	}

	if !reflect.DeepEqual(decodeInfo.MaxAdverInt, vrrpHeader.MaxAdverInt) {
		t.Error("max adver mismatch")
	}

	if !reflect.DeepEqual(decodeInfo.CheckSum, vrrpHeader.CheckSum) {
		t.Error("Mismatch in checksum")
	}

	if !reflect.DeepEqual(decodeInfo.IPv4Addr, vrrpHeader.IPv4Addr) {
		t.Error("IPV4 address mismtach")
	}
	/*
		fmt.Println(reflect.ValueOf(decodeInfo.IPv4Addr[0]).Kind())
		fmt.Println(reflect.ValueOf(vrrpHeader.IPv4Addr[0]).Kind())
		fmt.Println(reflect.ValueOf(decodeInfo.IPv4Addr[0]).Type())
		fmt.Println(reflect.ValueOf(vrrpHeader.IPv4Addr[0]).Type())
		fmt.Println(reflect.ValueOf(decodeInfo.IPv4Addr[0]).Len())
		fmt.Println(reflect.ValueOf(vrrpHeader.IPv4Addr[0]).Len())
		fmt.Println(reflect.ValueOf(decodeInfo.IPv4Addr).Len())
		fmt.Println(reflect.ValueOf(vrrpHeader.IPv4Addr).Len())
		if !reflect.DeepEqual(decodeInfo.IPv4Addr, vrrpHeader.IPv4Addr) {
			t.Error("IPV4 address mismtach")
		}

			fmt.Println("Decode:", *decodeInfo)
			fmt.Println("Local:", vrrpHeader)
		v1 := reflect.ValueOf(*decodeInfo)
		v2 := reflect.ValueOf(vrrpHeader)
		for i, n := 0, v1.NumField(); i < n; i++ {
			fmt.Println("v1:", v1.Field(i), "v2:", v2.Field(i))
			//fmt.Println("v1:", v1.Kind(), "v2:", v2.Kind())
			//fmt.Println("v1:", v1.Type(), "v2:", v2.Type())
			//fmt.Println("v1:", v1.Len(), "v2:", v2.Len())
			if !reflect.DeepEqual(v1.Field(i), v2.Field(i)) {
				//return false
				fmt.Println("failed")
			}
		}

		if !reflect.DeepEqual(decodeInfo, vrrpHeader) {
			t.Error("Decoding vrrp failed as the headers are not equal")
		}
	*/
}
