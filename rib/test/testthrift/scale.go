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

package routeThriftTest

import (
	"fmt"
	"ribd"
	"ribdInt"
	"strconv"
	"time"
)

func handleClient(client *ribd.RIBDServicesClient, maxCount int64) (err error) {
	fmt.Println("handleClient")
	var count int64 = 0
	//var maxCount int = 30000
	intByt2 := 1
	intByt3 := 1
	intByt1 := 22
	byte4 := "0"
	start := time.Now()
	var route ribd.IPv4Route
	routeCount, _ := client.GetTotalv4RouteCount()
	fmt.Println("Route count before scale test start:", routeCount)
	for {
		if intByt2 > 253 && intByt3 > 254 {
			intByt1++
			intByt2 = 1
			intByt3 = 1
		}
		if intByt3 > 254 {
			intByt3 = 1
			intByt2++
		} else {
			intByt3++
		}
		if intByt2 > 254 {
			intByt2 = 1
		} //else {
		//intByt2++
		//}

		route = ribd.IPv4Route{}
		byte1 := strconv.Itoa(intByt1)
		byte2 := strconv.Itoa(intByt2)
		byte3 := strconv.Itoa(intByt3)
		rtNet := byte1 + "." + byte2 + "." + byte3 + "." + byte4
		//nhintf, _ := client.GetRouteReachabilityInfo("11.1.10.2")
		route.DestinationNw = rtNet
		route.NetworkMask = "255.255.255.0"
		route.NextHop = make([]*ribd.NextHopInfo, 0)
		nh := ribd.NextHopInfo{
			NextHopIp: "11.1.10.2",
			//NextHopIntRef: strconv.Itoa(int(nhintf.NextHopIfIndex)),
			//			NextHopIntRef: "lo1",
		}
		route.NextHop = append(route.NextHop, &nh)
		route.Protocol = "STATIC"
		//fmt.Println("Creating Route ", route)
		rv := client.OnewayCreateIPv4Route(&route)
		if rv == nil {
			count++
		} else {
			fmt.Println("Call failed", rv, "count: ", count)
			elapsed := time.Since(start)
			fmt.Println(" ## Elapsed time is ", elapsed)
			return nil
		}
		if maxCount == count {
			fmt.Println("Done. Total calls executed", count)
			break
		}

	}
	//elapsed := time.Since(start)
	//	fmt.Println(" ## Elapsed time is ", elapsed)
	return nil
}
func handleBulkClient(client *ribd.RIBDServicesClient, maxCount int64) (err error) {
	fmt.Println("handleBulkClient")
	var count int64 = 0
	//timeFmt := "2006-01-02 15:04:05.999999999 +0000 UTC"
	//	var maxCount int = 30000
	intByt2 := 1
	intByt3 := 1
	byte1 := "42"
	byte4 := "0"
	//	start := time.Now()
	//	var scaleTestStartTime string
	//	var scaleTestEndTime string
	//	var startTime time.Time
	//	var endTime time.Time
	var route []ribdInt.IPv4RouteConfig
	var routes []*ribdInt.IPv4RouteConfig
	routes = make([]*ribdInt.IPv4RouteConfig, 0)
	route = make([]ribdInt.IPv4RouteConfig, maxCount)
	routeCount, _ := client.GetTotalv4RouteCount()
	fmt.Println("Route count before scale test start:", routeCount)
	for {
		if intByt3 > 254 {
			intByt3 = 1
			intByt2++
		} else {
			intByt3++
		}
		if intByt2 > 254 {
			intByt2 = 1
		}
		byte2 := strconv.Itoa(intByt2)
		byte3 := strconv.Itoa(intByt3)
		rtNet := byte1 + "." + byte2 + "." + byte3 + "." + byte4
		route[count].DestinationNw = rtNet
		route[count].NetworkMask = "255.255.255.0"
		route[count].NextHop = make([]*ribdInt.RouteNextHopInfo, 0)
		nh := ribdInt.RouteNextHopInfo{
			NextHopIp: "11.1.10.2",
		}
		route[count].NextHop = append(route[count].NextHop, &nh)
		route[count].Protocol = "STATIC"
		routes = append(routes, &route[count])
		count++
		if maxCount == count {
			//		fmt.Println("Done. Total route configs added ", count)
			break
		}

	}
	//elapsed := time.Since(start)
	//fmt.Println(" ## Elapsed time is ", elapsed)
	client.OnewayCreateBulkIPv4Route(routes)
	/*	scaleTestEndTime, err = client.GetRouteCreatedTime(ribdInt.Int(int(routeCount) + maxCount))
		if err != nil {
			fmt.Println("err ", err, " getting routecreated time for route #", int(routeCount)+maxCount)
			for {
				scaleTestEndTime, err = client.GetRouteCreatedTime(ribdInt.Int(int(routeCount) + maxCount))
				if err == nil {
					scaleTestStartTime, err = client.GetRouteCreatedTime(routeCount + 1)
					if err != nil {
						fmt.Println("err ", err, " getting routecreated time for route #", routeCount+1)
						return
					}
					fmt.Println("startTime:", scaleTestStartTime, " for the ", routeCount+1, " route")
					startTime, err = time.Parse(timeFmt, scaleTestStartTime)
					if err != nil {
						fmt.Println("err parsing obj time:", scaleTestStartTime, " into timeFmt:", timeFmt, " err:", err)
						return
					}
					break
				}
			}
			//return
		}
		fmt.Println("endTime:", scaleTestEndTime, " after the ", int(routeCount)+maxCount, " route")
		endTime, err = time.Parse(timeFmt, scaleTestEndTime)
		if err != nil {
			fmt.Println("err parsing obj time:", scaleTestEndTime, " into timeFmt:", timeFmt, " err:", err)
			return
		}
		fmt.Println("GetRouteCreatedTime() method Time to install ", maxCount, " number of routes is:", "duration:", endTime.Sub(startTime))*/
	return nil
}

//func main() {
func Scale(ribdClient *ribd.RIBDServicesClient, number int64) {
	/*ribdClient := testutils.GetRIBdClient()
	if ribdClient == nil {
		fmt.Println("RIBd client nil")
		return
	}*/
	handleClient(ribdClient, number) //ribd.NewRIBDServicesClientFactory(transport, protocolFactory))
	//handleBulkClient(ribdClient, number) //(ribd.NewRIBDServicesClientFactory(transport, protocolFactory))
}
