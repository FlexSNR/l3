package main

import (
	"fmt"
	"l3/rib/test/testthrift"
	"l3/rib/testutils"
	"os"
	"strconv"
)

func main() {
	ribdClient := testutils.GetRIBdClient()
	if ribdClient == nil {
		fmt.Println("RIBd client nil")
		return
	}

	routeThriftTest.Createv4RouteList()
	routeThriftTest.Createv6RouteList()

	route_ops := os.Args[1:]
	fmt.Println("op:", route_ops)
	for i := 0; i < len(route_ops); i++ {
		op := route_ops[i]
		switch op {
		case "createv4":
			fmt.Println("Create v4 route test")
			routeThriftTest.Createv4Routes(ribdClient)
		case "createv6":
			fmt.Println("Create v6 route test")
			routeThriftTest.Createv6Routes(ribdClient)
		case "verify":
			fmt.Println("Verify reachability info")
			routeThriftTest.CheckRouteReachability(ribdClient)
		case "deletev4":
			fmt.Println("Delete v4 route test")
			routeThriftTest.Deletev4Routes(ribdClient)
		case "deletev6":
			fmt.Println("Delete v6 route test")
			routeThriftTest.Deletev6Routes(ribdClient)
		case "scale":
			if (i + 1) == len(route_ops) {
				fmt.Println("Incorrect usage: should be ./main scale <number>")
				break
			}
			number, _ := strconv.Atoi(route_ops[i+1])
			i++
			fmt.Println("Scale test for ", number, " routes")
			routeThriftTest.Scale(ribdClient, int64(number))
		case "RouteCount":
			fmt.Println("RouteCount")
			routeThriftTest.GetTotalRouteCount(ribdClient)
		case "Time":
			if (i + 1) == len(route_ops) {
				fmt.Println("Incorrect usage: should be ./main Time <number>")
				break
			}
			number, _ := strconv.Atoi(route_ops[i+1])
			i++
			fmt.Println("Time for ", number, " route creation")
			routeThriftTest.GetRouteCreatedTime(ribdClient, number)
		}
	}
}
