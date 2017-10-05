// vxlandb.go
package vxlan

import (
	"fmt"
	"net"
)

// vni -> db entry
var vxlanDB map[uint32]*vxlanDbEntry

// vxlanDbEntry
// Struct to store the data associated with vxlan
type vxlanDbEntry struct {
	// VNI associated with the vxlan domain
	VNI uint32
	// VlanId associated with the Access endpoints
	VlanId uint16 // used to tag inner ethernet frame when egressing
	// Multicast IP group (NOT SUPPORTED)
	Group net.IP
	// Shortcut to apply MTU to each VTEP
	MTU uint32
	// VTEP's associated with this vxlan domain
	// Vlan db will hold port membership for access
	VtepMembers []uint32
}

// vlan -> vni mapping
var vxlanVlanToVniDb map[uint16]uint32

// NewVxlanDbEntry:
// Create a new vxlan db entry
func NewVxlanDbEntry(c *VxlanConfig) *vxlanDbEntry {
	return &vxlanDbEntry{
		VNI:         c.VNI,
		VlanId:      c.VlanId,
		Group:       c.Group,
		MTU:         c.MTU,
		VtepMembers: make([]uint32, 0),
	}
}

func GetVxlanDBEntry(vni uint32) *vxlanDbEntry {
	if vxlan, ok := vxlanDB[vni]; ok {
		return vxlan
	}
	return nil
}

// GetVxlanDB:
// returns the vxlan db
func GetVxlanDB() map[uint32]*vxlanDbEntry {
	return vxlanDB
}

// saveVxLanConfigData:
// function saves off the configuration data and saves off the vlan to vni mapping
func saveVxLanConfigData(c *VxlanConfig) {
	if _, ok := vxlanDB[c.VNI]; !ok {
		vxlan := NewVxlanDbEntry(c)
		vxlanDB[c.VNI] = vxlan
		vxlanVlanToVniDb[c.VlanId] = c.VNI
	}
}

// DeleteVxLAN:
// Configuration interface for creating the vlxlan instance
func CreateVxLAN(c *VxlanConfig) {
	saveVxLanConfigData(c)

	for _, client := range ClientIntf {
		// create vxlan resources in hw
		client.CreateVxlan(c)
	}

	// lets find all the vteps which are in VtepStatusConfigPending state
	// and initiate a hwConfig
	for _, vtep := range GetVtepDB() {
		if vtep.VxlanVtepMachineFsm.Machine.Curr.CurrentState() == VxlanVtepStateDetached {
			// restart the state machine
			vtep.VxlanVtepMachineFsm.VxlanVtepEvents <- MachineEvent{
				E:   VxlanVtepEventBegin,
				Src: VxlanVtepMachineModuleStr,
			}
		}
	}
}

// DeleteVxLAN:
// Configuration interface for deleting the vlxlan instance
func DeleteVxLAN(c *VxlanConfig) {

	// delete vxlan resources in hw
	for _, client := range ClientIntf {
		client.DeleteVxlan(c)
	}

	delete(vxlanDB, c.VNI)

	logger.Info(fmt.Sprintln("DeleteVxLAN", c.VNI))
}
