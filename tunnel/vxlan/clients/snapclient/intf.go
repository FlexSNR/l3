// base.go
package snapclient

import (
	nanomsg "github.com/op/go-nanomsg"
	vxlan "l3/tunnel/vxlan/protocol"
	"utils/logging"
)

// setup local refs to server info
var serverchannels *vxlan.VxLanConfigChannels
var logger *logging.Writer

// Base Snaproute Interface
type VXLANSnapClient struct {
	vxlan.BaseClientIntf
	ribdSubSocket       *nanomsg.SubSocket
	ribdSubSocketCh     chan []byte
	ribdSubSocketErrCh  chan error
	asicdSubSocket      *nanomsg.SubSocket
	asicdSubSocketCh    chan []byte
	asicdSubSocketErrCh chan error
}

func NewVXLANSnapClient(l *logging.Writer) *VXLANSnapClient {
	logger = l

	client := &VXLANSnapClient{
		ribdSubSocketCh:     make(chan []byte, 0),
		ribdSubSocketErrCh:  make(chan error, 0),
		asicdSubSocketCh:    make(chan []byte, 0),
		asicdSubSocketErrCh: make(chan error, 0),
	}

	go client.ClientChanListener()
	return client

}

func (intf VXLANSnapClient) ClientChanListener() {

	for {
		select {
		case rxBuf := <-intf.asicdSubSocketCh:
			intf.processAsicdNotification(rxBuf)
		case <-intf.asicdSubSocketErrCh:
			continue
		case rxBuf := <-intf.ribdSubSocketCh:
			intf.processRibdNotification(rxBuf)
		case <-intf.ribdSubSocketErrCh:
			continue
		}
	}
}

func (v VXLANSnapClient) SetServerChannels(s *vxlan.VxLanConfigChannels) {
	serverchannels = s
}

func (v VXLANSnapClient) IsClientIntfType(client vxlan.VXLANClientIntf, clientStr string) bool {
	logger.Info("IsClientIntfType", clientStr)
        switch client.(type) {
	case VXLANSnapClient:
		if clientStr == "SnapClient" {
			return true
		}
	default:
	logger.Info("IsClientInfType: default did not find client type")
	}
	return false
}
