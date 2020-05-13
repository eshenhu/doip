package doip

import (
	"log"
	"net"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// Table 39
const (
	localLogicalAddr uint16 = 0x1000
)

// Server : DoIP server
type DoIPServer struct {
	log      *log.Logger
	address  string
	addr     net.TCPAddr
	listener net.Listener
}

func TestDisconnectScenarios(t *testing.T) {
	c := NewDoIPTest()
	defer c.close()

	mux := NewServeMux(c.genOutChan)
	mux.HandleFunc(routingActivationRequest, handlerRoutingActiveReq)

	srv, _, err := RunLocalTCPServer("127.0.0.1:13400", mux)
	if err != nil {
		t.Fatalf("Error while starting the server %s", err)
	}
	defer srv.Shutdown()
	time.Sleep(1000 * time.Millisecond)

	t.Run("terminateFromDiagMaster", testNormalRAReq)
	//t.Run("terminateFromDiagMasterJustBeforeSend", testTerminateFromDiagMasterJustBeforedoIPSend)
}

func testNormalRAReq(t *testing.T) {
	doIP := NewDoIP(os.Stdout, 0x0E80, "127.0.0.1:13400")
	defer doIP.Disconnect()

	doIP.SetReadTimeout(200 * time.Millisecond)
	doIP.Connect()

	//err := doIP.Send(0x1D01, routingActivationRequest, []byte{0, 0, 0, 0, 0})
	req := &MsgActivationReq{
		id:             routingActivationRequest,
		srcAddress:     0x0E80,
		activationType: 0,
		reserveForStd:  []byte{0, 0, 0, 0},
		reserveForOEM:  []byte{},
	}

	err := doIP.SendMsg(req)
	// doIP.Send
	assert.NoError(t, err)

	_, _, _, err = doIP.Receive()
	assert.NoError(t, err)
}

/*
func testTerminateFromDiagMasterJustBeforedoIPSend(t *testing.T) {
	doIP = doip.NewDoIP(dutlogger, 0x0E80, fmt.Sprintf("127.0.0.1:%d", port))
	doIP.SetReadTimeout(200 * time.Millisecond)
	doIP.Connect()

	addr := uint32(0x1D01)
	err := doIP.Send(addr, []byte{0x22, 0x10, 0x11, 0x55, 0x33})
	assert.NoError(t, err)
	time.Sleep(100 * time.Millisecond)

	//Try to send a normal 0x22 request
	err = doIP.Send(addr, []byte{0x22, 0xDD, 0x01, 0x55, 0x33})
	assert.Error(t, err)
	assert.EqualError(t, err, "#11 <DoIP: Session disconnected>")
}
*/

func runWithConnection(doIP *DoIP, f func(t *testing.T)) func(t *testing.T) {
	return func(t *testing.T) {
		err := doIP.Connect()
		if err != nil {
			t.Fatalf("Could not create DoIP session %v", err)
		}
		f(t)
		doIP.Disconnect()
	}
}
