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

func TestShutdownSrvDuringOngoingActiveClient(t *testing.T) {
	c := NewDoIPTest()
	defer c.close()

	mux := NewServeMux(c.genOutChan)
	mux.HandleFunc(routingActivationRequest, handlerRoutingActiveReq)

	srv, _, err := RunLocalTCPServer("127.0.0.1:13400", mux)
	if err != nil {
		t.Fatalf("Error while starting the server %s", err)
	}
	time.Sleep(1000 * time.Millisecond)

	doIP := NewDoIP(os.Stdout, 0x0E80, "127.0.0.1:13400")
	doIP.SetReadTimeout(200 * time.Millisecond)
	doIP.Connect()

	srv.Shutdown()
	time.Sleep(4000 * time.Millisecond)

	//err := doIP.Send(addr, []byte{0x22, 0x10, 0x10, 0x55, 0x33})
	err = doIP.Send(0x1D01, routingActivationRequest, []byte{0, 0, 0, 0, 0})
	assert.Error(t, err)
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

	t.Run("terminateFromDiagMaster", testNormalRoutingActReq)
	t.Run("testAbnormalRoutingActReq", testAbnormalRoutingActReq)
}

func testNormalRoutingActReq(t *testing.T) {
	doIP := NewDoIP(os.Stdout, 0x0E80, "127.0.0.1:13400")
	doIP.SetReadTimeout(200 * time.Millisecond)
	doIP.Connect()

	//err := doIP.Send(addr, []byte{0x22, 0x10, 0x10, 0x55, 0x33})
	err := doIP.Send(0x1D01, routingActivationRequest, []byte{0, 0, 0, 0, 0})
	assert.NoError(t, err)

	_, _, _, err = doIP.Receive()
	assert.NoError(t, err)
}

func testAbnormalRoutingActReq(t *testing.T) {
	doIP := NewDoIP(os.Stdout, 0x0E80, "127.0.0.1:13400")
	doIP.SetReadTimeout(200 * time.Millisecond)
	doIP.Connect()

	//err := doIP.Send(addr, []byte{0x22, 0x10, 0x10, 0x55, 0x33})
	err := doIP.Send(0x1D01, routingActivationRequest, []byte{0, 0, 0, 0})
	assert.NoError(t, err)

	_, _, _, err = doIP.Receive()
	assert.Error(t, err)
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
/*
func TestDoIPOneConnection(t *testing.T) {
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

	doIP := NewDoIP(os.Stdout, 0x0E80, "127.0.0.1:13400")
	doIP.SetReadTimeout(200 * time.Millisecond)
	doIP.Connect()

	runWithConnection(func(t *testing.T) {
		t.Run("ReadShortDid", testReadShortDid)
		t.Run("LongDid", testLongDid)
		t.Run("VeryLongDid", testVeryLongDid)
		t.Run("ErrorDid", testErrorDid)
		t.Run("UnknownTargetAddress", testUnknownTargetAddress)
		t.Run("UnknownPayloadType", testUnknownPayloadType)
		t.Run("DoIPWrongProtocolVersion", testWrongProtocolVersion)
	})(t)
}

func testReadShortDid(t *testing.T) {
	addr := uint32(0x1D01)
	err := doIP.Send(addr, []byte{0x22, 0xDD, 0x01, 0x55, 0x33})
	assert.NoError(t, err)

	source, _, data, err := doIP.Receive()
	assert.NoError(t, err)
	assert.Equal(t, addr, source)
	assert.Equal(t, uint8(0x62), data[0])
	assert.Equal(t, data[1:3], []byte{0xDD, 0x01})
}

func testWrongProtocolVersion(t *testing.T) {
	addr := uint32(0x1D01)
	err := doIP.Send(addr, []byte{0x22, 0xDD, 0x02, 0x55, 0x33})
	assert.NoError(t, err)

	_, _, _, err = doIP.Receive()
	assert.Error(t, err)
	assert.EqualError(t, err, "#07 <DoIP: Header incorrect pattern format, close socket>")
}

func testLongDid(t *testing.T) {
	addr := uint32(0x1D01)
	err := doIP.Send(addr, []byte{0x22, 0xF1, 0xF2})
	assert.NoError(t, err)

	source, _, data, err := doIP.Receive()
	assert.NoError(t, err)
	assert.Equal(t, addr, source)
	assert.Equal(t, []byte{0x62, 0xf1, 0xf2, 0x49, 0x5f, 0x56, 0x45, 0x44, 0x5f, 0x58, 0x58, 0x5f, 0x58, 0x58, 0x5f, 0x31, 0x37, 0x46, 0x31, 0x31, 0x30, 0x5f, 0x31, 0x5f, 0x34, 0x30, 0x70, 0x72, 0x65, 0x34, 0x33, 0x75, 0x70, 0x64, 0x31, 0x5f, 0x35, 0x31, 0x37, 0x42, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x56, 0x34, 0x32, 0x36, 0x5f, 0x41, 0x55, 0x54, 0x5f, 0x41, 0x57, 0x44, 0x5f, 0x32, 0x33, 0x35, 0x68, 0x70, 0x5f, 0x45, 0x75, 0x36, 0x64, 0x2d, 0x74, 0x6d, 0x70, 0x5f, 0x48, 0x50, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x4d, 0x30, 0x31, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1}, data)
}

func testVeryLongDid(t *testing.T) {
	const length = 10000
	addr := uint32(0x1D01)
	err := doIP.Send(addr, []byte{0x22, 0x20, 0x01})
	assert.NoError(t, err)

	source, _, data, err := doIP.Receive()
	assert.NoError(t, err)
	assert.Equal(t, addr, source)
	// Length of data is 10000 minus length of header and address field
	assert.Equal(t, length-8-4, len(data))
	hash := sha1.Sum(data[:len(data)-20])
	assert.Equal(t, hash[:], data[len(data)-20:])
}

func testErrorDid(t *testing.T) {
	addr := uint32(0x1D01)
	err := doIP.Send(addr, []byte{0x22, 0xF8, 0x08})
	assert.NoError(t, err)

	source, _, data, err := doIP.Receive()
	assert.NoError(t, err)
	assert.Equal(t, addr, source)
	assert.Equal(t, []byte{0x7F, 0x22, 0x31}, data)
}

func testUnknownTargetAddress(t *testing.T) {
	addr := uint32(0x1000)
	err := doIP.Send(addr, []byte{0x22, 0xF8, 0x08})
	assert.NoError(t, err)

	source, _, data, err := doIP.Receive()
	assert.Error(t, err)
	assert.Equal(t, uint32(0x0), source)
	assert.Nil(t, data)
	assert.EqualError(t, err, "#09 <DoIP: Negative ACK response>")
}

func testUnknownPayloadType(t *testing.T) {
	addr := uint32(0x1D01)
	// sending to 0x8004 will get a response back for the diagnostic query but with the wrong 0x8004 payload type set
	err := doIP.Send(addr, []byte{0x22, 0xDD, 0x03})
	assert.NoError(t, err)

	_, _, _, err = doIP.Receive()
	assert.Error(t, err)
	assert.EqualError(t, err, "#01 <DoIP: Receive timeout>")
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
