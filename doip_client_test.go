package doip

import (
	"context"
	"log"
	"net"
	"os"
	"sync"
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
	mux.HandleFunc(routingActivationRequest, HandlerRoutingActiveReq)

	srv, _, err := RunLocalTCPServer("127.0.0.1:13400", mux)
	if err != nil {
		t.Fatalf("Error while starting the server %s", err)
	}
	defer srv.Shutdown()
	time.Sleep(1000 * time.Millisecond)

	t.Run("terminateFromDiagMaster", testTerminateFromDiagMaster)
	//t.Run("terminateFromDiagMasterJustBeforeSend", testTerminateFromDiagMasterJustBeforedoIPSend)
}

func HandlerRoutingActiveReq(w ResponseWriter, r Msg) {
	rr := r.(*MsgActivationReq)
	m := &MsgActivationRes{
		id:            routingActivationResponse,
		srcAddress:    rr.srcAddress,
		dstAddress:    localLogicalAddr,
		code:          routingSuccessfullyActivated,
		reserveForStd: []byte{0, 0, 0, 0},
		reserveForOEM: []byte{0, 0, 0, 0},
	}
	w.WriteMsg(m)
}

func testTerminateFromDiagMaster(t *testing.T) {
	doIP := NewDoIP(os.Stdout, 0x0E80, "127.0.0.1:13400")
	doIP.SetReadTimeout(200 * time.Millisecond)
	doIP.Connect()

	//err := doIP.Send(addr, []byte{0x22, 0x10, 0x10, 0x55, 0x33})
	err := doIP.Send(0x1D01, routingActivationRequest, []byte{0, 0, 0, 0, 0})
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
func RunLocalTCPServer(addr string, handler UDSHandler) (*Server, string, error) {
	server := &Server{
		Addr:    addr,
		Net:     "tcp",
		Handler: handler,
		log:     log.New(os.Stdout, "DoIP: ", log.Llongfile),
	}

	go func() {
		server.ListenAndServe()
	}()

	return server, addr, nil
}

type UDSMsg struct {
	src  uint16
	dst  uint16
	data []byte
}

// Simple doiptest, only dedicated service for only one user
type doiptest struct {
	mux     sync.RWMutex
	inChan  chan *UDSMsg
	outChan chan *MsgDiagMsgInd
	log     *log.Logger
}

func NewDoIPTest() *doiptest {
	c := &doiptest{
		inChan:  make(chan *UDSMsg, 1),
		outChan: make(chan *MsgDiagMsgInd, 1),
		log:     log.New(os.Stdout, "doiptest: ", log.Llongfile),
	}
	c.start()
	return c
}

func (srv *doiptest) start() {
	log.Printf("Start DoIPTest")
	go srv.process()
}

func (srv *doiptest) close() {
	log.Printf("Stop DoIPTest")
	close(srv.inChan)
}

func (srv *doiptest) process() {
	for m := range srv.inChan {
		sent := &MsgDiagMsgInd{
			id:         diagnosticMessage,
			srcAddress: m.src,
			dstAddress: m.dst,
			userdata:   m.data,
		}
		srv.outChan <- sent
	}
}

func (srv *doiptest) genOutChan(ctx context.Context, a net.Addr) <-chan *MsgDiagMsgInd {
	return srv.outChan
}

func (srv *doiptest) feedin(src uint16, dst uint16, data []byte) {
	m := &UDSMsg{
		src:  src,
		dst:  dst,
		data: data,
	}
	srv.inChan <- m
}

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
