package doip

import (
	"crypto/rand"
	"fmt"
	_ "io/ioutil"
	"log"
	"net"
	_ "os"
	"runtime"
	"testing"
	"time"
	"sync"

	"github.com/stretchr/testify/assert"
)

// Table 39
const (
	localLogicalAddr uint16 = 0x1000
)

var (
	port int
)

// Server : DoIP server
type DoIPServer struct {
	log      *log.Logger
	address  string
	addr     net.TCPAddr
	listener net.Listener
}

func TestShutdownSrvDuringOngoingActiveClient(t *testing.T) {
	hnd := &MsgHandler{
		HndRoutingActivationReqFunc: handlerRoutingActiveReq,
		HndDiagnosticMessageFunc: handlerDiagMsgReq,
		HndAliveCheckRequestFunc: handleAliveCheckReq,
	}

	srv, _, err := RunLocalTCPServer("127.0.0.1:0", hnd, loge)
	if err != nil {
		t.Fatalf("Error while starting the server %s", err)
	}
	//t.Logf("number of goroutines (before client) is %v\n", runtime.NumGoroutine())
	addr := srv.Listener.Addr().(*net.TCPAddr)
	doIP := NewDoIP(loge, 0x0E80, fmt.Sprintf("127.0.0.1:%d", addr.Port))
	doIP.Connect()

	time.Sleep(1000 * time.Microsecond) //give some time to server
	srv.Shutdown()

	err = doIP.SendRaw(0x1D01, RoutingActivationRequest, []byte{0, 0, 0, 0, 0})
	assert.NoError(t, err)

	_, _, _, err = doIP.Receive()
	assert.Error(t, err)
	assert.EqualError(t, err, "#12 <DoIP: Session disconnected>")

	doIP.Disconnect()
}

func TestNormalRAReq(t *testing.T) {
	hnd := &MsgHandler{
		HndRoutingActivationReqFunc: handlerRoutingActiveReq,
		HndDiagnosticMessageFunc: handlerDiagMsgReq,
		HndAliveCheckRequestFunc: handleAliveCheckReq,
	}

	srv, _, err := RunLocalTCPServer("127.0.0.1:0", hnd, loge)
	if err != nil {
		t.Fatalf("Error while starting the server %s", err)
	}
	defer srv.Shutdown()
	port = srv.Listener.Addr().(*net.TCPAddr).Port

	doIP := NewDoIP(loge, 0x0E80, fmt.Sprintf("127.0.0.1:%d", port))
	defer doIP.Disconnect()

	doIP.SetReadTimeout(200 * time.Millisecond)
	doIP.Connect()

	//err := doIP.Send(0x1D01, RoutingActivationRequest, []byte{0, 0, 0, 0, 0})
	req := &MsgActivationReq{
		Id:             RoutingActivationRequest,
		SrcAddress:     0x0E80,
		ActivationType: 0,
		ReserveForStd:  []byte{0, 0, 0, 0},
		ReserveForOEM:  []byte{},
	}

	err = doIP.SendMsg(req)
	assert.NoError(t, err)

	_, _, _, err = doIP.Receive()
	assert.NoError(t, err)
}

func TestAbnormalRoutingActReq(t *testing.T) {
	hnd := &MsgHandler{
		HndRoutingActivationReqFunc: handlerRoutingActiveReq,
		HndDiagnosticMessageFunc: handlerDiagMsgReq,
		HndAliveCheckRequestFunc: handleAliveCheckReq,
	}

	srv, _, err := RunLocalTCPServer("127.0.0.1:0", hnd, loge)
	if err != nil {
		t.Fatalf("Error while starting the server %s", err)
	}
	defer srv.Shutdown()
	port = srv.Listener.Addr().(*net.TCPAddr).Port

	doIP := NewDoIP(loge, 0x0E80, fmt.Sprintf("127.0.0.1:%d", port))
	defer doIP.Disconnect()

	doIP.SetReadTimeout(200 * time.Millisecond)
	doIP.Connect()

	// bad format on payload
	err = doIP.SendRaw(0x1D01, RoutingActivationRequest, []byte{0})
	assert.NoError(t, err)

	_, _, _, err = doIP.Receive()
	assert.Error(t, err)
	assert.EqualError(t, err, "#01 <DoIP: Receive timeout>")
}

// Per connection will consume 2 goroutines in client, 2 goroutines in server
// Then, it was expected to increase with 4 * connection goroutines
// 1. Making 100 client connections,
// 2. Send a RA message
// 3. Close 100 clients, check the number of goroutines
func testCheckGoroutineResource(t *testing.T) {
	numOfGoroutines := runtime.NumGoroutine()
	//t.Logf("number of goroutines (in entry) are %v\n", runtime.NumGoroutine())
	const n int = 10
	var clients [n]*Client

	//Stage 1
	for i := 0; i < n; i++ {
		clients[i] = NewDoIP(loge, 0x0E80+(uint16)(i), fmt.Sprintf("127.0.0.1:%d", port))
		clients[i].SetReadTimeout(2000 * time.Millisecond)
		err := clients[i].Connect()
		assert.NoError(t, err)
	}
	time.Sleep(5000 * time.Millisecond)
	//t.Logf("number of goroutines (after connect) are %v\n", runtime.NumGoroutine())

	//Stage 2
	for i := 0; i < n; i++ {
		req := &MsgActivationReq{
			Id:             RoutingActivationRequest,
			SrcAddress:     0x0E80 + (uint16)(i),
			ActivationType: 0,
			ReserveForStd:  []byte{0, 0, 0, 0},
			ReserveForOEM:  []byte{},
		}

		err := clients[i].SendMsg(req)
		assert.NoError(t, err)
		_, _, _, err = clients[i].Receive()
		assert.NoError(t, err)
		time.Sleep(200 * time.Millisecond)
	}
	//t.Logf("number of goroutines (after send) are %v\n", runtime.NumGoroutine())
	time.Sleep(5 * time.Second)

	//Stage 3
	for i := 0; i < n; i++ {
		clients[i].Disconnect()
	}
	time.Sleep(10 * time.Second)
	//t.Logf("number of goroutines (after disconnect) are %v\n", runtime.NumGoroutine())
	assert.LessOrEqual(t, runtime.NumGoroutine(), numOfGoroutines)
}

func TestDiagMessageReq(t *testing.T) {
	hnd := &MsgHandler{
		HndRoutingActivationReqFunc: handlerRoutingActiveReq,
		HndDiagnosticMessageFunc: handlerDiagMsgReq,
		HndAliveCheckRequestFunc: handleAliveCheckReq,
	}

	srv, _, err := RunLocalTCPServer("127.0.0.1:0", hnd, loge)
	if err != nil {
		t.Fatalf("Error while starting the server %s", err)
	}
	defer srv.Shutdown()
	port = srv.Listener.Addr().(*net.TCPAddr).Port

	doIP := NewDoIP(loge, 0x0E80, fmt.Sprintf("127.0.0.1:%d", port))
	defer doIP.Disconnect()
	doIP.Connect()

	token := make([]byte, 1200*10)
	rand.Read(token)
	// bad format on payload
	err = doIP.SendRaw(0x1D01, DiagnosticMessage, token)
	assert.NoError(t, err)

	_, _, tokenR, err := doIP.Receive()
	assert.NoError(t, err)
	assert.Equal(t, tokenR, token)
}

func TestNormalDiagMessageReq(t *testing.T) {
	hnd := &MsgHandler{
		HndRoutingActivationReqFunc: handlerRoutingActiveReq,
		HndDiagnosticMessageFunc: handlerDiagMsgReq,
		HndAliveCheckRequestFunc: handleAliveCheckReq,
	}

	srv, _, err := RunLocalTCPServer("127.0.0.1:0", hnd, loge)
	if err != nil {
		t.Fatalf("Error while starting the server %s", err)
	}
	defer srv.Shutdown()
	time.Sleep(1000 * time.Millisecond)

	addr := srv.Listener.Addr().(*net.TCPAddr)
	doIP := NewDoIP(loge, 0x0E80, fmt.Sprintf("127.0.0.1:%d", addr.Port))
	doIP.Connect()
	defer doIP.Disconnect()

	token := make([]byte, 12)
	rand.Read(token)

	// bad format on payload
	err = doIP.SendRaw(0x1D01, DiagnosticMessage, token)
	assert.NoError(t, err)

	_, _, tokenR1, err := doIP.Receive()
	assert.NoError(t, err)
	assert.Equal(t, tokenR1, token)

	tokenR2, err := doIP.Exchange(0x1D01, token)
	assert.NoError(t, err)
	assert.Equal(t, tokenR2, token)
}


func TestNormalDiagMessageReqWithMoreClient(t *testing.T) {
	hnd := &MsgHandler{
		HndRoutingActivationReqFunc: handlerRoutingActiveReq,
		HndDiagnosticMessageFunc: handlerDiagMsgReq,
		HndAliveCheckRequestFunc: handleAliveCheckReq,
	}

	srv, _, err := RunLocalTCPServer("127.0.0.1:0", hnd, loge)
	if err != nil {
		t.Fatalf("Error while starting the server %s", err)
	}
	defer srv.Shutdown()
	time.Sleep(1000 * time.Millisecond)

	addr := srv.Listener.Addr().(*net.TCPAddr)

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int){
			defer wg.Done()

			var srcAddr uint16 = 0x0E80
			srcAddr += 1

			doIP := NewDoIP(loge, srcAddr, fmt.Sprintf("127.0.0.1:%d", addr.Port))
			doIP.Connect()
			defer doIP.Disconnect()

			token := make([]byte, 12)
			rand.Read(token)

			// bad format on payload
			err := doIP.SendRaw(0x1D01, DiagnosticMessage, token)
			assert.NoError(t, err)

			_, _, tokenR1, err := doIP.Receive()
			assert.NoError(t, err)
			assert.Equal(t, tokenR1, token)

			tokenR2, err := doIP.Exchange(0x1D01, token)
			assert.NoError(t, err)
			assert.Equal(t, tokenR2, token)		

			sndChan := srv.IndChan()
			addr := doIP.connection.LocalAddr().String()
			sndChan <- &MsgDiagMsgIndDst{
				Addr : addr,
				MsgDiagMsgInd : MsgDiagMsgInd{
					Id: DiagnosticMessage,
					SrcAddress: 0x1D01,
					DstAddress: srcAddr,
					Userdata: token,
				},
			}
			_, _, tokenR3, err := doIP.Receive()
			assert.NoError(t, err)
			assert.Equal(t, tokenR3, token)

			addr = doIP.connection.LocalAddr().String()
			sndChan <- &MsgDiagMsgIndDst{
				Addr : addr,
				MsgDiagMsgInd : MsgDiagMsgInd{
					Id: DiagnosticMessage,
					SrcAddress: 0x1D01,
					DstAddress: srcAddr,
					Userdata: token,
				},
			}
			_, _, tokenR4, err := doIP.Receive()
			assert.NoError(t, err)
			assert.Equal(t, tokenR4, token)
		}(i)
	}
	wg.Wait()
}

func TestAbnormalDiagMessageReq(t *testing.T) {
	hnd := &MsgHandler{
		HndRoutingActivationReqFunc: handlerRoutingActiveNAckReq,
		HndDiagnosticMessageFunc: handlerDiagMsgReq,
		HndAliveCheckRequestFunc: handleAliveCheckReq,
	}

	srv, _, err := RunLocalTCPServer("127.0.0.1:0", hnd, loge)
	if err != nil {
		t.Fatalf("Error while starting the server %s", err)
	}
	defer srv.Shutdown()
	time.Sleep(1000 * time.Millisecond)

	addr := srv.Listener.Addr().(*net.TCPAddr)
	doIP := NewDoIP(loge, 0x0E80, fmt.Sprintf("127.0.0.1:%d", addr.Port))
	defer doIP.Disconnect()
	err = doIP.Connect()
	assert.Error(t, err)
	assert.EqualError(t, err, "#11 <DoIP: Routing activation failed>")
}

func TestNormalDiagMessageInd(t *testing.T) {
	hnd := &MsgHandler{
		HndRoutingActivationReqFunc: handlerRoutingActiveReq,
		HndDiagnosticMessageFunc: handlerDiagMsgReq,
		HndAliveCheckRequestFunc: handleAliveCheckReq,
	}

	srv, _, err := RunLocalTCPServer("127.0.0.1:0", hnd, loge)
	if err != nil {
		t.Fatalf("Error while starting the server %s", err)
	}
	defer srv.Shutdown()
	time.Sleep(5000 * time.Millisecond)

	sndChan := srv.IndChan()
	addrTCP := srv.Listener.Addr().(*net.TCPAddr)

	doIP := NewDoIP(loge, 0x0E80, fmt.Sprintf("127.0.0.1:%d", addrTCP.Port))
	doIP.Connect()
	defer doIP.Disconnect()

	token := make([]byte, 12)
	rand.Read(token)

	var tokenR []byte
	tokenR, err = doIP.Exchange(0x1D01, token)
	assert.NoError(t, err)
	assert.Equal(t, tokenR, token)

	addr := doIP.connection.LocalAddr().String()
	sndChan <- &MsgDiagMsgIndDst{
		Addr : addr,
		MsgDiagMsgInd : MsgDiagMsgInd{
			Id: DiagnosticMessage,
			SrcAddress: 0x1D01,
			DstAddress: 0x0E80,
			Userdata: token,
		},
	}

	_, _, tokenR, err = doIP.Receive()
	t.Logf("recv here")
	assert.NoError(t, err)
	assert.Equal(t, tokenR, token)

	sndChan <- &MsgDiagMsgIndDst{
		Addr : addr,
		MsgDiagMsgInd : MsgDiagMsgInd{
			Id: DiagnosticMessage,
			SrcAddress: 0x1D01,
			DstAddress: 0x0E81,
			Userdata: token,
		},
	}
	t.Logf("recv here 2")

	_, _, tokenR, err = doIP.Receive()
	assert.Error(t, err)
	assert.EqualError(t, err, "#02 <DoIP: Unmatched src address>")
}

func runWithConnection(doIP *Client, f func(t *testing.T)) func(t *testing.T) {
	return func(t *testing.T) {
		err := doIP.Connect()
		if err != nil {
			t.Fatalf("Could not create DoIP session %v", err)
		}
		f(t)
		doIP.Disconnect()
	}
}
