package uds_test

import (
	"crypto/rand"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/eshenhu/doip/doip"
	"github.com/eshenhu/doip/uds"
	"github.com/stretchr/testify/assert"
)

var arrayForTest []byte

type logger struct {
	log0 *log.Logger
}

func init() {
	arrayForTest = make([]byte, 10000)
	rand.Read(arrayForTest)
}

func HandlerRoutingActiveReq(w doip.ResponseWriter, r doip.Msg) {
	rr := r.(*doip.MsgActivationReq)
	m := &doip.MsgActivationRes{
		Id:            doip.RoutingActivationResponse,
		SrcAddress:    rr.SrcAddress,
		DstAddress:    0x1000,
		Code:          doip.RoutingSuccessfullyActivated,
		ReserveForStd: []byte{0, 0, 0, 0},
		ReserveForOEM: []byte{0, 0, 0, 0},
	}
	w.WriteMsg(m)
}

func HandlerDiagMsgReq(w doip.ResponseWriter, r doip.Msg) {
	rr := r.(*doip.MsgDiagMsgReq)
	m := &doip.MsgDiagMsgRes{
		Id:         doip.DiagnosticMessagePositiveAcknowledge,
		SrcAddress: rr.DstAddress,
		DstAddress: rr.SrcAddress,
		AckCode:    0,
		Userdata:   rr.Userdata,
	}
	w.WriteMsg(m)
}
func TestDoIPUDS(t *testing.T) {
	//log := ioutil.Discard
	log := NewLogger()

	c := uds.NewNotifyHdl(log)

	mux := doip.NewServeMuxWithNotifyChan(c)
	mux.HandleFunc(doip.RoutingActivationRequest, HandlerRoutingActiveReq)

	s, _, err := doip.RunLocalTCPServer("127.0.0.1:0", mux, log)
	if err != nil {
		t.Fatalf("TestServer: Could not start DoIP server " + err.Error())
		return
	}
	defer s.Shutdown()
	time.Sleep(10 * time.Millisecond)

	addr := s.Listener.Addr().(*net.TCPAddr)
	doIP := doip.NewDoIP(log, 0x0E80, fmt.Sprintf("127.0.0.1:%d", addr.Port))

	doIP.SetReadTimeout(30 * time.Millisecond)
	err = doIP.Connect()
	if err != nil {
		t.Fatalf("SIM: Could not create DoIP session " + err.Error())
		return
	}
	defer doIP.Disconnect()

	udsDoIP := uds.NewUDSWithPendingCount(log, doIP, 1)

	mux.HandleFunc(doip.DiagnosticMessage, func(w doip.ResponseWriter, r doip.Msg) {
		rr := r.(*doip.MsgDiagMsgReq)
		rr.Userdata = append(rr.Userdata, 0x00, 0x21, 0x07)
		rr.Userdata[0] = 0x62

		m := &doip.MsgDiagMsgRes{
			Id:         doip.DiagnosticMessagePositiveAcknowledge,
			SrcAddress: rr.DstAddress,
			DstAddress: rr.SrcAddress,
			AckCode:    0,
			Userdata:   rr.Userdata,
		}
		w.WriteMsg(m)
	})
	t.Run("DoIpShortDid", func(t *testing.T) {
		testDoIPShortDid(t, udsDoIP)
	})

	mux.HandleFunc(doip.DiagnosticMessage, func(w doip.ResponseWriter, r doip.Msg) {
		rr := r.(*doip.MsgDiagMsgReq)
		rr.Userdata = append(rr.Userdata, arrayForTest...)
		rr.Userdata[0] = 0x62

		m := &doip.MsgDiagMsgRes{
			Id:         doip.DiagnosticMessagePositiveAcknowledge,
			SrcAddress: rr.DstAddress,
			DstAddress: rr.SrcAddress,
			AckCode:    0,
			Userdata:   rr.Userdata,
		}
		w.WriteMsg(m)
	})
	t.Run("DoIpLongDid", func(t *testing.T) {
		testDoIPLongDid(t, udsDoIP)
	})
}

func TestDoIPUDSWithMultiClient(t *testing.T) {
	//log := ioutil.Discard
	log := NewLogger()

	c := uds.NewNotifyHdl(log)

	mux := doip.NewServeMuxWithNotifyChan(c)
	mux.HandleFunc(doip.RoutingActivationRequest, HandlerRoutingActiveReq)
	mux.HandleFunc(doip.DiagnosticMessage, func(w doip.ResponseWriter, r doip.Msg) {
		rr := r.(*doip.MsgDiagMsgReq)
		rr.Userdata = append(rr.Userdata, 0x00, 0x21, 0x07)
		rr.Userdata[0] = 0x62

		m := &doip.MsgDiagMsgRes{
			Id:         doip.DiagnosticMessagePositiveAcknowledge,
			SrcAddress: rr.DstAddress,
			DstAddress: rr.SrcAddress,
			AckCode:    0,
			Userdata:   rr.Userdata,
		}
		w.WriteMsg(m)
	})

	s, _, err := doip.RunLocalTCPServer("127.0.0.1:0", mux, log)
	if err != nil {
		t.Fatalf("TestServer: Could not start DoIP server " + err.Error())
		return
	}
	defer s.Shutdown()
	addr := s.Listener.Addr().(*net.TCPAddr)
	time.Sleep(10 * time.Millisecond)

	runWithTest := func() {
		doIP := doip.NewDoIP(log, 0x0E80, fmt.Sprintf("127.0.0.1:%d", addr.Port))
		doIP.SetReadTimeout(30 * time.Millisecond)
		err0 := doIP.Connect()
		if err0 != nil {
			t.Fatalf("SIM: Could not create DoIP session " + err.Error())
			return
		}
		defer doIP.Disconnect()

		for i := 0; i < 10; i++ {
			udsDoIP := uds.NewUDSWithPendingCount(log, doIP, 1)
			t.Run("DoIpShortDid", func(t *testing.T) {
				testDoIPShortDid(t, udsDoIP)
			})
			time.Sleep(10 * time.Millisecond)
		}
	}

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(n int) {
			t.Logf("Starting client[%v] now...", n)
			defer t.Logf("Ending client[%v] now...", n)

			runWithTest()
			wg.Done()
		}(i)
	}
	wg.Wait()

	t.Log("TestWithMultiClient Finished")
}

func testDoIPShortDid(t *testing.T, udsDoIP uds.UDS) {
	//query, resp, err := udsDoIP.UdsReadDID(0x1D01, 0xDD01)
	req, rep, err := udsDoIP.UdsReadDID(0x1D01, 0xDD01)
	assert.NoError(t, err)
	assert.Equal(t, []byte{0x22, 0xDD, 0x01}, req)
	assert.Equal(t, []byte{0x62, 0xDD, 0x01, 0x00, 0x21, 0x07}, rep)
}

func testDoIPLongDid(t *testing.T, udsDoIP uds.UDS) {
	req, rep, err := udsDoIP.UdsReadDID(0x1D01, 0xF1F2)
	assert.NoError(t, err)
	assert.Equal(t, []byte{0x22, 0xF1, 0xF2}, req)

	expect := []byte{0x62, 0xF1, 0xF2}
	expect = append(expect, arrayForTest...)
	assert.Equal(t, expect, rep)
}

func testDoIPErrorDid(t *testing.T, udsDoIP uds.UDS) {
	req, rep, err := udsDoIP.UdsReadDID(0x1D01, 0xF808)
	assert.NoError(t, err)
	assert.Equal(t, []byte{0x22, 0xF8, 0x08}, req)
	assert.Equal(t, []byte{0x7F, 0x22, 0x31}, rep)
}

func (l *logger) Debug(v ...interface{}) {
	l.log0.Println(v...)
}

func (l *logger) Debugf(format string, v ...interface{}) {
	l.log0.Printf(format, v...)
}

func (l *logger) Info(v ...interface{}) {
	l.log0.Println(v...)
}

func (l *logger) Infof(format string, v ...interface{}) {
	l.log0.Printf(format, v...)
}

func NewLogger() uds.Logger {
	return &logger{
		log0: log.New(ioutil.Discard, "INFO: ", log.Lshortfile),
	}
}
