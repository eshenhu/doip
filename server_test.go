package doip

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"io"
	"log"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func RunLocalTCPServer(addr string, handler UDSHandler, loge io.Writer) (*Server, string, error) {
	server := &Server{
		Addr:    addr,
		Net:     "tcp",
		Handler: handler,
		log:     log.New(loge, "DoIP: ", log.Llongfile|log.Lmicroseconds),
	}

	waitLock := sync.Mutex{}
	waitLock.Lock()
	server.NotifyStartedFunc = waitLock.Unlock

	go func() {
		server.ListenAndServe()
	}()

	waitLock.Lock()
	return server, addr, nil
}

func RunLocalTLSServer(addr string, handler UDSHandler, loge io.Writer) (*Server, string, error) {
	cert, err := tls.X509KeyPair(CertPEMBlock, KeyPEMBlock)
	if err != nil {
		return nil, "", err
	}

	config := tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	server := &Server{
		Addr:      addr,
		Net:       "tcp-tls",
		TLSConfig: &config,
		Handler:   handler,
		log:       log.New(loge, "DoIP Tls Srv: ", log.Llongfile|log.Lmicroseconds),
	}

	waitLock := sync.Mutex{}
	waitLock.Lock()
	server.NotifyStartedFunc = waitLock.Unlock

	go func() {
		server.ListenAndServe()
	}()

	waitLock.Lock()
	return server, addr, nil
}

func TestShutdownTCP(t *testing.T) {
	c := NewDoIPTest(loge)
	defer c.Close()

	mux := NewServeMux(c.genOutChan)
	mux.HandleFunc(routingActivationRequest, handlerRoutingActiveReq)
	mux.HandleFunc(diagnosticMessage, handlerDiagMsgReq)

	numOfGo := runtime.NumGoroutine()
	srv, _, err := RunLocalTCPServer(":0", mux, loge)
	if err != nil {
		t.Fatalf("Error while starting the server %s", err)
	}
	err = srv.Shutdown()
	if err != nil {
		t.Fatalf("could not shutdown test TCP server, %v", err)
	}
	time.Sleep(1 * time.Second)
	assert.LessOrEqual(t, runtime.NumGoroutine(), numOfGo)
}

func TestShutdownTLS(t *testing.T) {
	c := NewDoIPTest(loge)
	defer c.Close()

	mux := NewServeMux(c.genOutChan)
	mux.HandleFunc(routingActivationRequest, handlerRoutingActiveReq)

	s, _, err := RunLocalTLSServer(":0", mux, loge)
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	err = s.Shutdown()
	if err != nil {
		t.Errorf("could not shutdown test TLS server, %v", err)
	}
}

func TestServerStartStopRace(t *testing.T) {
	//t.Logf("number of goroutines (before client) is %v\n", runtime.NumGoroutine())
	numOfGo := runtime.NumGoroutine()
	for i := 0; i < 10; i++ {
		c := NewDoIPTest(loge)
		defer c.Close()

		mux := NewServeMux(c.genOutChan)
		mux.HandleFunc(routingActivationRequest, handlerRoutingActiveReq)

		srv, _, err := RunLocalTCPServer("127.0.0.1:0", mux, loge)
		if err != nil {
			t.Fatalf("Error while starting the server %s", err)
		}

		go func() {
			if err := srv.Shutdown(); err != nil {
				t.Fatalf("could not stop server: %s", err)
			}
		}()
	}
	time.Sleep(2 * time.Second)
	//t.Logf("number of goroutines (after client) is %v\n", runtime.NumGoroutine())
	assert.LessOrEqual(t, runtime.NumGoroutine(), numOfGo)
}

func BenchmarkServe(b *testing.B) {
	b.StopTimer()
	a := runtime.GOMAXPROCS(4)

	s := NewDoIPTest(loge)
	defer s.Close()

	mux := NewServeMux(s.genOutChan)
	mux.HandleFunc(routingActivationRequest, handlerRoutingActiveReq)
	mux.HandleFunc(diagnosticMessage, handlerDiagMsgReq)

	srv, _, err := RunLocalTCPServer("127.0.0.1:13400", mux, loge)
	if err != nil {
		b.Fatalf("Error while starting the server %s", err)
	}
	defer srv.Shutdown()

	doIP := NewDoIP(loge, 0x0E80, "127.0.0.1:13400")
	defer doIP.Disconnect()
	doIP.Connect()

	token := make([]byte, 12*100)
	rand.Read(token)

	b.StartTimer()
	for i := 0; i < b.N; i++ {
		_, _ = doIP.Exchange(0x1D01, token)
	}
	runtime.GOMAXPROCS(a)
}

func handlerRoutingActiveReq(w ResponseWriter, r Msg) {
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

func handlerRoutingActiveNAckReq(w ResponseWriter, r Msg) {
	rr := r.(*MsgActivationReq)
	m := &MsgActivationRes{
		id:            routingActivationResponse,
		srcAddress:    rr.srcAddress,
		dstAddress:    localLogicalAddr,
		code:          routingDeniedUnsupportedType,
		reserveForStd: []byte{0, 0, 0, 0},
		reserveForOEM: []byte{0, 0, 0, 0},
	}
	w.WriteMsg(m)
}

func handlerDiagMsgReq(w ResponseWriter, r Msg) {
	rr := r.(*MsgDiagMsgReq)
	m := &MsgDiagMsgRes{
		id:         diagnosticMessagePositiveAcknowledge,
		srcAddress: rr.dstAddress,
		dstAddress: rr.srcAddress,
		ackCode:    0,
		userdata:   rr.userdata,
	}
	w.WriteMsg(m)
}

type UDSMsg struct {
	src  uint16
	dst  uint16
	data []byte
}

// Simple UDSSrvTest, only dedicated service for only one user
type UDSSrvTest struct {
	mux     sync.RWMutex
	isRun   chan struct{}
	inChan  map[string]chan *UDSMsg
	outChan map[string]chan *MsgDiagMsgInd
	log     *log.Logger
}

func NewDoIPTest(loge io.Writer) *UDSSrvTest {
	c := &UDSSrvTest{
		isRun:   make(chan struct{}),
		inChan:  make(map[string]chan *UDSMsg),
		outChan: make(map[string]chan *MsgDiagMsgInd),
		log:     log.New(loge, "UDSSrvTest: ", log.Llongfile|log.Lmicroseconds),
	}
	c.Start()
	return c
}

func (srv *UDSSrvTest) Start() {
	srv.log.Printf("Start UDSSrvTest")
}

func (srv *UDSSrvTest) Close() {
	srv.log.Printf("Stop UDSSrvTest")
	close(srv.isRun)
}

func (srv *UDSSrvTest) process(inChan <-chan *UDSMsg, outChan chan<- *MsgDiagMsgInd) {
	for m := range inChan {
		sent := &MsgDiagMsgInd{
			id:         diagnosticMessage,
			srcAddress: m.src,
			dstAddress: m.dst,
			userdata:   m.data,
		}
		outChan <- sent
	}
}

func (srv *UDSSrvTest) genOutChan(ctx context.Context, a net.Addr) <-chan *MsgDiagMsgInd {
	srv.mux.Lock()

	if srv.outChan[a.String()] != nil {
		srv.mux.Unlock()
		srv.log.Printf("(%v) Existed instance in UDSSrv, Perhaps terminating previous instance ongoing", a.String())
		return nil
	}

	inChan := make(chan *UDSMsg, 1)
	outChan := make(chan *MsgDiagMsgInd, 1)
	srv.inChan[a.String()] = inChan
	srv.outChan[a.String()] = outChan
	srv.mux.Unlock()

	go srv.process(inChan, outChan)
	go func() {
		srv.log.Printf("(%v) genOutChan...", a.String())
		defer func() {
			close(inChan)
			close(outChan)

			srv.mux.Lock()
			delete(srv.inChan, a.String())
			delete(srv.outChan, a.String())
			srv.mux.Unlock()
		}()

		select {
		case <-srv.isRun:
			srv.log.Printf("(%v) Close srv..\n", a.String())
		case <-ctx.Done():
			srv.log.Printf("(%v) Ctx rcv cancel event, exit...\n", a.String())
		}
	}()
	return outChan
}

func (srv *UDSSrvTest) feedin(addr string, src uint16, dst uint16, data []byte) {
	m := &UDSMsg{
		src:  src,
		dst:  dst,
		data: data,
	}
	srv.log.Printf("(%v) Feed in data\n", addr)

	srv.mux.RLock()
	inChan := srv.inChan[addr]
	srv.mux.RUnlock()

	inChan <- m
}

var (
	// CertPEMBlock is a X509 data used to test TLS servers (used with tls.X509KeyPair)
	CertPEMBlock = []byte(`-----BEGIN CERTIFICATE-----
MIIDAzCCAeugAwIBAgIRAJFYMkcn+b8dpU15wjf++GgwDQYJKoZIhvcNAQELBQAw
EjEQMA4GA1UEChMHQWNtZSBDbzAeFw0xNjAxMDgxMjAzNTNaFw0xNzAxMDcxMjAz
NTNaMBIxEDAOBgNVBAoTB0FjbWUgQ28wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
ggEKAoIBAQDXjqO6skvP03k58CNjQggd9G/mt+Wa+xRU+WXiKCCHttawM8x+slq5
yfsHCwxlwsGn79HmJqecNqgHb2GWBXAvVVokFDTcC1hUP4+gp2gu9Ny27UHTjlLm
O0l/xZ5MN8tfKyYlFw18tXu3fkaPyHj8v/D1RDkuo4ARdFvGSe8TqisbhLk2+9ow
xfIGbEM9Fdiw8qByC2+d+FfvzIKz3GfQVwn0VoRom8L6NBIANq1IGrB5JefZB6nv
DnfuxkBmY7F1513HKuEJ8KsLWWZWV9OPU4j4I4Rt+WJNlKjbD2srHxyrS2RDsr91
8nCkNoWVNO3sZq0XkWKecdc921vL4ginAgMBAAGjVDBSMA4GA1UdDwEB/wQEAwIC
pDATBgNVHSUEDDAKBggrBgEFBQcDATAPBgNVHRMBAf8EBTADAQH/MBoGA1UdEQQT
MBGCCWxvY2FsaG9zdIcEfwAAATANBgkqhkiG9w0BAQsFAAOCAQEAGcU3iyLBIVZj
aDzSvEDHUd1bnLBl1C58Xu/CyKlPqVU7mLfK0JcgEaYQTSX6fCJVNLbbCrcGLsPJ
fbjlBbyeLjTV413fxPVuona62pBFjqdtbli2Qe8FRH2KBdm41JUJGdo+SdsFu7nc
BFOcubdw6LLIXvsTvwndKcHWx1rMX709QU1Vn1GAIsbJV/DWI231Jyyb+lxAUx/C
8vce5uVxiKcGS+g6OjsN3D3TtiEQGSXLh013W6Wsih8td8yMCMZ3w8LQ38br1GUe
ahLIgUJ9l6HDguM17R7kGqxNvbElsMUHfTtXXP7UDQUiYXDakg8xDP6n9DCDhJ8Y
bSt7OLB7NQ==
-----END CERTIFICATE-----`)

	// KeyPEMBlock is a X509 data used to test TLS servers (used with tls.X509KeyPair)
	KeyPEMBlock = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEA146jurJLz9N5OfAjY0IIHfRv5rflmvsUVPll4iggh7bWsDPM
frJaucn7BwsMZcLBp+/R5iannDaoB29hlgVwL1VaJBQ03AtYVD+PoKdoLvTctu1B
045S5jtJf8WeTDfLXysmJRcNfLV7t35Gj8h4/L/w9UQ5LqOAEXRbxknvE6orG4S5
NvvaMMXyBmxDPRXYsPKgcgtvnfhX78yCs9xn0FcJ9FaEaJvC+jQSADatSBqweSXn
2Qep7w537sZAZmOxdeddxyrhCfCrC1lmVlfTj1OI+COEbfliTZSo2w9rKx8cq0tk
Q7K/dfJwpDaFlTTt7GatF5FinnHXPdtby+IIpwIDAQABAoIBAAJK4RDmPooqTJrC
JA41MJLo+5uvjwCT9QZmVKAQHzByUFw1YNJkITTiognUI0CdzqNzmH7jIFs39ZeG
proKusO2G6xQjrNcZ4cV2fgyb5g4QHStl0qhs94A+WojduiGm2IaumAgm6Mc5wDv
ld6HmknN3Mku/ZCyanVFEIjOVn2WB7ZQLTBs6ZYaebTJG2Xv6p9t2YJW7pPQ9Xce
s9ohAWohyM4X/OvfnfnLtQp2YLw/BxwehBsCR5SXM3ibTKpFNtxJC8hIfTuWtxZu
2ywrmXShYBRB1WgtZt5k04bY/HFncvvcHK3YfI1+w4URKtwdaQgPUQRbVwDwuyBn
flfkCJECgYEA/eWt01iEyE/lXkGn6V9lCocUU7lCU6yk5UT8VXVUc5If4KZKPfCk
p4zJDOqwn2eM673aWz/mG9mtvAvmnugaGjcaVCyXOp/D/GDmKSoYcvW5B/yjfkLy
dK6Yaa5LDRVYlYgyzcdCT5/9Qc626NzFwKCZNI4ncIU8g7ViATRxWJ8CgYEA2Ver
vZ0M606sfgC0H3NtwNBxmuJ+lIF5LNp/wDi07lDfxRR1rnZMX5dnxjcpDr/zvm8J
WtJJX3xMgqjtHuWKL3yKKony9J5ZPjichSbSbhrzfovgYIRZLxLLDy4MP9L3+CX/
yBXnqMWuSnFX+M5fVGxdDWiYF3V+wmeOv9JvavkCgYEAiXAPDFzaY+R78O3xiu7M
r0o3wqqCMPE/wav6O/hrYrQy9VSO08C0IM6g9pEEUwWmzuXSkZqhYWoQFb8Lc/GI
T7CMXAxXQLDDUpbRgG79FR3Wr3AewHZU8LyiXHKwxcBMV4WGmsXGK3wbh8fyU1NO
6NsGk+BvkQVOoK1LBAPzZ1kCgYEAsBSmD8U33T9s4dxiEYTrqyV0lH3g/SFz8ZHH
pAyNEPI2iC1ONhyjPWKlcWHpAokiyOqeUpVBWnmSZtzC1qAydsxYB6ShT+sl9BHb
RMix/QAauzBJhQhUVJ3OIys0Q1UBDmqCsjCE8SfOT4NKOUnA093C+YT+iyrmmktZ
zDCJkckCgYEAndqM5KXGk5xYo+MAA1paZcbTUXwaWwjLU+XSRSSoyBEi5xMtfvUb
7+a1OMhLwWbuz+pl64wFKrbSUyimMOYQpjVE/1vk/kb99pxbgol27hdKyTH1d+ov
kFsxKCqxAnBVGEWAvVZAiiTOxleQFjz5RnL0BQp9Lg2cQe+dvuUmIAA=
-----END RSA PRIVATE KEY-----`)
)
