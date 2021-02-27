package doip

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

const (
	doIPTimeout    = 5 * time.Second
	tcpIdleTimeout = 15 * time.Second
	maxMsgSize     = ^uint32(0)
)

var (
	errMsgTooShort         = errors.New("Message too short")
	errMsgProtocolMismatch = errors.New("Message protocol mismatch")
	errMsgSecurity         = errors.New("RoutingActivation Failed")
)

/*
// UDSHandler is implemented by any value that implements Handler and NewIndChan()
type UDSHandler interface {
	Handler
	//NewIndChan(context.Context, net.Addr) <-chan *MsgDiagMsgInd
}
*/

// Handler is implemented by any value that implements ServeDoIP.
type UDSHandler interface {
	ServeDoIP(w ResponseWriter, r Msg)
}

// A ResponseWriter interface is used by an DoIP handler to
// construct an DoIP response.
type ResponseWriter interface {
	// LocalAddr returns the net.Addr of the server
	LocalAddr() net.Addr
	// RemoteAddr returns the net.Addr of the client that sent the current request.
	RemoteAddr() net.Addr
	// WriteMsg writes a reply back to the client.
	WriteMsg(Msg) error
	// Write writes a raw buffer back to the client.
	Write([]byte) (int, error)
	// Close closes the connection.
	Close() error
	// Hijack lets the caller take over the connection.
	// After a call to Hijack(), the DoIP package will not do anything with the connection.
	Hijack()
}

type response struct {
	hijacked   bool     // connection has been hijacked by handler
	tcp        net.Conn // i/o connection if TCP was used
	remoteAddr net.Addr // address of the client
	writer     Writer   // writer to output the raw byte
}

type MsgHandler struct {
	HndRoutingActivationReqFunc func(w ResponseWriter, r Msg)
	HndAliveCheckRequestFunc    func(w ResponseWriter, r Msg)
	HndDiagnosticMessageFunc    func(w ResponseWriter, r Msg)
}

// ServeDoIP : dispatches the request to the handler whose
// pattern most closely matches the request message.
func (hnd *MsgHandler) ServeDoIP(w ResponseWriter, req Msg) {
	switch req.GetID() {
	case RoutingActivationRequest:
		hnd.HndRoutingActivationReqFunc(w, req)
	case AliveCheckRequest:
		hnd.HndAliveCheckRequestFunc(w, req)
	case DiagnosticMessage:
		hnd.HndDiagnosticMessageFunc(w, req)
	default:
		failedHandler(w, DoIPHdrErrUnknownPayloadType)
	}
}

// Writer writes raw DNS messages; each call to Write should send an entire message.
type Writer interface {
	io.Writer
}

// Reader reads raw DoIP messages; each call to ReadTCP should return an entire message.
type Reader interface {
	// ReadTCP reads a raw message from a TCP connection. Implementations may alter
	// connection properties, for example the read-deadline.
	ReadTCP(conn net.Conn, timeout time.Duration) ([]byte, MsgTid, error)
}

// defaultReader is an adapter for the Server struct that implements the Reader interface
// using the readTCP and readUDP func of the embedded Server.
type defaultReader struct {
	*Server
}

func (dr *defaultReader) ReadTCP(conn net.Conn, timeout time.Duration) ([]byte, MsgTid, error) {
	return dr.readTCP(conn, timeout)
}

type defaultWriter struct {
	s *Server
	w ResponseWriter
	c *net.Conn
}

func (dw *defaultWriter) Write(p []byte) (n int, err error) {
	dw.s.InterceptWrite(dw.c, p)
	return dw.w.Write(p)
}

// A Server defines parameters for running an DoIP server.
type Server struct {
	// Address to listen on, ":domain" if empty.
	Addr string
	// if "tcp" or "tcp-tls" (DoIP over TLS) it will invoke a TCP listener
	Net string
	// TCP Listener to use, this is to aid in systemd's socket activation.
	Listener net.Listener
	// TLS connection configuration
	TLSConfig *tls.Config
	// Handler to invoke, DoIP.DefaultServeMux if nil.
	Handler UDSHandler
	// Intercept method for validation.Only after getting RoutingActiveAck, then handle the next.
	InterceptRead  func(*net.Conn, Msg) error
	InterceptWrite func(*net.Conn, []byte)
	// The net.Conn.SetReadTimeout value for new connections, defaults to 2 * time.Second.
	ReadTimeout time.Duration
	// The net.Conn.SetWriteTimeout value for new connections, defaults to 2 * time.Second.
	WriteTimeout time.Duration
	// TCP idle timeout for multiple queries, if nil, defaults to 8 * time.Second (RFC 5966).
	IdleTimeout func() time.Duration
	// If NotifyStartedFunc is set it is called once the server has started listening.
	NotifyStartedFunc func()
	// Shutdown handling
	lock sync.RWMutex
	// Tracking on the living connections
	activeConn map[*net.Conn]userInfo
	//
	router *Router
	// Logging
	log Logger
}

// see the Table 39 for the definition of Logical Address
// 0 : reserved by ISO , here we use as an invalid value
type userInfo struct {
	address uint16
}

// ListenAndServe starts a nameserver on the configured address in *Server.
func (srv *Server) ListenAndServe() error {
	srv.lock.Lock()
	defer srv.lock.Unlock()
	addr := srv.Addr
	if addr == "" {
		addr = ":domain"
	}

	if srv.InterceptRead == nil {
		srv.InterceptRead = func(c *net.Conn, m Msg) error {
			switch m.GetID() {
			case RoutingActivationRequest, AliveCheckRequest:
				return nil
			default:
				srv.lock.Lock()
				v, ok := srv.activeConn[c]
				srv.lock.Unlock()
				if ok && v.address != 0 {
					return nil
				}
				return errMsgSecurity
			}
		}
	}

	if srv.InterceptWrite == nil {
		// Associate Logical Address of External tools with socket for checking
		// the SrcAddress is right or not.
		// []byte : 0    1    2    3
		//        :rev ~rev  payloadType
		srv.InterceptWrite = func(c *net.Conn, b []byte) {
			t := (MsgTid)(binary.BigEndian.Uint16(b[2:4]))
			//srv.log.Debugf("InterceptWrite %v", t)
			switch t {
			case RoutingActivationResponse:
				var externalAddr uint16
				// b[12] is the AckCode, 0 : ACK others: NACK
				if b[12] == RoutingSuccessfullyActivated {
					externalAddr = binary.BigEndian.Uint16(b[8:10])
				}
				srv.updateConn(c, userInfo{address: externalAddr})
			default:
			}
		}
	}

	switch srv.Net {
	case "tcp", "tcp4", "tcp6":
		a, err := net.ResolveTCPAddr(srv.Net, addr)
		if err != nil {
			return err
		}
		l, err := net.ListenTCP(srv.Net, a)
		if err != nil {
			return err
		}
		srv.Listener = l
		srv.lock.Unlock()

		addr := srv.Listener.Addr().(*net.TCPAddr)
		srv.log.Debugf("Started server at %s", addr)

		err = srv.serveTCP(l)
		srv.lock.Lock() // to satisfy the defer at the top
		return err
	case "tcp-tls", "tcp4-tls", "tcp6-tls":
		network := "tcp"
		if srv.Net == "tcp4-tls" {
			network = "tcp4"
		} else if srv.Net == "tcp6-tls" {
			network = "tcp6"
		}

		l, err := tls.Listen(network, addr, srv.TLSConfig)
		if err != nil {
			return err
		}
		srv.Listener = l
		srv.lock.Unlock()

		addr := srv.Listener.Addr().(*net.TCPAddr)
		srv.log.Debugf("Started server at %s", addr)

		err = srv.serveTCP(l)
		srv.lock.Lock() // to satisfy the defer at the top
		return err
	}
	return errors.New("bad network")
}

// Shutdown shuts down a server. After a call to Shutdown, ListenAndServe
// will return.
func (srv *Server) Shutdown() error {
	//srv.lock.Unlock()

	if srv.Listener != nil {
		srv.Listener.Close()
	}
	return nil
}

// IndChan return unidirection channel to the user for sending indication 
// message to the server.
func (srv *Server) IndChan() chan<- *MsgDiagMsgIndDst {
	return srv.router.ch
}

// getReadTimeout is a helper func to use system timeout if server did not intend to change it.
func (srv *Server) getReadTimeout() time.Duration {
	rtimeout := doIPTimeout
	if srv.ReadTimeout != 0 {
		rtimeout = srv.ReadTimeout
	}
	return rtimeout
}

// serveTCP starts a TCP listener for the server.
// Each request is handled in a separate goroutine.
func (srv *Server) serveTCP(l net.Listener) error {
	defer l.Close()

	if srv.NotifyStartedFunc != nil {
		srv.NotifyStartedFunc()
	}

	handler := srv.Handler
	if handler == nil {
		panic("handler is nil")
	}

	var err error
	var wg sync.WaitGroup
	for {
		rw, e := l.Accept()
		if e != nil {
			if neterr, ok := e.(net.Error); ok && neterr.Temporary() {
				continue
			}
			err = e
			break
		}
		//Setup a new context
		srv.log.Debugf("New connection on %s", rw.RemoteAddr().String())
		c, cancel, err := srv.router.Add(rw.RemoteAddr().String())
		if err != nil {
			srv.log.Debugf("Failed to add new into router with %s", err)
			continue
		}

		wg.Add(1)
		go srv.serve(&wg, handler, rw, c, cancel)
	}
	srv.closeConnects()
	wg.Wait()
	return err
}

// Serve two input source
// 	i)  IndChan() <-chan comes from the UDS layer
//	ii) net.Conn comes from network
func (srv *Server) serve(wg *sync.WaitGroup, h UDSHandler, t net.Conn, ch <-chan *MsgDiagMsgInd, cancel2 func()) {
	defer func() {
		wg.Done()
		cancel2()
	}()

	srv.trackConn(&t, true)
	defer srv.trackConn(&t, false)

	ctx, cancel := context.WithCancel(context.Background())
	w := &response{tcp: t, remoteAddr: t.RemoteAddr()}
	wr := &defaultWriter{s: srv, w: w, c: &t}
	w.writer = wr
	// new goroutine was created for receiving indication from UpperLayer (f.g UDS)
	errInd := make(chan error, 1)
	go func() {
		srv.log.Debugf("Server new goroutine for recv indication (%s)\n", w.RemoteAddr().String())
	LL:
		for {
			select {
			case m, ok := <-ch:
				// Closed
				if !ok {
					srv.log.Debugf("UDS IndChan closed (%s), exiting...", w.RemoteAddr().String())
					errInd <- errors.New("UDS IndChan closed")
					break LL
				}
				err := w.WriteMsg(m)
				if err != nil {
					errInd <- err
					break LL
				}
			case <-ctx.Done():
				errInd <- ctx.Err()
				break LL
			}
		}
	}()

	idleTimeout := tcpIdleTimeout
	if srv.IdleTimeout != nil {
		idleTimeout = srv.IdleTimeout()
	}

	var (
		err error
	)
	reader := Reader(&defaultReader{srv})
	for {
		r, id, err := reader.ReadTCP(w.tcp, idleTimeout)
		if err != nil {
			srv.log.Debugf("rcv error on ReadTcp %v\n", err.Error())
			goto Exit
		}
		m, e := Unpack(r, id)
		if e != nil { // Send a FormatError back
			srv.log.Debugf("rcv error on %v\n", e.Error())
			continue
		}
		// Security Check
		if srv.InterceptRead(&t, m) != nil {
			srv.log.Debugf("InterceptRead err")
			failedHandler(w, DoIPHdrErrSecurity)
			continue
		}
		h.ServeDoIP(w, m) // Writes back to the client
	}
	/*
		if w.hijacked {
			return // client calls Close()
		}
	*/
Exit:
	if err != nil {
		srv.log.Debugf("Exit server with %s\n", t.RemoteAddr().String())
	} else {
		srv.log.Debugf("Exit server peacefully with %s", t.RemoteAddr().String())
	}
	// close the net.Conn
	w.Close()
	// cancel the IndChan
	cancel()
	// wait for sync with ind goroutine.
	<-errInd
	return
}

func (srv *Server) readTCP(conn net.Conn, timeout time.Duration) ([]byte, MsgTid, error) {
	//conn.SetReadDeadline(time.Now().Add(timeout))
	conn.SetReadDeadline(time.Time{})
	l := make([]byte, 8)
	n, err := conn.Read(l)
	if err != nil || n != 8 {
		if err != nil {
			return nil, 0, err
		}
		return nil, 0, errMsgTooShort
	}

	if l[0] != protocolVersion || l[1] != inverseProtocolVersion {
		return nil, 0, errMsgProtocolMismatch
	}

	p := (MsgTid)(binary.BigEndian.Uint16(l[2:4]))
	dataSize := binary.BigEndian.Uint32(l[4:8])

	if dataSize == 0 {
		return []byte{}, p, nil
	}

	m := make([]byte, dataSize)
	// Then receive the payload
	n, err = conn.Read(m[:int(dataSize)])
	if err != nil {
		return nil, 0, err
	}
	if n == 0 {
		return nil, 0, errMsgTooShort
	}
	i := n
	for i < int(dataSize) {
		j, err := conn.Read(m[i:int(dataSize)])
		if err != nil {
			return nil, 0, err
		}
		i += j
	}
	n = i
	m = m[:n]
	return m, p, nil
}

// closeConnects
func (srv *Server) closeConnects() {
	srv.lock.Lock()
	defer srv.lock.Unlock()
	for c := range srv.activeConn {
		(*c).(*net.TCPConn).Close()
		delete(srv.activeConn, c)
	}
}

func (srv *Server) trackConn(c *net.Conn, add bool) {
	srv.lock.Lock()
	defer srv.lock.Unlock()
	if srv.activeConn == nil {
		srv.activeConn = make(map[*net.Conn]userInfo)
	}
	if add {
		srv.activeConn[c] = userInfo{address: 0}
	} else {
		delete(srv.activeConn, c)
	}
}

func (srv *Server) updateConn(c *net.Conn, t userInfo) {
	srv.lock.Lock()
	defer srv.lock.Unlock()
	//srv.log.Debugf("updateConn %v", t.address)
	srv.activeConn[c] = t
}

// WriteMsg implements the ResponseWriter.WriteMsg method.
func (w *response) WriteMsg(m Msg) (err error) {
	b, err := Pack(m, m.GetID())
	if err != nil {
		return err
	}
	b, err = w.PackMsg(b, m.GetID())
	if err != nil {
		return err
	}
	_, err = w.writer.Write(b)
	return err
}

// Write implements the ResponseWriter.Write method.
func (w *response) Write(m []byte) (int, error) {
	switch {
	case w.tcp != nil:
		// header
		length := len(m)

		sent := 0
		for sent < length {
			n, err := w.tcp.Write(m[sent:])
			if err != nil {
				return 0, fmt.Errorf("Send: Conn write error (%v)", err)
			}
			sent += n
		}
		return sent, nil
	}
	panic("not reached")
}

// PackMsg: Packet the UDS message with L2 information
func (w *response) PackMsg(b []byte, id MsgTid) ([]byte, error) {
	// header
	length := len(b)
	h := []byte{protocolVersion, inverseProtocolVersion,
		(byte)(id >> 8), (byte)(id & 0xff), 0x00, 0x00, 0x00, 0x00}
	binary.BigEndian.PutUint32(h[4:8], (uint32)(length))

	h = append(h, b...)
	return h, nil
}

// LocalAddr implements the ResponseWriter.LocalAddr method.
func (w *response) LocalAddr() net.Addr {
	return w.tcp.LocalAddr()
}

// RemoteAddr implements the ResponseWriter.RemoteAddr method.
func (w *response) RemoteAddr() net.Addr { return w.remoteAddr }

// Hijack implements the ResponseWriter.Hijack method.
func (w *response) Hijack() { w.hijacked = true }

// Close implements the ResponseWriter.Close method
func (w *response) Close() error {
	// Can't close the udp conn, as that is actually the listener.
	if w.tcp != nil {
		e := w.tcp.Close()
		w.tcp = nil
		return e
	}
	return nil
}

func failedHandler(w ResponseWriter, err byte) {
	m := &MsgNACKReq{
		id:      GenericHeaderNegativeAcknowledge,
		errCode: err,
	}
	w.WriteMsg(m)
}

//RunLocalTCPServer give a method to start and run a server.
func RunLocalTCPServer(addr string, handler UDSHandler, logger Logger) (*Server, string, error) {
	r := NewRouter(logger)
	defer r.Close()

	server := &Server{
		Addr:    addr,
		Net:     "tcp",
		Handler: handler,
		router: r,
		log:     logger,
	}

	var wg sync.WaitGroup
	wg.Add(1)

	server.NotifyStartedFunc = func() {
		wg.Done()
	}

	go func() {
		server.ListenAndServe()
	}()

	wg.Wait()
	return server, addr, nil
}

//RunLocalTLSServer give a method to start and run a server.
func RunLocalTLSServer(addr string, handler UDSHandler, cert tls.Certificate, logger Logger) (*Server, string, error) {
	config := tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	r := NewRouter(logger)
	defer r.Close()

	server := &Server{
		Addr:      addr,
		Net:       "tcp-tls",
		TLSConfig: &config,
		Handler:   handler,
		router:    r,
		log:       logger,
	}

	var wg sync.WaitGroup
	wg.Add(1)

	server.NotifyStartedFunc = func() {
		wg.Done()
	}

	go func() {
		server.ListenAndServe()
	}()

	wg.Wait()
	return server, addr, nil
}
