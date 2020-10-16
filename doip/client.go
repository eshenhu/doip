package doip

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

const (
	testerPresent = 0x3
	aliveTimeout  = 1 * time.Second
	readTimeout   = 5 * time.Second
	interval      = 100 * time.Millisecond
)

// DoIP struct : internal represation on L3
type DoIP struct {
	log         Logger
	source      uint16
	server      string
	readTimeout time.Duration
	mtx         sync.Mutex
	inChan      chan *doIPMessage
	errChan     chan error
	running     chan struct{}
	connection  net.Conn
}

type doIPMessage struct {
	source uint16
	target uint16
	data   []byte
}

type doIPError int

const (
	noError                         doIPError = 0
	timeout                         doIPError = 1
	unmatchedSrcAddr                doIPError = 2
	incorrectPatternFormat          doIPError = 7
	invalidPayloadLength            doIPError = 8
	negativeAck                     doIPError = 9
	positiveAck                     doIPError = 10
	routingActivationResponseFailed doIPError = 11
	sessionDisconnected             doIPError = 12
	unknownPayloadType              doIPError = 13
	unknownError                    doIPError = 14
)

func (d doIPError) Error() string {
	switch d {
	case timeout:
		return fmt.Sprintf("#%02d <DoIP: Receive timeout>", d)
	case unmatchedSrcAddr:
		return fmt.Sprintf("#%02d <DoIP: Unmatched src address>", d)
	case incorrectPatternFormat:
		return fmt.Sprintf("#%02d <DoIP: Header incorrect pattern format, close socket>", d)
	case invalidPayloadLength:
		return fmt.Sprintf("#%02d <DoIP: Invalid payload length, close socket>", d)
	case negativeAck:
		return fmt.Sprintf("#%02d <DoIP: Negative ACK response>", d)
	case routingActivationResponseFailed:
		return fmt.Sprintf("#%02d <DoIP: Routing activation failed>", d)
	case sessionDisconnected:
		return fmt.Sprintf("#%02d <DoIP: Session disconnected>", d)
	case unknownPayloadType:
		return fmt.Sprintf("#%02d <DoIP: Unknown payload type>", d)
	default:
		return fmt.Sprintf("#%02d <DoIP: Unknown error>", unknownError)
	}
}

func (d doIPError) IsTimeout() bool {
	return d == timeout
}

func (d doIPError) IsDisconnected() bool {
	return d == sessionDisconnected
}

// NewDoIP : creates a new DoIP instance
// Initiates the Ip socket client
// Initiates the inputLoop routine to receive messages from the socket and
// the periodicTesterPresent routine for periodic requests to indicate that the client is still connected
// Returns the doip object and any error encountered.
func NewDoIP(logger Logger, sourceAddress uint16, server string) *DoIP {
	d := &DoIP{
		source:      sourceAddress,
		readTimeout: readTimeout,
		server:      server,
	}

	d.log = logger
	return d
}

// SetReadTimeout set a custom read timeout
func (d *DoIP) SetReadTimeout(timeout time.Duration) {
	d.readTimeout = timeout
}

// Connect : connect to the server and prepare to send/receive
// Initiates the inputLoop routine to receive messages from the socket and
// the periodicTesterPresent routine for periodic requests to indicate that the client is still connected
func (d *DoIP) Connect() (err error) {
	conn, err := net.DialTimeout("tcp", d.server, 10*time.Second)
	if err != nil {
		d.log.Debug("Dial failed")
		return
	}

	d.connection = conn

	d.inChan = make(chan *doIPMessage, 1)
	d.errChan = make(chan error, 1)
	d.running = make(chan struct{})

	// pass connection to inputLoop to avoid a race with Disconnect and try to access a nil pointer on the DoIP struct
	go d.inputLoop(conn)

	err = d.activationHandshake()
	if err != nil {
		d.log.Debugf("Activation handshake failed %v\n", err.Error())
		// we have to call disconnect here in order to close the connection and stop the input loop
		d.Disconnect()
		return
	}

	//go d.aliveCheckPeriodical()
	return
}

// Disconnect : closes the connection to the server
func (d *DoIP) Disconnect() {
	d.log.Debugf("Disconnect... ")
	d.mtx.Lock()
	defer d.mtx.Unlock()
	if d.connection == nil {
		return
	}
	close(d.running)
	err := d.connection.Close()
	if err != nil {
		d.log.Debugf("Failed to close the socket (%v)", err)
	}
	d.connection = nil
	return
}

// Exchange : sync way to send and rcv roundtrip message to the DoIP entity.
func (d *DoIP) Exchange(targetAddr uint16, writeData []byte) (readData []byte, err error) {
	if err := d.SendRaw(targetAddr, DiagnosticMessage, writeData); err != nil {
		return nil, err
	}
	_, _, readData, err = d.Receive()
	return readData, err
}

//SendMsg Message
func (d *DoIP) SendMsg(m MsgReq) error {
	data := m.Pack()
	ll := len(data)

	var buffer = make([]byte, 8+ll)

	buffer[0] = protocolVersion
	buffer[1] = inverseProtocolVersion
	binary.BigEndian.PutUint16(buffer[2:4], (uint16)(m.GetID()))

	switch m.GetID() {
	case AliveCheckRequest:
		binary.BigEndian.PutUint32(buffer[4:8], 0)
	default:
		binary.BigEndian.PutUint32(buffer[4:8], uint32(ll))
		copy(buffer[8:], data)
	}

	d.mtx.Lock()
	defer d.mtx.Unlock()
	if d.connection == nil {
		d.log.Debugf("Attempt to send when not connected")
		return sessionDisconnected
	}
	// TODO: Should we check the number of bytes and try again if less then expected?
	_, err := d.connection.Write(buffer)
	return err
}

// Send :
func (d *DoIP) Send(TargetAddress uint16, data []byte) error {
	return d.SendRaw(TargetAddress, DiagnosticMessage, data)
}

// SendRaw : Send only method
func (d *DoIP) SendRaw(TargetAddress uint16, payloadType MsgTid, data []byte) error {
	var size int
	switch payloadType {
	case AliveCheckRequest:
		size = 8
	case RoutingActivationRequest:
		size = 10
	default:
		size = 12
	}

	var buffer = make([]byte, size+len(data))

	buffer[0] = protocolVersion
	buffer[1] = inverseProtocolVersion
	binary.BigEndian.PutUint16(buffer[2:4], (uint16)(payloadType))

	switch payloadType {
	case AliveCheckRequest:
	case RoutingActivationRequest:
		binary.BigEndian.PutUint32(buffer[4:8], uint32(len(data))+2)
		binary.BigEndian.PutUint16(buffer[8:10], uint16(d.source))
		copy(buffer[10:], data)
	case DiagnosticMessage:
		binary.BigEndian.PutUint32(buffer[4:8], uint32(len(data))+4)
		binary.BigEndian.PutUint16(buffer[8:10], uint16(d.source))
		binary.BigEndian.PutUint16(buffer[10:12], uint16(TargetAddress))
		copy(buffer[12:], data)
	default:
		return unknownPayloadType
	}

	d.mtx.Lock()
	defer d.mtx.Unlock()
	if d.connection == nil {
		d.log.Debugf("DoIP: Attempt to send when not connected")
		return sessionDisconnected
	}
	// TODO: Should we check the number of bytes and try again if less then expected?
	_, err := d.connection.Write(buffer)
	return err
}

// Receive : get messages received. Set an error if a timeout or an error message has been received
func (d *DoIP) Receive() (source uint16, target uint16, data []byte, err error) {
	var ok bool
	select {
	case message, ok := <-d.inChan:
		if ok {
			source = message.source
			target = message.target
			data = message.data
			return
		}
		err = sessionDisconnected
		d.log.Debugf("%v", err)

	case err, ok = <-d.errChan:
		if !ok {
			err = sessionDisconnected
		}
		d.log.Debugf("%v", err)

	case <-time.After(d.readTimeout):
		err = timeout
		d.log.Debugf("%v", err)
	}
	return
}

// aliveCheckPeriodical : broadcasts the message to the server, every 1 second,
// to indicate that the client is still connected and that the diagnostic services are to remain active
// 7.1.7
func (d *DoIP) aliveCheckPeriodical() {
	d.log.Debugf("Starting alive routine (%s)\n", d.connection.LocalAddr().String())
	defer d.log.Debugf("Stopping alive routine (%s)\n", d.connection.LocalAddr().String())
	for {
		select {
		case <-time.After(aliveTimeout):
			err := d.SendRaw(0, AliveCheckRequest, nil)
			if err != nil {
				d.log.Debugf("TesterPresent send error %s", err)
			}
		case <-d.running:
			d.log.Debugf("Stop alive routine as closed(%s)\n", d.connection.LocalAddr().String())
			return
		}
	}
}

// See Table 22
func (d *DoIP) activationHandshake() (err error) {
	err = d.SendRaw(d.source, RoutingActivationRequest, []byte{0x00, 0x00, 0x00, 0x00, 0x00})
	if err != nil {
		return
	}

	_, _, data, err := d.Receive()
	if err != nil {
		return
	}
	// See Table 25
	if len(data) > 0 && data[0] != RoutingSuccessfullyActivated {
		err = routingActivationResponseFailed
	}
	return
}

func (d *DoIP) isStopped() bool {
	select {
	case _, ok := <-d.running:
		return !ok
	default:
		return false
	}
}

// inputLoop: waits for incoming data on the socket
// First, reads the header and extracts the package size
// Reads the package payload according to the size
// Drops message / sets errors as specified in the ISO or sends the message up
func (d *DoIP) inputLoop(connection net.Conn) {
	defer close(d.inChan)
	defer close(d.errChan)

	var header [8]byte
	for {
		// First receive and decode the header
		n, err := io.ReadFull(connection, header[:])
		if err != nil {
			if !d.isStopped() && err != io.EOF && err != io.ErrUnexpectedEOF {
				d.log.Debugf("DoIP: Failed to read from socket (recv: %v of %v, err: %v)", n, 8, err)
			}
			return
		}
		if header[0] != protocolVersion || header[1] != inverseProtocolVersion {
			d.log.Debugf("DoIP Protocol Error")
			d.errChan <- incorrectPatternFormat
			continue
		}

		payloadType := (MsgTid)(binary.BigEndian.Uint16(header[2:4]))
		//Extract the size of the payload from header
		dataSize := binary.BigEndian.Uint32(header[4:8])

		payload := make([]byte, dataSize)
		// Then receive the payload
		n, err = io.ReadFull(connection, payload)
		if err != nil {
			if !d.isStopped() && err != io.EOF && err != io.ErrUnexpectedEOF {
				d.log.Debugf("DoIP: Failed to read from socket (recv: %v of %v, err: %v)", n, dataSize, err)
			}
			return
		}

		sourceAddress, targetAddress := parseAddresses(payloadType, payload)

		switch {
		case payloadType == AliveCheckResponse:
			//Todo: Tracking on the activity of the client, terminate connection if Timeout
		case payloadType == GenericHeaderNegativeAcknowledge:
			d.log.Debug("DoIP: NACK - drop message")
			d.errChan <- unknownPayloadType

		case targetAddress != uint16(d.source):
			d.log.Debugf("DoIP: Unknown target address %v - drop message %v", targetAddress, payloadType)
			d.errChan <- unmatchedSrcAddr

		case payloadType == RoutingActivationResponse && dataSize != uint32(len(payload)):
			d.errChan <- invalidPayloadLength

		case payloadType == DiagnosticMessageNegativeAcknowledge:
			d.errChan <- negativeAck

		case payloadType == DiagnosticMessagePositiveAcknowledge:
			// This type carries tester present response and other messages that can be discarded
			d.inChan <- &doIPMessage{
				source: sourceAddress,
				target: targetAddress,
				data:   payload[5:],
			}

		case payloadType == DiagnosticMessage || payloadType == RoutingActivationResponse:
			d.inChan <- &doIPMessage{
				source: sourceAddress,
				target: targetAddress,
				data:   payload[4:],
			}
		default:
			d.log.Debugf("DoIP: Unknown payload type - drop message")
			d.errChan <- unknownPayloadType
		}
	}
}

func parseAddresses(payloadType MsgTid, payload []byte) (sourceAddress uint16, targetAddress uint16) {
	switch payloadType {
	case RoutingActivationResponse:
		targetAddress = binary.BigEndian.Uint16(payload[0:2])
		sourceAddress = binary.BigEndian.Uint16(payload[2:4])

	case GenericHeaderNegativeAcknowledge:

	case DiagnosticMessage:
		fallthrough
	case DiagnosticMessagePositiveAcknowledge:
		fallthrough
	case DiagnosticMessageNegativeAcknowledge:
		sourceAddress = binary.BigEndian.Uint16(payload[0:2])
		targetAddress = binary.BigEndian.Uint16(payload[2:4])
	case AliveCheckResponse:
		targetAddress = binary.BigEndian.Uint16(payload[0:2])
	}
	return
}
