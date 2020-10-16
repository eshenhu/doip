package uds

import (
	"bytes"
	"fmt"
	"time"
)

//The definition of these constants can be found in ISO 14229-1
// Request codes
const (
	udsDtcReq              uint8 = 0x19
	udsReadDIDReq          uint8 = 0x22
	udsReadMemByAddressReq uint8 = 0x23
)

// Response codes
const (
	udsReadDIDresp          uint8 = 0x62
	udsReadMemByAddressResp uint8 = 0x63
	udsDtcResp              uint8 = 0x59
	udsPosRespMask          uint8 = 0x40
	udsNegRespServID        uint8 = 0x7f
)

//Error codes
const (
	udsRespPending          uint8 = 0x78
	udsRequestOutOfRange    uint8 = 0x31
	udsServiceNotSupported  uint8 = 0x11
	udsConditionsNotCorrect uint8 = 0x22
)

// Subfunctions for udsDtcResp
const (
	udsDtcNumberByMask       uint8 = 0x01
	udsDtcByMask             uint8 = 0x02
	udsDtcSnapIdentification uint8 = 0x03
	udsDtcSnapRecByDtcNum    uint8 = 0x04
	udsDtcSnapRecByRecNum    uint8 = 0x05
	udsDtcExtendedByDtcNum   uint8 = 0x06
	udsReadSupportedDtc      uint8 = 0x0a
)

// FuncResponse holds one response
// from a functional request
type FuncResponse struct {
	Source   uint16
	Response []byte
	Query    []byte
}

const (
	// RvdcPrioClientIDLow : RVDC client priority low (kDoIPPrioClientIdRvdc)
	RvdcPrioClientIDLow byte = 0x03
	// RvdcPrioClientIDHigh : RVDC client priority high (kDoIPPrioClientIdRvdcHigh)
	RvdcPrioClientIDHigh byte = 0x08
)

// Logger interface should be implemented by the client
type Logger interface {
	Debug(v ...interface{})
	Debugf(format string, v ...interface{})
	Info(v ...interface{})
	Infof(format string, v ...interface{})
}

// TransPipe interface should be implemented by the layers
// intended to be used by uds. E.g. DoIP and DoCAN
type TransPipe interface {
	Connect() error
	Disconnect()
	Send(TargetAddress uint16, data []byte) error
	Receive() (SourceAddress uint16, TargetAddress uint16, data []byte, err error)
}

// TransReceiveError : interface for the errors in Receive()
type TransReceiveError interface {
	error
	IsDisconnected() bool
	IsTimeout() bool
	Responses() [][]byte
}

// Error : specific uds error
type Error interface {
	error
	Unrecoverable() bool
}

type udsError struct {
	code     int
	request  []byte
	response []byte
	addr     uint16
	source   uint16
	count    int8
	err      error
}

const (
	innerError             int = 0
	tooManyResponsePending int = 2
	unexpectedResponse     int = 4
	zeroLengthResponse     int = 5
	responseFromWrongEcu   int = 6
	unknownError           int = 12
)

func (u *udsError) Error() string {
	switch u.code {
	case innerError:
		return fmt.Sprintf("#%02d.%x.%x %s", u.code, u.addr, u.request, u.err)
	case tooManyResponsePending:
		return fmt.Sprintf("#%02d.%x.%x.%02x <%s>", u.code, u.addr, u.request, u.count, "Uds: Too many response pending messages received")
	case unexpectedResponse:
		return fmt.Sprintf("#%02d.%x.%x.%x <%s>", u.code, u.addr, u.request, u.response, "Uds: Unexpected response")
	case zeroLengthResponse:
		return fmt.Sprintf("#%02d.%x.%x.%x <%s>", u.code, u.addr, u.request, u.source, "Uds: Zero length Response")
	case responseFromWrongEcu:
		return fmt.Sprintf("#%02d.%x.%x.%x <%s>", u.code, u.addr, u.request, u.source, "Uds: Response from wrong ecu")
	default:
		return fmt.Sprintf("#%02d <Uds: Unknown error>", unknownError)
	}
}

func (u *udsError) Unrecoverable() bool {
	if u.err == nil {
		return false
	}

	doxErr, ok := u.err.(TransReceiveError)
	return ok && doxErr.IsDisconnected()
}

// UDS interface : functions that will be implemented by the UDS
type UDS interface {
	UdsReadDID(addr uint16, did uint16) ([]byte, []byte, error)
	UdsReadDTCByMask(addr uint16, mask uint8) ([]byte, []byte, error)
	UdsReadDTCSnapshotID(addr uint16) ([]byte, []byte, error)
	UdsReadDTCSnapshotRecord(addr uint16, dtcMask uint32, rec uint8) ([]byte, []byte, error)
	UdsReadDTCExtData(addr uint16, dtcMask uint32, rec uint8) ([]byte, []byte, error)
	UdsReadMemByAddress(addr uint16, addrLenFormatID uint8, memAddress []byte, memSize []byte) ([]byte, []byte, error)
	UdsReadDIDFunctional(did uint16) ([]byte, []FuncResponse, error)
	UdsReadDTCByMaskFunctional(mask uint8) ([]byte, []FuncResponse, error)
	UdsReadDTCSnapshotIDFunctional() ([]byte, []FuncResponse, error)
	UdsReadDTCSnapshotRecordFunctional(addr uint16, dtcMask uint32, snapRecNumber uint8) ([]byte, FuncResponse, error)
	UdsReadDTCExtDataFunctional(addr uint16, dtcMask uint32, extDataRecNumber uint8) ([]byte, FuncResponse, error)
}

type uds struct {
	log               Logger
	trans             TransPipe
	pendingCount      int8
	interRequestDelay time.Duration
}

// NewUDS creates a new UDS session with trans as the bearer, with the default value five for pendingCount
// trans can either be an DoIP or DoCAN session.
func NewUDS(log Logger, trans TransPipe) UDS {
	// The default value here is just set arbitrary
	return NewUDSWithPendingCount(log, trans, 5)

}

// NewUDSWithPendingCount creates a new UDS session with trans as the bearer.
// count is the number or response pending messages the UDS layer will accept before returning an error.
// trans can either be an DoIP or DoCAN session.
func NewUDSWithPendingCount(log Logger, trans TransPipe, count int8) UDS {
	u := new(uds)
	u.log = log
	u.trans = trans
	u.pendingCount = count
	return u
}

// UdsReadDID : ReadDataByIdentifier (0x22) service: requests data record values from the server identified by one or more data identifiers
func (u *uds) UdsReadDID(addr uint16, did uint16) ([]byte, []byte, error) {
	request := []byte{udsReadDIDReq, byte(did >> 8), byte(did)}
	response, err := u.doUdsRawReq(addr, request)
	return request, response, err
}

// UdsReadDTCByMask : ReadDTCInformation (0x19) service : sub-function (0x02): retrieves a list of DTCs that match the status mask specified
func (u *uds) UdsReadDTCByMask(addr uint16, statusMask uint8) ([]byte, []byte, error) {
	request := []byte{udsDtcReq, udsDtcByMask, statusMask}
	response, err := u.doUdsRawReq(addr, request)
	return request, response, err
}

// UdsReadDTCSnapshotID : ReadDTCInformation (0x19) service : subfunction  (0x03): lists the DTC that have saved snapshot data.
func (u *uds) UdsReadDTCSnapshotID(addr uint16) ([]byte, []byte, error) {
	request := []byte{udsDtcReq, udsDtcSnapIdentification}
	response, err := u.doUdsRawReq(addr, request)
	return request, response, err
}

// UdsReadDTCSnapshotID : ReadDTCInformation (0x19) service : sub-function (0x04): used to download the snapshot data records, one by one.
func (u *uds) UdsReadDTCSnapshotRecord(addr uint16, dtcMask uint32, snapRecNumber uint8) ([]byte, []byte, error) {
	request := []byte{udsDtcReq, udsDtcSnapRecByDtcNum,
		byte(dtcMask >> 16), byte(dtcMask >> 8), byte(dtcMask), snapRecNumber}
	response, err := u.doUdsRawReq(addr, request)
	return request, response, err
}

// UdsReadDTCExtData : ReadDTCInformation (0x19) service : sub-function  (0x06): retrieve extended data for a client defined in conjunction with the record number
func (u *uds) UdsReadDTCExtData(addr uint16, dtcMask uint32, extDataRecNumber uint8) ([]byte, []byte, error) {
	request := []byte{udsDtcReq, udsDtcExtendedByDtcNum,
		byte(dtcMask >> 16), byte(dtcMask >> 8), byte(dtcMask), extDataRecNumber}
	response, err := u.doUdsRawReq(addr, request)
	return request, response, err
}

// UdsReadMemByAddress : ReadMemByAddress (0x23) service :  request memory data from the server via provided starting address and size of memory to read
func (u *uds) UdsReadMemByAddress(addr uint16, addrLenFormatID uint8, memAddress []byte, memSize []byte) ([]byte, []byte, error) {
	var request = []byte{udsReadMemByAddressReq, byte(addrLenFormatID)}
	request = append(request, memAddress...)
	request = append(request, memSize...)
	response, err := u.doUdsRawReq(addr, request)
	return request, response, err
}

// UdsReadDIDFunctional executes a functional request for a specific DID
func (u *uds) UdsReadDIDFunctional(did uint16) (request []byte, response []FuncResponse, err error) {
	request = []byte{udsReadDIDReq, byte(did >> 8), byte(did)}
	response, err = u.doUdsFuncReq(request, true)
	return
}

func (u *uds) UdsReadDTCByMaskFunctional(mask uint8) (request []byte, response []FuncResponse, err error) {
	request = []byte{udsDtcReq, udsDtcByMask, mask}
	response, err = u.doUdsFuncReq(request, false)
	return
}

func (u *uds) UdsReadDTCSnapshotIDFunctional() (request []byte, response []FuncResponse, err error) {
	request = []byte{udsDtcReq, udsDtcSnapIdentification}
	response, err = u.doUdsFuncReq(request, false)
	return
}

func (u *uds) UdsReadDTCSnapshotRecordFunctional(addr uint16, dtcMask uint32, snapRecNumber uint8) (request []byte, response FuncResponse, err error) {
	request, response.Response, err = u.UdsReadDTCSnapshotRecord(addr, dtcMask, snapRecNumber)
	if err == nil {
		response.Source = addr
	}
	return
}

func (u *uds) UdsReadDTCExtDataFunctional(addr uint16, dtcMask uint32, extDataRecNumber uint8) (request []byte, response FuncResponse, err error) {
	request, response.Response, err = u.UdsReadDTCExtData(addr, dtcMask, extDataRecNumber)
	if err == nil {
		response.Source = addr
	}
	return
}

// doUdsRawReq is a helper function that handles errors in send/receive and retries on UDS response pending
func (u *uds) doUdsRawReq(addr uint16, request []byte) (response []byte, err error) {
	u.log.Debugf("Sending uds request to %x with payload %x", addr, request)
	err = u.trans.Send(addr, request)
	if err != nil {
		u.log.Infof("Sending uds request to %x with payload %x failed with %s", addr, request, err)
		err = &udsError{
			err:     err,
			code:    innerError,
			request: request,
			addr:    addr,
			source:  addr,
		}
		return
	}

	var source uint16
	count := int8(0)

	for count <= u.pendingCount {
		u.log.Debugf("Waiting for uds response for request %x", request)
		source, _, response, err = u.trans.Receive()
		if len(response) == 0 && err == nil {
			err = &udsError{
				code:    zeroLengthResponse,
				request: request,
				addr:    addr,
				source:  source,
			}
			return
		}
		switch {
		case err != nil:
			err = &udsError{
				code:    innerError,
				request: request,
				addr:    addr,
				err:     err,
			}
			return

		case response[0] == udsNegRespServID:
			if len(response) < 3 || response[2] != udsRespPending {
				u.log.Debugf("Received a negative response %v", response)
				return // got a negative response, all good for us send it up
			}

			// try to handle the pending response by call Receive again
			count++
			u.log.Debugf("response pending, count: %v of %v", count, u.pendingCount)

		case source != addr:
			u.log.Debugf("Received a response from the wrong source %d with payload %v", source, response)
			err = &udsError{
				code:    responseFromWrongEcu,
				request: request,
				addr:    addr,
				source:  source,
			}
			return

		case !u.validatePositiveResponse(request, response):
			u.log.Debugf("Received an unexpected response %v", response)
			err = &udsError{
				code:     unexpectedResponse,
				request:  request,
				addr:     addr,
				response: response,
			}
			return

		default: // good answer
			u.log.Debugf("Received positive response %v", response)
			return
		}
	}
	err = &udsError{
		code:    tooManyResponsePending,
		request: request,
		addr:    addr,
		count:   count,
	}
	return
}

func (u *uds) doUdsFuncReq(request []byte, addIncomplete bool) (response []FuncResponse, err error) {
	addr := uint16(0x1FFF)
	err = u.trans.Send(addr, request)
	if err != nil {
		u.log.Debugf("Sending uds request to %x with payload %x failed with %s", 0x1FFF, request, err)
		err = &udsError{
			err:     err,
			code:    innerError,
			request: request,
			addr:    addr,
			source:  addr,
		}
		return
	}
	for {
		var r FuncResponse
		r.Source, _, r.Response, err = u.trans.Receive()
		if len(r.Response) == 0 && err == nil {
			u.log.Debug("Zero length Response")
			response = append(response, r)
		} else {
			switch {
			case err != nil:
				switch err.(type) {
				case TransReceiveError:
					errors := err.(TransReceiveError)
					if errors.IsDisconnected() {
						err = &udsError{
							err:     err,
							code:    innerError,
							request: request,
							addr:    addr,
							source:  r.Source,
						}
						return
					}
					if addIncomplete {
						for _, errResponse := range errors.Responses() {
							r.Response = errResponse
							response = append(response, r)
							break
						}
					}
					if errors.IsTimeout() {
						err = nil
						return
					}
				default:
					u.log.Infof("Got error %v", err)
				}
			case r.Response[0] == udsNegRespServID && r.Response[2] == udsRespPending: //Response pending, drop the message
				u.log.Debug("response pending, drop the message")
			default: // good answer
				response = append(response, r)
			}
		}
	}
}

// validatePositiveResponse : check that the response received has the correct format (len, ECU address)
func (u *uds) validatePositiveResponse(request []byte, response []byte) bool {
	if len(response) == 0 || request[0]|udsPosRespMask != response[0] {
		return false
	}

	switch request[0] {
	case udsReadDIDReq:
		params := len(request) - 1
		return len(response) >= params+1 && bytes.Equal(request[1:params+1], response[1:params+1])
	case udsDtcReq:
		return len(response) > 1 && request[1] == response[1]
	case udsReadMemByAddressReq:
		return len(response) >= 1
	default:
		return true
	}
}
