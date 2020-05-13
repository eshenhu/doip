package doip

import (
	"encoding/binary"
	"errors"
)

// Error for NACK HEADER Message
const (
	DoIPHdrErrIncorrectFormat    byte = 0
	DoIPHdrErrUnknownPayloadType byte = 1
	DoIPHdrErrMsgTooLarge        byte = 2
	DoIPHdrErrOutOfMemory        byte = 3
	DoIPHdrErrInvalidLen         byte = 4
)

// Errors
var (
	ErrDoIPHdrErr          error = &Error{err: "header error"}
	ErrDoIPTmo             error = &Error{err: "timeout"}
	ErrDoIPUnknownSA       error = &Error{err: "unknown sa"}
	ErrDoIPInvalidSA       error = &Error{err: "invalid sa"}
	ErrDoIPUnknownTA       error = &Error{err: "unknown ta"}
	ErrDoIPMsgTooLarge     error = &Error{err: "message too large"}
	ErrDoIPOutOfMem        error = &Error{err: "out of memory"}
	ErrDoIPTargetUnreached error = &Error{err: "target unreachable"}
	ErrDoIPNoLink          error = &Error{err: "no link"}
	ErrDoIPNoSocket        error = &Error{err: "no socket"}
	ErrDoIPError           error = &Error{err: "other error"}
)

// Unpack error
var (
	ErrUnpackNoExist  = errors.New("Unpack No existed")
	ErrUnpackNil      = errors.New("Unpack nil")
	ErrUnpackTooShort = errors.New("Unpack Too short")
)

// Pack error
var (
	ErrPackNoExist = errors.New("Pack No existed")
	ErrPackNil     = errors.New("Pack nil")
)

// mhs returns the map
var (
	mhUnpack = map[MsgTid]func([]byte) (Msg, error){
		routingActivationRequest: unpackReqRA,
		aliveCheckRequest:        unpackReqAC,
		diagnosticMessage:        unpackReqDM,
	}

	mhPack = map[MsgTid]func(Msg) ([]byte, error){
		genericHeaderNegativeAcknowledge:     packResNAK,
		routingActivationResponse:            packResRA,
		aliveCheckResponse:                   packResAC,
		diagnosticMessagePositiveAcknowledge: packResDM,
		diagnosticMessageNegativeAcknowledge: packResDM,
		diagnosticMessage:                    packResInd, // Indication from Service Provider
	}
)

// Unpack the raw bytes into the formated Message
func Unpack(b []byte, id MsgTid) (Msg, error) {
	if f, ok := mhUnpack[id]; ok {
		return f(b)
	}
	return nil, ErrUnpackNoExist
}

// Pack the Msg into bytes
func Pack(m Msg, id MsgTid) ([]byte, error) {
	if f, ok := mhPack[id]; ok {
		return f(m)
	}
	return nil, ErrPackNoExist
}

// MsgTid represent the type of data
type MsgTid uint16

// Error represents a DoIP error.
type Error struct{ err string }

func (e *Error) Error() string {
	if e == nil {
		return "DoIP: <nil>"
	}
	return "DoIP: " + e.err
}

// Msg represent the L2 Message
type Msg interface {
	GetID() MsgTid
}

// MsgReq represent ReqMsg
type MsgReq interface {
	Msg
	Pack() []byte
}

// MsgNACKReq : NACK message
type MsgNACKReq struct {
	id      MsgTid
	errCode byte
}

// GetID returns id
func (r *MsgNACKReq) GetID() MsgTid { return r.id }

//Pack message
func (r *MsgNACKReq) Pack() []byte {
	return []byte{}
}

// MsgActivationReq :
type MsgActivationReq struct {
	id             MsgTid
	srcAddress     uint16
	activationType byte
	reserveForStd  []byte
	reserveForOEM  []byte
}

// GetID returns id
func (r *MsgActivationReq) GetID() MsgTid { return r.id }

//Pack message
func (r *MsgActivationReq) Pack() []byte {
	ln := 2 + 1 + 4
	if len(r.reserveForOEM) == 4 {
		ln += 4
	}

	buf := make([]byte, ln)
	binary.BigEndian.PutUint16(buf[:2], uint16(r.srcAddress))
	buf[2] = r.activationType
	copy(buf[3:], r.reserveForStd) 

	if len(r.reserveForOEM) == 4 {
		copy(buf[7:], r.reserveForOEM)
	}
	return buf
}

// MsgActivationRes Res
type MsgActivationRes struct {
	id            MsgTid
	srcAddress    uint16
	dstAddress    uint16
	code          byte
	reserveForStd []byte
	reserveForOEM []byte
}

//GetID returns id
func (w *MsgActivationRes) GetID() MsgTid { return w.id }

// MsgAliveChkReq AliveCheck
type MsgAliveChkReq struct {
	id MsgTid
}

//GetID returns id
func (r *MsgAliveChkReq) GetID() MsgTid { return r.id }

//Pack message
func (r *MsgAliveChkReq) Pack() []byte {
	return []byte{}
} 

//MsgAliveChkRes AliveCheck
type MsgAliveChkRes struct {
	id MsgTid
}

//GetID returns id
func (w *MsgAliveChkRes) GetID() MsgTid { return w.id }

//MsgDiagMsgReq DiagMsg
type MsgDiagMsgReq struct {
	id         MsgTid
	srcAddress uint16
	dstAddress uint16
	userdata   []byte
}

//GetID returns id
func (r *MsgDiagMsgReq) GetID() MsgTid { return r.id }

//Pack message
func (r *MsgDiagMsgReq) Pack() []byte {
	ln := 4 + len(r.userdata)
	buf := make([]byte, ln)

	binary.BigEndian.PutUint16(buf[0:2], uint16(r.srcAddress))
	binary.BigEndian.PutUint16(buf[2:4], uint16(r.dstAddress))
	copy(buf[4:], r.userdata)

	return buf
}

//MsgDiagMsgRes DiagMsg
type MsgDiagMsgRes struct {
	id         MsgTid
	srcAddress uint16
	dstAddress uint16
	ackCode    byte // 0: Ack 1..0xFF NAck
	userdata   []byte
}

// GetID returns id
func (w *MsgDiagMsgRes) GetID() MsgTid { return w.id }

// MsgDiagMsgInd which send from UDS layer
type MsgDiagMsgInd MsgDiagMsgReq

// GetID returns id
func (r *MsgDiagMsgInd) GetID() MsgTid { return r.id }

//Pack message
func (r *MsgDiagMsgInd) Pack() []byte {
	ln := 4 + len(r.userdata)
	buf := make([]byte, ln)

	binary.BigEndian.PutUint16(buf[0:2], uint16(r.srcAddress))
	binary.BigEndian.PutUint16(buf[2:4], uint16(r.dstAddress))
	copy(buf[4:], r.userdata)

	return buf
}

func packResNAK(m Msg) ([]byte, error) {
	r, ok := m.(*MsgNACKReq)
	if !ok {
		return nil, ErrPackNil
	}
	b := []byte{r.errCode}
	return b, nil
}

func unpackReqRA(b []byte) (w Msg, err error) {
	ll := len(b)
	if !(ll == 7 || ll == 11) {
		return nil, ErrUnpackTooShort
	}
	m := &MsgActivationReq{
		id:             routingActivationRequest,
		srcAddress:     binary.BigEndian.Uint16(b[0:2]),
		activationType: b[2],
		reserveForStd:  b[3:7],
	}
	if ll == 11 {
		m.reserveForOEM = b[7:11]
	}
	return m, nil
}

func packResRA(m Msg) ([]byte, error) {
	r, ok := m.(*MsgActivationRes)
	if !ok {
		return nil, ErrPackNil
	}
	len := 9
	if r.reserveForOEM != nil {
		len += 4
	}

	w := make([]byte, len)
	binary.BigEndian.PutUint16(w[0:2], r.srcAddress)
	binary.BigEndian.PutUint16(w[2:4], r.dstAddress)
	w[4] = r.code
	binary.BigEndian.PutUint16(w[5:9], 0)

	if len == 13 {
		copy(w[9:13], r.reserveForOEM[:4])
	}
	return w, nil
}

func unpackReqAC(b []byte) (w Msg, err error) {
	r := &MsgAliveChkReq{
		id: aliveCheckRequest,
	}
	return r, nil
}

func packResAC(m Msg) ([]byte, error) {
	return nil, nil
}

func unpackReqDM(b []byte) (w Msg, err error) {
	ll := len(b)
	if ll <= 4 {
		return nil, ErrUnpackTooShort
	}
	m := &MsgDiagMsgReq{
		id:         diagnosticMessage,
		srcAddress: binary.BigEndian.Uint16(b[0:2]),
		dstAddress: binary.BigEndian.Uint16(b[2:4]),
		userdata:   b[4:],
	}
	return m, nil
}

func packResDM(m Msg) ([]byte, error) {
	r, ok := m.(*MsgDiagMsgRes)
	if !ok {
		return nil, ErrPackNil
	}
	len := 5 + len(r.userdata)
	w := make([]byte, len)
	binary.BigEndian.PutUint16(w[0:2], r.srcAddress)
	binary.BigEndian.PutUint16(w[2:4], r.dstAddress)
	w[4] = r.ackCode
	copy(w[5:len], r.userdata)
	return w, nil
}

func packResInd(m Msg) ([]byte, error) {
	r, ok := m.(*MsgDiagMsgInd)
	if !ok {
		return nil, ErrPackNil
	}
	len := 4 + len(r.userdata)
	w := make([]byte, len)
	binary.BigEndian.PutUint16(w[0:2], r.srcAddress)
	binary.BigEndian.PutUint16(w[2:4], r.dstAddress)
	copy(w[4:len], r.userdata)
	return w, nil
}
