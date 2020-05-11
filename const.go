package doip

const (
	protocolVersion        uint8 = 0x02 //DoIP ISO 13400-2:2012
	inverseProtocolVersion uint8 = ^protocolVersion
)

//Table 12:  DoIP Payload types
var (
	genericHeaderNegativeAcknowledge     MsgTid = 0x0000
	routingActivationRequest             MsgTid = 0x0005
	routingActivationResponse            MsgTid = 0x0006
	aliveCheckRequest                    MsgTid = 0x0007
	aliveCheckResponse                   MsgTid = 0x0008
	diagnosticMessage                    MsgTid = 0x8001
	diagnosticMessagePositiveAcknowledge MsgTid = 0x8002
	diagnosticMessageNegativeAcknowledge MsgTid = 0x8003
)

//Table 14: Generic DoIP header NACK codes
var (
	headerIncorrectPatternFormat uint8 = 0x00 // incorrect protocol version / inverse protocol version: close socket
	headerUnknownPayloadType     uint8 = 0x01 // payload type not supported: discard message
	headerMessageTooLarge        uint8 = 0x02 // payload length > max: discard message
	headerOutOfMemory            uint8 = 0x03 // > discard message
	headerInvalidPayloadLength   uint8 = 0x04 // payload length != expected length > close socket
)

//Table 25: Routing activation response code values
var (
	routingDeniedUnsupportedType uint8 = 0x06
	routingSuccessfullyActivated uint8 = 0x10
)
