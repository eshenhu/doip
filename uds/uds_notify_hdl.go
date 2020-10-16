package uds

import (
	"context"
	"net"
	"sync"

	"github.com/eshenhu/doip/doip"
)

// Msg represent the format of data.
type Msg struct {
	src  uint16
	dst  uint16
	data []byte
}

// NotifyImpl only dedicated service for only one user
type NotifyImpl struct {
	mux     sync.RWMutex
	isRun   chan struct{}
	outChan map[string]chan *doip.MsgDiagMsgInd
	log     Logger
}

func NewNotifyHdl(logger Logger) *NotifyImpl {
	c := &NotifyImpl{
		isRun:   make(chan struct{}),
		outChan: make(map[string]chan *doip.MsgDiagMsgInd),
		log:     logger,
	}
	c.Start()
	return c
}

func (srv *NotifyImpl) Start() {
	srv.log.Debugf("Start NotifyImpl")
}

func (srv *NotifyImpl) Close() {
	srv.log.Debugf("Stop NotifyImpl")
	close(srv.isRun)
}

func (srv *NotifyImpl) MakeARcvChan(ctx context.Context, a net.Addr) <-chan *doip.MsgDiagMsgInd {
	srv.mux.Lock()

	if srv.outChan[a.String()] != nil {
		srv.mux.Unlock()
		srv.log.Debugf("(%v) Existed instance in UDSSrv, Perhaps terminating previous instance ongoing", a.String())
		return nil
	}

	ch := make(chan *doip.MsgDiagMsgInd, 1)
	srv.outChan[a.String()] = ch
	srv.mux.Unlock()

	go func() {
		srv.log.Debugf("(%v) GenOutChan...", a.String())
		defer func() {
			close(ch)

			srv.mux.Lock()
			delete(srv.outChan, a.String())
			srv.mux.Unlock()
		}()

		select {
		case <-srv.isRun:
			srv.log.Debugf("(%v) Close srv..\n", a.String())
		case <-ctx.Done():
			srv.log.Debugf("(%v) Ctx rcv cancel event, exit...\n", a.String())
		}
	}()

	return ch
}

//Notify the client with event happened.
func (srv *NotifyImpl) Send(addr string, src uint16, dst uint16, data []byte) {
	m := &Msg{
		src:  src,
		dst:  dst,
		data: data,
	}
	srv.log.Debugf("(%v) Feed in data\n", addr)

	srv.mux.RLock()
	outChan := srv.outChan[addr]
	srv.mux.RUnlock()

	//inChan <- m
	sent := &doip.MsgDiagMsgInd{
		Id:         doip.MsgTid(0x8001),
		SrcAddress: m.src,
		DstAddress: m.dst,
		Userdata:   m.data,
	}
	outChan <- sent
}
