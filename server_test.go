package doip

import (
	"context"
	"log"
	"net"
	"os"
	"sync"
)

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

type UDSMsg struct {
	src  uint16
	dst  uint16
	data []byte
}

// Simple doiptest, only dedicated service for only one user
type doiptest struct {
	mux            sync.RWMutex
	inChan         chan *UDSMsg
	outChan        chan *MsgDiagMsgInd
	ctxTrackClient context.Context
	log            *log.Logger
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
	//close(srv.outChan)
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
	srv.ctxTrackClient = ctx
	go func() {
		srv.log.Println("genOutChan...")
		select {
		case <-srv.ctxTrackClient.Done():
			srv.log.Printf("Ctx rcv cancel event, exit...\n")
			srv.outChan <- nil
			break
		}
	}()
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
