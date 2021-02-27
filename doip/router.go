package doip

import (
	"fmt"
	"sync"
)

// Router receive the message from upstream `ch` and send into the right channel in downstream
// with its addr `m map[addr]chan`.
type Router struct {
	sync.Mutex
	ch  chan *MsgDiagMsgIndDst
	m   map[string]chan *MsgDiagMsgInd
	done chan struct{}
	log Logger
}

// NewRouter creates a new route to dispatch indication to the right channel
// according to the address
func NewRouter(log Logger) *Router {
	r := &Router{
		ch:  make(chan *MsgDiagMsgIndDst),
		m:   make(map[string]chan *MsgDiagMsgInd),
		done: make(chan struct{}),
		log: log,
	}

	go r.run(r.done)
	return r
}

// Close stops the route when exit the server. 
func (r *Router) Close() {
	r.Lock()
	defer r.Unlock()

	for k, v := range r.m {
		close(v)
		delete(r.m, k)
	}
	close(r.done)
}

// Add adds a new channle if new connection is established.
func (r *Router) Add(addr string) (<-chan *MsgDiagMsgInd, func(), error) {
	r.Lock()
	defer r.Unlock()
	if _, ok := r.m[addr]; ok {
		return nil, nil, fmt.Errorf("router: failed to add as %s had already existed", addr)
	}

	ch := make(chan *MsgDiagMsgInd)
	r.m[addr] = ch

	cancel := func() {
		r.Lock()
		close(ch)
		delete(r.m, addr)
		r.Unlock()
	}

	return ch, cancel, nil
}

func (r *Router) run(done <-chan struct{}) {
	for {
		select {
		case m := <-r.ch:
			r.Lock()
			ch, ok := r.m[m.Addr]
			r.Unlock()

			if ok {
				select {
				case ch <- &m.MsgDiagMsgInd:
				default:
				}
			} else {
				r.log.Debugf("Router: faile to find the right channel with %s\n", m.Addr)
			}
		case <- done:
			break
		}
	}
}