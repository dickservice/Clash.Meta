package sing_tun

import (
	"errors"
	"net"
	"testing"
	"time"
)

// Exercise production ownership and Close with a real partially-created socket.
// No TUN privilege, packet routing, or dependency-failure injection is claimed.
type partialStartStack struct {
	listener net.Listener
	exited   chan struct{}
	closed   int
	fail     bool
}

func (s *partialStartStack) Start() error {
	var err error
	s.listener, err = net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return err
	}
	s.exited = make(chan struct{})
	go func() {
		defer close(s.exited)
		for {
			c, err := s.listener.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	if s.fail {
		return errors.New("second-family startup failure")
	}
	return nil
}
func (s *partialStartStack) Close() error {
	s.closed++
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}
func TestStackOwnershipBeforePartialStartFailure(t *testing.T) {
	for i := 0; i < 20; i++ {
		l := &Listener{}
		s := &partialStartStack{fail: true}
		if err := l.startStack(s); err == nil {
			t.Fatal("expected startup failure")
		}
		if l.tunStack != s {
			t.Fatal("partial stack not owned")
		}
		if err := l.Close(); err != nil {
			t.Fatal(err)
		}
		if s.closed != 1 {
			t.Fatalf("close count %d", s.closed)
		}
		select {
		case <-s.exited:
		case <-time.After(time.Second):
			t.Fatal("accept worker leaked")
		}
		if c, err := net.DialTimeout("tcp4", s.listener.Addr().String(), time.Second); err == nil {
			c.Close()
			t.Fatal("listener remains open")
		}
	}
}
func TestStackOwnershipSuccessfulStart(t *testing.T) {
	l := &Listener{}
	s := &partialStartStack{}
	if err := l.startStack(s); err != nil {
		t.Fatal(err)
	}
	if l.tunStack != s {
		t.Fatal("successful stack not owned")
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-s.exited:
	case <-time.After(time.Second):
		t.Fatal("accept worker leaked")
	}
}
