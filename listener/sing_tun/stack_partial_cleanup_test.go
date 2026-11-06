package sing_tun

import (
	"errors"
	"testing"
)

type cleanupCountingStack struct {
	startErr error
	closes   int
}

func (s *cleanupCountingStack) Start() error { return s.startErr }
func (s *cleanupCountingStack) Close() error { s.closes++; return nil }

func TestPartialCleanupPreservesOrdinaryStackOwner(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "failure"}[fail], func(t *testing.T) {
			s := &cleanupCountingStack{}
			if fail {
				s.startErr = errors.New("partial start")
			}
			l := &Listener{}
			if err := l.startStack(s); err != s.startErr {
				t.Fatalf("Start error = %v, want %v", err, s.startErr)
			}
			if l.tunStack != s {
				t.Fatal("ordinary stack owner replaced")
			}
			if s.closes != 0 {
				t.Fatal("closed before deferred listener cleanup")
			}
			if err := l.Close(); err != nil {
				t.Fatal(err)
			}
			if s.closes != 1 {
				t.Fatalf("Close calls = %d, want 1", s.closes)
			}
		})
	}
}
