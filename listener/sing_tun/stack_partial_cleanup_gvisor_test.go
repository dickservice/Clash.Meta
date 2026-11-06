//go:build with_gvisor && linux

package sing_tun

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	gstack "github.com/metacubex/gvisor/pkg/tcpip/stack"
	tun "github.com/metacubex/sing-tun"
)

func socketFDs(t *testing.T) map[string]string {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	result := make(map[string]string)
	for _, entry := range entries {
		path := filepath.Join("/proc/self/fd", entry.Name())
		target, err := os.Readlink(path)
		if err == nil && strings.HasPrefix(target, "socket:[") {
			result[path] = target
		}
	}
	return result
}

// Exercise the actual upstream Mixed.Start failure, not a fake stack: IPv4
// binds to loopback, then IPv6 fails on a documentation-only unassigned address.
// No packets, TUN device, privilege, or private upstream fields are required.
func TestMixedPartialStartClosesRealIPv4Socket(t *testing.T) {
	// Upstream retries EADDRNOTAVAIL three times with one-second sleeps.
	for i := 0; i < 1; i++ {
		system, err := tun.NewSystem(tun.StackOptions{
			Context: context.Background(),
			TunOptions: tun.Options{
				Inet4Address: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/8")},
				Inet6Address: []netip.Prefix{netip.MustParsePrefix("2001:db8::1/64")},
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		mixed := &tun.Mixed{System: system.(*tun.System)}
		before := socketFDs(t)
		l := &Listener{}
		err = l.startStack(mixed)
		// Always clean up, even if host IPv6 setup differs from the test fixture.
		defer func() {
			if l.tunStack != nil {
				_ = l.Close()
			}
		}()
		if !errors.Is(err, syscall.EADDRNOTAVAIL) && !errors.Is(err, syscall.EAFNOSUPPORT) {
			t.Fatalf("expected unavailable IPv6 bind, got %v", err)
		}
		if l.tunStack != mixed.System {
			t.Fatal("failed Mixed must transfer cleanup to System")
		}
		after := socketFDs(t)
		var created []string
		for path, target := range after {
			if before[path] != target {
				created = append(created, path)
			}
		}
		if len(created) != 1 {
			t.Fatalf("partial start created %d sockets, want IPv4 socket", len(created))
		}
		// Demonstrate the upstream bug: Mixed.Close leaves the actual socket open.
		if err := mixed.Close(); err != nil {
			t.Fatal(err)
		}
		if target, err := os.Readlink(created[0]); err != nil || target != after[created[0]] {
			t.Fatal("fixture no longer exhibits upstream Mixed.Close partial-start leak")
		}
		if err := l.Close(); err != nil {
			t.Fatalf("cleanup: %v", err)
		}
		l.tunStack = nil // prevent the test's safety defer from closing twice
		if target, err := os.Readlink(created[0]); err == nil && target == after[created[0]] {
			t.Fatal("partial IPv4 socket remains open")
		}
		// A second System.Close must see the closed socket. This also establishes
		// the first cleanup was not silently deferred or skipped.
		if err := mixed.System.Close(); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("second close = %v, want net.ErrClosed", err)
		}
	}
}

// A userspace-only TUN stand-in lets the real Mixed success path run without
// opening a TUN device. Its lifetime remains separate from stack ownership.
type cleanupTestTun struct {
	ctx context.Context
}

func (t *cleanupTestTun) Read([]byte) (int, error) {
	<-t.ctx.Done()
	return 0, net.ErrClosed
}
func (t *cleanupTestTun) Write(p []byte) (int, error)                   { return len(p), nil }
func (t *cleanupTestTun) Close() error                                  { return nil }
func (t *cleanupTestTun) WritePacket(*gstack.PacketBuffer) (int, error) { return 0, nil }
func (t *cleanupTestTun) NewEndpoint() (gstack.LinkEndpoint, gstack.NICOptions, error) {
	return nil, gstack.NICOptions{}, errors.New("unused by Mixed")
}

func TestMixedSuccessfulStartRetainsSingleCleanupOwner(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stack, err := tun.NewMixed(tun.StackOptions{
		Context:     ctx,
		UDPTimeout:  time.Minute,
		ICMPTimeout: time.Minute,
		Tun:         &cleanupTestTun{ctx: ctx},
		TunOptions: tun.Options{
			MTU:          1500,
			Inet4Address: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/8")},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	l := &Listener{}
	if err := l.startStack(stack); err != nil {
		_ = l.Close()
		t.Fatal(err)
	}
	if l.tunStack != stack {
		t.Fatal("successful Mixed owner replaced")
	}
	cancel() // stop fake packet workers; Listener normally owns context/TUN too
	if err := l.Close(); err != nil {
		t.Fatalf("successful Mixed cleanup (must not double-close System): %v", err)
	}
}
