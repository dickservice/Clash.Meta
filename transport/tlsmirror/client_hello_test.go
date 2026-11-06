package tlsmirror

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	tlsC "github.com/metacubex/mihomo/component/tls"
	"github.com/metacubex/tls"
)

// This observer verifies which production branch runs without changing ECH or TLS.
type helloBranchObserver struct{ branch chan string }

func (o helloBranchObserver) ClientHandle(context.Context, *tls.Config) error {
	o.branch <- "tls"
	return nil
}
func (o helloBranchObserver) ClientHandleUTLS(context.Context, *tlsC.Config) error {
	o.branch <- "utls"
	return nil
}

func TestTLSMirrorDialClientHelloBytes(t *testing.T) {
	old := tlsC.GetGlobalFingerprint()
	t.Cleanup(func() { tlsC.SetGlobalFingerprint(old) })
	for _, tc := range []struct{ local, global, branch string }{
		{"", "chrome", "tls"}, {"none", "chrome", "tls"},
		{"invalid-profile", "chrome", "tls"}, {"chrome", "firefox", "utls"},
		{"firefox", "chrome", "utls"},
	} {
		t.Run(fmt.Sprintf("local=%s/global=%s", tc.local, tc.global), func(t *testing.T) {
			tlsC.SetGlobalFingerprint(tc.global)
			client, capture := net.Pipe()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			defer client.Close()
			defer capture.Close()
			if err := capture.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			branch := make(chan string, 1)
			done := make(chan error, 1)
			go func() {
				conn, err := Dial(ctx, client, ClientConfig{
					Config: Config{PrimaryKey: testPrimaryKey}, ServerName: "fixture.invalid",
					ALPN: []string{"h2", "http/1.1"}, ClientFingerprint: tc.local,
					ECH: helloBranchObserver{branch: branch},
				})
				if conn != nil {
					_ = conn.Close()
				}
				done <- err
			}()
			// Read actual wire records from Dial, not a separately constructed hello.
			var handshake []byte
			for len(handshake) < 4 || len(handshake) < 4+(int(handshake[1])<<16|int(handshake[2])<<8|int(handshake[3])) {
				header := make([]byte, 5)
				if _, err := io.ReadFull(capture, header); err != nil {
					t.Fatal(err)
				}
				if header[0] != 22 || header[1] != 3 {
					t.Fatalf("unexpected record header %x", header)
				}
				payload := make([]byte, binary.BigEndian.Uint16(header[3:]))
				if _, err := io.ReadFull(capture, payload); err != nil {
					t.Fatal(err)
				}
				handshake = append(handshake, payload...)
				if len(handshake) > 65536 {
					t.Fatal("unbounded ClientHello")
				}
			}
			exts := parseCapturedHello(t, handshake)
			if !bytes.Equal(exts[0], append([]byte{0, 18, 0, 0, 15}, []byte("fixture.invalid")...)) {
				t.Fatalf("unexpected SNI %x", exts[0])
			}
			if !bytes.Equal(exts[16], []byte{0, 12, 2, 'h', '2', 8, 'h', 't', 't', 'p', '/', '1', '.', '1'}) {
				t.Fatalf("unexpected ALPN %x", exts[16])
			}
			select {
			case got := <-branch:
				if got != tc.branch {
					t.Fatalf("branch %s, want %s", got, tc.branch)
				}
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			_ = capture.Close()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("capture-only peer must not finish handshake")
				}
			case <-ctx.Done():
				t.Fatal("Dial did not stop after peer close")
			}
		})
	}
}

func TestTLSMirrorDialCancellationClosesCarrier(t *testing.T) {
	for _, fingerprint := range []string{"", "chrome"} {
		t.Run("fingerprint="+fingerprint, func(t *testing.T) {
			client, peer := net.Pipe()
			defer client.Close()
			defer peer.Close()
			if err := peer.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				conn, err := Dial(ctx, client, ClientConfig{
					Config:     Config{PrimaryKey: testPrimaryKey},
					ServerName: "fixture.invalid", ClientFingerprint: fingerprint,
				})
				if conn != nil {
					_ = conn.Close()
				}
				done <- err
			}()
			// Cancel after production Dial emits its first handshake record.
			header := make([]byte, 5)
			if _, err := io.ReadFull(peer, header); err != nil {
				t.Fatal(err)
			}
			if header[0] != 22 {
				t.Fatalf("expected handshake, got %x", header)
			}
			payload := make([]byte, binary.BigEndian.Uint16(header[3:]))
			if _, err := io.ReadFull(peer, payload); err != nil {
				t.Fatal(err)
			}
			cancel()
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("Dial cancellation = %v", err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("Dial did not return after caller cancellation")
			}
			if _, err := peer.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
				t.Fatalf("carrier peer after cancellation = %v, want EOF", err)
			}
		})
	}
}

func parseCapturedHello(t *testing.T, raw []byte) map[uint16][]byte {
	t.Helper()
	if len(raw) < 4 || raw[0] != 1 {
		t.Fatal("not a ClientHello")
	}
	size := int(raw[1])<<16 | int(raw[2])<<8 | int(raw[3])
	if len(raw) != size+4 {
		t.Fatal("invalid handshake length")
	}
	b := raw[4:]
	take := func(n int) []byte {
		if n < 0 || n > len(b) {
			t.Fatal("truncated ClientHello")
		}
		v := b[:n]
		b = b[n:]
		return v
	}
	take(34) // legacy version and random
	take(int(take(1)[0]))
	take(int(binary.BigEndian.Uint16(take(2))))
	take(int(take(1)[0]))
	n := int(binary.BigEndian.Uint16(take(2)))
	if n != len(b) {
		t.Fatal("extension vector length mismatch")
	}
	exts := make(map[uint16][]byte)
	for len(b) > 0 {
		id := binary.BigEndian.Uint16(take(2))
		value := take(int(binary.BigEndian.Uint16(take(2))))
		if _, exists := exts[id]; exists {
			t.Fatalf("duplicate extension %d", id)
		}
		exts[id] = value
	}
	return exts
}
