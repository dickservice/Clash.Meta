package tls_test

import (
	"context"
	"errors"
	"net"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/ech"
	tlsC "github.com/metacubex/mihomo/component/tls"
	corelog "github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/transport/vmess"
	"github.com/metacubex/tls"
)

type restoreForbiddenConn struct{ calls int }

func (c *restoreForbiddenConn) touched() {
	c.calls++
	panic("configuration-only regression reached net.Conn")
}
func (c *restoreForbiddenConn) Read([]byte) (int, error)         { c.touched(); return 0, nil }
func (c *restoreForbiddenConn) Write([]byte) (int, error)        { c.touched(); return 0, nil }
func (c *restoreForbiddenConn) Close() error                     { c.touched(); return nil }
func (c *restoreForbiddenConn) LocalAddr() net.Addr              { c.touched(); return nil }
func (c *restoreForbiddenConn) RemoteAddr() net.Addr             { c.touched(); return nil }
func (c *restoreForbiddenConn) SetDeadline(time.Time) error      { c.touched(); return nil }
func (c *restoreForbiddenConn) SetReadDeadline(time.Time) error  { c.touched(); return nil }
func (c *restoreForbiddenConn) SetWriteDeadline(time.Time) error { c.touched(); return nil }

type restoreConsumerProbe struct {
	t      *testing.T
	ctx    context.Context
	stop   error
	calls  int
	branch string
}

func (p *restoreConsumerProbe) beforeHandshake(ctx context.Context, serverName string) ([]byte, error) {
	p.t.Helper()
	p.calls++
	if ctx != p.ctx || serverName != "consumer.invalid" {
		p.t.Errorf("ECH inputs context=%v serverName=%q", ctx == p.ctx, serverName)
	}
	// Both real consumers reach ECH after branch selection, before any TLS handshake.
	pcs := make([]uintptr, 32)
	n := runtime.Callers(1, pcs)
	frames := runtime.CallersFrames(pcs[:n])
	var names []string
	for {
		frame, more := frames.Next()
		names = append(names, frame.Function)
		switch frame.Function {
		case "github.com/metacubex/mihomo/component/ech.(*Config).ClientHandleUTLS":
			p.branch = "utls"
		case "github.com/metacubex/mihomo/component/ech.(*Config).ClientHandle":
			p.branch = "tls"
		}
		if !more {
			break
		}
	}
	if p.branch == "" {
		p.t.Errorf("no real ECH consumer branch in stack: %s", strings.Join(names, "\n"))
	}
	return nil, p.stop
}

type restoreConsumer struct {
	stream *vmess.TLSConfig
	ws     *vmess.WebsocketConfig
}

func newRestoreConsumer(kind, local string, skipVerify bool) *restoreConsumer {
	if kind == "stream" {
		return &restoreConsumer{stream: &vmess.TLSConfig{
			Host: "consumer.invalid", ClientFingerprint: local,
			NextProtos: []string{"h2", "http/1.1"}, SkipCertVerify: skipVerify,
		}}
	}
	return &restoreConsumer{ws: &vmess.WebsocketConfig{
		Host: "consumer.invalid", Port: "443", Path: "/regression", TLS: true,
		ClientFingerprint: local,
		TLSConfig: &tls.Config{
			ServerName: "consumer.invalid", NextProtos: []string{"http/1.1"},
			InsecureSkipVerify: skipVerify,
		},
	}}
}

func (c *restoreConsumer) check(t *testing.T, wantBranch, wantClient string) {
	t.Helper()
	sub := corelog.Subscribe()
	defer corelog.UnSubscribe(sub)
	barrier := "restore fingerprint consumer observation boundary"
	corelog.Debugln(barrier)
	for event := range sub {
		if event.Payload == barrier {
			break
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	probe := &restoreConsumerProbe{t: t, ctx: ctx, stop: errors.New("restore ECH pre-handshake stop")}
	echConfig := &ech.Config{GetEncryptedClientHelloConfigList: probe.beforeHandshake}
	conn := &restoreForbiddenConn{}
	var result net.Conn
	var err error
	if c.stream != nil {
		before := *c.stream
		before.NextProtos = append([]string(nil), c.stream.NextProtos...)
		c.stream.ECH = echConfig
		before.ECH = echConfig
		result, err = vmess.StreamTLSConn(ctx, conn, c.stream)
		if !reflect.DeepEqual(*c.stream, before) {
			t.Error("stream consumer mutated configured proxy options")
		}
	} else {
		before := c.ws.TLSConfig.Clone()
		before.NextProtos = append([]string(nil), c.ws.TLSConfig.NextProtos...)
		c.ws.ECHConfig = echConfig
		result, err = vmess.StreamWebsocketConn(ctx, conn, c.ws)
		if !reflect.DeepEqual(c.ws.TLSConfig, before) {
			t.Error("WebSocket consumer mutated configured TLS options")
		}
	}
	if result != nil || !errors.Is(err, probe.stop) {
		t.Fatalf("consumer did not stop before TLS construction: conn=%T err=%v", result, err)
	}
	if probe.calls != 1 || probe.branch != wantBranch || conn.calls != 0 {
		t.Fatalf("consumer calls=%d branch=%q IO=%d; want one %q callback and no IO", probe.calls, probe.branch, conn.calls, wantBranch)
	}
	if wantClient != "" {
		timer := time.NewTimer(time.Second)
		defer timer.Stop()
		selected := ""
		for selected == "" {
			select {
			case event := <-sub:
				for _, prefix := range []string{"use specified fingerprint:", "use initial random HelloID:"} {
					if strings.HasPrefix(event.Payload, prefix) {
						selected = strings.TrimPrefix(event.Payload, prefix)
					}
				}
			case <-timer.C:
				t.Fatal("real consumer did not publish its selected fingerprint diagnostic")
			}
		}
		if wantClient == "random" {
			if selected != "Chrome" && selected != "Firefox" && selected != "Safari" && selected != "iOS" {
				t.Fatalf("unexpected process-random consumer profile %q", selected)
			}
		} else if selected != wantClient {
			t.Fatalf("real consumer selected profile %q, want %q", selected, wantClient)
		}
		t.Logf("actual consumer selected profile=%s", selected)
	}
	t.Logf("actual consumer branch=%s ECH callbacks=%d net.Conn calls=%d", probe.branch, probe.calls, conn.calls)
}

func restorePreserveGlobal(t *testing.T) {
	t.Helper()
	old := tlsC.GetGlobalFingerprint()
	t.Cleanup(func() { tlsC.SetGlobalFingerprint(old) })
}

func TestRestoreEffectiveFingerprintConsumers(t *testing.T) {
	restorePreserveGlobal(t)
	cases := []struct {
		name, global, local, branch, client string
	}{
		{"unset", "", "", "tls", ""},
		{"inherit-chrome", "chrome", "", "utls", "Chrome"},
		{"inherit-firefox", "firefox", "", "utls", "Firefox"},
		{"inherit-random", "random", "", "utls", "random"},
		{"global-none", "none", "", "tls", ""},
		{"invalid-global", "invalid-global", "", "tls", ""},
		{"local-override", "chrome", "firefox", "utls", "Firefox"},
		{"local-none", "chrome", "none", "tls", ""},
		{"invalid-local-no-fallback", "chrome", "invalid-local", "tls", ""},
		{"whitespace-local-no-fallback", "chrome", " ", "tls", ""},
		{"local-with-global-disabled", "none", "ios", "utls", "iOS"},
		{"local-with-invalid-global", "invalid-global", "safari", "utls", "Safari"},
	}
	for _, kind := range []string{"stream", "websocket"} {
		for _, tc := range cases {
			for _, skipVerify := range []bool{false, true} {
				name := kind + "/" + tc.name + "/verify"
				if skipVerify {
					name = kind + "/" + tc.name + "/skip-verify"
				}
				t.Run(name, func(t *testing.T) {
					tlsC.SetGlobalFingerprint(tc.global)
					newRestoreConsumer(kind, tc.local, skipVerify).check(t, tc.branch, tc.client)
					if tlsC.GetGlobalFingerprint() != tc.global {
						t.Fatal("consumer changed global setting")
					}
				})
			}
		}
	}
}

func TestRestoreEffectiveFingerprintConsumerReloadReset(t *testing.T) {
	restorePreserveGlobal(t)
	for _, kind := range []string{"stream", "websocket"} {
		t.Run(kind, func(t *testing.T) {
			// Reuse the same configuration objects across every update, not copied defaults.
			inherited := newRestoreConsumer(kind, "", false)
			explicit := newRestoreConsumer(kind, "firefox", false)
			optedOut := newRestoreConsumer(kind, "none", false)
			for _, state := range []struct{ name, global, branch, client string }{
				{"profile-A", "chrome", "utls", "Chrome"},
				{"profile-B", "firefox", "utls", "Firefox"},
				{"disabled", "none", "tls", ""},
				{"invalid", "invalid-global", "tls", ""},
				{"empty-default", "", "tls", ""},
				{"reapply-A", "chrome", "utls", "Chrome"},
				{"clear-again", "", "tls", ""},
			} {
				t.Run(state.name, func(t *testing.T) {
					tlsC.SetGlobalFingerprint(state.global)
					inherited.check(t, state.branch, state.client)
					explicit.check(t, "utls", "Firefox")
					optedOut.check(t, "tls", "")
				})
			}
		})
	}
}
