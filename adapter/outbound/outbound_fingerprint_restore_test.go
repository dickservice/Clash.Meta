package outbound

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/ech"
	tlsC "github.com/metacubex/mihomo/component/tls"
	C "github.com/metacubex/mihomo/constant"
	corelog "github.com/metacubex/mihomo/log"
)

type outboundRestoreForbiddenConn struct{ calls int }

func (c *outboundRestoreForbiddenConn) touched() {
	c.calls++
	panic("outbound configuration regression reached net.Conn before its ECH stop")
}
func (c *outboundRestoreForbiddenConn) Read([]byte) (int, error)         { c.touched(); return 0, nil }
func (c *outboundRestoreForbiddenConn) Write([]byte) (int, error)        { c.touched(); return 0, nil }
func (c *outboundRestoreForbiddenConn) Close() error                     { c.touched(); return nil }
func (c *outboundRestoreForbiddenConn) LocalAddr() net.Addr              { c.touched(); return nil }
func (c *outboundRestoreForbiddenConn) RemoteAddr() net.Addr             { c.touched(); return nil }
func (c *outboundRestoreForbiddenConn) SetDeadline(time.Time) error      { c.touched(); return nil }
func (c *outboundRestoreForbiddenConn) SetReadDeadline(time.Time) error  { c.touched(); return nil }
func (c *outboundRestoreForbiddenConn) SetWriteDeadline(time.Time) error { c.touched(); return nil }

type outboundRestoreInput struct {
	server, serverName, network, local, pin, verifyName string
	alpn                                                []string
	skipVerify, tls                                     bool
	reality                                             RealityOptions
	wsHeaders                                           map[string]string
	wsEarly                                             int
}

func outboundRestoreDefaults() outboundRestoreInput {
	return outboundRestoreInput{
		server: "origin.invalid", serverName: "sni.invalid", tls: true,
		alpn: []string{"outbound-private/1", "http/1.1"},
		pin:  strings.Repeat("12", 32), verifyName: "certificate-name.invalid",
	}
}

type outboundRestoreConsumer struct {
	stream    func(context.Context, net.Conn, bool) (net.Conn, error)
	public    func(context.Context, net.Conn) (net.Conn, error)
	setECH    func(*ech.Config)
	snapshot  func() string
	reality   *tlsC.RealityConfig
	parsedECH *ech.Config
	kind      string
}

func outboundRestoreSnapshot(t *testing.T, option any) string {
	t.Helper()
	data, err := json.Marshal(option)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func newOutboundRestoreConsumer(t *testing.T, kind string, in outboundRestoreInput) (*outboundRestoreConsumer, error) {
	t.Helper()
	echOptions := ECHOptions{Enable: true, Config: base64.StdEncoding.EncodeToString([]byte("outbound in-memory ECH fixture"))}
	wsOptions := WSOptions{Path: "/configuration-only", Headers: in.wsHeaders, MaxEarlyData: in.wsEarly}
	consumer := &outboundRestoreConsumer{kind: kind}
	metadata := &C.Metadata{NetWork: C.TCP, Host: "destination.invalid", DstPort: 443}
	var storedLocal, storedPin, storedName, storedVerifyName string
	var storedALPN []string
	var storedSkip bool
	switch kind {
	case "vmess":
		v, err := NewVmess(VmessOption{
			Name: "restore-vmess", Server: in.server, Port: 443,
			UUID: "00112233-4455-6677-8899-aabbccddeeff", Cipher: "auto",
			TLS: in.tls, Network: in.network, ALPN: in.alpn, ServerName: in.serverName,
			ClientFingerprint: in.local, Fingerprint: in.pin, SkipCertVerify: in.skipVerify,
			NameCertVerify: in.verifyName, ECHOpts: echOptions, RealityOpts: in.reality, WSOpts: wsOptions,
		})
		if err != nil {
			return nil, err
		}
		if v.client == nil || v.gunClient != nil || v.mekyaClient != nil {
			t.Fatal("VMess fixture did not construct only the reviewed client path")
		}
		consumer.stream = v.streamTLSConn
		consumer.public = func(ctx context.Context, conn net.Conn) (net.Conn, error) {
			return v.StreamConnContext(ctx, conn, metadata)
		}
		consumer.setECH = func(cfg *ech.Config) { v.echConfig = cfg }
		consumer.snapshot = func() string { return outboundRestoreSnapshot(t, v.option) }
		consumer.reality, consumer.parsedECH = v.realityConfig, v.echConfig
		storedLocal, storedPin, storedName = v.option.ClientFingerprint, v.option.Fingerprint, v.option.ServerName
		storedVerifyName, storedALPN, storedSkip = v.option.NameCertVerify, v.option.ALPN, v.option.SkipCertVerify
	case "vless":
		v, err := NewVless(VlessOption{
			Name: "restore-vless", Server: in.server, Port: 443,
			UUID: "00112233-4455-6677-8899-aabbccddeeff",
			TLS:  in.tls, Network: in.network, ALPN: in.alpn, ServerName: in.serverName,
			ClientFingerprint: in.local, Fingerprint: in.pin, SkipCertVerify: in.skipVerify,
			NameCertVerify: in.verifyName, ECHOpts: echOptions, RealityOpts: in.reality, WSOpts: wsOptions,
		})
		if err != nil {
			return nil, err
		}
		if v.client == nil || v.encryption != nil || v.gunClient != nil || v.xhttpClient != nil {
			t.Fatal("VLESS fixture did not construct only the reviewed client path")
		}
		consumer.stream = v.streamTLSConn
		consumer.public = func(ctx context.Context, conn net.Conn) (net.Conn, error) {
			return v.StreamConnContext(ctx, conn, metadata)
		}
		consumer.setECH = func(cfg *ech.Config) { v.echConfig = cfg }
		consumer.snapshot = func() string { return outboundRestoreSnapshot(t, v.option) }
		consumer.reality, consumer.parsedECH = v.realityConfig, v.echConfig
		storedLocal, storedPin, storedName = v.option.ClientFingerprint, v.option.Fingerprint, v.option.ServerName
		storedVerifyName, storedALPN, storedSkip = v.option.NameCertVerify, v.option.ALPN, v.option.SkipCertVerify
	case "trojan":
		v, err := NewTrojan(TrojanOption{
			Name: "restore-trojan", Server: in.server, Port: 443, Password: "memory-only-fixture",
			Network: in.network, ALPN: in.alpn, SNI: in.serverName,
			ClientFingerprint: in.local, Fingerprint: in.pin, SkipCertVerify: in.skipVerify,
			NameCertVerify: in.verifyName, ECHOpts: echOptions, RealityOpts: in.reality, WSOpts: wsOptions,
		})
		if err != nil {
			return nil, err
		}
		if v.gunClient != nil || v.ssCipher != nil {
			t.Fatal("Trojan fixture constructed an unreviewed transport")
		}
		consumer.public = func(ctx context.Context, conn net.Conn) (net.Conn, error) {
			return v.StreamConnContext(ctx, conn, metadata)
		}
		consumer.stream = func(ctx context.Context, conn net.Conn, _ bool) (net.Conn, error) {
			return consumer.public(ctx, conn)
		}
		consumer.setECH = func(cfg *ech.Config) { v.echConfig = cfg }
		consumer.snapshot = func() string { return outboundRestoreSnapshot(t, v.option) }
		consumer.reality, consumer.parsedECH = v.realityConfig, v.echConfig
		storedLocal, storedPin, storedName = v.option.ClientFingerprint, v.option.Fingerprint, v.option.SNI
		storedVerifyName, storedALPN, storedSkip = v.option.NameCertVerify, v.option.ALPN, v.option.SkipCertVerify
	default:
		t.Fatalf("unreviewed outbound kind %q", kind)
	}
	wantName := in.serverName
	if kind == "trojan" && wantName == "" {
		wantName = in.server
	}
	if storedLocal != in.local || storedPin != in.pin || storedName != wantName || storedVerifyName != in.verifyName ||
		!reflect.DeepEqual(storedALPN, in.alpn) || storedSkip != in.skipVerify {
		t.Fatal("real constructor changed fingerprint, certificate pin/name, SNI, ALPN, or verification options")
	}
	if consumer.parsedECH == nil || consumer.parsedECH.GetEncryptedClientHelloConfigList == nil {
		t.Fatal("real constructor did not parse enabled in-memory ECH options")
	}
	data, err := consumer.parsedECH.GetEncryptedClientHelloConfigList(context.Background(), "no-query.invalid")
	if err != nil || string(data) != "outbound in-memory ECH fixture" {
		t.Fatalf("constructor ECH fixture=%q error=%v", data, err)
	}
	return consumer, nil
}

func mustOutboundRestoreConsumer(t *testing.T, kind string, in outboundRestoreInput) *outboundRestoreConsumer {
	t.Helper()
	consumer, err := newOutboundRestoreConsumer(t, kind, in)
	if err != nil {
		t.Fatal(err)
	}
	return consumer
}

func outboundRestorePreserveGlobal(t *testing.T) {
	t.Helper()
	before := tlsC.GetGlobalFingerprint()
	t.Cleanup(func() { tlsC.SetGlobalFingerprint(before) })
}

func (c *outboundRestoreConsumer) check(t *testing.T, public, isH2 bool, wantName, wantBranch, wantClient, wantError string) {
	t.Helper()
	before, global := c.snapshot(), tlsC.GetGlobalFingerprint()
	sub := corelog.Subscribe()
	defer corelog.UnSubscribe(sub)
	barrier := "outbound restore fingerprint observation boundary"
	corelog.Debugln(barrier)
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	for ready := false; !ready; {
		select {
		case event := <-sub:
			ready = event.Payload == barrier
		case <-timer.C:
			t.Fatal("log observation boundary timed out")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stop := errors.New("outbound ECH pre-handshake sentinel")
	calls, branch := 0, ""
	c.setECH(&ech.Config{GetEncryptedClientHelloConfigList: func(gotCtx context.Context, name string) ([]byte, error) {
		calls++
		if gotCtx != ctx || name != wantName {
			t.Errorf("real ECH consumer context=%v serverName=%q; want %q", gotCtx == ctx, name, wantName)
		}
		pcs := make([]uintptr, 48)
		n := runtime.Callers(1, pcs)
		frames := runtime.CallersFrames(pcs[:n])
		var stack []string
		for {
			frame, more := frames.Next()
			stack = append(stack, frame.Function)
			switch frame.Function {
			case "github.com/metacubex/mihomo/component/ech.(*Config).ClientHandleUTLS":
				branch = "utls"
			case "github.com/metacubex/mihomo/component/ech.(*Config).ClientHandle":
				branch = "tls"
			}
			if !more {
				break
			}
		}
		text := strings.Join(stack, "\n")
		wantTransport := "github.com/metacubex/mihomo/transport/vmess.StreamTLSConn"
		if public && strings.Contains(before, `"Network":"ws"`) {
			wantTransport = "github.com/metacubex/mihomo/transport/vmess.StreamWebsocketConn"
		}
		wantMethod := "streamTLSConn"
		if public || c.kind == "trojan" {
			wantMethod = "StreamConnContext"
		}
		wantType := map[string]string{"vmess": "Vmess", "vless": "Vless", "trojan": "Trojan"}[c.kind]
		wantOutbound := "github.com/metacubex/mihomo/adapter/outbound.(*" + wantType + ")." + wantMethod
		if branch == "" || !strings.Contains(text, wantTransport) || !strings.Contains(text, wantOutbound) {
			t.Errorf("missing actual outbound -> transport -> ECH consumer frames:\n%s", text)
		}
		return nil, stop
	}})
	conn := &outboundRestoreForbiddenConn{}
	var result net.Conn
	var err error
	if public {
		result, err = c.public(ctx, conn)
	} else {
		result, err = c.stream(ctx, conn, isH2)
	}
	if result != nil || conn.calls != 0 || before != c.snapshot() || global != tlsC.GetGlobalFingerprint() {
		t.Fatalf("consumer returned connection, touched IO, or changed options/global: conn=%T IO=%d", result, conn.calls)
	}
	if wantError != "" {
		if err == nil || !strings.Contains(err.Error(), wantError) || calls != 0 || branch != "" {
			t.Fatalf("pre-consumer error=%v ECH=%d branch=%q; want %q before ECH/IO", err, calls, branch, wantError)
		}
		if strings.HasPrefix(wantError, "REALITY") && err.Error() != wantError {
			t.Fatalf("REALITY rejection changed: got %q want exact %q", err, wantError)
		}
		if !strings.HasPrefix(wantError, "REALITY") {
			barrier := "outbound invalid pin observation boundary"
			corelog.Debugln(barrier)
			for ready := false; !ready; {
				select {
				case event := <-sub:
					ready = event.Payload == barrier
					if strings.HasPrefix(event.Payload, "use specified fingerprint:") || strings.HasPrefix(event.Payload, "use initial random HelloID:") {
						t.Errorf("browser selection ran before invalid certificate pin rejection: %q", event.Payload)
					}
				case <-timer.C:
					t.Fatal("invalid pin observation boundary timed out")
				}
			}
		}
		t.Logf("actual %s rejection=%q ECH=0 net.Conn=0", c.kind, err)
		return
	}
	if !errors.Is(err, stop) || calls != 1 || branch != wantBranch {
		t.Fatalf("consumer error=%v ECH=%d branch=%q; want sentinel in %q", err, calls, branch, wantBranch)
	}
	if wantClient != "" {
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
				t.Fatal("actual consumer did not publish its selected browser fingerprint")
			}
		}
		if selected != wantClient {
			t.Fatalf("actual selected browser=%q; want %q", selected, wantClient)
		}
	}
	t.Logf("actual %s consumer branch=%s browser=%q SNI=%q ECH=1 net.Conn=0", c.kind, branch, wantClient, wantName)
}

func TestRestoreOutboundFingerprintConsumers(t *testing.T) {
	outboundRestorePreserveGlobal(t)
	random, enabled := tlsC.GetFingerprintWithoutGlobal("random")
	if !enabled {
		t.Fatal("process-random fixture did not resolve to a browser")
	}
	cases := []struct{ name, global, local, branch, browser string }{
		{"unset", "", "", "tls", ""},
		{"inherit-chrome", "chrome", "", "utls", "Chrome"},
		{"inherit-firefox", "firefox", "", "utls", "Firefox"},
		{"inherit-process-random", "random", "", "utls", random.Client},
		{"local-override", "chrome", "firefox", "utls", "Firefox"},
		{"local-none", "chrome", "none", "tls", ""},
		{"invalid-local-no-fallback", "chrome", "invalid-local", "tls", ""},
		{"whitespace-local-no-fallback", "chrome", " ", "tls", ""},
		{"invalid-global", "invalid-global", "", "tls", ""},
		{"global-none", "none", "", "tls", ""},
		{"local-over-disabled-global", "none", "ios", "utls", "iOS"},
		{"local-over-invalid-global", "invalid-global", "safari", "utls", "Safari"},
	}
	for _, kind := range []string{"vmess", "vless", "trojan"} {
		for _, tc := range cases {
			for _, skip := range []bool{false, true} {
				name := kind + "/" + tc.name + "/verify"
				if skip {
					name = kind + "/" + tc.name + "/skip-verify"
				}
				t.Run(name, func(t *testing.T) {
					tlsC.SetGlobalFingerprint(tc.global)
					in := outboundRestoreDefaults()
					in.local, in.skipVerify = tc.local, skip
					mustOutboundRestoreConsumer(t, kind, in).check(t, false, false, in.serverName, tc.branch, tc.browser, "")
				})
			}
		}
	}
}

func TestRestoreOutboundFingerprintGlobalChanges(t *testing.T) {
	outboundRestorePreserveGlobal(t)
	for _, kind := range []string{"vmess", "vless", "trojan"} {
		t.Run(kind, func(t *testing.T) {
			tlsC.SetGlobalFingerprint("chrome")
			var consumers []*outboundRestoreConsumer
			for _, local := range []string{"", "firefox", "none", "invalid-local"} {
				in := outboundRestoreDefaults()
				in.local = local
				consumers = append(consumers, mustOutboundRestoreConsumer(t, kind, in))
			}
			for _, state := range []struct{ name, global, branch, browser string }{
				{"first", "chrome", "utls", "Chrome"},
				{"changed", "firefox", "utls", "Firefox"},
				{"disabled", "none", "tls", ""},
				{"invalid", "invalid-global", "tls", ""},
				{"cleared", "", "tls", ""},
				{"reapplied", "chrome", "utls", "Chrome"},
				{"cleared-again", "", "tls", ""},
			} {
				t.Run(state.name, func(t *testing.T) {
					tlsC.SetGlobalFingerprint(state.global)
					consumers[0].check(t, false, false, "sni.invalid", state.branch, state.browser, "")
					consumers[1].check(t, false, false, "sni.invalid", "utls", "Firefox", "")
					consumers[2].check(t, false, false, "sni.invalid", "tls", "", "")
					consumers[3].check(t, false, false, "sni.invalid", "tls", "", "")
				})
			}
		})
	}
}

func TestRestoreOutboundServerNameRoutesAndALPNOptions(t *testing.T) {
	outboundRestorePreserveGlobal(t)
	for _, kind := range []string{"vmess", "vless", "trojan"} {
		for _, network := range []string{"tcp", "http", "h2", "ws"} {
			if kind == "trojan" && (network == "http" || network == "h2") {
				continue
			}
			for _, local := range []string{"", "none"} {
				for _, alpn := range []struct {
					name string
					list []string
				}{
					{"nil-default", nil}, {"explicit-empty", []string{}},
					{"explicit-list", []string{"outbound-private/1", "http/1.1"}},
				} {
					for _, override := range []bool{false, true} {
						name := kind + "/" + network + "/inherit/" + alpn.name + "/default-name"
						if local == "none" {
							name = strings.Replace(name, "/inherit/", "/local-none/", 1)
						}
						if override {
							name = strings.Replace(name, "/default-name", "/explicit-name", 1)
						}
						t.Run(name, func(t *testing.T) {
							tlsC.SetGlobalFingerprint("chrome")
							in := outboundRestoreDefaults()
							in.network, in.local, in.alpn = network, local, alpn.list
							in.serverName = ""
							in.wsHeaders = map[string]string{"Host": "ws-host.invalid"}
							wantName := in.server
							if network == "ws" && kind != "trojan" {
								wantName = "ws-host.invalid"
							}
							if override {
								in.serverName, wantName = "explicit-sni.invalid", "explicit-sni.invalid"
							}
							branch, browser := "utls", "Chrome"
							if local == "none" {
								branch, browser = "tls", ""
							}
							// ECH exposes SNI/branch, not the final TLS NextProtos. ALPN here is constructor/input preservation only.
							mustOutboundRestoreConsumer(t, kind, in).check(t, true, false, wantName, branch, browser, "")
						})
					}
				}
			}
		}
	}
}

func TestRestoreOutboundIPv6DefaultServerName(t *testing.T) {
	outboundRestorePreserveGlobal(t)
	tlsC.SetGlobalFingerprint("none")
	for _, kind := range []string{"vmess", "vless", "trojan"} {
		t.Run(kind, func(t *testing.T) {
			in := outboundRestoreDefaults()
			in.server, in.serverName = "2001:db8::1", ""
			mustOutboundRestoreConsumer(t, kind, in).check(t, false, false, in.server, "tls", "", "")
		})
	}
}

func TestRestoreOutboundCertificatePinPrecedence(t *testing.T) {
	outboundRestorePreserveGlobal(t)
	tlsC.SetGlobalFingerprint("chrome")
	for _, kind := range []string{"vmess", "vless", "trojan"} {
		for _, network := range []string{"tcp", "h2", "ws"} {
			if kind == "trojan" && network == "h2" {
				continue
			}
			for _, local := range []string{"", "none", "invalid-local", "firefox"} {
				for _, pin := range []struct{ name, value, message string }{
					{"browser-as-pin", "chrome", "`fingerprint` is used for TLS certificate pinning. If you need to specify the browser fingerprint, use `client-fingerprint`"},
					{"wrong-length", "01", "fingerprint string length error,need sha256 fingerprint"},
					{"malformed", "not-hex", "fingerprint string decode error"},
				} {
					localName := local
					if localName == "" {
						localName = "inherit"
					}
					t.Run(kind+"/"+network+"/"+localName+"/"+pin.name, func(t *testing.T) {
						in := outboundRestoreDefaults()
						in.network, in.local, in.pin, in.skipVerify = network, local, pin.value, true
						mustOutboundRestoreConsumer(t, kind, in).check(t, true, false, in.serverName, "", "", pin.message)
					})
				}
			}
		}
	}
}

func outboundRestoreRealityOptions() RealityOptions {
	publicKey := make([]byte, 32)
	publicKey[0] = 9
	return RealityOptions{
		PublicKey: base64.RawURLEncoding.EncodeToString(publicKey), ShortID: "01020304a0b0c0d0", SupportX25519MLKEM768: true,
	}
}

func TestRestoreOutboundRealityRejectsDisabledFingerprint(t *testing.T) {
	outboundRestorePreserveGlobal(t)
	for _, kind := range []string{"vmess", "vless", "trojan"} {
		for _, tc := range []struct{ name, global, local string }{
			{"unset", "", ""}, {"global-none", "none", ""}, {"invalid-global", "invalid-global", ""},
			{"local-none", "chrome", "none"}, {"invalid-local", "chrome", "invalid-local"}, {"whitespace-local", "chrome", " "},
		} {
			t.Run(kind+"/"+tc.name, func(t *testing.T) {
				tlsC.SetGlobalFingerprint(tc.global)
				// Enabled REALITY bypasses ECH and is deliberately not executable in this no-handshake fixture.
				if _, enabled := tlsC.GetFingerprint(tc.local); enabled {
					t.Fatal("REALITY negative fixture unexpectedly enables a handshake")
				}
				in := outboundRestoreDefaults()
				in.local, in.reality = tc.local, outboundRestoreRealityOptions()
				consumer := mustOutboundRestoreConsumer(t, kind, in)
				if consumer.reality == nil || consumer.reality.PublicKey == nil {
					t.Fatal("REALITY options were dropped by the real constructor")
				}
				key, _ := base64.RawURLEncoding.DecodeString(in.reality.PublicKey)
				wantID := [8]byte{1, 2, 3, 4, 0xa0, 0xb0, 0xc0, 0xd0}
				if !bytes.Equal(consumer.reality.PublicKey.Bytes(), key) || consumer.reality.ShortID != wantID || !consumer.reality.SupportX25519MLKEM768 {
					t.Fatal("real constructor changed REALITY public key/short ID/ML-KEM flag")
				}
				consumer.check(t, true, false, in.serverName, "", "", "REALITY is based on uTLS, please set a client-fingerprint")
				in.pin = "chrome"
				mustOutboundRestoreConsumer(t, kind, in).check(t, true, false, in.serverName, "", "", "TLS certificate pinning")
			})
		}
	}
}

func TestRestoreOutboundRealityConstructorValidation(t *testing.T) {
	for _, kind := range []string{"vmess", "vless", "trojan"} {
		for _, tc := range []struct{ name, key, shortID, message string }{
			{"bad-base64", "!", "", "invalid REALITY public key"},
			{"short-key", "CQ", "", "invalid REALITY public key"},
			{"bad-short-id", outboundRestoreRealityOptions().PublicKey, "zz", "invalid REALITY short ID"},
			{"long-short-id", outboundRestoreRealityOptions().PublicKey, strings.Repeat("01", 9), "invalid REALITY short id"},
		} {
			t.Run(kind+"/"+tc.name, func(t *testing.T) {
				in := outboundRestoreDefaults()
				in.reality = RealityOptions{PublicKey: tc.key, ShortID: tc.shortID}
				consumer, err := newOutboundRestoreConsumer(t, kind, in)
				if consumer != nil || err == nil || err.Error() != tc.message {
					t.Fatalf("real constructor result=%v error=%v; want %q", consumer, err, tc.message)
				}
			})
		}
		if kind != "trojan" {
			t.Run(kind+"/requires-tls", func(t *testing.T) {
				in := outboundRestoreDefaults()
				in.tls, in.reality = false, outboundRestoreRealityOptions()
				consumer, err := newOutboundRestoreConsumer(t, kind, in)
				if consumer != nil || err == nil || err.Error() != "REALITY requires TLS" {
					t.Fatalf("real constructor result=%v error=%v; want REALITY requires TLS", consumer, err)
				}
			})
		}
	}
}

func TestRestoreOutboundTLSDisabledDoesNotConsumeFingerprintOrPin(t *testing.T) {
	outboundRestorePreserveGlobal(t)
	tlsC.SetGlobalFingerprint("chrome")
	for _, kind := range []string{"vmess", "vless"} {
		t.Run(kind, func(t *testing.T) {
			in := outboundRestoreDefaults()
			in.tls, in.pin = false, "chrome"
			consumer := mustOutboundRestoreConsumer(t, kind, in)
			before := consumer.snapshot()
			consumer.setECH(&ech.Config{GetEncryptedClientHelloConfigList: func(context.Context, string) ([]byte, error) {
				t.Fatal("TLS-disabled stream unexpectedly reached ECH")
				return nil, errors.New("unreachable ECH")
			}})
			for _, isH2 := range []bool{false, true} {
				conn := &outboundRestoreForbiddenConn{}
				got, err := consumer.stream(context.Background(), conn, isH2)
				if got != conn || err != nil || conn.calls != 0 || consumer.snapshot() != before || tlsC.GetGlobalFingerprint() != "chrome" {
					t.Fatalf("TLS-disabled stream changed/touched input: conn=%T error=%v IO=%d", got, err, conn.calls)
				}
			}
		})
	}
}
