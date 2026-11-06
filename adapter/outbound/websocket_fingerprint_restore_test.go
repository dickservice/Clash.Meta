package outbound

import (
	"context"
	"net"
	"reflect"
	"testing"

	N "github.com/metacubex/mihomo/common/net"
)

func outboundRestoreLazyWebsocketConfig(t *testing.T, conn net.Conn) reflect.Value {
	t.Helper()
	var value any = conn
	for depth := 0; depth < 12; depth++ {
		v := reflect.ValueOf(value)
		if v.Kind() == reflect.Pointer && v.Elem().Type().PkgPath() == "github.com/metacubex/mihomo/transport/vmess" &&
			v.Elem().Type().Name() == "websocketWithEarlyDataConn" {
			cfg := v.Elem().FieldByName("config")
			if cfg.Kind() != reflect.Pointer || cfg.IsNil() {
				t.Fatal("actual deferred WebSocket consumer has no configuration")
			}
			return cfg.Elem()
		}
		upstream, ok := value.(interface{ Upstream() any })
		if !ok {
			t.Fatalf("missing reviewed deferred WebSocket in actual wrapper chain at %T", value)
		}
		value = upstream.Upstream()
	}
	t.Fatal("actual deferred WebSocket wrapper chain exceeded review bound")
	return reflect.Value{}
}

func outboundRestoreReadStrings(t *testing.T, v reflect.Value) []string {
	t.Helper()
	if v.Kind() != reflect.Slice || v.Type().Elem().Kind() != reflect.String {
		t.Fatal("actual consumer field is not a string slice")
	}
	if v.IsNil() {
		return nil
	}
	values := make([]string, v.Len())
	for i := range values {
		values[i] = v.Index(i).String()
	}
	return values
}

func TestRestoreOutboundDeferredWebsocketALPNOverride(t *testing.T) {
	outboundRestorePreserveGlobal(t)
	// VMess/VLESS defer protocol headers too. Trojan writes its header immediately, so cannot return this inspection boundary.
	for _, kind := range []string{"vmess", "vless"} {
		for _, option := range []struct {
			name string
			alpn []string
		}{
			{"nil", nil}, {"empty", []string{}}, {"custom", []string{"outbound-private/1", "h2"}},
		} {
			for _, skip := range []bool{false, true} {
				name := kind + "/" + option.name + "/pinned"
				if skip {
					name += "-skip-verify"
				}
				t.Run(name, func(t *testing.T) {
					in := outboundRestoreDefaults()
					in.network, in.wsEarly, in.alpn, in.skipVerify = "ws", 64, option.alpn, skip
					in.local = "firefox"
					consumer := mustOutboundRestoreConsumer(t, kind, in)
					before := consumer.snapshot()
					conn := &outboundRestoreForbiddenConn{}
					got, err := consumer.public(context.Background(), conn)
					if err != nil || got == nil || conn.calls != 0 || before != consumer.snapshot() {
						t.Fatalf("actual deferred constructor result=%T error=%v IO=%d", got, err, conn.calls)
					}
					cfg := outboundRestoreLazyWebsocketConfig(t, got)
					if !cfg.FieldByName("TLS").Bool() || cfg.FieldByName("ClientFingerprint").String() != in.local ||
						cfg.FieldByName("MaxEarlyData").Int() != 64 || cfg.FieldByName("ECHConfig").IsNil() {
						t.Fatal("actual WebSocket consumer lost TLS/client-fingerprint/ECH/early-data options")
					}
					tlsConfig := cfg.FieldByName("TLSConfig")
					if tlsConfig.IsNil() {
						t.Fatal("actual WebSocket consumer has no TLS configuration")
					}
					tlsConfig = tlsConfig.Elem()
					if alpn := outboundRestoreReadStrings(t, tlsConfig.FieldByName("NextProtos")); !reflect.DeepEqual(alpn, []string{"http/1.1"}) {
						t.Fatalf("actual WebSocket ALPN=%q; explicit/nil/empty input must all yield HTTP/1.1", alpn)
					}
					if tlsConfig.FieldByName("ServerName").String() != in.serverName || tlsConfig.FieldByName("RootCAs").IsNil() ||
						!tlsConfig.FieldByName("InsecureSkipVerify").Bool() || tlsConfig.FieldByName("VerifyConnection").IsNil() {
						t.Fatal("actual WebSocket TLS configuration lost SNI/trust/explicit pin verifier")
					}
					if !N.NeedHandshake(got) || conn.calls != 0 {
						t.Fatal("inspection completed a deferred protocol/TLS handshake or touched the underlying connection")
					}
					t.Logf("actual %s deferred WebSocket ALPN=[http/1.1], configured=%v, pin verifier present, handshake still required, net.Conn=0", kind, in.alpn)
				})
			}
		}
	}
}

func TestRestoreOutboundDeferredWebsocketTrustOptions(t *testing.T) {
	outboundRestorePreserveGlobal(t)
	for _, kind := range []string{"vmess", "vless"} {
		for _, mode := range []struct {
			name, pin, verifyName    string
			skip, wantSkip, verifier bool
		}{
			{"ordinary-verify", "", "", false, false, false},
			{"ordinary-skip", "", "", true, true, false},
			{"name-only", "", "certificate-name.invalid", false, true, true},
			{"leaf-pin", outboundRestoreDefaults().pin, "", false, true, true},
		} {
			t.Run(kind+"/"+mode.name, func(t *testing.T) {
				in := outboundRestoreDefaults()
				in.network, in.wsEarly, in.serverName = "ws", 64, ""
				in.pin, in.verifyName, in.skipVerify = mode.pin, mode.verifyName, mode.skip
				in.wsHeaders = map[string]string{"Host": "ws-host.invalid"}
				consumer := mustOutboundRestoreConsumer(t, kind, in)
				conn := &outboundRestoreForbiddenConn{}
				got, err := consumer.public(context.Background(), conn)
				if err != nil || got == nil || conn.calls != 0 {
					t.Fatalf("deferred WebSocket result=%T error=%v IO=%d", got, err, conn.calls)
				}
				cfg := outboundRestoreLazyWebsocketConfig(t, got)
				tlsConfig := cfg.FieldByName("TLSConfig").Elem()
				if tlsConfig.FieldByName("ServerName").String() != "ws-host.invalid" ||
					tlsConfig.FieldByName("InsecureSkipVerify").Bool() != mode.wantSkip ||
					!tlsConfig.FieldByName("VerifyConnection").IsNil() != mode.verifier ||
					!tlsConfig.FieldByName("VerifyPeerCertificate").IsNil() || tlsConfig.FieldByName("RootCAs").IsNil() ||
					!N.NeedHandshake(got) || conn.calls != 0 {
					t.Fatal("actual deferred consumer did not preserve independent name/pin/skip verification settings")
				}
			})
		}
	}
}
