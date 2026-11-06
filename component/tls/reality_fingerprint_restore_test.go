package tls_test

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/metacubex/mihomo/component/ech"
	tlsC "github.com/metacubex/mihomo/component/tls"
	"github.com/metacubex/mihomo/transport/vmess"
)

func TestRestoreRealityRejectsDisabledFingerprintBeforeHandshake(t *testing.T) {
	restorePreserveGlobal(t)
	for _, tc := range []struct{ name, global, local string }{
		{"empty", "", ""},
		{"global-none", "none", ""},
		{"invalid-global", "invalid-global", ""},
		{"local-none", "chrome", "none"},
		{"invalid-local-no-fallback", "chrome", "invalid-local"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tlsC.SetGlobalFingerprint(tc.global)
			// Fail closed before a changed resolver could enter REALITY handshake-state construction.
			if _, enabled := tlsC.GetFingerprint(tc.local); enabled {
				t.Fatal("negative REALITY fixture unexpectedly enables a browser fingerprint")
			}
			echCalls := 0
			cfg := &vmess.TLSConfig{
				Host: "consumer.invalid", ClientFingerprint: tc.local,
				NextProtos: []string{"h2"}, Reality: &tlsC.RealityConfig{},
				ECH: &ech.Config{GetEncryptedClientHelloConfigList: func(context.Context, string) ([]byte, error) {
					echCalls++
					return nil, errors.New("unexpected ECH before REALITY rejection")
				}},
			}
			before := *cfg
			before.NextProtos = append([]string(nil), cfg.NextProtos...)
			conn := &restoreForbiddenConn{}
			result, err := vmess.StreamTLSConn(context.Background(), conn, cfg)
			if result != nil || err == nil || err.Error() != "REALITY is based on uTLS, please set a client-fingerprint" {
				t.Fatalf("disabled REALITY result=%T error=%v", result, err)
			}
			if echCalls != 0 || conn.calls != 0 || !reflect.DeepEqual(*cfg, before) || tlsC.GetGlobalFingerprint() != tc.global {
				t.Fatalf("REALITY rejection changed inputs or reached ECH/connection: ECH=%d IO=%d", echCalls, conn.calls)
			}
			t.Log("actual REALITY rejection before ECH/handshake: ECH callbacks=0 net.Conn calls=0")
		})
	}
}

func TestRestoreConsumerPinErrorPrecedesFingerprintBranch(t *testing.T) {
	restorePreserveGlobal(t)
	tlsC.SetGlobalFingerprint("chrome")
	for _, local := range []string{"", "none"} {
		name := "inherit-chrome"
		if local != "" {
			name = "local-none"
		}
		t.Run(name, func(t *testing.T) {
			echCalls := 0
			cfg := &vmess.TLSConfig{
				Host: "consumer.invalid", ClientFingerprint: local, FingerPrint: "chrome",
				ECH: &ech.Config{GetEncryptedClientHelloConfigList: func(context.Context, string) ([]byte, error) {
					echCalls++
					return nil, errors.New("unexpected ECH after invalid pin")
				}},
			}
			conn := &restoreForbiddenConn{}
			result, err := vmess.StreamTLSConn(context.Background(), conn, cfg)
			if result != nil || err == nil || !strings.Contains(err.Error(), "certificate pinning") || !strings.Contains(err.Error(), "client-fingerprint") {
				t.Fatalf("browser-as-pin consumer result=%T error=%v", result, err)
			}
			if echCalls != 0 || conn.calls != 0 || cfg.FingerPrint != "chrome" || cfg.ClientFingerprint != local || tlsC.GetGlobalFingerprint() != "chrome" {
				t.Fatalf("pin error changed policy or reached ECH/connection: ECH=%d IO=%d", echCalls, conn.calls)
			}
			t.Log("actual consumer rejected browser-as-pin before ECH: ECH callbacks=0 net.Conn calls=0")
		})
	}
}
