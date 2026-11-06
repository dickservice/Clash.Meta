package tls_test

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"reflect"
	"strings"
	"testing"

	tlsC "github.com/metacubex/mihomo/component/tls"
	"github.com/metacubex/mihomo/transport/vmess"
	"github.com/metacubex/tls"
	utls "github.com/metacubex/utls"
)

func TestRestoreFingerprintClientConfiguration(t *testing.T) {
	restorePreserveGlobal(t)
	cases := []struct {
		name, global, local string
		want                utls.ClientHelloID
		enabled             bool
	}{
		{"inherited-chrome", "chrome", "", utls.HelloChrome_Auto, true},
		{"inherited-firefox", "firefox", "", utls.HelloFirefox_Auto, true},
		{"local-firefox", "chrome", "firefox", utls.HelloFirefox_Auto, true},
		{"local-safari", "firefox", "safari", utls.HelloSafari_Auto, true},
		{"local-ios", "none", "ios", utls.HelloIOS_Auto, true},
		{"local-opt-out", "chrome", "none", utls.ClientHelloID{}, false},
		{"invalid-local", "chrome", "invalid-local", utls.ClientHelloID{}, false},
		{"invalid-global", "invalid-global", "", utls.ClientHelloID{}, false},
		{"empty-default", "", "", utls.ClientHelloID{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tlsC.SetGlobalFingerprint(tc.global)
			cfg := &vmess.TLSConfig{
				Host: "consumer.invalid", NextProtos: []string{"h2", "http/1.1"},
				ClientFingerprint: tc.local,
			}
			std, err := cfg.ToStdConfig()
			if err != nil {
				t.Fatal(err)
			}
			if std.ServerName != cfg.Host || !reflect.DeepEqual(std.NextProtos, cfg.NextProtos) ||
				std.InsecureSkipVerify || std.RootCAs == nil || std.Time == nil ||
				std.VerifyConnection != nil || std.VerifyPeerCertificate != nil {
				t.Fatal("browser choice changed standard TLS verification or routing configuration")
			}
			id, enabled := tlsC.GetFingerprint(cfg.ClientFingerprint)
			if enabled != tc.enabled || !reflect.DeepEqual(id, tc.want) {
				t.Fatalf("effective HelloID=%v,%v; want %v,%v", id, enabled, tc.want, tc.enabled)
			}
			conn := &restoreForbiddenConn{}
			if enabled {
				uConfig := tlsC.UConfig(std)
				if uConfig.RootCAs != std.RootCAs || uConfig.ServerName != std.ServerName ||
					!reflect.DeepEqual(uConfig.NextProtos, std.NextProtos) || uConfig.InsecureSkipVerify ||
					uConfig.VerifyConnection != nil || uConfig.VerifyPeerCertificate != nil {
					t.Fatal("uTLS conversion changed trust, SNI, ALPN, or verification")
				}
				client := tlsC.UClient(conn, uConfig, id)
				if !reflect.DeepEqual(client.ClientHelloID, tc.want) || client.ConnectionState().HandshakeComplete {
					t.Fatal("memory-only UClient did not retain effective HelloID before handshake")
				}
				t.Logf("constructed UClient HelloID=%s without handshake", client.ClientHelloID.Str())
			} else {
				client := tls.Client(conn, std)
				if client.ConnectionState().HandshakeComplete {
					t.Fatal("ordinary TLS client unexpectedly handshook")
				}
			}
			if conn.calls != 0 {
				t.Fatalf("configuration touched connection %d times", conn.calls)
			}
		})
	}
}

func TestRestoreFingerprintPinningRemainsIndependent(t *testing.T) {
	restorePreserveGlobal(t)
	der := []byte("memory-only certificate identity fixture")
	digest := sha256.Sum256(der)
	for _, global := range []string{"chrome", "firefox", "none", "invalid-global", ""} {
		t.Run("global-"+global, func(t *testing.T) {
			tlsC.SetGlobalFingerprint(global)
			cfg := &vmess.TLSConfig{
				Host: "consumer.invalid", ClientFingerprint: "firefox",
				NextProtos: []string{"h2"}, FingerPrint: hex.EncodeToString(digest[:]),
			}
			std, err := cfg.ToStdConfig()
			if err != nil {
				t.Fatal(err)
			}
			if !std.InsecureSkipVerify || std.VerifyConnection == nil {
				t.Fatal("explicit certificate pin verifier missing")
			}
			state := tls.ConnectionState{
				ServerName:       cfg.Host,
				PeerCertificates: []*x509.Certificate{{Raw: der}},
			}
			if err := std.VerifyConnection(state); err != nil {
				t.Fatalf("matching in-memory leaf pin rejected: %v", err)
			}
			state.PeerCertificates = []*x509.Certificate{{Raw: []byte("different certificate")}}
			if err := std.VerifyConnection(state); err == nil {
				t.Fatal("mismatched certificate accepted by explicit pin")
			}
			uConfig := tlsC.UConfig(std)
			if !uConfig.InsecureSkipVerify || uConfig.VerifyConnection == nil {
				t.Fatal("uTLS conversion lost explicit certificate pin verifier")
			}
			if err := uConfig.VerifyConnection(utls.ConnectionState{
				ServerName: cfg.Host, PeerCertificates: []*x509.Certificate{{Raw: der}},
			}); err != nil {
				t.Fatalf("uTLS matching pin rejected: %v", err)
			}
			if err := uConfig.VerifyConnection(utls.ConnectionState{
				ServerName: cfg.Host, PeerCertificates: state.PeerCertificates,
			}); err == nil {
				t.Fatal("uTLS conversion bypassed certificate pin")
			}
			cfg.FingerPrint = "chrome"
			if _, err := cfg.ToStdConfig(); err == nil || !strings.Contains(err.Error(), "certificate pinning") {
				t.Fatalf("browser fingerprint incorrectly accepted as certificate pin: %v", err)
			}
		})
	}
}
