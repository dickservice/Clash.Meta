package config

import (
	"fmt"
	"testing"

	ST "github.com/metacubex/mihomo/constant/sniffer"
)

func TestParseSnifferRestoreOverridePrecedence(t *testing.T) {
	falseValue, trueValue := false, true
	for _, enable := range []bool{false, true} {
		for _, global := range []bool{false, true} {
			for _, override := range []struct {
				name  string
				value *bool
			}{
				{"inherit", nil}, {"explicit_false", &falseValue}, {"explicit_true", &trueValue},
			} {
				t.Run(fmt.Sprintf("enable_%t/global_%t/%s", enable, global, override.name), func(t *testing.T) {
					raw := RawSniffer{
						Enable: enable, OverrideDest: global, ForceDnsMapping: !global, ParsePureIp: global,
						Sniff: map[string]RawSniffingConfig{
							"hTtP": {Ports: []string{"80", "8080-8081"}, OverrideDest: override.value},
							"tLs":  {Ports: []string{"443", "8443"}, OverrideDest: override.value},
							"qUiC": {Ports: []string{"443", "4443"}, OverrideDest: override.value},
						},
					}
					parsed, err := parseSniffer(raw, nil)
					if err != nil {
						t.Fatal(err)
					}
					if parsed.Enable != enable || parsed.ForceDnsMapping != raw.ForceDnsMapping || parsed.ParsePureIp != raw.ParsePureIp {
						t.Fatalf("parsed flags = %#v, raw = %#v", parsed, raw)
					}
					if len(parsed.Sniffers) != 3 {
						t.Fatalf("got %d sniffers, want 3", len(parsed.Sniffers))
					}
					wantOverride := global
					if override.value != nil {
						wantOverride = *override.value
					}
					for protocol, wantPorts := range map[ST.Type]string{
						ST.HTTP: "80/8080-8081", ST.TLS: "443/8443", ST.QUIC: "443/4443",
					} {
						got, ok := parsed.Sniffers[protocol]
						if !ok || got.OverrideDest != wantOverride || got.Ports.String() != wantPorts {
							t.Errorf("%s = %#v (present %t), want override %t, ports %s", protocol, got, ok, wantOverride, wantPorts)
						}
					}
				})
			}
		}
	}
}

func TestParseSnifferRestoreIndependentProtocolOverrides(t *testing.T) {
	falseValue, trueValue := false, true
	parsed, err := parseSniffer(RawSniffer{
		Enable: true, OverrideDest: true,
		Sniff: map[string]RawSniffingConfig{
			"HTTP": {OverrideDest: &falseValue},
			"TLS":  {},
			"QUIC": {OverrideDest: &trueValue},
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for protocol, want := range map[ST.Type]bool{ST.HTTP: false, ST.TLS: true, ST.QUIC: true} {
		got, ok := parsed.Sniffers[protocol]
		if !ok || got.OverrideDest != want {
			t.Errorf("%s override = %t (present %t), want %t", protocol, got.OverrideDest, ok, want)
		}
	}
}
