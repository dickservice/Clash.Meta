package sniffer

import (
	"errors"
	"fmt"
	"reflect"
	"testing"

	C "github.com/metacubex/mihomo/constant"
	ST "github.com/metacubex/mihomo/constant/sniffer"
)

func TestRestoreNewSnifferConstruction(t *testing.T) {
	for _, tc := range []struct {
		kind     ST.Type
		protocol string
	}{
		{ST.TLS, "tls"}, {ST.HTTP, "http"}, {ST.QUIC, "quic"},
		{ST.Type(-1), ""}, {ST.Type(3), ""}, {ST.Type(255), ""},
	} {
		t.Run(fmt.Sprintf("type_%d", tc.kind), func(t *testing.T) {
			got, err := NewSniffer(tc.kind, SnifferConfig{})
			if tc.protocol == "" {
				if got != nil || !errors.Is(err, ErrorUnsupportedSniffer) {
					t.Fatalf("NewSniffer(%d) = %v, %v; want nil, unsupported", tc.kind, got, err)
				}
				return
			}
			if err != nil || got == nil {
				t.Fatalf("NewSniffer(%d) = %v, %v", tc.kind, got, err)
			}
			if got.Protocol() != tc.protocol {
				t.Fatalf("protocol = %q, want %q", got.Protocol(), tc.protocol)
			}
		})
	}
}

func TestRestoreNewDispatcherConstruction(t *testing.T) {
	for _, enable := range []bool{false, true} {
		for _, populated := range []bool{false, true} {
			t.Run(fmt.Sprintf("enable_%t/populated_%t", enable, populated), func(t *testing.T) {
				config := &Config{Enable: enable, ForceDnsMapping: true, ParsePureIp: true}
				if populated {
					config.Sniffers = map[ST.Type]SnifferConfig{
						ST.TLS: {OverrideDest: true}, ST.HTTP: {OverrideDest: false}, ST.QUIC: {OverrideDest: true},
					}
				}
				got, err := NewDispatcher(config)
				if err != nil || got == nil {
					t.Fatalf("NewDispatcher = %v, %v", got, err)
				}
				if got.Enable() != enable || got.forceDnsMapping != config.ForceDnsMapping || got.parsePureIp != config.ParsePureIp {
					t.Fatalf("dispatcher flags = %#v, config = %#v", got, config)
				}
				if len(got.sniffers) != len(config.Sniffers) {
					t.Fatalf("got %d sniffers, want %d", len(got.sniffers), len(config.Sniffers))
				}
				seen := make(map[ST.Type]bool)
				for _, current := range got.sniffers {
					var kind ST.Type
					switch current.Protocol() {
					case "tls":
						kind = ST.TLS
					case "http":
						kind = ST.HTTP
					case "quic":
						kind = ST.QUIC
					default:
						t.Fatalf("unexpected protocol %q", current.Protocol())
					}
					if seen[kind] {
						t.Fatalf("duplicate protocol %s", kind)
					}
					seen[kind] = true
					if !reflect.DeepEqual(current.config, config.Sniffers[kind]) {
						t.Errorf("%s config = %#v, want %#v", kind, current.config, config.Sniffers[kind])
					}
				}
			})
		}
	}
	var absent *Dispatcher
	if absent.Enable() {
		t.Fatal("nil dispatcher must be disabled")
	}
}

func TestRestoreNewDispatcherUnsupportedReturnsFreshDisabled(t *testing.T) {
	for _, enable := range []bool{false, true} {
		for _, mixed := range []bool{false, true} {
			t.Run(fmt.Sprintf("enable_%t/mixed_%t", enable, mixed), func(t *testing.T) {
				config := &Config{
					Enable: enable, ForceDnsMapping: true, ParsePureIp: true,
					Sniffers:       map[ST.Type]SnifferConfig{ST.Type(3): {OverrideDest: true}},
					ForceDomain:    []C.DomainMatcher{nil},
					SkipDomain:     []C.DomainMatcher{nil},
					SkipSrcAddress: []C.IpMatcher{nil},
					SkipDstAddress: []C.IpMatcher{nil},
				}
				if mixed {
					config.Sniffers[ST.TLS] = SnifferConfig{OverrideDest: true}
					config.Sniffers[ST.HTTP] = SnifferConfig{}
					config.Sniffers[ST.QUIC] = SnifferConfig{OverrideDest: true}
				}
				first, err := NewDispatcher(config)
				if !errors.Is(err, ErrorUnsupportedSniffer) || first == nil {
					t.Fatalf("NewDispatcher = %v, %v; want nonnil, unsupported", first, err)
				}
				if first.Enable() || !reflect.DeepEqual(first, &Dispatcher{}) {
					t.Fatalf("failed dispatcher retained partial state: %#v", first)
				}
				second, err := NewDispatcher(config)
				if !errors.Is(err, ErrorUnsupportedSniffer) || second == nil || second == first || !reflect.DeepEqual(second, &Dispatcher{}) {
					t.Fatalf("second construction = %p, %v; want fresh zero dispatcher distinct from %p", second, err, first)
				}
			})
		}
	}
}
