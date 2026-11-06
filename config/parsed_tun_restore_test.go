package config

import (
	"encoding/json"
	"net/netip"
	"reflect"
	"testing"

	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
)

func TestParseTunRestoreFakeIPPrefix(t *testing.T) {
	for _, tc := range []struct {
		name, fakeIP, want string
	}{
		{"default", "", "198.18.0.1/30"},
		{"custom_host_bits", "203.0.113.19/24", "203.0.113.19/30"},
		{"custom_large_range", "198.18.23.7/16", "198.18.23.7/30"},
		{"custom_single_address", "192.0.2.9/32", "192.0.2.9/30"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var fakeIP netip.Prefix
			if tc.fakeIP != "" {
				fakeIP = netip.MustParsePrefix(tc.fakeIP)
			}
			dns := &DNS{FakeIPRange: fakeIP}
			general := &General{}
			if err := parseTun(RawTun{}, dns, general); err != nil {
				t.Fatal(err)
			}
			want := []netip.Prefix{netip.MustParsePrefix(tc.want)}
			if !reflect.DeepEqual(general.Tun.Inet4Address, want) {
				t.Fatalf("Inet4Address = %v, want %v (including host bits)", general.Tun.Inet4Address, want)
			}
			if dns.FakeIPRange != fakeIP {
				t.Fatalf("parseTun changed DNS fake-IP prefix: %v -> %v", fakeIP, dns.FakeIPRange)
			}
		})
	}
}

func TestParseTunRestoreFieldCopy(t *testing.T) {
	prefix := netip.MustParsePrefix
	for _, tc := range []struct {
		name string
		raw  RawTun
		want LC.Tun
	}{
		{"nil_routes", RawTun{}, LC.Tun{}},
		{
			name: "empty_routes",
			raw: RawTun{
				RouteAddress: []netip.Prefix{}, RouteExcludeAddress: []netip.Prefix{},
				RouteAddressSet: []string{}, RouteExcludeAddressSet: []string{},
			},
			want: LC.Tun{
				RouteAddress: []netip.Prefix{}, RouteExcludeAddress: []netip.Prefix{},
				RouteAddressSet: []string{}, RouteExcludeAddressSet: []string{},
			},
		},
		{
			name: "mixed_prefixes_and_filters",
			raw: RawTun{
				Enable: true, Device: "parser-only", Stack: C.TunMixed,
				DNSHijack: []string{"any:53", "tcp://any:53"}, AutoRoute: true, AutoDetectInterface: true,
				MTU: 1400, GSO: true, GSOMaxSize: 32768,
				Inet6Address:       []netip.Prefix{prefix("fd00::7/126")},
				IPRoute2TableIndex: 2022, IPRoute2RuleIndex: 9000,
				AutoRedirect: true, AutoRedirectInputMark: 101, AutoRedirectOutputMark: 102,
				AutoRedirectIPRoute2FallbackRuleIndex: 32760,
				LoopbackAddress:                       []netip.Addr{netip.MustParseAddr("10.0.0.1")}, StrictRoute: true,
				RouteAddress:           []netip.Prefix{prefix("2001:db8::7/64"), prefix("192.0.2.9/24")},
				RouteExcludeAddress:    []netip.Prefix{prefix("198.51.100.17/25"), prefix("2001:db8:1::9/80")},
				RouteAddressSet:        []string{"routes-b", "routes-a"},
				RouteExcludeAddressSet: []string{"exclude-b", "exclude-a"},
				IncludeInterface:       []string{"if-b", "if-a"}, ExcludeInterface: []string{"if-c"},
				IncludeUID: []uint32{10002, 10001}, IncludeUIDRange: []string{"11000:11999"},
				ExcludeUID: []uint32{12001}, ExcludeUIDRange: []string{"13000:13999"},
				ExcludeSrcPort: []uint16{53}, ExcludeSrcPortRange: []string{"1000:1010"},
				ExcludeDstPort: []uint16{5353}, ExcludeDstPortRange: []string{"2000:2010"},
				IncludeAndroidUser: []int{10, 0}, IncludePackage: []string{"example.include"},
				ExcludePackage:    []string{"example.exclude"},
				IncludeMACAddress: []string{"00:11:22:33:44:55"}, ExcludeMACAddress: []string{"00:11:22:33:44:66"},
				EndpointIndependentNat: true, UDPTimeout: 29, DisableICMPForwarding: true, FileDescriptor: 77,
				Inet4RouteAddress:        []netip.Prefix{prefix("203.0.113.11/24")},
				Inet6RouteAddress:        []netip.Prefix{prefix("2001:db8:2::5/64")},
				Inet4RouteExcludeAddress: []netip.Prefix{prefix("192.0.2.19/28")},
				Inet6RouteExcludeAddress: []netip.Prefix{prefix("2001:db8:3::6/96")},
				RecvMsgX:                 true, SendMsgX: true,
			},
			want: LC.Tun{
				Enable: true, Device: "parser-only", Stack: C.TunMixed,
				DNSHijack: []string{"any:53", "tcp://any:53"}, AutoRoute: true, AutoDetectInterface: true,
				MTU: 1400, GSO: true, GSOMaxSize: 32768,
				Inet6Address:       []netip.Prefix{prefix("fd00::7/126")},
				IPRoute2TableIndex: 2022, IPRoute2RuleIndex: 9000,
				AutoRedirect: true, AutoRedirectInputMark: 101, AutoRedirectOutputMark: 102,
				AutoRedirectIPRoute2FallbackRuleIndex: 32760,
				LoopbackAddress:                       []netip.Addr{netip.MustParseAddr("10.0.0.1")}, StrictRoute: true,
				RouteAddress:           []netip.Prefix{prefix("2001:db8::7/64"), prefix("192.0.2.9/24")},
				RouteExcludeAddress:    []netip.Prefix{prefix("198.51.100.17/25"), prefix("2001:db8:1::9/80")},
				RouteAddressSet:        []string{"routes-b", "routes-a"},
				RouteExcludeAddressSet: []string{"exclude-b", "exclude-a"},
				IncludeInterface:       []string{"if-b", "if-a"}, ExcludeInterface: []string{"if-c"},
				IncludeUID: []uint32{10002, 10001}, IncludeUIDRange: []string{"11000:11999"},
				ExcludeUID: []uint32{12001}, ExcludeUIDRange: []string{"13000:13999"},
				ExcludeSrcPort: []uint16{53}, ExcludeSrcPortRange: []string{"1000:1010"},
				ExcludeDstPort: []uint16{5353}, ExcludeDstPortRange: []string{"2000:2010"},
				IncludeAndroidUser: []int{10, 0}, IncludePackage: []string{"example.include"},
				ExcludePackage:    []string{"example.exclude"},
				IncludeMACAddress: []string{"00:11:22:33:44:55"}, ExcludeMACAddress: []string{"00:11:22:33:44:66"},
				EndpointIndependentNat: true, UDPTimeout: 29, DisableICMPForwarding: true, FileDescriptor: 77,
				Inet4RouteAddress:        []netip.Prefix{prefix("203.0.113.11/24")},
				Inet6RouteAddress:        []netip.Prefix{prefix("2001:db8:2::5/64")},
				Inet4RouteExcludeAddress: []netip.Prefix{prefix("192.0.2.19/28")},
				Inet6RouteExcludeAddress: []netip.Prefix{prefix("2001:db8:3::6/96")},
				RecvMsgX:                 true, SendMsgX: true,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before, err := json.Marshal(tc.raw)
			if err != nil {
				t.Fatal(err)
			}
			general := &General{}
			if err := parseTun(tc.raw, &DNS{}, general); err != nil {
				t.Fatal(err)
			}
			tc.want.Inet4Address = []netip.Prefix{prefix("198.18.0.1/30")}
			if !reflect.DeepEqual(general.Tun, tc.want) {
				t.Fatalf("Tun = %#v, want %#v", general.Tun, tc.want)
			}
			after, err := json.Marshal(tc.raw)
			if err != nil {
				t.Fatal(err)
			}
			if string(before) != string(after) {
				t.Fatalf("parseTun mutated input:\nbefore %s\nafter  %s", before, after)
			}
		})
	}
}

// The original RawTun lacks this field; this locks the fork's additive behavior,
// not an original-APK timeout default or effective ICMP behavior.
func TestParseTunCurrentAdditiveICMPTimeout(t *testing.T) {
	const baseline = "tun:\n  enable: true\n  udp-timeout: 29\n  route-address: [192.0.2.9/24, '2001:db8::7/64']\n"
	base, err := UnmarshalRawConfig([]byte(baseline))
	if err != nil {
		t.Fatal(err)
	}
	baseGeneral := &General{}
	if err := parseTun(base.Tun, &DNS{}, baseGeneral); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, extra string
		want        int64
	}{
		{"omitted", "", 0},
		{"explicit_zero", "  icmp-timeout: 0\n", 0},
		{"explicit_value", "  icmp-timeout: 17\n", 17},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := UnmarshalRawConfig([]byte(baseline + tc.extra))
			if err != nil {
				t.Fatal(err)
			}
			wantRaw := base.Tun
			wantRaw.ICMPTimeout = tc.want
			if !reflect.DeepEqual(raw.Tun, wantRaw) {
				t.Fatalf("decoded Tun = %#v, want %#v", raw.Tun, wantRaw)
			}
			general := &General{}
			if err := parseTun(raw.Tun, &DNS{}, general); err != nil {
				t.Fatal(err)
			}
			wantTun := baseGeneral.Tun
			wantTun.ICMPTimeout = tc.want
			if !reflect.DeepEqual(general.Tun, wantTun) {
				t.Fatalf("parsed Tun = %#v, want %#v", general.Tun, wantTun)
			}
		})
	}
}
