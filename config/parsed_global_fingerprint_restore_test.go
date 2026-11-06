package config

import (
	"reflect"
	"testing"

	tlsC "github.com/metacubex/mihomo/component/tls"

	utls "github.com/metacubex/utls"
)

// Keep the seam below ParseRawConfig: it temporarily updates executor globals and constructs providers.
func TestParsedGeneralFingerprintSetterResetRestore(t *testing.T) {
	for _, baseline := range []struct{ name, value string }{
		{"empty", ""}, {"chrome", "chrome"}, {"none", "none"},
	} {
		for _, profile := range []struct{ name, yaml, want string }{
			{"chrome", "global-client-fingerprint: chrome\n", "chrome"},
			{"none", "global-client-fingerprint: none\n", "none"},
			{"empty", "global-client-fingerprint: ''\n", ""},
			{"omitted", "{}\n", ""},
		} {
			t.Run(baseline.name+"_to_"+profile.name, func(t *testing.T) {
				old := tlsC.GetGlobalFingerprint()
				t.Cleanup(func() { tlsC.SetGlobalFingerprint(old) })
				tlsC.SetGlobalFingerprint(baseline.value)

				raw, err := UnmarshalRawConfig([]byte(profile.yaml))
				if err != nil {
					t.Fatal(err)
				}
				general, err := parseGeneral(raw)
				if err != nil {
					t.Fatal(err)
				}
				if raw.GlobalClientFingerprint != profile.want || general.GlobalClientFingerprint != profile.want {
					t.Fatalf("raw/General fingerprint = %q/%q, want %q", raw.GlobalClientFingerprint, general.GlobalClientFingerprint, profile.want)
				}
				if got := tlsC.GetGlobalFingerprint(); got != baseline.value {
					t.Fatalf("decode/parse changed global to %q, want %q", got, baseline.value)
				}

				tlsC.SetGlobalFingerprint(general.GlobalClientFingerprint)
				assertParsedFingerprintSnapshotRestore(t, profile.want)

				raw.GlobalClientFingerprint = "firefox"
				general.GlobalClientFingerprint = "firefox"
				assertParsedFingerprintSnapshotRestore(t, profile.want)

				tlsC.SetGlobalFingerprint("")
				assertParsedFingerprintSnapshotRestore(t, "")
				tlsC.SetGlobalFingerprint("")
				assertParsedFingerprintSnapshotRestore(t, "")
				tlsC.SetGlobalFingerprint("chrome")
				assertParsedFingerprintSnapshotRestore(t, "chrome")
				tlsC.SetGlobalFingerprint("")
				assertParsedFingerprintSnapshotRestore(t, "")
			})
		}
	}
}

func assertParsedFingerprintSnapshotRestore(t *testing.T, wantGlobal string) {
	t.Helper()
	if got := tlsC.GetGlobalFingerprint(); got != wantGlobal {
		t.Fatalf("stored fingerprint = %q, want %q", got, wantGlobal)
	}
	for _, local := range []string{"", "chrome", "none"} {
		wantOK := local == "chrome" || local == "" && wantGlobal == "chrome"
		want := tlsC.UClientHelloID{}
		if wantOK {
			want = utls.HelloChrome_Auto
		}
		if got, ok := tlsC.GetFingerprint(local); ok != wantOK || !reflect.DeepEqual(got, want) {
			t.Fatalf("global %q, local %q: fingerprint = %#v/%t, want %#v/%t", wantGlobal, local, got, ok, want, wantOK)
		}
		if got := tlsC.GetGlobalFingerprint(); got != wantGlobal {
			t.Fatalf("local resolution changed global to %q, want %q", got, wantGlobal)
		}
	}
}
