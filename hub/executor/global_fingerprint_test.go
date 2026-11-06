package executor

import (
	"encoding/json"
	"testing"

	tlsC "github.com/metacubex/mihomo/component/tls"
)

func TestGlobalFingerprintProfileReset(t *testing.T) {
	old := GetGeneral()
	t.Cleanup(func() { updateGeneral(old, false) })
	// Use a full General snapshot to keep unrelated runtime settings unchanged.
	for _, tc := range []struct {
		name, value string
		logging     bool
	}{
		{"profile A", "chrome", true}, {"profile B", "firefox", false},
		{"explicit none", "none", false}, {"empty profile clears", "", true},
		{"profile after clear", "chrome", false}, {"default reset clears without logging", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			general := *old
			general.GlobalClientFingerprint = tc.value
			updateGeneral(&general, tc.logging)
			if got := tlsC.GetGlobalFingerprint(); got != tc.value {
				t.Fatalf("global = %q, want %q", got, tc.value)
			}
			current := GetGeneral()
			if current.GlobalClientFingerprint != tc.value {
				t.Fatalf("GetGeneral = %q, want %q", current.GlobalClientFingerprint, tc.value)
			}
			data, err := json.Marshal(current)
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(data, &fields); err != nil {
				t.Fatal(err)
			}
			var got string
			if err := json.Unmarshal(fields["global-client-fingerprint"], &got); err != nil {
				t.Fatal(err)
			}
			if got != tc.value {
				t.Fatalf("JSON = %q, want %q", got, tc.value)
			}
			_, ok := tlsC.GetFingerprint("")
			wantOK := tc.value != "" && tc.value != "none"
			if ok != wantOK {
				t.Fatalf("empty local resolution = %v, want %v", ok, wantOK)
			}
		})
	}
}

func TestGlobalFingerprintTemporaryGeneralRollback(t *testing.T) {
	old := GetGeneral()
	t.Cleanup(func() { updateGeneral(old, false) })
	for _, baseline := range []string{"", "chrome"} {
		general := *old
		general.GlobalClientFingerprint = baseline
		updateGeneral(&general, false)
		temporary := general
		temporary.GlobalClientFingerprint = "firefox"
		rollback := temporaryUpdateGeneral(&temporary)
		if got := tlsC.GetGlobalFingerprint(); got != "firefox" {
			t.Fatalf("temporary = %q", got)
		}
		rollback()
		if got := tlsC.GetGlobalFingerprint(); got != baseline {
			t.Fatalf("rollback = %q, want %q", got, baseline)
		}
	}
}
