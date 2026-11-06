package config

import (
	"encoding/json"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestGlobalFingerprintRawToGeneral(t *testing.T) {
	for _, value := range []string{"", "chrome", "none", "invalid", "random"} {
		raw := &RawConfig{GlobalClientFingerprint: value}
		general, err := parseGeneral(raw)
		if err != nil {
			t.Fatal(err)
		}
		if general.GlobalClientFingerprint != value {
			t.Fatalf("parseGeneral = %q, want %q", general.GlobalClientFingerprint, value)
		}
		data, err := json.Marshal(general)
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
		if got != value {
			t.Fatalf("serialized %q, want %q", got, value)
		}
	}
}

func TestGlobalFingerprintRawDecoding(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{"{}", ""}, {"global-client-fingerprint: ''", ""},
		{"global-client-fingerprint: null", ""}, {"global-client-fingerprint: chrome", "chrome"},
		{"global-client-fingerprint: none", "none"}, {"global-client-fingerprint: invalid", "invalid"},
	} {
		raw := &RawConfig{}
		if err := yaml.Unmarshal([]byte(tc.input), raw); err != nil {
			t.Fatal(err)
		}
		general, err := parseGeneral(raw)
		if err != nil {
			t.Fatal(err)
		}
		if general.GlobalClientFingerprint != tc.want {
			t.Fatalf("input %q: got %q, want %q", tc.input, general.GlobalClientFingerprint, tc.want)
		}
	}
}
