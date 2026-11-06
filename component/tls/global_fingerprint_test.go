package tls

import (
	"reflect"
	"sync"
	"testing"
)

func preserveGlobalFingerprint(t *testing.T) {
	t.Helper()
	old := GetGlobalFingerprint()
	t.Cleanup(func() { SetGlobalFingerprint(old) })
}

func TestGlobalFingerprintResolution(t *testing.T) {
	preserveGlobalFingerprint(t)
	cases := []struct {
		name, local, global, want string
		ok                        bool
	}{
		{"unset", "", "", "", false},
		{"global none", "", "none", "", false},
		{"global chrome", "", "chrome", "chrome", true},
		{"local wins", "firefox", "chrome", "firefox", true},
		{"local none", "none", "chrome", "", false},
		{"invalid local does not fall back", "invalid-local", "chrome", "", false},
		{"invalid global", "", "invalid-global", "", false},
		{"valid local ignores invalid global", "safari", "invalid-global", "safari", true},
		{"local with no global", "ios", "", "ios", true},
		{"empty is not whitespace", " ", "chrome", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			SetGlobalFingerprint(tc.global)
			if got := GetGlobalFingerprint(); got != tc.global {
				t.Fatalf("stored %q, want %q", got, tc.global)
			}
			got, ok := GetFingerprint(tc.local)
			want := UClientHelloID{}
			if tc.ok {
				want = fingerprints[tc.want]
			}
			if ok != tc.ok || !reflect.DeepEqual(got, want) {
				t.Fatalf("GetFingerprint(%q) = %v, %v; want %v, %v", tc.local, got, ok, want, tc.ok)
			}
		})
	}
}

func TestGlobalFingerprintRandomAndClear(t *testing.T) {
	preserveGlobalFingerprint(t)
	SetGlobalFingerprint("random")
	first, ok := GetFingerprint("")
	if !ok {
		t.Fatal("global random did not resolve")
	}
	allowed := false
	for _, name := range []string{"chrome", "safari", "ios", "firefox"} {
		allowed = allowed || reflect.DeepEqual(first, fingerprints[name])
	}
	if !allowed {
		t.Fatalf("unexpected weighted random choice: %v", first)
	}
	for i := 0; i < 20; i++ {
		got, ok := GetFingerprint("random")
		if !ok || !reflect.DeepEqual(got, first) {
			t.Fatal("random choice is not process-once")
		}
	}
	SetGlobalFingerprint("")
	if GetGlobalFingerprint() != "" {
		t.Fatal("clear retained old value")
	}
	if got, ok := GetFingerprint(""); ok || !reflect.DeepEqual(got, UClientHelloID{}) {
		t.Fatal("clear retained effective choice")
	}
	SetGlobalFingerprint("chrome")
	if got, ok := GetFingerprint(""); !ok || !reflect.DeepEqual(got, fingerprints["chrome"]) {
		t.Fatal("update after clear failed")
	}
}

func TestGlobalFingerprintZeroInitialization(t *testing.T) {
	preserveGlobalFingerprint(t)
	// No first Store is necessary: nil is the same state as a zero-value atomic.Pointer.
	globalFingerprint.Store(nil)
	if got := GetGlobalFingerprint(); got != "" {
		t.Fatalf("zero snapshot = %q", got)
	}
	if _, ok := GetFingerprint(""); ok {
		t.Fatal("zero snapshot selected uTLS")
	}
}

func TestGlobalFingerprintConcurrentSnapshots(t *testing.T) {
	preserveGlobalFingerprint(t)
	SetGlobalFingerprint("")
	var wg sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < 1000; i++ {
				if worker%2 == 0 {
					SetGlobalFingerprint([]string{"", "chrome", "firefox", "none"}[i%4])
					continue
				}
				switch got := GetGlobalFingerprint(); got {
				case "", "chrome", "firefox", "none":
				default:
					t.Errorf("torn snapshot %q", got)
					return
				}
				got, ok := GetFingerprint("")
				if ok && !reflect.DeepEqual(got, fingerprints["chrome"]) && !reflect.DeepEqual(got, fingerprints["firefox"]) {
					t.Errorf("invalid resolved snapshot %v", got)
					return
				}
				if !ok && !reflect.DeepEqual(got, UClientHelloID{}) {
					t.Errorf("unexpected disabled ID %v", got)
					return
				}
				local, ok := GetFingerprint("ios")
				if !ok || !reflect.DeepEqual(local, fingerprints["ios"]) {
					t.Error("global update overrode local fingerprint")
					return
				}
			}
		}(worker)
	}
	wg.Wait()
	SetGlobalFingerprint("")
	if _, ok := GetFingerprint(""); ok {
		t.Fatal("final clear failed")
	}
}

func TestGlobalFingerprintLocalOnlyIsolation(t *testing.T) {
	preserveGlobalFingerprint(t)
	SetGlobalFingerprint("chrome")
	for _, local := range []string{"", "none", "invalid-profile"} {
		if _, ok := GetFingerprintWithoutGlobal(local); ok {
			t.Fatalf("local-only %q unexpectedly inherited global", local)
		}
	}
	got, ok := GetFingerprintWithoutGlobal("firefox")
	want, wantOK := GetFingerprint("firefox")
	if !ok || !wantOK || !reflect.DeepEqual(got, want) {
		t.Fatal("local-only explicit fingerprint changed")
	}
	if _, ok := GetFingerprint(""); !ok {
		t.Fatal("historical path lost global fallback")
	}
}

func TestGlobalFingerprintExplicitOnlyIsolation(t *testing.T) {
	preserveGlobalFingerprint(t)
	for _, global := range []string{"chrome", "firefox", "random", "none", "invalid", ""} {
		SetGlobalFingerprint(global)
		for _, local := range []string{"", "none", "invalid-local", "chrome", "ios", "random"} {
			got, ok := GetFingerprintWithoutGlobal(local)
			want := UClientHelloID{}
			wantOK := false
			if local == "random" {
				want, wantOK = randomFingerprint(), true
			} else if id, exists := fingerprints[local]; exists {
				want, wantOK = id, true
			}
			if ok != wantOK || !reflect.DeepEqual(got, want) {
				t.Fatalf("explicit-only local=%q global=%q: got %v,%v want %v,%v", local, global, got, ok, want, wantOK)
			}
		}
	}
}
