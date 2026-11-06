package tunnel

import (
	"errors"
	"fmt"
	"testing"

	"github.com/metacubex/mihomo/component/sniffer"
	ST "github.com/metacubex/mihomo/constant/sniffer"
)

func preserveRestoreSnifferState(t *testing.T) {
	t.Helper()
	configMux.Lock()
	oldDispatcher, oldEnable := snifferDispatcher, sniffingEnable
	configMux.Unlock()
	oldTCP, oldUDP, oldUDPWorkers := tcpQueue, udpQueue, len(udpQueues)
	t.Cleanup(func() {
		configMux.Lock()
		snifferDispatcher, sniffingEnable = oldDispatcher, oldEnable
		configMux.Unlock()
		if tcpQueue != oldTCP || udpQueue != oldUDP || len(udpQueues) != oldUDPWorkers {
			t.Error("state-only sniffer test initialized traffic queues")
		}
	})
}

func restoreTestDispatcher(t *testing.T, enable bool) *sniffer.Dispatcher {
	t.Helper()
	dispatcher, err := sniffer.NewDispatcher(&sniffer.Config{Enable: enable})
	if err != nil || dispatcher == nil {
		t.Fatalf("NewDispatcher = %v, %v", dispatcher, err)
	}
	return dispatcher
}

func TestRestoreSnifferSetGate(t *testing.T) {
	preserveRestoreSnifferState(t)
	for _, tc := range []struct {
		name       string
		dispatcher *sniffer.Dispatcher
	}{
		{"nil", nil},
		{"disabled", restoreTestDispatcher(t, false)},
		{"enabled", restoreTestDispatcher(t, true)},
	} {
		for _, initial := range []bool{false, true} {
			for _, requested := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/initial_%t/request_%t", tc.name, initial, requested), func(t *testing.T) {
					configMux.Lock()
					snifferDispatcher, sniffingEnable = tc.dispatcher, initial
					configMux.Unlock()
					SetSniffing(requested)
					want := initial
					if tc.dispatcher.Enable() {
						want = requested
					}
					if got := IsSniffing(); got != want || snifferDispatcher != tc.dispatcher {
						t.Fatalf("IsSniffing = %t, want %t; dispatcher preserved = %t", got, want, snifferDispatcher == tc.dispatcher)
					}
				})
			}
		}
	}
}

func TestRestoreSnifferUpdateResetsToggle(t *testing.T) {
	preserveRestoreSnifferState(t)
	for _, tc := range []struct {
		name       string
		dispatcher *sniffer.Dispatcher
	}{
		{"nil", nil},
		{"disabled", restoreTestDispatcher(t, false)},
		{"enabled", restoreTestDispatcher(t, true)},
	} {
		for _, initial := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/initial_%t", tc.name, initial), func(t *testing.T) {
				UpdateSniffer(restoreTestDispatcher(t, true))
				SetSniffing(initial)
				UpdateSniffer(tc.dispatcher)
				if got := IsSniffing(); got != tc.dispatcher.Enable() || snifferDispatcher != tc.dispatcher {
					t.Fatalf("IsSniffing = %t, want %t; new dispatcher installed = %t", got, tc.dispatcher.Enable(), snifferDispatcher == tc.dispatcher)
				}
			})
		}
	}
}

func TestRestoreSnifferConstructorFailureReplacesOld(t *testing.T) {
	preserveRestoreSnifferState(t)
	old := restoreTestDispatcher(t, true)
	UpdateSniffer(old)
	failed, err := sniffer.NewDispatcher(&sniffer.Config{
		Enable: true,
		Sniffers: map[ST.Type]sniffer.SnifferConfig{
			ST.TLS: {}, ST.Type(3): {},
		},
	})
	if !errors.Is(err, sniffer.ErrorUnsupportedSniffer) || failed == nil {
		t.Fatalf("NewDispatcher = %v, %v; want disabled nonnil, unsupported", failed, err)
	}
	UpdateSniffer(failed)
	if snifferDispatcher != failed || snifferDispatcher == old || IsSniffing() {
		t.Fatal("failed construction must replace the previous enabled dispatcher and reset the toggle")
	}
	SetSniffing(true)
	if IsSniffing() {
		t.Fatal("SetSniffing re-enabled the failed dispatcher")
	}
}
