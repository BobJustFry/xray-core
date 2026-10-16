package burst

import (
	"context"
	"os"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet/tagged"
)

// Test hygiene for -race (test-only).
//
// Tests here swap package globals (tagged.Dialer, Vupen* settings) while probe
// and round goroutines of a HealthPing — their own or a previous test's — may
// still be running. A plain write to a global that such a goroutine reads is a
// data race, even if the goroutine ended long ago in wall time, because nothing
// orders its end before the write.
//
//   - tagged.Dialer is written exactly once, in TestMain, before any test runs:
//     it dispatches to a per-test fake stored atomically (setTestDialer).
//   - Tests that start a scheduler stop it with quiesce, which waits until every
//     goroutine of that HealthPing has returned and then takes its locks, so all
//     of their reads happen before the test restores globals.

var testDialer atomic.Pointer[tagged.DialFunc]

func TestMain(m *testing.M) {
	real := tagged.Dialer
	tagged.Dialer = func(ctx context.Context, d routing.Dispatcher, dest net.Destination, tag string) (net.Conn, error) {
		if f := testDialer.Load(); f != nil {
			return (*f)(ctx, d, dest, tag)
		}
		if real == nil {
			return nil, context.Canceled
		}
		return real(ctx, d, dest, tag)
	}
	os.Exit(m.Run())
}

// setTestDialer — fake tagged dialer for this test; the previous one is restored
// at cleanup.
func setTestDialer(t *testing.T, f tagged.DialFunc) {
	t.Helper()
	old := testDialer.Swap(&f)
	t.Cleanup(func() { testDialer.Store(old) })
}

// quiesce — stop h's scheduler and wait until none of its goroutines run.
func quiesce(t *testing.T, h *HealthPing) {
	t.Helper()
	h.StopScheduler()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if h.cancelPending.Load() == nil && !healthPingGoroutinesRunning() {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("HealthPing goroutines still running 5 s after StopScheduler")
		}
		time.Sleep(5 * time.Millisecond)
	}
	// Order their last accesses before ours: each of them leaves through these locks.
	h.access.Lock()
	h.access.Unlock()
	h.tspu.mu.Lock()
	h.tspu.mu.Unlock()
	vupenObs.mu.Lock()
	vupenObs.mu.Unlock()
}

// healthPingGoroutinesRunning — some goroutine is inside the scheduler, a round,
// a probe or a TSPU check (any HealthPing of this package).
func healthPingGoroutinesRunning() bool {
	buf := make([]byte, 1<<20)
	n := runtime.Stack(buf, true)
	self := "burst.healthPingGoroutinesRunning"
	for _, g := range strings.Split(string(buf[:n]), "\n\n") {
		if strings.Contains(g, self) {
			continue
		}
		if strings.Contains(g, "app/observatory/burst.(*HealthPing)") ||
			strings.Contains(g, "app/observatory/burst.(*pingClient)") {
			return true
		}
	}
	return false
}
