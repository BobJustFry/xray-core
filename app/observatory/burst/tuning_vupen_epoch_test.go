package burst

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// Ядро 83 (T-102): проверки поиска и смена сети.

func epochTestPing(t *testing.T, epoch *atomic.Uint64, probe func(ctx context.Context, tag string, stall time.Duration) (vupenTspuVerdict, string)) *Observer {
	t.Helper()
	h, _ := tspuTestPing(t)
	h.tspuProbe = probe
	old := vupenBurstEpochNow
	vupenBurstEpochNow = func() uint64 { return epoch.Load() }
	t.Cleanup(func() { vupenBurstEpochNow = old })
	return &Observer{hp: h, ctx: context.Background()}
}

func suspectProbe(epoch *atomic.Uint64, bump bool) func(context.Context, string, time.Duration) (vupenTspuVerdict, string) {
	var once atomic.Bool
	return func(ctx context.Context, tag string, stall time.Duration) (vupenTspuVerdict, string) {
		if bump && once.CompareAndSwap(false, true) {
			epoch.Add(1) // сеть сменилась во время проверки
		}
		return vupenTspuSuspect, "frozen"
	}
}

// CR-003: заморозка из проверки, начатой в другой сети, не ставится; контроль —
// без смены сети заморозка ставится.
func TestVupenVerifyAcrossEpochChangeDoesNotFreeze(t *testing.T) {
	var epoch atomic.Uint64
	epoch.Store(2)
	o := epochTestPing(t, &epoch, suspectProbe(&epoch, true))
	if got := o.VupenStickyVerifyCtx(context.Background(), "proxy-1", nil); got != VupenStickyUnknown {
		t.Fatalf("verdict %s, want unknown", got)
	}
	if o.VupenStickyExcluded("proxy-1") {
		t.Fatal("a verify that crossed a network change must not freeze the node")
	}
	// Контроль: сеть не менялась.
	o2 := epochTestPing(t, &epoch, suspectProbe(&epoch, false))
	if got := o2.VupenStickyVerifyCtx(context.Background(), "proxy-1", nil); got != VupenStickyFailed || !o2.VupenStickyExcluded("proxy-1") {
		t.Fatalf("control: verdict %s excluded=%v, want failed and frozen", got, o2.VupenStickyExcluded("proxy-1"))
	}
}

// CR-003: пока сеть — БС (hold), проваленная проверка не замораживает; успех остаётся успехом.
func TestVupenVerifyInWhitelistDoesNotFreeze(t *testing.T) {
	var epoch atomic.Uint64
	o := epochTestPing(t, &epoch, suspectProbe(&epoch, false))
	if got := o.VupenStickyVerifyCtx(context.Background(), "proxy-1", func() bool { return true }); got != VupenStickyUnknown || o.VupenStickyExcluded("proxy-1") {
		t.Fatalf("whitelist: verdict %s excluded=%v", got, o.VupenStickyExcluded("proxy-1"))
	}
	okProbe := func(context.Context, string, time.Duration) (vupenTspuVerdict, string) { return vupenTspuOK, "ok" }
	o2 := epochTestPing(t, &epoch, okProbe)
	if got := o2.VupenStickyVerifyCtx(context.Background(), "proxy-2", func() bool { return true }); got != VupenStickyOK {
		t.Fatalf("a passed verify stays ok: %s", got)
	}
}

// CR-001: проверку можно прервать; прерванная — «не поняли», узел не тронут.
func TestVupenVerifyAbortedByCaller(t *testing.T) {
	var epoch atomic.Uint64
	started := make(chan struct{})
	probe := func(ctx context.Context, tag string, stall time.Duration) (vupenTspuVerdict, string) {
		close(started)
		<-ctx.Done()
		return vupenTspuSuspect, "cut"
	}
	o := epochTestPing(t, &epoch, probe)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan string, 1)
	go func() { done <- o.VupenStickyVerifyCtx(ctx, "proxy-1", nil) }()
	<-started
	cancel()
	select {
	case got := <-done:
		if got != VupenStickyUnknown || o.VupenStickyExcluded("proxy-1") {
			t.Fatalf("aborted verify: %s excluded=%v", got, o.VupenStickyExcluded("proxy-1"))
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the verify did not stop with the context")
	}
}

// CR-002: замеры прежней сети забываются на первой пробе в новой эпохе.
func TestVupenProbeDropsPreviousNetworkResults(t *testing.T) {
	var epoch atomic.Uint64
	epoch.Store(2)
	o := epochTestPing(t, &epoch, nil)
	h := o.hp
	h.vupenDropStaleResults() // эпоха 2
	h.PutResult("proxy-1", 30*time.Millisecond)
	h.PutResult("proxy-2", 40*time.Millisecond)
	alive := func() int {
		n := 0
		for _, st := range o.createResult() {
			if st.Alive {
				n++
			}
		}
		return n
	}
	if alive() != 2 {
		t.Fatalf("alive %d, want 2 before the change", alive())
	}
	if n, _ := h.vupenDropStaleResults(); n != 0 || alive() != 2 {
		t.Fatalf("same epoch: nothing dropped (%d), alive %d", n, alive())
	}
	epoch.Store(3)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // сами пробы нам не нужны, только сброс замеров в начале
	o.VupenStickyProbeCtx(ctx, []string{"proxy-1"})
	if alive() != 0 {
		t.Fatalf("alive %d after a probe in the new epoch, want 0 (stale Wi-Fi results)", alive())
	}
}

// CR-003: снять заморозки, поставленные с момента since.
func TestVupenUnfreezeSince(t *testing.T) {
	var epoch atomic.Uint64
	o := epochTestPing(t, &epoch, suspectProbe(&epoch, false))
	t0 := time.Now()
	if got := o.VupenStickyVerifyCtx(context.Background(), "proxy-1", nil); got != VupenStickyFailed {
		t.Fatalf("verify: %s", got)
	}
	if tags := o.VupenStickyUnfreezeSince(t0.Add(time.Hour)); len(tags) != 0 || !o.VupenStickyExcluded("proxy-1") {
		t.Fatalf("frozen before since stays frozen: %v", tags)
	}
	if tags := o.VupenStickyUnfreezeSince(t0.Add(-time.Second)); len(tags) != 1 || o.VupenStickyExcluded("proxy-1") {
		t.Fatalf("frozen after since is released: %v excluded=%v", tags, o.VupenStickyExcluded("proxy-1"))
	}
}
