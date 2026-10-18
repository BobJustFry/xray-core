package burst

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/routing"
)

// Ядро 83 (T-108): прерываемые пробы и проверки, заморозки эры БС, брошенная проверка.

// CR-002: отмена раунда проб обрывает идущие замеры и освобождает слоты полос — новый
// раунд (после смены сети) не ждёт таймаута проб.
func TestVupenDoCheckCancelReleasesLaneSlots(t *testing.T) {
	var inflight, sawCancel atomic.Int32
	setTestDialer(t, func(ctx context.Context, d routing.Dispatcher, dest net.Destination, tag string) (net.Conn, error) {
		inflight.Add(1)
		<-ctx.Done()
		sawCancel.Add(1)
		return nil, ctx.Err()
	})
	h := NewHealthPing(context.Background(), nil, &HealthPingConfig{
		Interval:      int64(10 * time.Second),
		SamplingCount: 1,
		Timeout:       int64(30 * time.Second), // обрыв без отмены ждал бы всё это время
		Destination:   "http://127.0.0.1:9/generate_204",
	})
	t.Cleanup(h.cancelCtx)
	o := &Observer{hp: h}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		o.VupenStickyProbeCtx(ctx, []string{"a", "b", "c"})
		close(done)
	}()
	deadline := time.Now().Add(3 * time.Second)
	for inflight.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if inflight.Load() < 3 {
		t.Fatalf("probes did not start: %d in flight", inflight.Load())
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("the probe round did not stop with the context")
	}
	deadline = time.Now().Add(2 * time.Second)
	for (len(h.lanes.tcp) != 0 || sawCancel.Load() < 3) && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if n := len(h.lanes.tcp); n != 0 {
		t.Fatalf("%d TCP lane slots still held after the cancel (the next round would wait for the probe timeout)", n)
	}
	if sawCancel.Load() != 3 {
		t.Fatalf("in-flight probes saw the cancel: %d of 3", sawCancel.Load())
	}
	if h.Results != nil && len(h.Results) != 0 {
		t.Fatalf("cancelled probes must not record results: %v", h.Results)
	}
}

// CR-002: проверка 24 КБ прерывается вместе с контекстом и даёт unknown, а не провал.
func TestVupenStickyCheckCtxAbortIsUnknown(t *testing.T) {
	started := make(chan struct{}, 4)
	setTestDialer(t, func(ctx context.Context, d routing.Dispatcher, dest net.Destination, tag string) (net.Conn, error) {
		started <- struct{}{}
		<-ctx.Done()
		return nil, ctx.Err() // оборванная загрузка выглядит как «соединение не установилось»
	})
	h := NewHealthPing(context.Background(), nil, nil)
	t.Cleanup(h.cancelCtx)
	o := &Observer{hp: h}
	opt := VupenCheckOptions{URL: "http://127.0.0.1:9/24k.bin", FallbackURL: "http://127.0.0.1:9/fb.bin", Timeout: 20 * time.Second}
	ctx, cancel := context.WithCancel(context.Background())
	got := make(chan VupenCheckResult, 1)
	go func() { got <- o.VupenStickyCheckWithCtx(ctx, "proxy-1", opt) }()
	<-started
	start := time.Now()
	cancel()
	select {
	case r := <-got:
		if r.Verdict != VupenStickyUnknown {
			t.Fatalf("aborted check: %+v, want unknown (not failed)", r)
		}
		if time.Since(start) > 2*time.Second {
			t.Fatalf("abort took %v", time.Since(start))
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the 24 KB check did not stop with the context")
	}
	select {
	case <-started:
		t.Fatal("the fallback download must not start after the abort")
	case <-time.After(100 * time.Millisecond):
	}
}

// CR-002: быстрые пробы switch прерываются вместе с контекстом.
func TestVupenStickyQuickProbeCtxAbort(t *testing.T) {
	started := make(chan struct{}, 4)
	setTestDialer(t, func(ctx context.Context, d routing.Dispatcher, dest net.Destination, tag string) (net.Conn, error) {
		started <- struct{}{}
		<-ctx.Done()
		return nil, ctx.Err()
	})
	h := NewHealthPing(context.Background(), nil, &HealthPingConfig{Destination: "http://127.0.0.1:9/generate_204"})
	t.Cleanup(h.cancelCtx)
	o := &Observer{hp: h}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	go func() {
		done <- o.VupenStickyQuickProbeCtx(ctx, []string{"a", "b"}, 20*time.Second, time.Now().Add(time.Minute),
			func(string, time.Duration, bool) bool { return false })
	}()
	<-started
	cancel()
	select {
	case n := <-done:
		if n != 0 {
			t.Fatalf("answered %d", n)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the quick probe did not stop with the context")
	}
}

// CR-004: эра БС снимает только заморозки проверки 64 КБ и только узлов пула; исключения
// по настоящей причине (24 КБ, heal, сторож) и чужой пул остаются.
func TestVupenUnfreezeOnlyVerifyFreezesOfThePool(t *testing.T) {
	var epoch atomic.Uint64
	o := epochTestPing(t, &epoch, suspectProbe(&epoch, false))
	t0 := time.Now()
	for _, tag := range []string{"reg-1", "lte-1"} {
		if got := o.VupenStickyVerifyCtx(context.Background(), tag, nil); got != VupenStickyFailed {
			t.Fatalf("%s verify: %s", tag, got)
		}
	}
	o.VupenStickyExcludeFor("reg-2", "24 KB check failed", time.Hour) // настоящая причина
	for _, tag := range []string{"reg-1", "lte-1", "reg-2"} {
		if !o.VupenStickyExcluded(tag) {
			t.Fatalf("%s must be frozen", tag)
		}
	}
	// Узел заморожен проверкой, затем исключён по настоящей причине - причина настоящая.
	for _, tag := range []string{"reg-3", "reg-4"} {
		if got := o.VupenStickyVerifyCtx(context.Background(), tag, nil); got != VupenStickyFailed {
			t.Fatal(got)
		}
	}
	o.VupenStickyExcludeFor("reg-4", "heal", time.Hour)
	tags := o.VupenStickyUnfreezeTags(t0.Add(-time.Second), []string{"reg-1", "reg-2", "reg-3", "reg-4"})
	if len(tags) != 2 {
		t.Fatalf("released %v, want reg-1 and reg-3", tags)
	}
	if o.VupenStickyExcluded("reg-1") || o.VupenStickyExcluded("reg-3") {
		t.Fatal("verify freezes of the pool must be released")
	}
	if !o.VupenStickyExcluded("reg-2") || !o.VupenStickyExcluded("reg-4") {
		t.Fatal("an exclusion made for a real reason must stay (also over a verify freeze)")
	}
	if !o.VupenStickyExcluded("lte-1") {
		t.Fatal("a verify freeze of a node outside the pool (LTE group) must stay")
	}
}

// CR-005: брошенная вызывающим (без контекста) проверка, дожившая в фоне через смену
// сети, не замораживает узел.
func TestVupenStickyVerifyWithoutCtxIsGuarded(t *testing.T) {
	var epoch atomic.Uint64
	epoch.Store(2)
	o := epochTestPing(t, &epoch, suspectProbe(&epoch, true))
	if got := o.VupenStickyVerify("proxy-1"); got != VupenStickyUnknown {
		t.Fatalf("verdict %s, want unknown", got)
	}
	if o.VupenStickyExcluded("proxy-1") {
		t.Fatal("a verify that crossed a network change must not freeze the node after it was abandoned")
	}
	o2 := epochTestPing(t, &epoch, suspectProbe(&epoch, false))
	if got := o2.VupenStickyVerify("proxy-1"); got != VupenStickyFailed || !o2.VupenStickyExcluded("proxy-1") {
		t.Fatalf("control: %s excluded=%v", got, o2.VupenStickyExcluded("proxy-1"))
	}
}
