package burst

import (
	"context"
	"errors"
	"fmt"
	stdnet "net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet"
)

func graceArmed(h *HealthPing) bool { return h.wakeGraceUntil.Load() > time.Now().UnixNano() }

// CR-105: окно проб взводится на КАЖДОЙ смене типа или подписи, включая мигание
// назад; тот же тип с подписью и неверный тип — нет.
func TestVupenSetUplinkArmsGraceOnEveryChange(t *testing.T) {
	vupenObsResetForTest(t, time.Hour, time.Hour)
	h := newSleepTestPing()
	vupenObsRegister(h)
	t.Cleanup(func() { vupenObsUnregister(h) })
	run := time.Now().UnixNano()
	sig := func(s string) string { return fmt.Sprintf("cr105-%s-%d", s, run) }
	if e := VupenSetUplink("wifi", sig("prime")); e != "" {
		t.Fatal(e)
	}
	for i, s := range []struct {
		kind, sig string
		arm       bool
	}{
		{"cellular", sig("a"), true},
		{"cellular", sig("a"), false}, // без смены
		{"wifi", sig("b"), true},
		{"cellular", sig("a"), true}, // мигание назад до 9 с — тоже смена
		{"cellular", "", true},       // пустая подпись = тип
	} {
		h.wakeGraceUntil.Store(0)
		if e := VupenSetUplink(s.kind, s.sig); e != "" {
			t.Fatalf("step %d: %s", i, e)
		}
		if graceArmed(h) != s.arm {
			t.Fatalf("step %d %s/%s: grace armed=%v, want %v", i, s.kind, s.sig, graceArmed(h), s.arm)
		}
		if internet.VupenUplinkKind() != s.kind {
			t.Fatalf("step %d: epoch kind %q", i, internet.VupenUplinkKind())
		}
	}
	h.wakeGraceUntil.Store(0)
	if e := VupenSetUplink("lte", sig("x")); e == "" || graceArmed(h) || internet.VupenUplinkKind() != "cellular" {
		t.Fatalf("unknown kind must be rejected and change nothing: %q armed=%v kind=%s", e, graceArmed(h), internet.VupenUplinkKind())
	}
}

// CR-105: перед закрытием соединений (чистка через 9 с после последней смены) окно
// взводится снова — при миганиях окно первой смены к этому моменту истекло.
func TestVupenGraceArmedBeforeConnectionsClose(t *testing.T) {
	vupenObsResetForTest(t, time.Hour, time.Hour)
	h := newSleepTestPing()
	vupenObsRegister(h)
	t.Cleanup(func() { vupenObsUnregister(h) })
	h.wakeGraceUntil.Store(0)
	vupenOnNetEvent(internet.VupenNetStable)
	vupenOnNetEvent(internet.VupenNetChanged)
	if graceArmed(h) {
		t.Fatal("only the closing event arms the window here")
	}
	vupenOnNetEvent(internet.VupenNetClosing)
	if !graceArmed(h) {
		t.Fatal("connections are about to be closed: the probe window must be armed")
	}
}

func TestVupenSetCheckURL(t *testing.T) {
	t.Cleanup(func() { vupenCheckURLs.Store(nil) })
	vupenCheckURLs.Store(nil)
	def, defFB := vupenCheckFiles()
	for _, c := range [][2]string{
		{"", ""}, {"http://vupen.fun/24k.bin", ""}, {"https://", ""}, {"https://user:pw@vupen.fun/x", ""},
		{"vupen.fun/24k.bin", ""}, {"https://vupen.fun/24k.bin", "ftp://x/y"}, {"https://vupen.fun/24k.bin", "https:///x"},
		{"https://vupen.fun/%zz", ""},
	} {
		if e := VupenSetCheckURL(c[0], c[1]); e == "" {
			t.Fatalf("%q/%q must be rejected", c[0], c[1])
		}
		if p, f := vupenCheckFiles(); p != def || f != defFB {
			t.Fatalf("a rejected call changed the files: %s %s", p, f)
		}
	}
	if e := VupenSetCheckURL("https://vupen.fun/app/probe/24k.bin", "https://speed.cloudflare.com/__down?bytes=24576"); e != "" {
		t.Fatal(e)
	}
	if p, f := vupenCheckFiles(); p != "https://vupen.fun/app/probe/24k.bin" || f != "https://speed.cloudflare.com/__down?bytes=24576" {
		t.Fatalf("files: %s %s", p, f)
	}
	if e := VupenSetCheckURL("https://vupen.fun/app/probe/24k.bin", ""); e != "" {
		t.Fatal(e)
	}
	if _, f := vupenCheckFiles(); f != "" {
		t.Fatalf("fallback cleared: %q", f)
	}
}

// Вид провала для VupenCheckRoute: stall | nostart | error | http.
func TestVupenStickyCheckWithKinds(t *testing.T) {
	var mode atomic.Value
	mode.Store("")
	setTestDialer(t, func(ctx context.Context, d routing.Dispatcher, dest net.Destination, tag string) (net.Conn, error) {
		if mode.Load().(string) == "refuse" {
			return nil, errors.New("dial tcp: connection refused")
		}
		return stdnet.Dial("tcp", dest.NetAddr())
	})
	h := NewHealthPing(context.Background(), nil, nil)
	t.Cleanup(h.cancelCtx)
	o := &Observer{hp: h}
	opt := VupenCheckOptions{Bytes: 24576, Stall: 300 * time.Millisecond, FirstByte: 500 * time.Millisecond, Timeout: 3 * time.Second}
	for _, c := range []struct {
		name         string
		mode         string
		status, send int
		delay        time.Duration
		verdict      string
		kind         string
	}{
		{"whole file", "", 200, 24576, 0, VupenStickyOK, ""},
		{"stalled at 8 KB", "", 200, 8192, 0, VupenStickyFailed, "stall"},
		{"never started", "", 200, 24576, 5 * time.Second, VupenStickyFailed, "nostart"},
		{"HTTP 429", "", 429, 0, 0, VupenStickyUnknown, "http"},
		{"refused", "refuse", 200, 24576, 0, VupenStickyFailed, "error"},
	} {
		mode.Store(c.mode)
		opt.URL = fileServer24(t, c.status, c.send, c.delay)
		r := o.VupenStickyCheckWith("proxy-1", opt)
		if r.Verdict != c.verdict || r.Kind != c.kind || r.Detail == "" {
			t.Errorf("%s: %+v, want %s/%s", c.name, r, c.verdict, c.kind)
		}
	}
}

// Основной «не понял» (HTTP ≠ 200) — запасной; основной показал провал — запасной не нужен.
func TestVupenStickyCheckFallback(t *testing.T) {
	setTestDialer(t, func(ctx context.Context, d routing.Dispatcher, dest net.Destination, tag string) (net.Conn, error) {
		return stdnet.Dial("tcp", dest.NetAddr())
	})
	var fbHits atomic.Int32
	fb := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fbHits.Add(1)
		w.Header().Set("Content-Length", "24576")
		_, _ = w.Write([]byte(strings.Repeat("x", 24576)))
	}))
	t.Cleanup(fb.Close)
	h := NewHealthPing(context.Background(), nil, nil)
	t.Cleanup(h.cancelCtx)
	o := &Observer{hp: h}
	opt := VupenCheckOptions{Stall: 300 * time.Millisecond, FirstByte: time.Second, Timeout: 3 * time.Second, FallbackURL: fb.URL}

	opt.URL = fileServer24(t, 404, 0, 0)
	if r := o.VupenStickyCheckWith("proxy-1", opt); r.Verdict != VupenStickyOK || !strings.Contains(r.Detail, "fallback") || fbHits.Load() != 1 {
		t.Fatalf("primary 404 → fallback: %+v hits=%d", r, fbHits.Load())
	}
	opt.URL = fileServer24(t, 200, 8192, 0)
	if r := o.VupenStickyCheckWith("proxy-1", opt); r.Verdict != VupenStickyFailed || r.Kind != "stall" || fbHits.Load() != 1 {
		t.Fatalf("primary frozen → verdict without fallback: %+v hits=%d", r, fbHits.Load())
	}

	// Собственная проверка ядра (VupenStickyCheck) тоже идёт на запасной (тест —
	// через переменные: https в тесте не поднять).
	oldURL, oldFB, oldStall, oldFirst, oldTO := VupenStickyCheckURL, VupenStickyCheckFallbackURL,
		VupenStickyCheckStall, VupenStickyCheckFirstByte, VupenStickyCheckTimeout
	t.Cleanup(func() {
		VupenStickyCheckURL, VupenStickyCheckFallbackURL = oldURL, oldFB
		VupenStickyCheckStall, VupenStickyCheckFirstByte, VupenStickyCheckTimeout = oldStall, oldFirst, oldTO
	})
	VupenStickyCheckStall, VupenStickyCheckFirstByte, VupenStickyCheckTimeout = 300*time.Millisecond, time.Second, 3*time.Second
	VupenStickyCheckURL, VupenStickyCheckFallbackURL = fileServer24(t, 429, 0, 0), fb.URL
	if v := o.VupenStickyCheck("proxy-1"); v != VupenStickyOK || fbHits.Load() != 2 {
		t.Fatalf("the core's own 24 KB check uses the fallback too: %s hits=%d", v, fbHits.Load())
	}
}

// CR-704: бюджет на обе загрузки: основной «не понял», запасной не начинается —
// проверка кончается по бюджету, а не через два таймаута.
func TestVupenStickyCheckBudget(t *testing.T) {
	setTestDialer(t, func(ctx context.Context, d routing.Dispatcher, dest net.Destination, tag string) (net.Conn, error) {
		return stdnet.Dial("tcp", dest.NetAddr())
	})
	h := NewHealthPing(context.Background(), nil, nil)
	t.Cleanup(h.cancelCtx)
	o := &Observer{hp: h}
	opt := VupenCheckOptions{Stall: 300 * time.Millisecond, FirstByte: 5 * time.Second, Timeout: 3 * time.Second,
		URL: fileServer24(t, 404, 0, 0), FallbackURL: fileServer24(t, 200, 24576, 10*time.Second), Budget: time.Second}
	start := time.Now()
	r := o.VupenStickyCheckWith("proxy-1", opt)
	if took := time.Since(start); took > 2*time.Second || r.Verdict != VupenStickyFailed || r.Kind != "nostart" {
		t.Fatalf("budget 1 s: took %v, %+v", took, r)
	}
	opt.Budget = 0 // без бюджета запасной ждёт свой таймаут (3 с)
	start = time.Now()
	if o.VupenStickyCheckWith("proxy-1", opt); time.Since(start) < 2500*time.Millisecond {
		t.Fatal("without a budget the fallback keeps its own timeout")
	}
}

func TestVupenStickyExcludeFor(t *testing.T) {
	h := NewHealthPing(context.Background(), nil, nil)
	t.Cleanup(h.cancelCtx)
	o := &Observer{hp: h}
	o.VupenStickyExcludeFor("proxy-1", "test", 30*time.Minute)
	h.tspu.mu.Lock()
	until := h.tspu.entryLocked("proxy-1").frozenUntil
	h.tspu.mu.Unlock()
	if d := time.Until(until); d < 29*time.Minute || d > 30*time.Minute || !o.VupenStickyExcluded("proxy-1") {
		t.Fatalf("excluded for %v", d)
	}
	o.VupenStickyExcludeFor("proxy-2", "test", 0)
	h.tspu.mu.Lock()
	until = h.tspu.entryLocked("proxy-2").frozenUntil
	h.tspu.mu.Unlock()
	if d := time.Until(until); d < VupenTspuFrozenFor-time.Minute || d > VupenTspuFrozenFor {
		t.Fatalf("0 → default %v, got %v", VupenTspuFrozenFor, d)
	}
}
