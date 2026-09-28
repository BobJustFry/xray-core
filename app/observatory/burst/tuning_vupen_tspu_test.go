package burst

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestVupenTspuClassify(t *testing.T) {
	const want = 64 << 10
	cases := []struct {
		name string
		r    vupenDownloadResult
		v    vupenTspuVerdict
	}{
		{"whole file", vupenDownloadResult{status: 200, bytes: want, expected: want, started: true}, vupenTspuOK},
		{"stalled at 16 KB", vupenDownloadResult{status: 200, bytes: 16 << 10, expected: want, started: true, stalled: true}, vupenTspuSuspect},
		{"never started, timed out", vupenDownloadResult{timedOut: true}, vupenTspuSuspect},
		{"Cloudflare 429", vupenDownloadResult{status: 429}, vupenTspuUnknown},
		{"instant error", vupenDownloadResult{err: fmt.Errorf("connection refused")}, vupenTspuUnknown},
		{"dropped mid-file with an error", vupenDownloadResult{status: 200, bytes: 9000, expected: want, started: true, err: fmt.Errorf("reset")}, vupenTspuUnknown},
	}
	for _, c := range cases {
		if got := vupenTspuClassify(c.r, want); got != c.v {
			t.Errorf("%s: got %v, want %v", c.name, got, c.v)
		}
	}
}

// tspuFileServer: отдаёт send байт из 64 КБ и дальше молчит (как соединение под
// заморозкой); headerDelay — тишина до заголовков.
func tspuFileServer(t *testing.T, send int, headerDelay time.Duration) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if headerDelay > 0 {
			select {
			case <-time.After(headerDelay):
			case <-r.Context().Done():
				return
			}
		}
		w.Header().Set("Content-Length", fmt.Sprint(64<<10))
		w.WriteHeader(200)
		_, _ = w.Write([]byte(strings.Repeat("x", send)))
		w.(http.Flusher).Flush()
		if send < 64<<10 {
			<-r.Context().Done()
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestVupenDownload(t *testing.T) {
	ctx := context.Background()
	full := vupenDownload(ctx, http.DefaultClient, tspuFileServer(t, 64<<10, 0).URL, 5*time.Second, 300*time.Millisecond)
	if vupenTspuClassify(full, 64<<10) != vupenTspuOK {
		t.Fatalf("whole file: %+v", full)
	}
	stall := vupenDownload(ctx, http.DefaultClient, tspuFileServer(t, 16<<10, 0).URL, 5*time.Second, 300*time.Millisecond)
	if !stall.stalled || stall.bytes != 16<<10 || vupenTspuClassify(stall, 64<<10) != vupenTspuSuspect {
		t.Fatalf("freeze at 16 KB: %+v", stall)
	}
	silent := vupenDownload(ctx, http.DefaultClient, tspuFileServer(t, 64<<10, time.Minute).URL, 700*time.Millisecond, 300*time.Millisecond)
	if silent.started || !silent.timedOut || vupenTspuClassify(silent, 64<<10) != vupenTspuSuspect {
		t.Fatalf("never started: %+v", silent)
	}
}

// tspuTestPing — HealthPing без сети: проверка подменена сценарием.
func tspuTestPing(t *testing.T, script ...vupenTspuVerdict) (*HealthPing, *atomic.Int32) {
	t.Helper()
	oldPause := VupenTspuRetryPause
	VupenTspuRetryPause = 10 * time.Millisecond
	t.Cleanup(func() { VupenTspuRetryPause = oldPause })
	h := NewHealthPing(context.Background(), nil, nil)
	t.Cleanup(func() { h.cancelCtx() })
	var calls atomic.Int32
	var mu sync.Mutex
	h.tspuProbe = func(ctx context.Context, tag string, stall time.Duration) (vupenTspuVerdict, string) {
		i := int(calls.Add(1)) - 1
		mu.Lock()
		defer mu.Unlock()
		if i < len(script) {
			return script[i], fmt.Sprintf("probe %d", i+1)
		}
		return vupenTspuUnknown, "extra probe"
	}
	return h, &calls
}

func waitTspuIdle(t *testing.T, h *HealthPing, tag string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		h.tspu.mu.Lock()
		e := h.tspu.m[tag]
		busy := e != nil && e.checking
		h.tspu.mu.Unlock()
		if !busy {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("verification did not finish")
}

func TestVupenTspuFrozenOnlyAfterTwoSuspects(t *testing.T) {
	h, calls := tspuTestPing(t, vupenTspuSuspect, vupenTspuSuspect)
	h.vupenTspuRequest("proxy-7", false, "candidate")
	waitTspuIdle(t, h, "proxy-7")
	if calls.Load() != 2 || !h.vupenTspuFrozen("proxy-7") || h.vupenTspuVerified("proxy-7") {
		t.Fatalf("two suspects must freeze the node: calls=%d", calls.Load())
	}
	// Заморожен — повторно не проверяем до конца штрафа.
	h.vupenTspuRequest("proxy-7", true, "silent connection")
	time.Sleep(30 * time.Millisecond)
	if calls.Load() != 2 {
		t.Fatalf("a frozen node must not be re-checked, calls=%d", calls.Load())
	}
}

func TestVupenTspuOneSuspectThenCleanIsNotAVerdict(t *testing.T) {
	h, _ := tspuTestPing(t, vupenTspuSuspect, vupenTspuOK)
	h.vupenTspuRequest("proxy-7", false, "candidate")
	waitTspuIdle(t, h, "proxy-7")
	if h.vupenTspuFrozen("proxy-7") || h.vupenTspuVerified("proxy-7") {
		t.Fatal("TSPU is inconsistent: one freeze out of two is neither verified nor frozen")
	}
}

func TestVupenTspuVerifiedIsCachedAndSuspectForcesARecheck(t *testing.T) {
	oldEvery := VupenTspuSuspectEvery
	VupenTspuSuspectEvery = 0
	t.Cleanup(func() { VupenTspuSuspectEvery = oldEvery })
	h, calls := tspuTestPing(t, vupenTspuOK, vupenTspuSuspect, vupenTspuSuspect)
	h.vupenTspuRequest("proxy-4", false, "candidate")
	waitTspuIdle(t, h, "proxy-4")
	if !h.vupenTspuVerified("proxy-4") {
		t.Fatal("a whole file must verify the node")
	}
	// Проверенный узел кандидатом повторно не гоняем…
	h.vupenTspuRequest("proxy-4", false, "candidate")
	time.Sleep(30 * time.Millisecond)
	if calls.Load() != 1 {
		t.Fatalf("a verified node must not be re-probed as a candidate, calls=%d", calls.Load())
	}
	// …а тревога сторожа проверяет его заново — и замораживает.
	h.vupenTspuRequest("proxy-4", true, "silent connection")
	waitTspuIdle(t, h, "proxy-4")
	if !h.vupenTspuFrozen("proxy-4") || h.vupenTspuVerified("proxy-4") {
		t.Fatalf("a confirmed freeze on a verified node must freeze it, calls=%d", calls.Load())
	}
}

func TestVupenTspuFrozenNodeIsNotAliveForBalancers(t *testing.T) {
	h, _ := tspuTestPing(t, vupenTspuSuspect, vupenTspuSuspect)
	h.Settings.SamplingCount = 3
	h.PutResult("proxy-7", 266*time.Millisecond)
	h.PutResult("proxy-10", 312*time.Millisecond)
	h.vupenTspuRequest("proxy-7", false, "candidate")
	waitTspuIdle(t, h, "proxy-7")
	o := &Observer{hp: h}
	alive := map[string]bool{}
	for _, s := range o.createResult() {
		alive[s.OutboundTag] = s.Alive
	}
	if alive["proxy-7"] || !alive["proxy-10"] {
		t.Fatalf("frozen proxy-7 must be dead for balancers, proxy-10 alive: %v", alive)
	}
	if !strings.Contains(h.vupenRoundSummary("scheduled", []string{"proxy-7", "proxy-10"}), "proxy-7=frozen(tspu)") {
		t.Fatal("the round line must show the frozen node")
	}
}

func TestVupenTspuAfterRoundChecksTopCandidatesOnly(t *testing.T) {
	oldK := VupenTspuTopK
	VupenTspuTopK = 2
	t.Cleanup(func() { VupenTspuTopK = oldK })
	h, calls := tspuTestPing(t, vupenTspuOK, vupenTspuOK, vupenTspuOK, vupenTspuOK)
	h.Settings.SamplingCount = 3
	h.PutResult("slow", 900*time.Millisecond)
	h.PutResult("fast", 250*time.Millisecond)
	h.PutResult("mid", 400*time.Millisecond)
	h.PutResult("dead", rttFailed)
	h.vupenTspuAfterRound([]string{"slow", "fast", "mid", "dead"})
	for _, tag := range []string{"fast", "mid"} {
		waitTspuIdle(t, h, tag)
	}
	if !h.vupenTspuVerified("fast") || !h.vupenTspuVerified("mid") || h.vupenTspuVerified("slow") {
		t.Fatalf("only the two fastest alive nodes are checked, calls=%d", calls.Load())
	}
	if calls.Load() != 2 {
		t.Fatalf("expected 2 probes, got %d", calls.Load())
	}
}

// «Не поняли» не должно превращаться в проверку на каждом новом соединении.
func TestVupenTspuUnknownIsNotRecheckedOnEveryConnection(t *testing.T) {
	h, calls := tspuTestPing(t, vupenTspuUnknown, vupenTspuOK)
	h.vupenTspuRequest("proxy-9", false, "switch")
	waitTspuIdle(t, h, "proxy-9")
	for i := 0; i < 20; i++ {
		h.vupenTspuRequest("proxy-9", false, "switch")
	}
	time.Sleep(30 * time.Millisecond)
	if calls.Load() != 1 {
		t.Fatalf("an inconclusive check must wait VupenTspuRecheckAfter, calls=%d", calls.Load())
	}
}
