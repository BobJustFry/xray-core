package burst

import (
	"context"
	stdnet "net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/routing"
)

// T-131 (CR-001/002/005/006): мёртвый УЗЕЛ через tagged.Dialer — это не «refused» и не
// «no such host», а труба без ошибки набора, закрытая сразу (EOF / closed pipe) на
// каждом хосте. Это те же ошибки, что у мёртвых хостов проверки, поэтому «unknown»
// допустим только при доказательстве, что узел жив.

// closedPipeConn — то, что отдаёт tagged.Dialer, когда исходящее не соединилось.
func closedPipeConn() (net.Conn, error) {
	c, s := stdnet.Pipe()
	_ = s.Close()
	return c, nil
}

// pipeDialer — мёртвый узел: на хостах из pipePorts (все, если nil) труба закрыта сразу,
// остальные идут напрямую.
func pipeDialer(t *testing.T, pipePorts ...string) {
	t.Helper()
	setTestDialer(t, func(ctx context.Context, d routing.Dispatcher, dest net.Destination, tag string) (net.Conn, error) {
		if len(pipePorts) == 0 {
			return closedPipeConn()
		}
		for _, p := range pipePorts {
			if dest.Port.String() == p {
				return closedPipeConn()
			}
		}
		return stdnet.Dial("tcp", dest.NetAddr())
	})
}

func urlPort(u string) string { return u[strings.LastIndex(u, ":")+1:] }

// probeAt — замер узла tag в h.Results: удачный (ok) или нет, возраста age.
func probeAt(h *HealthPing, tag string, ok bool, age time.Duration) {
	h.access.Lock()
	defer h.access.Unlock()
	if h.Results == nil {
		h.Results = make(map[string]*HealthPingRTTS)
	}
	r := NewHealthPingResult(4, time.Hour)
	if ok {
		r.Put(80 * time.Millisecond)
	} else {
		r.Put(rttFailed)
	}
	r.rtts[r.idx].time = time.Now().Add(-age)
	h.Results[tag] = r
}

// probeAdd — дописывает в кольцо узла tag ещё один замер возраста age (probeAt перезаписывает).
func probeAdd(h *HealthPing, tag string, ok bool, age time.Duration) {
	h.access.Lock()
	defer h.access.Unlock()
	r := h.Results[tag]
	if ok {
		r.Put(80 * time.Millisecond)
	} else {
		r.Put(rttFailed)
	}
	r.rtts[r.idx].time = time.Now().Add(-age)
}

// CR-101: доказательство жизни — это самая свежая проба, а не любая удача за 60 с.
func TestVupenCheckNewestFailedProbeVoidsProof(t *testing.T) {
	a, b := "http://cdn-a.invalid:8081/x", "http://cdn-b.invalid:8082/x"
	o, h := listCheckEnv(t, a, b)
	pipeDialer(t)

	// ok 50 с назад, затем провал 5 с назад → узел умер после удачи → failed.
	probeAt(h, "proxy-1", true, 50*time.Second)
	probeAdd(h, "proxy-1", false, 5*time.Second)
	if r := o.VupenStickyCheckWith("proxy-1", VupenCheckOptions{}); r.Verdict != VupenStickyFailed {
		t.Fatalf("ok -50s then failed -5s: %+v", r)
	}
	// провал 50 с назад, затем ok 5 с назад → жив → unknown.
	probeAt(h, "proxy-1", false, 50*time.Second)
	probeAdd(h, "proxy-1", true, 5*time.Second)
	if r := o.VupenStickyCheckWith("proxy-1", VupenCheckOptions{}); r.Verdict != VupenStickyUnknown {
		t.Fatalf("failed -50s then ok -5s: %+v", r)
	}
}

func TestVupenCheckDeadNodePipeIsFailed(t *testing.T) {
	a, b := "http://cdn-a.invalid:8081/x", "http://cdn-b.invalid:8082/x"
	o, h := listCheckEnv(t, a, b)
	pipeDialer(t)

	// 1) Мёртвый узел: оба хоста — закрытая труба, ни статуса, ни свежей пробы → провал.
	if r := o.VupenStickyCheckWith("proxy-1", VupenCheckOptions{}); r.Verdict != VupenStickyFailed {
		t.Fatalf("dead node, no proof: %+v", r)
	}
	// 2) Свежая НЕудачная проба и устаревшая удачная — не доказательство.
	probeAt(h, "proxy-1", false, time.Second)
	if r := o.VupenStickyCheckWith("proxy-1", VupenCheckOptions{}); r.Verdict != VupenStickyFailed {
		t.Fatalf("fresh failed probe is no proof: %+v", r)
	}
	probeAt(h, "proxy-1", true, 5*time.Minute)
	if r := o.VupenStickyCheckWith("proxy-1", VupenCheckOptions{}); r.Verdict != VupenStickyFailed {
		t.Fatalf("stale ok probe is no proof: %+v", r)
	}
	// 3) Свежая удачная проба этого узла — доказательство: виноваты хосты, итог unknown.
	probeAt(h, "proxy-1", true, 5*time.Second)
	if r := o.VupenStickyCheckWith("proxy-1", VupenCheckOptions{}); r.Verdict != VupenStickyUnknown || !strings.Contains(r.Detail, "check hosts unreachable") {
		t.Fatalf("fresh ok probe + dead hosts: %+v", r)
	}
	// Проба другого узла узлу proxy-1 не засчитывается.
	if r := o.VupenStickyCheckWith("proxy-2", VupenCheckOptions{}); r.Verdict != VupenStickyFailed {
		t.Fatalf("a probe of another node: %+v", r)
	}
}

func TestVupenCheckHTTPStatusIsProofOfLife(t *testing.T) {
	h404 := listServer(t, 24576, "404")
	dead := "http://cdn-b.invalid:8082/x"
	o, _ := listCheckEnv(t, h404.url, dead)
	pipeDialer(t, "8082") // первый адрес отвечает 404 через узел, второй — закрытая труба

	// 404 + EOF: ответ пришёл через узел → узел жив, проверочные хосты нет → unknown (без проб).
	r := o.VupenStickyCheckWith("proxy-1", VupenCheckOptions{})
	if r.Verdict != VupenStickyUnknown || h404.hits.Load() != 1 {
		t.Fatalf("404 then EOF: %+v hits=%d", r, h404.hits.Load())
	}
	// Тот же порядок наоборот: закрытая труба, затем 404.
	vupenCheckURLs.store([]string{dead, h404.url})
	if r := o.VupenStickyCheckWith("proxy-1", VupenCheckOptions{}); r.Verdict != VupenStickyUnknown {
		t.Fatalf("EOF then 404: %+v", r)
	}
}

// CR-005: проверка 64 КБ по списку укладывается в общий бюджет, а не в 2 × таймаут.
func TestVupenTspuProbeBudget(t *testing.T) {
	slow404 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(time.Second)
		w.WriteHeader(404)
	}))
	t.Cleanup(slow404.Close)
	hang := listServer(t, 87533, "slow") // заголовки через 5 с
	_, h := listCheckEnv(t)
	oldT, oldB, oldM := VupenTspuTimeout, VupenTspuBudget, vupenTspuMinTry
	VupenTspuTimeout, VupenTspuBudget, vupenTspuMinTry = 10*time.Second, 3*time.Second, 500*time.Millisecond
	t.Cleanup(func() { VupenTspuTimeout, VupenTspuBudget, vupenTspuMinTry = oldT, oldB, oldM })
	vupenTspuURLs.store([]string{slow404.URL, hang.url})

	begin := time.Now()
	v, d := h.vupenTspuProbeOnce(context.Background(), "proxy-1", 10*time.Second)
	el := time.Since(begin)
	// Без бюджета второй адрес ждал бы свои 5 с до заголовков; с бюджетом он обрывается на ~2 с.
	if el > 4*time.Second || hang.hits.Load() != 1 {
		t.Fatalf("budget not applied: %s hits=%d verdict=%v %s", el, hang.hits.Load(), v, d)
	}
	// Бюджет кончился до второго адреса — он не пробуется вовсе.
	vupenTspuMinTry = 5 * time.Second
	hang2 := listServer(t, 87533, "")
	vupenTspuURLs.store([]string{slow404.URL, hang2.url})
	if v, _ := h.vupenTspuProbeOnce(context.Background(), "proxy-1", 10*time.Second); hang2.hits.Load() != 0 {
		t.Fatalf("left < min try: second url must be skipped (verdict %v, hits %d)", v, hang2.hits.Load())
	}
}

// CR-006: сообщения без Content-Length и пол want при коротком Content-Length.
func TestVupenDownloadResultStringAndFloor(t *testing.T) {
	chunked := vupenDownloadResult{status: 200, bytes: 87533, started: true, elapsed: 120 * time.Millisecond}
	if s := chunked.String(); strings.Contains(s, "of 0") || !strings.Contains(s, "85 KB") || !strings.Contains(s, "no Content-Length") {
		t.Fatalf("chunked: %q", s)
	}
	cut := vupenDownloadResult{status: 200, bytes: 10 << 10, started: true}
	if s := cut.String(); strings.Contains(s, "of 0") {
		t.Fatalf("cut without CL: %q", s)
	}
	if s := (vupenDownloadResult{status: 200, bytes: 10 << 10, expected: 24 << 10, started: true}).String(); s != "10 KB of 24 KB" {
		t.Fatalf("cut with CL: %q", s)
	}
	const want = 64 << 10
	short := vupenDownloadResult{status: 200, bytes: 10 << 10, expected: 10 << 10, started: true}
	if vupenTspuClassify(short, want) == vupenTspuOK {
		t.Fatal("a 200 with Content-Length 10 KB must not verify 64 KB")
	}
	if vupenTspuClassify(vupenDownloadResult{status: 200, bytes: 87533, expected: 87533, started: true}, want) != vupenTspuOK {
		t.Fatal("whole 87 533 B file must verify 64 KB")
	}
	if vupenTspuClassify(vupenDownloadResult{status: 200, bytes: 70 << 10, expected: 87533, started: true}, want) == vupenTspuOK {
		t.Fatal("cut before Content-Length is not a verified file")
	}
	if vupenTspuClassify(chunked, want) != vupenTspuOK {
		t.Fatal("chunked 85 KB ≥ want must verify")
	}
}
