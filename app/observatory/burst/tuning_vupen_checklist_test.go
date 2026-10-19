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
)

// Ядро 85 (T-129): список адресов проверки.

type listSrv struct {
	url  string
	hits *atomic.Int32
}

// listServer — файл size байт (Content-Length) с первого байта; mode: "" — целиком,
// "stall" — половина и тишина, "slow" — заголовки через 5 с, "404" — HTTP 404.
func listServer(t *testing.T, size int, mode string) listSrv {
	t.Helper()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		switch mode {
		case "404":
			w.WriteHeader(404)
			return
		case "slow":
			select {
			case <-time.After(5 * time.Second):
			case <-r.Context().Done():
				return
			}
		}
		w.Header().Set("Content-Length", fmt.Sprint(size))
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		n := size
		if mode == "stall" {
			n = size / 3
		}
		_, _ = w.Write([]byte(strings.Repeat("x", n)))
		w.(http.Flusher).Flush()
		if mode == "stall" {
			<-r.Context().Done()
		}
	}))
	t.Cleanup(srv.Close)
	return listSrv{srv.URL, &hits}
}

// deadServer — адрес, на котором никто не слушает (отказ в соединении).
func deadServer(t *testing.T) listSrv {
	t.Helper()
	srv := httptest.NewServer(http.NotFoundHandler())
	u := srv.URL
	srv.Close()
	return listSrv{u, new(atomic.Int32)}
}

func listCheckEnv(t *testing.T, urls ...string) (*Observer, *HealthPing) {
	t.Helper()
	setTestDialer(t, func(ctx context.Context, d routing.Dispatcher, dest net.Destination, tag string) (net.Conn, error) {
		return stdnet.Dial("tcp", dest.NetAddr())
	})
	oldS, oldF, oldT := VupenStickyCheckStall, VupenStickyCheckFirstByte, VupenStickyCheckTimeout
	VupenStickyCheckStall, VupenStickyCheckFirstByte, VupenStickyCheckTimeout = 300*time.Millisecond, 500*time.Millisecond, 3*time.Second
	vupenCheckURLs.reset()
	vupenTspuURLs.reset()
	t.Cleanup(func() {
		VupenStickyCheckStall, VupenStickyCheckFirstByte, VupenStickyCheckTimeout = oldS, oldF, oldT
		vupenCheckURLs.reset()
		vupenTspuURLs.reset()
	})
	if len(urls) > 0 {
		vupenCheckURLs.store(urls)
	}
	h := NewHealthPing(context.Background(), nil, nil)
	t.Cleanup(h.cancelCtx)
	return &Observer{hp: h}, h
}

func TestVupenCheckDefaultList(t *testing.T) {
	want := []string{"cdn.jsdelivr.net", "code.jquery.com", "speed.cloudflare.com"}
	for name, l := range map[string][]string{"24": VupenCheckDefaultURLs, "64": VupenTspuDefaultURLs} {
		if len(l) != 3 {
			t.Fatalf("%s: %v", name, l)
		}
		for i, h := range want {
			if !strings.HasPrefix(l[i], "https://"+h+"/") || VupenCheckURLError(l[i]) != "" {
				t.Errorf("%s[%d] = %s, want host %s", name, i, l[i], h)
			}
			if strings.Contains(l[i], "vupen.fun") {
				t.Errorf("%s: own host in the list: %s", name, l[i])
			}
		}
	}
	if !strings.HasSuffix(VupenCheckDefaultURLs[2], "bytes=24576") || !strings.HasSuffix(VupenTspuDefaultURLs[2], "bytes=65536") {
		t.Fatalf("Cloudflare sizes: %s / %s", VupenCheckDefaultURLs[2], VupenTspuDefaultURLs[2])
	}
	vupenCheckURLs.reset()
	vupenTspuURLs.reset()
	oldC, oldT := VupenStickyCheckURL, VupenTspuURL
	VupenStickyCheckURL, VupenTspuURL = "", ""
	t.Cleanup(func() { VupenStickyCheckURL, VupenTspuURL = oldC, oldT })
	if l := vupenCheckList(); len(l) != 3 || l[0] != VupenCheckDefaultURLs[0] {
		t.Fatalf("default 24 KB list: %v", l)
	}
	if l := vupenTspuList(); len(l) != 3 || l[2] != VupenTspuDefaultURLs[2] {
		t.Fatalf("default 64 KB list: %v", l)
	}
}

func TestVupenSetCheckURLList(t *testing.T) {
	vupenCheckURLs.reset()
	t.Cleanup(vupenCheckURLs.reset)
	a, b, c := "https://a.example/x", "https://b.example/y", "https://c.example/z"
	if e := VupenSetCheckURL(a, b+" \n"+c+" "+a); e != "" {
		t.Fatal(e)
	}
	if l := vupenCheckList(); strings.Join(l, " ") != a+" "+b+" "+c {
		t.Fatalf("list (dedup, order): %v", l)
	}
	var many string
	for i := 0; i < 9; i++ {
		many += fmt.Sprintf("https://m%d.example/x ", i)
	}
	for _, bad := range [][2]string{{a, b + " http://c.example/z"}, {a, "https://"}, {"", b}, {a, many}} {
		if e := VupenSetCheckURL(bad[0], bad[1]); e == "" {
			t.Errorf("%q must be rejected", bad)
		}
		if l := vupenCheckList(); len(l) != 3 {
			t.Fatalf("a rejected call changed the list: %v", l)
		}
	}
	// Тот же список (приложение зовёт на каждом запуске) память выигравшего не сбрасывает.
	vupenCheckURLs.winner.Store(2)
	if e := VupenSetCheckURL(a, b+" "+c); e != "" || vupenCheckURLs.winner.Load() != 2 {
		t.Fatalf("same list resets the winner: %q %d", e, vupenCheckURLs.winner.Load())
	}
	if e := VupenSetCheckURL(b, a); e != "" || vupenCheckURLs.winner.Load() != 0 {
		t.Fatalf("a new list starts from the top: %q %d", e, vupenCheckURLs.winner.Load())
	}

	vupenTspuURLs.reset()
	t.Cleanup(vupenTspuURLs.reset)
	if e := VupenSetTspuURLs(nil); e == "" {
		t.Fatal("an empty 64 KB list must be rejected")
	}
	if e := VupenSetTspuURLs([]string{a, "http://x.example/y"}); e == "" {
		t.Fatal("a non-https 64 KB url must be rejected")
	}
	if vupenTspuURLs.set.Load() != nil {
		t.Fatal("a rejected 64 KB list was stored")
	}
	if e := VupenSetTspuURLs([]string{a, b}); e != "" || len(vupenTspuList()) != 2 {
		t.Fatalf("64 KB list: %q %v", e, vupenTspuList())
	}
}

// Порядок + выигравший запоминается: следующая проверка начинается с него, а при его
// провале «со стороны хоста» идёт по кругу к началу списка.
func TestVupenCheckListOrderAndWinner(t *testing.T) {
	a := listServer(t, 24576, "404")
	b := listServer(t, 24576, "")
	c := listServer(t, 24576, "")
	o, _ := listCheckEnv(t, a.url, b.url, c.url)

	r := o.VupenStickyCheckWith("proxy-1", VupenCheckOptions{})
	if r.Verdict != VupenStickyOK || !strings.Contains(r.Detail, "fallback") || a.hits.Load() != 1 || b.hits.Load() != 1 || c.hits.Load() != 0 {
		t.Fatalf("1st: %+v a=%d b=%d c=%d", r, a.hits.Load(), b.hits.Load(), c.hits.Load())
	}
	if vupenCheckURLs.winner.Load() != 1 {
		t.Fatalf("winner = %d, want 1", vupenCheckURLs.winner.Load())
	}
	r = o.VupenStickyCheckWith("proxy-1", VupenCheckOptions{})
	if r.Verdict != VupenStickyOK || strings.Contains(r.Detail, "fallback") || a.hits.Load() != 1 || b.hits.Load() != 2 {
		t.Fatalf("2nd must start from the winner: %+v a=%d b=%d", r, a.hits.Load(), b.hits.Load())
	}
	// Победитель — последний в списке и он не понял (404): по кругу к началу списка.
	first := listServer(t, 24576, "")
	last := listServer(t, 24576, "404")
	vupenCheckURLs.store([]string{first.url, a.url, last.url})
	vupenCheckURLs.winner.Store(2)
	r = o.VupenStickyCheckWith("proxy-1", VupenCheckOptions{})
	if r.Verdict != VupenStickyOK || last.hits.Load() != 1 || first.hits.Load() != 1 || a.hits.Load() != 1 {
		t.Fatalf("wrap-around: %+v last=%d first=%d a=%d", r, last.hits.Load(), first.hits.Load(), a.hits.Load())
	}
	if vupenCheckURLs.winner.Load() != 0 {
		t.Fatalf("winner = %d, want 0", vupenCheckURLs.winner.Load())
	}
}

// Ошибка соединения с основным (отказ) — запасной; не больше двух адресов за проверку.
func TestVupenCheckListFallbackOnConnectError(t *testing.T) {
	d := deadServer(t)
	ok := listServer(t, 24576, "")
	o, _ := listCheckEnv(t, d.url, ok.url)
	r := o.VupenStickyCheckWith("proxy-1", VupenCheckOptions{})
	if r.Verdict != VupenStickyOK || !strings.Contains(r.Detail, "fallback") || ok.hits.Load() != 1 {
		t.Fatalf("refused primary → fallback: %+v hits=%d", r, ok.hits.Load())
	}
	if vupenCheckURLs.winner.Load() != 1 {
		t.Fatalf("winner = %d", vupenCheckURLs.winner.Load())
	}
}

// Встал или не начался на основном — рисунок заморозки: запасной НЕ пробуем.
func TestVupenCheckListNoFallbackOnStall(t *testing.T) {
	ok := listServer(t, 24576, "")
	for _, c := range []struct{ mode, kind string }{{"stall", "stall"}, {"slow", "nostart"}} {
		stalled := listServer(t, 24576, c.mode)
		o, _ := listCheckEnv(t, stalled.url, ok.url)
		before := ok.hits.Load()
		r := o.VupenStickyCheckWith("proxy-1", VupenCheckOptions{})
		if r.Verdict != VupenStickyFailed || r.Kind != c.kind || ok.hits.Load() != before || stalled.hits.Load() != 1 {
			t.Errorf("%s: %+v fallback hits %d→%d", c.mode, r, before, ok.hits.Load())
		}
		if vupenCheckURLs.winner.Load() != 0 {
			t.Errorf("%s: a failed check moved the winner to %d", c.mode, vupenCheckURLs.winner.Load())
		}
	}
}

// Все (оба пробованных) адреса не открылись одним видом соединения — unknown, не failed;
// третий адрес не пробуем (максимум два за проверку).
func TestVupenCheckListAllConnectFailIsUnknown(t *testing.T) {
	d1, d2 := deadServer(t), deadServer(t)
	third := listServer(t, 24576, "")
	o, h := listCheckEnv(t, d1.url, d2.url, third.url)
	probeAt(h, "proxy-1", true, time.Second) // свежая проба — доказательство, что узел жив (T-131)
	r := o.VupenStickyCheckWith("proxy-1", VupenCheckOptions{})
	if r.Verdict != VupenStickyUnknown || r.Kind != "error" || third.hits.Load() != 0 || !strings.Contains(r.Detail, "check hosts unreachable") {
		t.Fatalf("both refused: %+v third hits=%d", r, third.hits.Load())
	}
	// HTTP на одном и отказ на другом — тоже хост проверки, а не узел.
	h404 := listServer(t, 24576, "404")
	vupenCheckURLs.store([]string{h404.url, d1.url})
	if r := o.VupenStickyCheckWith("proxy-1", VupenCheckOptions{}); r.Verdict != VupenStickyUnknown {
		t.Fatalf("404 + refused: %+v", r)
	}
	// Один адрес в списке: хост проверки от мёртвого узла не отличить — прежнее «failed».
	vupenCheckURLs.store([]string{d1.url})
	if r := o.VupenStickyCheckWith("proxy-1", VupenCheckOptions{}); r.Verdict != VupenStickyFailed || r.Kind != "error" {
		t.Fatalf("single url refused: %+v", r)
	}
}

// Разные виды ошибок соединения, либо один адрес встал — это уже не «хост проверки».
func TestVupenCheckListMixedFailuresStayFailed(t *testing.T) {
	refused, other := deadServer(t), deadServer(t)
	stalled := listServer(t, 24576, "stall")
	o, h := listCheckEnv(t)
	probeAt(h, "proxy-1", true, time.Second) // доказательство жизни узла (T-131)
	setTestDialer(t, func(ctx context.Context, d routing.Dispatcher, dest net.Destination, tag string) (net.Conn, error) {
		if strings.HasSuffix(refused.url, dest.Port.String()) {
			return nil, errors.New("dial tcp: connection refused")
		}
		if strings.HasSuffix(other.url, dest.Port.String()) {
			return nil, errors.New("lookup cdn.example: no such host")
		}
		return stdnet.Dial("tcp", dest.NetAddr())
	})
	vupenCheckURLs.store([]string{refused.url, other.url})
	if r := o.VupenStickyCheckWith("proxy-1", VupenCheckOptions{}); r.Verdict != VupenStickyFailed {
		t.Fatalf("refused + dns are different kinds: %+v", r)
	}
	vupenCheckURLs.store([]string{refused.url, stalled.url})
	if r := o.VupenStickyCheckWith("proxy-1", VupenCheckOptions{}); r.Verdict != VupenStickyFailed || r.Kind != "stall" {
		t.Fatalf("refused, then the second stalls: %+v", r)
	}
	vupenCheckURLs.store([]string{refused.url, refused.url + "/other"})
	if r := o.VupenStickyCheckWith("proxy-1", VupenCheckOptions{}); r.Verdict != VupenStickyUnknown {
		t.Fatalf("the same kind twice: %+v", r)
	}
}

// Адреса вызывающего (opt.URL + FallbackURL со списком) идут без памяти выигравшего.
func TestVupenCheckExplicitURLsKeepNoMemory(t *testing.T) {
	a := listServer(t, 24576, "404")
	b := listServer(t, 24576, "")
	o, _ := listCheckEnv(t, "https://unused.example/x")
	opt := VupenCheckOptions{URL: a.url, FallbackURL: b.url}
	for i := 1; i <= 2; i++ {
		if r := o.VupenStickyCheckWith("proxy-1", opt); r.Verdict != VupenStickyOK || a.hits.Load() != int32(i) {
			t.Fatalf("round %d: %+v a=%d", i, r, a.hits.Load())
		}
	}
	if vupenCheckURLs.winner.Load() != 0 {
		t.Fatal("explicit urls must not touch the platform winner")
	}
}

// Файл больше 24 КБ (jQuery, 87 533 Б): читаем целиком и сверяем с Content-Length.
func TestVupenCheckBigFileIsFine(t *testing.T) {
	big := listServer(t, 87533, "")
	o, _ := listCheckEnv(t, big.url)
	if r := o.VupenStickyCheckWith("proxy-1", VupenCheckOptions{}); r.Verdict != VupenStickyOK || !strings.Contains(r.Detail, "85 KB") {
		t.Fatalf("87 533 B file: %+v", r)
	}
}

// Проверка 64 КБ (vupenTspuProbeOnce) идёт по тому же правилу.
func TestVupenTspuProbeList(t *testing.T) {
	probe := func(h *HealthPing, urls ...string) (vupenTspuVerdict, string) {
		vupenTspuURLs.store(urls)
		return h.vupenTspuProbeOnce(context.Background(), "proxy-1", 300*time.Millisecond)
	}
	d1, d2 := deadServer(t), deadServer(t)
	ok := listServer(t, 87533, "")
	stalled := listServer(t, 87533, "stall")
	h404 := listServer(t, 87533, "404")
	_, h := listCheckEnv(t)

	if v, d := probe(h, d1.url, ok.url); v != vupenTspuOK || !strings.Contains(d, "fallback") || vupenTspuURLs.winner.Load() != 1 {
		t.Fatalf("refused → fallback: %v %s winner=%d", v, d, vupenTspuURLs.winner.Load())
	}
	before := ok.hits.Load()
	if v, _ := probe(h, stalled.url, ok.url); v != vupenTspuSuspect || ok.hits.Load() != before {
		t.Fatalf("a stall on the first → frozen, no fallback: %v hits %d→%d", v, before, ok.hits.Load())
	}
	if v, _ := probe(h, d1.url, d2.url); v != vupenTspuUnknown {
		t.Fatalf("both refused → unknown: %v", v)
	}
	if v, _ := probe(h, h404.url, stalled.url); v != vupenTspuSuspect {
		t.Fatalf("404 then a stall → frozen: %v", v)
	}
	if v, d := probe(h, h404.url, ok.url); v != vupenTspuOK || vupenTspuURLs.winner.Load() != 1 {
		t.Fatalf("404 → fallback ok: %v %s", v, d)
	}
	// Старый путь: одна переменная VupenTspuURL (e2e-тесты) заменяет список по умолчанию.
	vupenTspuURLs.reset()
	old := VupenTspuURL
	VupenTspuURL = ok.url
	t.Cleanup(func() { VupenTspuURL = old })
	if v, _ := h.vupenTspuProbeOnce(context.Background(), "proxy-1", 300*time.Millisecond); v != vupenTspuOK {
		t.Fatalf("VupenTspuURL override: %v", v)
	}
}
