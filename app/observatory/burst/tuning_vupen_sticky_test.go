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
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// ── fakes ───────────────────────────────────────────────────────────────────

type stickyFakeHandler struct {
	tag     string
	typ     string
	dialErr error
	dials   atomic.Int32
}

func (h *stickyFakeHandler) Start() error                                    { return nil }
func (h *stickyFakeHandler) Close() error                                    { return nil }
func (h *stickyFakeHandler) Tag() string                                     { return h.tag }
func (h *stickyFakeHandler) Dispatch(ctx context.Context, l *transport.Link) {}
func (h *stickyFakeHandler) SenderSettings() *serial.TypedMessage            { return nil }
func (h *stickyFakeHandler) ProxySettings() *serial.TypedMessage {
	return &serial.TypedMessage{Type: h.typ}
}
func (h *stickyFakeHandler) Dial(ctx context.Context, dest net.Destination) (stat.Connection, error) {
	h.dials.Add(1)
	if h.dialErr != nil {
		return nil, h.dialErr
	}
	c1, c2 := stdnet.Pipe()
	c2.Close()
	return c1, nil
}

type stickyFakeOhm struct {
	outbound.Manager
	handlers []outbound.Handler
}

func (m *stickyFakeOhm) GetHandler(tag string) outbound.Handler {
	for _, h := range m.handlers {
		if h.Tag() == tag {
			return h
		}
	}
	return nil
}
func (m *stickyFakeOhm) ListHandlers(ctx context.Context) []outbound.Handler { return m.handlers }

func onDemandObserver(t *testing.T, onDemand bool) (*Observer, *atomic.Int64) {
	t.Helper()
	vupenObsResetForTest(t, time.Hour, time.Millisecond)
	var dials atomic.Int64
	setTestDialer(t, func(ctx context.Context, d routing.Dispatcher, dest net.Destination, tag string) (net.Conn, error) {
		dials.Add(1)
		return nil, errors.New("down")
	})
	oldInit := VupenObservatoryInitialDelay
	VupenObservatoryInitialDelay = 10 * time.Millisecond
	t.Cleanup(func() { VupenObservatoryInitialDelay = oldInit })
	o := &Observer{
		config: &Config{SubjectSelector: []string{"proxy"}, VupenOnDemand: onDemand},
		ctx:    context.Background(),
		hp:     newSleepTestPing(),
		ohm:    &stickyFakeOhm{},
	}
	return o, &dials
}

// ── tests ───────────────────────────────────────────────────────────────────

// vupenOnDemand: планировщик не запускается — ни стартовой пачки, ни раундов;
// без поля — как раньше (стартовая пачка уходит).
func TestVupenOnDemandNoScheduledRounds(t *testing.T) {
	t.Run("on demand", func(t *testing.T) {
		o, dials := onDemandObserver(t, true)
		hs := &stickySelector{tags: []string{"proxy-1", "proxy-2"}}
		o.ohm = hs
		if err := o.Start(); err != nil {
			t.Fatal(err)
		}
		time.Sleep(200 * time.Millisecond)
		if n := dials.Load(); n != 0 || o.hp.ticker != nil {
			t.Fatalf("on demand: %d probes, ticker=%v — want none", n, o.hp.ticker != nil)
		}
		vupenObs.mu.Lock()
		_, registered := vupenObs.pings[o.hp]
		vupenObs.mu.Unlock()
		if !registered {
			t.Fatal("on-demand observatory must still see sleep/network signals")
		}
		o.Close()
		vupenObs.mu.Lock()
		_, registered = vupenObs.pings[o.hp]
		vupenObs.mu.Unlock()
		if registered || o.hp.ctx.Err() == nil {
			t.Fatal("Close must unregister and cancel")
		}
	})
	t.Run("scheduled (unchanged)", func(t *testing.T) {
		o, dials := onDemandObserver(t, false)
		o.ohm = &stickySelector{tags: []string{"proxy-1", "proxy-2"}}
		if err := o.Start(); err != nil {
			t.Fatal(err)
		}
		defer quiesce(t, o.hp)
		deadline := time.Now().Add(2 * time.Second)
		for dials.Load() == 0 && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		if dials.Load() == 0 || o.hp.ticker == nil {
			t.Fatal("without vupenOnDemand the scheduler must run as before")
		}
	})
}

type stickySelector struct {
	stickyFakeOhm
	tags []string
}

func (s *stickySelector) Select([]string) []string { return s.tags }

// По требованию: проверка топ-3 после раунда и пачка на пробуждении не идут.
func TestVupenOnDemandSkipsAfterRoundAndWakeBurst(t *testing.T) {
	h, calls := tspuTestPing(t, vupenTspuOK, vupenTspuOK, vupenTspuOK)
	h.vupenOnDemand = true
	h.Settings.SamplingCount = 3
	h.PutResult("fast", 100*time.Millisecond)
	h.vupenTspuAfterRound([]string{"fast"})
	time.Sleep(50 * time.Millisecond)
	if calls.Load() != 0 {
		t.Fatalf("no after-round 64 KB checks on demand, got %d", calls.Load())
	}

	vupenObsResetForTest(t, 0, 0)
	vupenObsRegister(h)
	t.Cleanup(func() { vupenObsUnregister(h) })
	VupenObservatoryPause("test sleep")
	time.Sleep(5 * time.Millisecond)
	VupenObservatoryResume("test wake")
	if h.wakeBurst.Load() {
		t.Fatal("no wake burst for an on-demand observatory")
	}
}

// Подписка селектора узнаёт узлы пула без замеров (сторож заморозки, D-16).
func TestVupenOnDemandSubjectBySelector(t *testing.T) {
	o := &Observer{config: &Config{SubjectSelector: []string{"proxy", "lte-"}}}
	for tag, want := range map[string]bool{"proxy-1": true, "lte-proxy-2": true, "direct": false, "block": false} {
		if got := o.vupenIsSubject(tag); got != want {
			t.Errorf("%s: %v, want %v", tag, got, want)
		}
	}
}

func fileServer24(t *testing.T, status, send int, headerDelay time.Duration) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if status != 200 {
			w.WriteHeader(status)
			return
		}
		w.Header().Set("Content-Length", fmt.Sprint(24576))
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		select {
		case <-time.After(headerDelay):
		case <-r.Context().Done():
			return
		}
		_, _ = w.Write([]byte(strings.Repeat("x", send)))
		w.(http.Flusher).Flush()
		if send < 24576 {
			<-r.Context().Done()
		}
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// Проверка 24 КБ через узел: пришёл весь файл — ok; встал или не начался — failed;
// HTTP ≠ 200 — unknown («не поняли», узел не трогаем).
func TestVupenStickyCheck24(t *testing.T) {
	old := []any{VupenStickyCheckURL, VupenStickyCheckStall, VupenStickyCheckFirstByte, VupenStickyCheckTimeout}
	t.Cleanup(func() {
		VupenStickyCheckURL = old[0].(string)
		VupenStickyCheckStall = old[1].(time.Duration)
		VupenStickyCheckFirstByte = old[2].(time.Duration)
		VupenStickyCheckTimeout = old[3].(time.Duration)
	})
	// FirstByte < Timeout < задержки тела: «не началась» должна сработать по
	// FirstByte, а не по общему таймауту.
	VupenStickyCheckStall, VupenStickyCheckFirstByte, VupenStickyCheckTimeout = 300*time.Millisecond, 500*time.Millisecond, 3*time.Second
	var mode atomic.Value // "", "refuse", "rst"
	mode.Store("")
	rst := rstListener(t)
	midRst := midBodyRstListener(t)
	setTestDialer(t, func(ctx context.Context, d routing.Dispatcher, dest net.Destination, tag string) (net.Conn, error) {
		switch mode.Load().(string) {
		case "refuse":
			return nil, errors.New("dial tcp: connection refused")
		case "rst":
			return stdnet.Dial("tcp", rst)
		case "midrst":
			return stdnet.Dial("tcp", midRst)
		}
		return stdnet.Dial("tcp", dest.NetAddr())
	})
	h := NewHealthPing(context.Background(), nil, nil)
	t.Cleanup(h.cancelCtx)
	o := &Observer{hp: h}
	for _, c := range []struct {
		name         string
		mode         string
		status, send int
		headerDelay  time.Duration
		want         string
		maxTime      time.Duration
	}{
		{"whole file", "", 200, 24576, 0, VupenStickyOK, 0},
		{"stalled at 8 KB", "", 200, 8192, 0, VupenStickyFailed, 0},
		{"never started (first-byte limit)", "", 200, 24576, 5 * time.Second, VupenStickyFailed, 2 * time.Second},
		{"HTTP 429", "", 429, 0, 0, VupenStickyUnknown, 0},
		// CR-201: нет ответа узла вовсе — провал (дальше решает проверка сети).
		{"dial refused", "refuse", 200, 24576, 0, VupenStickyFailed, 0},
		{"connection reset", "rst", 200, 24576, 0, VupenStickyFailed, 0},
		// CR-207: 200 и Content-Length 24576, 8 КБ тела, затем RST.
		{"reset mid-body", "midrst", 200, 24576, 0, VupenStickyFailed, 0},
	} {
		mode.Store(c.mode)
		VupenStickyCheckURL = fileServer24(t, c.status, c.send, c.headerDelay)
		start := time.Now()
		got := o.VupenStickyCheck("proxy-1")
		took := time.Since(start)
		if got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
		if c.maxTime > 0 && took >= c.maxTime {
			t.Errorf("%s: took %v — the first-byte limit (%v) must end it before the timeout (%v)",
				c.name, took, VupenStickyCheckFirstByte, VupenStickyCheckTimeout)
		}
	}
}

// midBodyRstListener — отвечает 200 с Content-Length 24576, отдаёт 8 КБ тела и
// сбрасывает соединение (RST).
func midBodyRstListener(t *testing.T) string {
	t.Helper()
	l, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func(c stdnet.Conn) {
				buf := make([]byte, 4096)
				_, _ = c.Read(buf) // запрос
				_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 24576\r\n\r\n" + strings.Repeat("x", 8192)))
				time.Sleep(50 * time.Millisecond)
				_ = c.(*stdnet.TCPConn).SetLinger(0)
				c.Close()
			}(c)
		}
	}()
	return l.Addr().String()
}

// rstListener — принимает соединение и сразу сбрасывает его (RST).
func rstListener(t *testing.T) string {
	t.Helper()
	l, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			_ = c.(*stdnet.TCPConn).SetLinger(0)
			c.Close()
		}
	}()
	return l.Addr().String()
}

// «Есть ли сеть у устройства»: через outbound direct, если он freedom; иначе
// через любой freedom; нет ни того, ни другого — unknown.
func TestVupenStickyNetwork(t *testing.T) {
	freedom, vless := "xray.proxy.freedom.Config", "xray.proxy.vless.outbound.Config"
	direct := &stickyFakeHandler{tag: "direct", typ: freedom}
	if got := (&Observer{ctx: context.Background(), ohm: &stickyFakeOhm{handlers: []outbound.Handler{direct}}}).VupenStickyNetwork(); got != VupenNetUp || direct.dials.Load() != 1 {
		t.Fatalf("direct freedom up: %s dials=%d", got, direct.dials.Load())
	}
	down := &stickyFakeHandler{tag: "direct", typ: freedom, dialErr: errors.New("no route")}
	if got := (&Observer{ctx: context.Background(), ohm: &stickyFakeOhm{handlers: []outbound.Handler{down}}}).VupenStickyNetwork(); got != VupenNetDown {
		t.Fatalf("direct freedom down: %s", got)
	}
	notFreedom := &stickyFakeHandler{tag: "direct", typ: vless}
	other := &stickyFakeHandler{tag: "free", typ: freedom}
	if got := (&Observer{ctx: context.Background(), ohm: &stickyFakeOhm{handlers: []outbound.Handler{notFreedom, other}}}).VupenStickyNetwork(); got != VupenNetUp ||
		notFreedom.dials.Load() != 0 || other.dials.Load() != 1 {
		t.Fatalf("direct is not freedom → any freedom: %s", got)
	}
	none := &Observer{ctx: context.Background(), ohm: &stickyFakeOhm{handlers: []outbound.Handler{notFreedom}}}
	if got := none.VupenStickyNetwork(); got != VupenNetUnknown {
		t.Fatalf("no freedom outbound → unknown, got %s", got)
	}
}

// Проверка 64 КБ синхронно — тот же итог, что у ядра 71.
func TestVupenStickyVerify(t *testing.T) {
	for _, c := range []struct {
		script []vupenTspuVerdict
		want   string
	}{
		{[]vupenTspuVerdict{vupenTspuOK}, VupenStickyOK},
		{[]vupenTspuVerdict{vupenTspuSuspect, vupenTspuSuspect}, VupenStickyFailed},
		{[]vupenTspuVerdict{vupenTspuUnknown}, VupenStickyUnknown},
	} {
		h, _ := tspuTestPing(t, c.script...)
		o := &Observer{hp: h}
		if got := o.VupenStickyVerify("proxy-3"); got != c.want {
			t.Fatalf("%v: %s, want %s", c.script, got, c.want)
		}
		if (c.want == VupenStickyFailed) != o.VupenStickyExcluded("proxy-3") {
			t.Fatalf("%v: excluded=%v", c.script, o.VupenStickyExcluded("proxy-3"))
		}
	}
	h, _ := tspuTestPing(t)
	o := &Observer{hp: h, ctx: context.Background()}
	o.VupenStickyExclude("proxy-9", "test")
	if !o.VupenStickyExcluded("proxy-9") {
		t.Fatal("VupenStickyExclude must exclude")
	}
}

// CR-202: итог — этой проверки. Свежая проверка «не поняли» после прежнего
// «проверен» (отметка ещё действует 30 мин) не даёт перейти на узел.
func TestVupenStickyVerifyUsesThisRunsVerdict(t *testing.T) {
	h, calls := tspuTestPing(t, vupenTspuOK, vupenTspuUnknown)
	o := &Observer{hp: h}
	if got := o.VupenStickyVerify("proxy-3"); got != VupenStickyOK {
		t.Fatalf("first search: %s", got)
	}
	if got := o.VupenStickyVerify("proxy-3"); got != VupenStickyUnknown || calls.Load() != 2 {
		t.Fatalf("second search after an inconclusive run must not be ok: %s (probes %d)", got, calls.Load())
	}
}

// CR-202: идущая проверка ядра 71 — ждём её и берём её итог, второй раз не качаем.
func TestVupenStickyVerifyWaitsForInflightCheck(t *testing.T) {
	h, calls := tspuTestPing(t, vupenTspuSuspect, vupenTspuSuspect)
	release := make(chan struct{})
	probe := h.tspuProbe
	h.tspuProbe = func(ctx context.Context, tag string, stall time.Duration) (vupenTspuVerdict, string) {
		<-release
		return probe(ctx, tag, stall)
	}
	h.vupenTspuRequest("proxy-5", false, "candidate")
	o := &Observer{hp: h}
	done := make(chan string, 1)
	go func() { done <- o.VupenStickyVerify("proxy-5") }()
	time.Sleep(100 * time.Millisecond)
	close(release)
	select {
	case got := <-done:
		if got != VupenStickyFailed || calls.Load() != 2 {
			t.Fatalf("in-flight verdict: %s, probes %d (want failed, 2 — no second download)", got, calls.Load())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("VupenStickyVerify did not return")
	}
}

// Ядро 76: по требованию тишина и итоги соединений идут подписчику (балансировщику
// «держать текущий»), а не в проверку 64 КБ ядра 71; без поля — как раньше.
func TestVupenSignalsRouting(t *testing.T) {
	type sig struct {
		tag, kind string
		ok        bool
	}
	h, calls := tspuTestPing(t, vupenTspuOK, vupenTspuOK)
	o := &Observer{hp: h}
	got := make(chan sig, 8)
	unsub := o.VupenStickyListen(func(tag, kind string, ok bool, detail string) { got <- sig{tag, kind, ok} })

	h.vupenOnDemand = true
	vupenTspuSuspectHook(h, "proxy-1", 16<<10, 2<<10)
	vupenTspuAttemptHook(h, "proxy-1", false, "refused")
	vupenTspuAttemptHook(h, "proxy-1", true, "")
	for _, want := range []sig{{"proxy-1", "freeze", false}, {"proxy-1", "dial", false}, {"proxy-1", "dial", true}} {
		select {
		case g := <-got:
			if g != want {
				t.Fatalf("signal %+v, want %+v", g, want)
			}
		case <-time.After(time.Second):
			t.Fatalf("missing signal %+v", want)
		}
	}
	time.Sleep(30 * time.Millisecond)
	if calls.Load() != 0 {
		t.Fatalf("on demand the watchdog must not start the 64 KB check, probes %d", calls.Load())
	}

	h.vupenOnDemand = false
	vupenTspuAttemptHook(h, "proxy-1", false, "refused")
	vupenTspuSuspectHook(h, "proxy-2", 16<<10, 2<<10)
	waitTspuIdle(t, h, "proxy-2")
	if calls.Load() == 0 {
		t.Fatal("without vupenOnDemand the watchdog keeps the core-71 64 KB check")
	}
	select {
	case g := <-got:
		t.Fatalf("no signals without vupenOnDemand: %+v", g)
	default:
	}
	unsub()
}

// Пробы и проверки (24/64 КБ) открываются в служебном контексте — сторож их не наблюдает.
func TestVupenProbeConnectionsAreService(t *testing.T) {
	var service atomic.Bool
	setTestDialer(t, func(ctx context.Context, d routing.Dispatcher, dest net.Destination, tag string) (net.Conn, error) {
		service.Store(internet.VupenIsServiceContext(ctx))
		return nil, errors.New("down")
	})
	c := newHTTPClient(context.Background(), nil, "proxy-1", time.Second)
	_, _ = c.Get("http://probe.test/")
	if !service.Load() {
		t.Fatal("probe connections must carry the service marker")
	}
}
