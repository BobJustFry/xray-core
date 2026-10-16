package burst_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	stdnet "net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/observatory/burst"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/extension"
	"github.com/xtls/xray-core/features/routing"
	routing_session "github.com/xtls/xray-core/features/routing/session"
	coreserial "github.com/xtls/xray-core/infra/conf/serial"
	"github.com/xtls/xray-core/transport/internet"
)

// vupenStickySettings — короткие тайминги проверок для тестов, с восстановлением.
func vupenStickySettings(t *testing.T, netCheckAddr string) {
	t.Helper()
	durs := []*time.Duration{&burst.VupenStickyCheckStall, &burst.VupenStickyCheckFirstByte, &burst.VupenStickyCheckTimeout,
		&burst.VupenTspuStall, &burst.VupenTspuRetryPause, &burst.VupenTspuTimeout, &burst.VupenObservatoryInitialDelay}
	vals := []time.Duration{300 * time.Millisecond, time.Second, 3 * time.Second,
		300 * time.Millisecond, 20 * time.Millisecond, 3 * time.Second, 100 * time.Millisecond}
	for i, p := range durs {
		old := *p
		*p = vals[i]
		t.Cleanup(func() { *p = old })
	}
	oldURL, oldTspu, oldNet := burst.VupenStickyCheckURL, burst.VupenTspuURL, burst.VupenNetCheckAddr
	burst.VupenStickyCheckURL, burst.VupenTspuURL, burst.VupenNetCheckAddr = "http://probe.test/file24", "http://probe.test/file", netCheckAddr
	t.Cleanup(func() {
		burst.VupenStickyCheckURL, burst.VupenTspuURL, burst.VupenNetCheckAddr = oldURL, oldTspu, oldNet
	})
}

// nodeServer — «узел»: проба (20 мс), файлы 24 КБ и 64 КБ.
func nodeServer(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		size := 0
		switch r.URL.Path {
		case "/file24":
			size = 24576
		case "/file":
			size = 64 << 10
		}
		if size > 0 {
			w.Header().Set("Content-Length", fmt.Sprint(size))
			w.WriteHeader(200)
			_, _ = w.Write([]byte(strings.Repeat("x", size)))
			return
		}
		time.Sleep(vupenProbeRTT)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://")
}

// localListener — «есть сеть у устройства»: принимает TCP и закрывает.
func localListener(t *testing.T) string {
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
			c.Close()
		}
	}()
	return l.Addr().String()
}

func startCore(t *testing.T, cfg string) *core.Instance {
	t.Helper()
	config, err := coreserial.LoadJSONConfig(strings.NewReader(cfg))
	if err != nil {
		t.Fatal(err)
	}
	inst, err := core.New(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := inst.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { inst.Close() })
	return inst
}

func pickREG(t *testing.T, inst *core.Instance) string {
	t.Helper()
	r := inst.GetFeature(routing.RouterType()).(routing.Router)
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
		Target: xnet.TCPDestination(xnet.DomainAddress("example.com"), 443),
	}})
	route, err := r.PickRoute(routing_session.AsRoutingContext(ctx))
	if err != nil {
		t.Fatal(err)
	}
	return route.GetOutboundTag()
}

// Настоящее ядро в АВТО 4.1: последний рабочий узел заморожен (24 КБ встают на
// 16 КБ), сеть у устройства есть → он исключается, поиск проверяет 64 КБ и
// переходит на рабочий; плановых раундов нет.
func TestVupenStickyEndToEnd(t *testing.T) {
	vupenStickySettings(t, localListener(t))
	good, frozenBackend := nodeServer(t), nodeServer(t)
	relay := freezeRelay(t, frozenBackend, 16<<10)
	inst := startCore(t, fmt.Sprintf(`{
	  "log": {"loglevel": "none"},
	  "outbounds": [
	    {"tag": "proxy-frozen", "protocol": "freedom", "settings": {"redirect": "127.0.0.1:%d"}},
	    {"tag": "proxy-good", "protocol": "freedom", "settings": {"redirect": "%s"}},
	    {"tag": "direct", "protocol": "freedom"}
	  ],
	  "routing": {
	    "rules": [{"port": "0-65535", "balancerTag": "REG"}],
	    "balancers": [{"tag": "REG", "selector": ["proxy"], "strategy": {"type": "leastPing"},
	      "fallbackTag": "proxy-frozen", "vupenSticky": {"initial": "proxy-frozen"}}]
	  },
	  "burstObservatory": {
	    "subjectSelector": ["proxy"], "vupenOnDemand": true,
	    "pingConfig": {"destination": "http://probe.test/ping", "interval": "10s", "sampling": 1, "timeout": "3s"}
	  }
	}`, relay, good))
	obs := inst.GetFeature(extension.ObservatoryType()).(*burst.Observer)

	if got := pickREG(t, inst); got != "proxy-frozen" {
		t.Fatalf("while checking initial the traffic goes to initial, got %q", got)
	}
	// Пока идёт поиск, fallbackTag (= отказавший initial) исключён, и трафик идёт
	// во временный кандидат; выбор фиксируется после проверки 64 КБ.
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if obs.VupenTspuVerified("proxy-good") {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if got := pickREG(t, inst); got != "proxy-good" {
		t.Fatalf("after the failed initial check the verified node must be chosen, got %q", got)
	}
	if !obs.VupenStickyExcluded("proxy-frozen") {
		t.Fatal("the failed initial must be excluded")
	}
	if !obs.VupenTspuVerified("proxy-good") {
		t.Fatal("the new node must have passed the 64 KB check")
	}
}

// muxBackend — «сервер за узлом»: HTTP-запросы проб и проверок (HEAD/GET:
// /ping 204 через 20 мс, /file24 — 24 КБ, /file — 64 КБ); остальное — эхо
// первых 2 КБ (приветствие), дальше сервер только принимает (как загрузку).
func muxBackend(t *testing.T) string {
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
				defer c.Close()
				buf := make([]byte, 64<<10)
				n, err := c.Read(buf)
				if err != nil {
					return
				}
				head := string(buf[:n])
				if !strings.HasPrefix(head, "GET ") && !strings.HasPrefix(head, "HEAD ") {
					echoed := 0
					for echoed < 2048 {
						if _, err := c.Write(buf[:n]); err != nil {
							return
						}
						echoed += n
						if echoed >= 2048 {
							break
						}
						if n, err = c.Read(buf); err != nil {
							return
						}
					}
					_, _ = io.Copy(io.Discard, c)
					return
				}
				path := strings.Fields(head)[1]
				size := 0
				switch path {
				case "/file24":
					size = 24576
				case "/file":
					size = 64 << 10
				default:
					time.Sleep(vupenProbeRTT)
					_, _ = c.Write([]byte("HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n"))
					return
				}
				_, _ = c.Write([]byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", size)))
				if strings.HasPrefix(head, "GET ") {
					_, _ = c.Write([]byte(strings.Repeat("x", size)))
				}
			}(c)
		}
	}()
	return l.Addr().String()
}

// frozenAppConn — соединение приложения через узел: 2 КБ туда и обратно (данные в
// обе стороны), затем 16 КБ туда — на «замороженном» узле в ответ тишина.
func frozenAppConn(t *testing.T, inst *core.Instance, ctx context.Context) {
	t.Helper()
	conn, err := core.Dial(ctx, inst, xnet.TCPDestination(xnet.DomainAddress("app.test"), 443))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	hello := []byte(strings.Repeat("h", 2048))
	if _, err := conn.Write(hello); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	got := 0
	buf := make([]byte, 4096)
	for got < len(hello) {
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatalf("echo before the freeze: %v (got %d)", err, got)
		}
		got += n
	}
	if _, err := conn.Write([]byte(strings.Repeat("y", 16<<10))); err != nil {
		t.Fatal(err)
	}
}

// switchRelay — ретранслятор, который можно «заморозить» (после этого каждое
// соединение молчит после limit байт) или выключить (порт закрыт — dial-ошибки).
type switchRelay struct {
	t       *testing.T
	backend string
	port    int
	frozen  atomic.Bool
	closing atomic.Bool // принимает и сразу закрывает (рукопожатие TLS не проходит)
	ln      stdnet.Listener
}

func newSwitchRelay(t *testing.T, backend string, limit int64) *switchRelay {
	t.Helper()
	r := &switchRelay{t: t, backend: backend}
	ln, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r.ln = ln
	r.port = ln.Addr().(*stdnet.TCPAddr).Port
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go r.serve(c, limit)
		}
	}()
	return r
}

func (r *switchRelay) serve(c stdnet.Conn, limit int64) {
	defer c.Close()
	if r.closing.Load() {
		return
	}
	s, err := stdnet.Dial("tcp", r.backend)
	if err != nil {
		return
	}
	defer s.Close()
	var total atomic.Int64
	stop := make(chan struct{})
	var once sync.Once
	pipe := func(dst, src stdnet.Conn) {
		buf := make([]byte, 1024)
		for {
			n, err := src.Read(buf)
			if n > 0 {
				if r.frozen.Load() && total.Add(int64(n)) > limit {
					once.Do(func() { close(stop) })
					return
				}
				if _, err := dst.Write(buf[:n]); err != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}
	done := make(chan struct{}, 2)
	go func() { pipe(s, c); done <- struct{}{} }()
	go func() { pipe(c, s); done <- struct{}{} }()
	select {
	case <-done:
	case <-stop:
		_, _ = io.Copy(io.Discard, c) // молчим, но читаем: соединение «живое»
	}
}

func autoConfig(nodeA, nodeGood int, goodAddr string) string {
	good := goodAddr
	if good == "" {
		good = fmt.Sprintf("127.0.0.1:%d", nodeGood)
	}
	return fmt.Sprintf(`{
	  "log": {"loglevel": "none"},
	  "outbounds": [
	    {"tag": "proxy-a", "protocol": "freedom", "settings": {"redirect": "127.0.0.1:%d"}},
	    {"tag": "proxy-good", "protocol": "freedom", "settings": {"redirect": "%s"}},
	    {"tag": "direct", "protocol": "freedom"}
	  ],
	  "routing": {
	    "rules": [{"port": "0-65535", "balancerTag": "REG"}],
	    "balancers": [{"tag": "REG", "selector": ["proxy"], "strategy": {"type": "leastPing"},
	      "fallbackTag": "proxy-a", "vupenSticky": {"initial": "proxy-a"}}]
	  },
	  "burstObservatory": {
	    "subjectSelector": ["proxy"], "vupenOnDemand": true,
	    "pingConfig": {"destination": "http://probe.test/ping", "interval": "10s", "sampling": 1, "timeout": "3s"}
	  }
	}`, nodeA, good)
}

func waitPick(t *testing.T, inst *core.Instance, want string, within time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if pickREG(t, inst) == want {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

// П2 в АВТО 4.1 (ядро 76): текущий узел работал, потом его «заморозили». Одно
// замолчавшее соединение — ничего; два — проверка 24 КБ текущего, она не прошла,
// сеть есть → узел исключён, поиск, переход на проверенный.
func TestVupenStickyFreezeSignalSwitches(t *testing.T) {
	vupenStickySettings(t, localListener(t))
	oldSilence := internet.VupenFreezeSilence
	internet.VupenFreezeSilence = 300 * time.Millisecond
	t.Cleanup(func() { internet.VupenFreezeSilence = oldSilence })
	a := newSwitchRelay(t, muxBackend(t), 16<<10)
	inst := startCore(t, autoConfig(a.port, 0, muxBackend(t)))
	obs := inst.GetFeature(extension.ObservatoryType()).(*burst.Observer)
	if got := pickREG(t, inst); got != "proxy-a" {
		t.Fatalf("start: %q", got)
	}
	time.Sleep(time.Second) // проверка initial прошла (узел не заморожен)
	if got := pickREG(t, inst); got != "proxy-a" || obs.VupenStickyExcluded("proxy-a") {
		t.Fatalf("working initial must be kept: %q", got)
	}

	a.frozen.Store(true)
	frozenAppConn(t, inst, context.Background())
	time.Sleep(10 * internet.VupenFreezeSilence)
	if got := pickREG(t, inst); got != "proxy-a" || obs.VupenStickyExcluded("proxy-a") {
		t.Fatalf("one silent connection must not move the node: %q", got)
	}
	frozenAppConn(t, inst, context.Background())
	if !waitPick(t, inst, "proxy-good", 10*time.Second) || !obs.VupenStickyExcluded("proxy-a") {
		t.Fatalf("two silent connections → check failed → switch; pick %q", pickREG(t, inst))
	}
}

// CR-304: по требованию тревога сторожа идёт в проверку 24 КБ балансировщика,
// а не в проверку 64 КБ ядра 71: проверка не прошла, но сети у устройства нет —
// узел остаётся и не исключается (64 КБ заморозили бы его без проверки сети).
func TestVupenStickyFreezeSignalNetworkDownKeeps(t *testing.T) {
	closed, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	noNet := closed.Addr().String()
	closed.Close()
	vupenStickySettings(t, noNet) // проверка сети: порт закрыт → «сети нет»
	oldSilence := internet.VupenFreezeSilence
	internet.VupenFreezeSilence = 300 * time.Millisecond
	t.Cleanup(func() { internet.VupenFreezeSilence = oldSilence })
	a := newSwitchRelay(t, muxBackend(t), 16<<10)
	inst := startCore(t, autoConfig(a.port, 0, muxBackend(t)))
	obs := inst.GetFeature(extension.ObservatoryType()).(*burst.Observer)
	if got := pickREG(t, inst); got != "proxy-a" {
		t.Fatalf("start: %q", got)
	}
	time.Sleep(time.Second)
	a.frozen.Store(true)
	frozenAppConn(t, inst, context.Background())
	frozenAppConn(t, inst, context.Background())
	time.Sleep(5 * time.Second) // тревога, проверка 24 КБ (встаёт), проверка сети (нет)
	if got := pickREG(t, inst); got != "proxy-a" || obs.VupenStickyExcluded("proxy-a") {
		t.Fatalf("no network on the device: the node must be kept, got %q excluded=%v", got, obs.VupenStickyExcluded("proxy-a"))
	}
}

// П1 в АВТО 4.1 (ядро 76): текущий узел работал, потом пропал (порт закрыт):
// три неудачных соединения → проверка → провал, сеть есть → переход.
func TestVupenStickyDialFailuresSwitch(t *testing.T) {
	vupenStickySettings(t, localListener(t))
	reportUplink() // П1 по итогу internet.Dial — только когда платформа сообщила сеть
	a := newSwitchRelay(t, muxBackend(t), 1<<30)
	inst := startCore(t, autoConfig(a.port, 0, muxBackend(t)))
	if got := pickREG(t, inst); got != "proxy-a" {
		t.Fatalf("start: %q", got)
	}
	time.Sleep(time.Second)
	if got := pickREG(t, inst); got != "proxy-a" {
		t.Fatalf("working initial must be kept: %q", got)
	}
	a.ln.Close()
	for i := 0; i < 3; i++ {
		conn, err := core.Dial(context.Background(), inst, xnet.TCPDestination(xnet.DomainAddress("app.test"), 443))
		if err != nil {
			t.Fatal(err)
		}
		_, _ = conn.Write([]byte("hello"))
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _ = conn.Read(make([]byte, 16))
		conn.Close()
	}
	if !waitPick(t, inst, "proxy-good", 10*time.Second) {
		t.Fatalf("3 dial failures → check failed → switch; pick %q", pickREG(t, inst))
	}
}

// CR-201: последний рабочий узел мёртв (порт закрыт — ответа нет вовсе): это
// провал проверки, а не «не поняли»; сеть есть → исключён, поиск, переход.
func TestVupenStickyEndToEndDeadInitial(t *testing.T) {
	vupenStickySettings(t, localListener(t))
	// Пределы проверки 24 КБ — длинные: мёртвый узел должен распознаваться по
	// ошибке установления сразу, а не по «не начался за FirstByte».
	oldFB, oldTO := burst.VupenStickyCheckFirstByte, burst.VupenStickyCheckTimeout
	burst.VupenStickyCheckFirstByte, burst.VupenStickyCheckTimeout = 20*time.Second, 30*time.Second
	t.Cleanup(func() { burst.VupenStickyCheckFirstByte, burst.VupenStickyCheckTimeout = oldFB, oldTO })
	start := time.Now()
	good := nodeServer(t)
	closed, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadPort := closed.Addr().(*stdnet.TCPAddr).Port
	closed.Close()
	inst := startCore(t, fmt.Sprintf(`{
	  "log": {"loglevel": "none"},
	  "outbounds": [
	    {"tag": "proxy-dead", "protocol": "freedom", "settings": {"redirect": "127.0.0.1:%d"}},
	    {"tag": "proxy-good", "protocol": "freedom", "settings": {"redirect": "%s"}},
	    {"tag": "direct", "protocol": "freedom"}
	  ],
	  "routing": {
	    "rules": [{"port": "0-65535", "balancerTag": "REG"}],
	    "balancers": [{"tag": "REG", "selector": ["proxy"], "strategy": {"type": "leastPing"},
	      "fallbackTag": "proxy-dead", "vupenSticky": {"initial": "proxy-dead"}}]
	  },
	  "burstObservatory": {
	    "subjectSelector": ["proxy"], "vupenOnDemand": true,
	    "pingConfig": {"destination": "http://probe.test/ping", "interval": "10s", "sampling": 1, "timeout": "3s"}
	  }
	}`, deadPort, good))
	obs := inst.GetFeature(extension.ObservatoryType()).(*burst.Observer)
	if got := pickREG(t, inst); got != "proxy-dead" {
		t.Fatalf("while checking initial: %q", got)
	}
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) && !obs.VupenTspuVerified("proxy-good") {
		time.Sleep(50 * time.Millisecond)
	}
	if got := pickREG(t, inst); got != "proxy-good" || !obs.VupenStickyExcluded("proxy-dead") {
		t.Fatalf("a dead initial must be replaced: pick %q, dead excluded %v", got, obs.VupenStickyExcluded("proxy-dead"))
	}
	if took := time.Since(start); took > 10*time.Second {
		t.Fatalf("a dead initial must be recognised by the dial error, not by the first-byte limit: took %v", took)
	}
}

// reportUplink — как платформа: сообщить ядру сеть (уникальная подпись на вызов,
// состояние эпохи общее на процесс). Зовётся до старта ядра.
func reportUplink() {
	internet.VupenSetUplink("wifi", fmt.Sprintf("burst-e2e-%d", time.Now().UnixNano()))
}

// tlsNodeServer — «узел» за TLS (сертификат httptest): проба, 24 КБ, 64 КБ.
// Возвращает адрес и SHA-256 сертификата для pinnedPeerCertSha256.
func tlsNodeServer(t *testing.T) (string, string) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		size := 0
		switch r.URL.Path {
		case "/file24":
			size = 24576
		case "/file":
			size = 64 << 10
		}
		if size > 0 {
			w.Header().Set("Content-Length", fmt.Sprint(size))
			w.WriteHeader(200)
			_, _ = w.Write([]byte(strings.Repeat("x", size)))
			return
		}
		time.Sleep(vupenProbeRTT)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	sum := sha256.Sum256(srv.Certificate().Raw)
	return strings.TrimPrefix(srv.URL, "https://"), hex.EncodeToString(sum[:])
}

func tlsStream(pin string) string {
	return fmt.Sprintf(`"streamSettings": {"security": "tls", "tlsSettings": {"serverName": "example.com", "pinnedPeerCertSha256": "%s"}}`, pin)
}

// П1 (ядро 76) через TLS: узел работал, потом рукопожатие TLS перестало проходить
// (соединение принимается и сразу закрывается) — ошибки internet.Dial в
// outbound-обработчике → проверка → провал, сеть есть → переход.
func TestVupenStickyTLSHandshakeFailuresSwitch(t *testing.T) {
	vupenStickySettings(t, localListener(t))
	reportUplink() // П1/П5 по итогу internet.Dial — только когда платформа сообщила сеть
	node, pin := tlsNodeServer(t)
	a := newSwitchRelay(t, node, 1<<30)
	inst := startCore(t, fmt.Sprintf(`{
	  "log": {"loglevel": "none"},
	  "outbounds": [
	    {"tag": "proxy-a", "protocol": "freedom", "settings": {"redirect": "127.0.0.1:%d"}, %s},
	    {"tag": "proxy-good", "protocol": "freedom", "settings": {"redirect": "%s"}},
	    {"tag": "direct", "protocol": "freedom"}
	  ],
	  "routing": {
	    "rules": [{"port": "0-65535", "balancerTag": "REG"}],
	    "balancers": [{"tag": "REG", "selector": ["proxy"], "strategy": {"type": "leastPing"},
	      "fallbackTag": "proxy-a", "vupenSticky": {"initial": "proxy-a"}}]
	  },
	  "burstObservatory": {
	    "subjectSelector": ["proxy"], "vupenOnDemand": true,
	    "pingConfig": {"destination": "http://probe.test/ping", "interval": "10s", "sampling": 1, "timeout": "3s"}
	  }
	}`, a.port, tlsStream(pin), muxBackend(t)))
	if got := pickREG(t, inst); got != "proxy-a" {
		t.Fatalf("start: %q", got)
	}
	time.Sleep(time.Second)
	if got := pickREG(t, inst); got != "proxy-a" {
		t.Fatalf("the TLS node works at start (24 KB check passed): %q", got)
	}
	a.closing.Store(true)
	for i := 0; i < 3; i++ {
		conn, err := core.Dial(context.Background(), inst, xnet.TCPDestination(xnet.DomainAddress("app.test"), 443))
		if err != nil {
			t.Fatal(err)
		}
		_, _ = conn.Write([]byte("hello"))
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _ = conn.Read(make([]byte, 16))
		conn.Close()
	}
	if !waitPick(t, inst, "proxy-good", 10*time.Second) {
		t.Fatalf("3 TLS handshake failures → check failed → switch; pick %q", pickREG(t, inst))
	}
}

// П1/П5 (ядро 76): ошибка рукопожатия TLS и QUIC-рукопожатия Hysteria доходит до
// подписчика АВТО 4.1 как неудачная попытка. (Что без АВТО 4.1 итог internet.Dial
// не сообщается, проверяет TestVupenFreezeAttempts в transport/internet: здесь
// плановая обсерватория оставила бы после теста горутины раунда.)
func TestVupenTransportHandshakeFailuresAreSignals(t *testing.T) {
	reportUplink()
	_, pin := tlsNodeServer(t)
	closing := newSwitchRelay(t, "127.0.0.1:9", 0)
	closing.closing.Store(true)
	deadUDP, err := stdnet.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	udpPort := deadUDP.LocalAddr().(*stdnet.UDPAddr).Port
	t.Cleanup(func() { deadUDP.Close() }) // принимает и молчит: QUIC-рукопожатие не проходит
	outbounds := fmt.Sprintf(`
	    {"tag": "proxy-tls", "protocol": "freedom", "settings": {"redirect": "127.0.0.1:%d"}, %s},
	    {"tag": "proxy-hy", "protocol": "hysteria", "settings": {"version": 2, "address": "127.0.0.1", "port": %d},
	      "streamSettings": {"network": "hysteria", "security": "tls",
	        "tlsSettings": {"serverName": "example.com", "pinnedPeerCertSha256": "%s"},
	        "hysteriaSettings": {"version": 2, "auth": "pw", "udpIdleTimeout": 60}}},
	    {"tag": "direct", "protocol": "freedom"}`, closing.port, tlsStream(pin), udpPort, pin)
	for _, auto41 := range []bool{true} {
		onDemand := ""
		if auto41 {
			onDemand = `"vupenOnDemand": true,`
		}
		inst := startCore(t, fmt.Sprintf(`{
		  "log": {"loglevel": "none"},
		  "outbounds": [%s],
		  "burstObservatory": {
		    "subjectSelector": ["proxy"], %s
		    "pingConfig": {"destination": "http://probe.test/ping", "interval": "1h", "sampling": 1, "timeout": "3s"}
		  }
		}`, outbounds, onDemand))
		obs := inst.GetFeature(extension.ObservatoryType()).(*burst.Observer)
		type sig struct {
			tag  string
			ok   bool
			kind string
		}
		got := make(chan sig, 32)
		unsub := obs.VupenStickyListen(func(tag, kind string, ok bool, detail string) { got <- sig{tag, ok, kind} })
		for _, tag := range []string{"proxy-tls", "proxy-hy"} {
			ctx := session.SetForcedOutboundTagToContext(context.Background(), tag)
			conn, err := core.Dial(ctx, inst, xnet.TCPDestination(xnet.DomainAddress("app.test"), 443))
			if err != nil {
				t.Fatal(err)
			}
			_, _ = conn.Write([]byte("hello"))
			go func() { _, _ = conn.Read(make([]byte, 16)); conn.Close() }()
		}
		seen := map[string]bool{}
		wait := 20 * time.Second
		if !auto41 {
			wait = 8 * time.Second // в АВТО 4.1 обе ошибки приходят за ~5 с
		}
		deadline := time.After(wait)
		for (auto41 && len(seen) < 2) || (!auto41 && len(seen) == 0) {
			select {
			case s := <-got:
				if s.kind == "dial" && !s.ok {
					seen[s.tag] = true
				}
			case <-deadline:
				if auto41 {
					t.Fatalf("AUTO 4.1: handshake failures must reach the listener, got %v", seen)
				}
				seen["timeout"] = true
			}
		}
		if !auto41 && len(seen) != 1 {
			t.Fatalf("without AUTO 4.1 no signals: %v", seen)
		}
		unsub()
	}
}

// Ядро 77 (2.5) на настоящем ядре: REG мёртв, LTE жив. На сотовой — после
// поиска по REG трафик идёт через проверенный узел LTE; стала Wi-Fi — новые
// соединения сразу в REG (на Wi-Fi LTE никогда).
func TestVupenSpillEndToEnd(t *testing.T) {
	vupenStickySettings(t, localListener(t))
	internet.VupenSetUplink("cellular", fmt.Sprintf("spill-e2e-cell-%d", time.Now().UnixNano()))
	dead := func() int {
		l, err := stdnet.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		p := l.Addr().(*stdnet.TCPAddr).Port
		l.Close()
		return p
	}
	inst := startCore(t, fmt.Sprintf(`{
	  "log": {"loglevel": "none"},
	  "outbounds": [
	    {"tag": "proxy-1", "protocol": "freedom", "settings": {"redirect": "127.0.0.1:%d"}},
	    {"tag": "proxy-2", "protocol": "freedom", "settings": {"redirect": "127.0.0.1:%d"}},
	    {"tag": "lte-proxy-1", "protocol": "freedom", "settings": {"redirect": "%s"}},
	    {"tag": "direct", "protocol": "freedom"}
	  ],
	  "routing": {
	    "rules": [{"port": "0-65535", "balancerTag": "REG"}],
	    "balancers": [
	      {"tag": "REG", "selector": ["proxy"], "strategy": {"type": "leastPing"}, "fallbackTag": "proxy-1",
	       "vupenSticky": {}, "vupenSpill": {"balancerTag": "LTE", "uplink": ["cellular"]}},
	      {"tag": "LTE", "selector": ["lte-"], "strategy": {"type": "leastPing"}, "fallbackTag": "lte-proxy-1",
	       "vupenSticky": {}}
	    ]
	  },
	  "burstObservatory": {
	    "subjectSelector": ["proxy", "lte-"], "vupenOnDemand": true,
	    "pingConfig": {"destination": "http://probe.test/ping", "interval": "10s", "sampling": 1, "timeout": "3s"}
	  }
	}`, dead(), dead(), muxBackend(t)))
	obs := inst.GetFeature(extension.ObservatoryType()).(*burst.Observer)
	pickREG(t, inst) // the first connection starts REG: its search finds nothing
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) && !obs.VupenTspuVerified("lte-proxy-1") {
		pickREG(t, inst) // spilled: picks reach LTE, which searches and verifies
		time.Sleep(50 * time.Millisecond)
	}
	if got := pickREG(t, inst); got != "lte-proxy-1" {
		t.Fatalf("cellular, REG dead: traffic via the verified LTE node, got %q", got)
	}
	internet.VupenSetUplink("wifi", fmt.Sprintf("spill-e2e-wifi-%d", time.Now().UnixNano()))
	if got := pickREG(t, inst); strings.HasPrefix(got, "lte-") {
		t.Fatalf("Wi-Fi: new connections go to REG at once, got %q", got)
	}
}
