package burst_test

import (
	"context"
	"fmt"
	stdnet "net"
	"net/http"
	"net/http/httptest"
	"strings"
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

// По требованию сторож заморозки узнаёт узлы пула по селектору, даже без замеров:
// тихое соединение на узле → проверка → узел исключён.
func TestVupenStickyOnDemandSentinel(t *testing.T) {
	vupenStickySettings(t, localListener(t))
	oldK, oldSilence := burst.VupenTspuTopK, internet.VupenFreezeSilence
	burst.VupenTspuTopK, internet.VupenFreezeSilence = 0, 300*time.Millisecond
	t.Cleanup(func() { burst.VupenTspuTopK, internet.VupenFreezeSilence = oldK, oldSilence })
	relay := freezeRelay(t, nodeServer(t), 16<<10)
	inst := startCore(t, fmt.Sprintf(`{
	  "log": {"loglevel": "none"},
	  "outbounds": [
	    {"tag": "proxy-frozen", "protocol": "freedom", "settings": {"redirect": "127.0.0.1:%d"}},
	    {"tag": "direct", "protocol": "freedom"}
	  ],
	  "burstObservatory": {
	    "subjectSelector": ["proxy"], "vupenOnDemand": true,
	    "pingConfig": {"destination": "http://probe.test/ping", "interval": "10s", "sampling": 1, "timeout": "3s"}
	  }
	}`, relay))
	obs := inst.GetFeature(extension.ObservatoryType()).(*burst.Observer)

	ctx := session.SetForcedOutboundTagToContext(context.Background(), "proxy-frozen")
	conn, err := core.Dial(ctx, inst, xnet.TCPDestination(xnet.DomainAddress("probe.test"), 80))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("POST /upload HTTP/1.1\r\nHost: probe.test\r\nContent-Length: 20000\r\n\r\n" + strings.Repeat("y", 20000))); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if obs.VupenStickyExcluded("proxy-frozen") {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("on demand (no probe results) the watchdog must still watch pool nodes")
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
