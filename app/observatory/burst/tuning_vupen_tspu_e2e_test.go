package burst_test

import (
	"context"
	"fmt"
	stdnet "net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/observatory"
	"github.com/xtls/xray-core/app/observatory/burst"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/extension"
	coreserial "github.com/xtls/xray-core/infra/conf/serial"
	_ "github.com/xtls/xray-core/main/distro/all"
	"github.com/xtls/xray-core/transport/internet"
)

// freezeRelay — TCP-ретранслятор, который ведёт себя как ТСПУ: после limit байт в
// одном соединении перестаёт пересылать, не закрывая его.
func freezeRelay(t *testing.T, backend string, limit int64) int {
	t.Helper()
	ln, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	t.Cleanup(func() { ln.Close(); wg.Wait() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer c.Close()
				s, err := stdnet.Dial("tcp", backend)
				if err != nil {
					return
				}
				defer s.Close()
				var total atomic.Int64
				frozen := make(chan struct{})
				var once sync.Once
				pipe := func(dst, src stdnet.Conn) {
					buf := make([]byte, 1024)
					for {
						n, err := src.Read(buf)
						if n > 0 {
							if total.Add(int64(n)) > limit {
								once.Do(func() { close(frozen) })
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
				case <-frozen:
					buf := make([]byte, 1024)
					for {
						if _, err := c.Read(buf); err != nil {
							return
						}
					}
				}
			}()
		}
	}()
	return ln.Addr().(*stdnet.TCPAddr).Port
}

// Настоящее ядро: два узла, «замороженный» отвечает на пробы быстрее, но 64 КБ
// через него не проходят. Обсерватория должна проверить обоих, заморозить его и
// отдать балансировщикам мёртвым, а второй — пометить проверенным.
func TestVupenTspuEndToEnd(t *testing.T) {
	restore := []func(){}
	set := func(p *time.Duration, v time.Duration) {
		old := *p
		*p = v
		restore = append(restore, func() { *p = old })
	}
	set(&burst.VupenObservatoryInitialDelay, 100*time.Millisecond)
	set(&burst.VupenTspuStall, 300*time.Millisecond)
	set(&burst.VupenTspuRetryPause, 20*time.Millisecond)
	set(&burst.VupenTspuTimeout, 3*time.Second)
	oldURL := burst.VupenTspuURL
	burst.VupenTspuURL = "http://probe.test/file"
	defer func() {
		burst.VupenTspuURL = oldURL
		for _, f := range restore {
			f()
		}
	}()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/file" {
			w.Header().Set("Content-Length", fmt.Sprint(64<<10))
			w.WriteHeader(200)
			_, _ = w.Write([]byte(strings.Repeat("x", 64<<10)))
			return
		}
		// Проба через «замороженный» узел — быстрая: лучшим по задержке был бы он.
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	backend := strings.TrimPrefix(srv.URL, "http://")
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/file" {
			w.Header().Set("Content-Length", fmt.Sprint(64<<10))
			w.WriteHeader(200)
			_, _ = w.Write([]byte(strings.Repeat("x", 64<<10)))
			return
		}
		time.Sleep(60 * time.Millisecond)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer slow.Close()
	relayPort := freezeRelay(t, backend, 16<<10)

	cfg := fmt.Sprintf(`{
	  "log": {"loglevel": "none"},
	  "outbounds": [
	    {"tag": "proxy-good", "protocol": "freedom", "settings": {"redirect": "%s"}},
	    {"tag": "proxy-frozen", "protocol": "freedom", "settings": {"redirect": "127.0.0.1:%d"}}
	  ],
	  "burstObservatory": {
	    "subjectSelector": ["proxy"],
	    "pingConfig": {"destination": "http://probe.test/ping", "interval": "10s", "sampling": 1, "timeout": "3s"}
	  }
	}`, strings.TrimPrefix(slow.URL, "http://"), relayPort)
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
	defer inst.Close()

	obs := inst.GetFeature(extension.ObservatoryType()).(*burst.Observer)
	deadline := time.Now().Add(10 * time.Second)
	var alive map[string]bool
	for time.Now().Before(deadline) {
		res, _ := obs.GetObservation(context.Background())
		alive = map[string]bool{}
		probesPass := false
		for _, s := range res.(*observatory.ObservationResult).Status {
			alive[s.OutboundTag] = s.Alive
			// Короткие пробы через «замороженный» узел проходят — мёртвым его
			// делает только проверка ТСПУ.
			if s.OutboundTag == "proxy-frozen" && s.HealthPing != nil &&
				s.HealthPing.All > s.HealthPing.Fail {
				probesPass = true
			}
		}
		if obs.VupenTspuVerified("proxy-good") && len(alive) == 2 &&
			!alive["proxy-frozen"] && probesPass {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("expected proxy-good verified and proxy-frozen dead: verified(good)=%v alive=%v",
		obs.VupenTspuVerified("proxy-good"), alive)
}

// Сторож на настоящем трафике: проверка кандидатов выключена (TopK=0), через
// «замороженный» узел идёт обычное соединение — 16 КБ туда, в ответ тишина.
// Сторож должен найти обсерваторию своего ядра, та — проверить узел и заморозить.
func TestVupenTspuSentinelOnRealTraffic(t *testing.T) {
	oldK := burst.VupenTspuTopK
	burst.VupenTspuTopK = 0
	oldSilence := internet.VupenFreezeSilence
	internet.VupenFreezeSilence = 300 * time.Millisecond
	restore := []func(){func() { burst.VupenTspuTopK = oldK }, func() { internet.VupenFreezeSilence = oldSilence }}
	set := func(p *time.Duration, v time.Duration) {
		old := *p
		*p = v
		restore = append(restore, func() { *p = old })
	}
	set(&burst.VupenObservatoryInitialDelay, 100*time.Millisecond)
	set(&burst.VupenTspuStall, 300*time.Millisecond)
	set(&burst.VupenTspuRetryPause, 20*time.Millisecond)
	set(&burst.VupenTspuTimeout, 3*time.Second)
	oldURL := burst.VupenTspuURL
	burst.VupenTspuURL = "http://probe.test/file"
	defer func() {
		burst.VupenTspuURL = oldURL
		for _, f := range restore {
			f()
		}
	}()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/file" {
			w.Header().Set("Content-Length", fmt.Sprint(64<<10))
			w.WriteHeader(200)
			_, _ = w.Write([]byte(strings.Repeat("x", 64<<10)))
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	relayPort := freezeRelay(t, strings.TrimPrefix(srv.URL, "http://"), 16<<10)

	cfg := fmt.Sprintf(`{
	  "log": {"loglevel": "none"},
	  "outbounds": [
	    {"tag": "proxy-frozen", "protocol": "freedom", "settings": {"redirect": "127.0.0.1:%d"}}
	  ],
	  "burstObservatory": {
	    "subjectSelector": ["proxy"],
	    "pingConfig": {"destination": "http://probe.test/ping", "interval": "10s", "sampling": 1, "timeout": "3s"}
	  }
	}`, relayPort)
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
	defer inst.Close()
	obs := inst.GetFeature(extension.ObservatoryType()).(*burst.Observer)

	// Ждём первую удачную пробу: без неё обсерватория узел ещё не наблюдает.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		res, _ := obs.GetObservation(context.Background())
		if st := res.(*observatory.ObservationResult).Status; len(st) == 1 && st[0].Alive {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	ctx := session.SetForcedOutboundTagToContext(context.Background(), "proxy-frozen")
	conn, err := core.Dial(ctx, inst, xnet.TCPDestination(xnet.DomainAddress("probe.test"), 80))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("POST /upload HTTP/1.1\r\nHost: probe.test\r\nContent-Length: 20000\r\n\r\n" + strings.Repeat("y", 20000))); err != nil {
		t.Fatal(err)
	}

	deadline = time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		res, _ := obs.GetObservation(context.Background())
		if st := res.(*observatory.ObservationResult).Status; len(st) == 1 && !st[0].Alive {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("a silent connection on a watched node must get it checked and frozen")
}
