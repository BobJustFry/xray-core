package burst

import (
	"context"
	stdnet "net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/routing"
)

// Ядро 80 (D-43): быстрый поиск для VupenCheckRoute(switch).

// quickRig — обсерватория без планировщика; узел "fast-*" отвечает через сервер
// (после answerAfter), "dead-*" висит до отмены (как мёртвый узел с таймаутом 10 с).
type quickRig struct {
	o              *Observer
	inFlight, peak atomic.Int32
	dials          sync.Map // tag → struct{}
}

func newQuickRig(t *testing.T, answerAfter time.Duration) *quickRig {
	t.Helper()
	r := &quickRig{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		n := r.inFlight.Add(1)
		for {
			p := r.peak.Load()
			if n <= p || r.peak.CompareAndSwap(p, n) {
				break
			}
		}
		time.Sleep(answerAfter)
		r.inFlight.Add(-1)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	addr := srv.Listener.Addr().String()
	setTestDialer(t, func(ctx context.Context, d routing.Dispatcher, dest net.Destination, tag string) (net.Conn, error) {
		r.dials.Store(tag, struct{}{})
		if strings.HasPrefix(tag, "dead-") {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return stdnet.Dial("tcp", addr)
	})
	r.o = &Observer{ctx: context.Background(), hp: newSleepTestPing()}
	return r
}

type quickEvent struct {
	tag string
	ok  bool
	at  time.Duration
}

func (r *quickRig) probe(tags []string, timeout time.Duration, deadline time.Time, stopAt string) ([]quickEvent, int, time.Duration) {
	start := time.Now()
	var evs []quickEvent
	n := r.o.VupenStickyQuickProbe(tags, timeout, deadline, func(tag string, rtt time.Duration, ok bool) bool {
		evs = append(evs, quickEvent{tag, ok, time.Since(start)})
		return ok && tag == stopAt
	})
	return evs, n, time.Since(start)
}

// Мёртвые узлы не задерживают: ответ живого приходит сразу, хотя рядом узлы,
// которые висели бы 10 с; на первом подошедшем остальные отменяются.
func TestVupenQuickProbeFirstAnswerDoesNotWaitForDead(t *testing.T) {
	r := newQuickRig(t, 20*time.Millisecond)
	tags := []string{"dead-1", "dead-2", "fast-1", "dead-3"}
	evs, n, took := r.probe(tags, 10*time.Second, time.Time{}, "fast-1")
	if n != 1 || len(evs) != 1 || evs[0].tag != "fast-1" || !evs[0].ok || took > 2*time.Second {
		t.Fatalf("events %+v answered %d took %s", evs, n, took)
	}
	for _, tag := range tags {
		if _, ok := r.dials.Load(tag); !ok {
			t.Fatalf("%s was not probed at once", tag)
		}
	}
}

// Пачка идёт параллельно, мимо полос плановых раундов (TCP ×3): 8 ответов по
// 150 мс — около 150 мс, а не 8×150.
func TestVupenQuickProbeParallel(t *testing.T) {
	r := newQuickRig(t, 150*time.Millisecond)
	var tags []string
	for i := 0; i < 8; i++ {
		tags = append(tags, "fast-"+string(rune('a'+i)))
	}
	evs, n, took := r.probe(tags, 5*time.Second, time.Time{}, "")
	if n != 8 || len(evs) != 8 || took > 900*time.Millisecond {
		t.Fatalf("answered %d, events %d, took %s", n, len(evs), took)
	}
	if p := r.peak.Load(); p < 4 {
		t.Fatalf("probes were not parallel: peak %d in flight", p)
	}
	// Удачные ответы записаны в результаты обсерватории (кэш для следующего switch).
	rec := r.o.VupenStickyRecent(tags, time.Minute)
	if len(rec) != 8 || rec["fast-a"] <= 0 {
		t.Fatalf("recent: %v", rec)
	}
}

// Таймаут пробы: молчащий узел — провал через timeout (each(ok=false)), в
// результаты не пишется; deadline обрывает всё.
func TestVupenQuickProbeTimeoutAndDeadline(t *testing.T) {
	r := newQuickRig(t, 10*time.Millisecond)
	evs, n, took := r.probe([]string{"dead-1", "fast-1"}, 300*time.Millisecond, time.Time{}, "")
	if n != 1 || len(evs) != 2 || evs[0].tag != "fast-1" || evs[1].tag != "dead-1" || evs[1].ok ||
		evs[1].at < 250*time.Millisecond || took > 2*time.Second {
		t.Fatalf("events %+v answered %d took %s", evs, n, took)
	}
	if rec := r.o.VupenStickyRecent([]string{"dead-1"}, time.Minute); len(rec) != 0 {
		t.Fatalf("a quick-probe failure is not recorded: %v", rec)
	}
	evs, _, took = r.probe([]string{"dead-2", "dead-3"}, 10*time.Second, time.Now().Add(200*time.Millisecond), "")
	if len(evs) != 0 || took > time.Second {
		t.Fatalf("deadline: events %+v took %s", evs, took)
	}
}

// Кэш: последний замер не старше maxAge; провал — -1; старый и непробованный — нет.
func TestVupenStickyRecent(t *testing.T) {
	o := &Observer{ctx: context.Background(), hp: newSleepTestPing()}
	h := o.hp
	h.PutResult("a", 30*time.Millisecond)
	h.PutResult("b", 40*time.Millisecond)
	h.PutResult("b", rttFailed)
	h.PutResult("c", 50*time.Millisecond)
	h.access.Lock()
	h.Results["c"].rtts[h.Results["c"].idx].time = time.Now().Add(-10 * time.Minute)
	h.access.Unlock()
	got := o.VupenStickyRecent([]string{"a", "b", "c", "d"}, 5*time.Minute)
	if len(got) != 2 || got["a"] != 30*time.Millisecond || got["b"] != -1 {
		t.Fatalf("recent: %v", got)
	}
	if got := o.VupenStickyRecent([]string{"a"}, 0); len(got) != 0 {
		t.Fatalf("maxAge 0: %v", got)
	}
	if got := (&Observer{}).VupenStickyRecent([]string{"a"}, time.Minute); len(got) != 0 {
		t.Fatalf("no healthping: %v", got)
	}
}
