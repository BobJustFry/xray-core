package dispatcher

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/protocol/quic"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/transport/internet"
)

// Vupen (T-083): S0, S3, S4, S7.

type t083Handler struct {
	outbound.Handler
	tag, typ string
}

func (h *t083Handler) Tag() string                         { return h.tag }
func (h *t083Handler) ProxySettings() *serial.TypedMessage { return &serial.TypedMessage{Type: h.typ} }

type t083Ohm struct {
	outbound.Manager
	m map[string]outbound.Handler
}

func (o *t083Ohm) GetHandler(tag string) outbound.Handler { return o.m[tag] }

func t083Ctx(srcPort uint16) context.Context {
	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{
		Source: net.UDPDestination(net.IPAddress([]byte{10, 0, 0, 2}), net.Port(srcPort)),
	})
	dst := net.UDPDestination(net.IPAddress([]byte{17, 1, 2, 3}), 443)
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{OriginalTarget: dst, Target: dst}})
	return session.ContextWithContent(ctx, &session.Content{})
}

var t083Dst = net.UDPDestination(net.IPAddress([]byte{17, 1, 2, 3}), 443)

func t083Dispatcher() *DefaultDispatcher {
	return &DefaultDispatcher{
		ohm: &t083Ohm{m: map[string]outbound.Handler{
			"proxy-3": &t083Handler{tag: "proxy-3", typ: "xray.proxy.vless.outbound.Config"},
			"direct":  &t083Handler{tag: "direct", typ: "xray.proxy.freedom.Config"},
		}},
		vupenRoutes: newVupenRouteMemory(),
	}
}

// S4: повтор того же UDP-потока (src:port → dst:port) идёт тем же outbound'ом без снифа.
func TestVupenRouteMemoryRecall(t *testing.T) {
	d := t083Dispatcher()
	ctx := t083Ctx(50000)
	if _, ok := d.vupenRouteRecall(ctx, t083Dst); ok {
		t.Fatal("nothing remembered yet")
	}
	d.vupenRouteRemember(ctx, "proxy-3")
	rctx, ok := d.vupenRouteRecall(t083Ctx(50000), t083Dst)
	if !ok {
		t.Fatal("repeat of the same flow not recalled")
	}
	if h := d.vupenRouteMemoryHandler(rctx, t083Dst); h == nil || h.Tag() != "proxy-3" {
		t.Fatalf("recalled handler %v", h)
	}
	// Другой порт источника — другой поток.
	if _, ok := d.vupenRouteRecall(t083Ctx(50001), t083Dst); ok {
		t.Fatal("another source port must not be recalled")
	}
	// TCP и адрес-домен не запоминаются.
	if k := vupenRouteKey(ctx, net.TCPDestination(net.IPAddress([]byte{17, 1, 2, 3}), 443)); k != "" {
		t.Fatalf("tcp key %q", k)
	}
	if k := vupenRouteKey(ctx, net.UDPDestination(net.DomainAddress("apple.com"), 443)); k != "" {
		t.Fatalf("domain key %q", k)
	}
	// Outbound пропал (конфиг другой) — память не используется.
	d.vupenRouteRemember(t083Ctx(50002), "gone")
	if _, ok := d.vupenRouteRecall(t083Ctx(50002), t083Dst); ok {
		t.Fatal("a missing outbound must not be recalled")
	}
}

// S4: сменилось поколение (сеть, узел АВТО, перелив, настройка Apple) — прежнее решение не берётся.
func TestVupenRouteMemoryGenerationAndTTL(t *testing.T) {
	d := t083Dispatcher()
	d.vupenRouteRemember(t083Ctx(50010), "proxy-3")
	internet.VupenBumpRouteGeneration()
	if _, ok := d.vupenRouteRecall(t083Ctx(50010), t083Dst); ok {
		t.Fatal("decision of an old generation recalled")
	}
	m := newVupenRouteMemory()
	now := time.Now()
	m.put("k", "proxy-3", now)
	if m.get("k", now.Add(VupenRouteMemoryTTL-time.Second)) != "proxy-3" {
		t.Fatal("within TTL")
	}
	// Повтор продлевает срок с последнего использования.
	if m.get("k", now.Add(2*VupenRouteMemoryTTL-2*time.Second)) != "proxy-3" {
		t.Fatal("TTL is counted from the last repeat")
	}
	if m.get("k", now.Add(4*VupenRouteMemoryTTL)) != "" || m.size() != 0 {
		t.Fatal("expired entry kept")
	}
}

// S4: не больше VupenRouteMemoryMax потоков, вытесняется самый давний.
func TestVupenRouteMemoryCap(t *testing.T) {
	m := newVupenRouteMemory()
	now := time.Now()
	for i := 0; i < VupenRouteMemoryMax+50; i++ {
		m.put(fmt.Sprint("k", i), "proxy-3", now)
		if i == 10 {
			m.get("k0", now) // k0 использовали — он свежий
		}
	}
	if m.size() != VupenRouteMemoryMax {
		t.Fatalf("size %d", m.size())
	}
	if m.get("k1", now) != "" {
		t.Fatal("the oldest entry must be evicted")
	}
	if m.get(fmt.Sprint("k", VupenRouteMemoryMax+49), now) == "" {
		t.Fatal("the newest entry is missing")
	}
}

func TestVupenRouteMemoryConcurrent(t *testing.T) {
	d := t083Dispatcher()
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				ctx := t083Ctx(uint16(40000 + (w*500+i)%700))
				d.vupenRouteRemember(ctx, "proxy-3")
				d.vupenRouteRecall(ctx, t083Dst)
				if i%100 == 0 {
					internet.VupenBumpRouteGeneration()
				}
			}
		}(w)
	}
	wg.Wait()
	if n := d.vupenRoutes.size(); n > VupenRouteMemoryMax {
		t.Fatalf("size %d", n)
	}
}

// S0: итог снифа QUIC по потоку — последний ответ снифера; счётчики по причинам.
func TestVupenQUICFlowCounters(t *testing.T) {
	before := vupenQUICStatsString()
	for _, c := range []struct {
		err  error
		want string
	}{
		{quic.ErrQUICNoSNI, "nosni"},
		{quic.ErrQUICNotFirstInitial, "notfirst"},
		{protocol.ErrProtoNeedMoreData, "more"},
	} {
		ctx := t083Ctx(1)
		vupenRecordQUICResult(ctx, nil, protocol.ErrProtoNeedMoreData)
		vupenRecordQUICResult(ctx, nil, c.err) // последний ответ — итог
		if got := session.ContentFromContext(ctx).Attribute(vupenQUICLastAttr); got != c.want {
			t.Fatalf("%v → %q, want %q", c.err, got, c.want)
		}
		vupenCountQUICFlow(ctx)
	}
	vupenCountQUICFlow(t083Ctx(2)) // QUIC не участвовал — не считается
	after := vupenQUICStatsString()
	if before == after || !strings.Contains(after, "quic[") {
		t.Fatalf("counters: %s → %s", before, after)
	}
	if !strings.Contains(VupenSniffStats(), "quic[") {
		t.Fatal("heartbeat line lacks quic counters")
	}
}

// S0: паузы между приходами данных в строке тайм-аута.
func TestVupenSniffGaps(t *testing.T) {
	tr := &vupenSniffTrace{start: time.Now().Add(-time.Second)}
	tr.arrivals = []time.Duration{5 * time.Millisecond, 255 * time.Millisecond, 760 * time.Millisecond}
	if got := vupenSniffGaps(tr); got != "dt=5,250,505ms" {
		t.Fatalf("gaps %q", got)
	}
	if vupenSniffGaps(&vupenSniffTrace{}) != "dt=—" {
		t.Fatal("empty")
	}
}

// S3: баннер direct-miss — только когда известное имя ушло бы напрямую; иначе
// строка Info без маркера; узлы direct и block не считаются.
func TestVupenHandlerKind(t *testing.T) {
	for typ, want := range map[string]string{
		"xray.proxy.freedom.Config":        "direct",
		"xray.proxy.blackhole.Config":      "block",
		"xray.proxy.vless.outbound.Config": "proxy",
	} {
		if got := vupenHandlerKind(&t083Handler{tag: "x", typ: typ}); got != want {
			t.Fatalf("%s → %s", typ, got)
		}
	}
	if vupenHandlerKind(nil) != "" {
		t.Fatal("nil handler")
	}
}

// S7: добавочного ожидания пустого TCP больше нет.
func TestVupenSniffEmptyTCPWaitOff(t *testing.T) {
	if vupenSniffEmptyWaitAllowed(net.Network_TCP, 443, &vupenSniffTrace{}) {
		t.Fatal("empty TCP wait must be off by default")
	}
}
