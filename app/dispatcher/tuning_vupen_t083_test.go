package dispatcher

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/protocol/quic"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/pipe"
)

// Vupen (T-083): S0, S3, S4, S7. T-087: review fixes CR-001..008.

type t083Handler struct {
	outbound.Handler
	tag, typ   string
	onDispatch func(ctx context.Context, link *transport.Link)
}

func (h *t083Handler) Dispatch(ctx context.Context, link *transport.Link) {
	if h.onDispatch != nil {
		h.onDispatch(ctx, link)
	}
}

func (h *t083Handler) Tag() string                         { return h.tag }
func (h *t083Handler) ProxySettings() *serial.TypedMessage { return &serial.TypedMessage{Type: h.typ} }

type t083Ohm struct {
	outbound.Manager
	m map[string]outbound.Handler
}

func (o *t083Ohm) GetHandler(tag string) outbound.Handler { return o.m[tag] }

// GetDefaultHandler — freedom по умолчанию.
func (o *t083Ohm) GetDefaultHandler() outbound.Handler { return o.m["direct"] }

func t083Ctx(srcPort uint16) context.Context {
	return t083CtxTo(srcPort, net.UDPDestination(net.IPAddress([]byte{17, 1, 2, 3}), 443), false)
}

func t083CtxTo(srcPort uint16, dst net.Destination, sniff bool) context.Context {
	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{
		Source: net.UDPDestination(net.IPAddress([]byte{10, 0, 0, 2}), net.Port(srcPort)),
	})
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{OriginalTarget: dst, Target: dst}})
	return session.ContextWithContent(ctx, &session.Content{SniffingRequest: session.SniffingRequest{Enabled: sniff}})
}

// t083Router — PickRoute пишет, что видел; tag — куда отправить.
type t083Router struct {
	routing.Router
	mu      sync.Mutex
	tag     string
	calls   int
	domains []string
	skipDNS []bool
	onPick  func()
}

type t083Route struct {
	routing.Context
	tag string
}

func (r *t083Route) GetOutboundTag() string         { return r.tag }
func (r *t083Route) GetOutboundGroupTags() []string { return nil }
func (r *t083Route) GetRuleTag() string             { return "" }

func (r *t083Router) PickRoute(ctx routing.Context) (routing.Route, error) {
	r.mu.Lock()
	r.calls++
	r.domains = append(r.domains, ctx.GetTargetDomain())
	r.skipDNS = append(r.skipDNS, ctx.GetSkipDNSResolve())
	tag, onPick := r.tag, r.onPick
	r.mu.Unlock()
	if onPick != nil {
		onPick()
	}
	return &t083Route{tag: tag}, nil
}

// t083FakeDNS — пул 198.18.0.0/15.
type t083FakeDNS struct{ dns.FakeDNSEngineRev0 }

func (t083FakeDNS) IsIPInIPPool(a net.Address) bool {
	return a.Family().IsIP() && a.IP()[0] == 198 && a.IP()[1] == 18
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
	d.vupenRouteRemember(ctx, "proxy-3", internet.VupenRouteGeneration())
	rctx, ok := d.vupenRouteRecall(t083Ctx(50000), t083Dst)
	if !ok {
		t.Fatal("repeat of the same flow not recalled")
	}
	if h := d.vupenRouteMemoryHandler(rctx, t083Dst, rctx.Value(vupenRouteMemKey{}).(string)); h == nil || h.Tag() != "proxy-3" {
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
	d.vupenRouteRemember(t083Ctx(50002), "gone", internet.VupenRouteGeneration())
	if _, ok := d.vupenRouteRecall(t083Ctx(50002), t083Dst); ok {
		t.Fatal("a missing outbound must not be recalled")
	}
}

// S4: сменилось поколение (сеть, узел АВТО, перелив, настройка Apple) — прежнее решение не берётся.
func TestVupenRouteMemoryGenerationAndTTL(t *testing.T) {
	d := t083Dispatcher()
	d.vupenRouteRemember(t083Ctx(50010), "proxy-3", internet.VupenRouteGeneration())
	internet.VupenBumpRouteGeneration()
	if _, ok := d.vupenRouteRecall(t083Ctx(50010), t083Dst); ok {
		t.Fatal("decision of an old generation recalled")
	}
	m := newVupenRouteMemory()
	now := time.Now()
	m.put("k", "proxy-3", internet.VupenRouteGeneration(), now)
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
		m.put(fmt.Sprint("k", i), "proxy-3", internet.VupenRouteGeneration(), now)
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
				d.vupenRouteRemember(ctx, "proxy-3", internet.VupenRouteGeneration())
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

// ── T-087: review fixes ─────────────────────────────────────────────────────

func t083Recorder(tag string, calls *int, ctxs *[]context.Context) *t083Handler {
	return &t083Handler{tag: tag, typ: "xray.proxy.vless.outbound.Config", onDispatch: func(ctx context.Context, _ *transport.Link) {
		*calls++
		if ctxs != nil {
			*ctxs = append(*ctxs, ctx)
		}
	}}
}

// CR-001: память маршрута используется один раз — вложенный диспатч (loopback
// outbound → DispatchLink с тем же ctx) её не берёт и не запоминает: рекурсии нет.
func TestVupenRouteMemoryNotLeakedIntoNestedDispatch(t *testing.T) {
	d := t083Dispatcher()
	var viaMem, viaDefault int
	var seen []context.Context
	mem := t083Recorder("proxy-3", &viaMem, &seen)
	mem.onDispatch = func(ctx context.Context, link *transport.Link) {
		viaMem++
		seen = append(seen, ctx)
		if viaMem < 20 { // вложенный диспатч с тем же ctx, как делает loopback outbound
			d.routedDispatch(ctx, link, t083Dst)
		}
	}
	direct := t083Recorder("direct", &viaDefault, nil)
	direct.typ = "xray.proxy.freedom.Config"
	d.ohm = &t083Ohm{m: map[string]outbound.Handler{"proxy-3": mem, "direct": direct}}

	ctx := t083CtxTo(50100, t083Dst, true)
	d.vupenRouteRemember(ctx, "proxy-3", internet.VupenRouteGeneration())
	rctx, ok := d.vupenRouteRecall(ctx, t083Dst)
	if !ok {
		t.Fatal("repeat not recalled")
	}
	d.routedDispatch(rctx, &transport.Link{}, t083Dst)
	if viaMem != 1 || viaDefault != 1 {
		t.Fatalf("memory used %d times (want 1), nested went default %d times (want 1)", viaMem, viaDefault)
	}
	if v, present := seen[0].Value(vupenRouteMemKey{}).(string); !present || v != "" {
		t.Fatalf("ctx handed to the handler must carry an empty marker, got %q present=%v", v, present)
	}
	if _, ok := d.vupenRouteRecall(seen[0], t083Dst); ok {
		t.Fatal("a routed ctx must not recall again")
	}
	// CR-101: вложенный диспатч (ушёл в direct) не перезаписал внешний маршрут.
	if got := d.vupenRoutes.get(vupenRouteKey(ctx, t083Dst), time.Now()); got != "proxy-3" {
		t.Fatalf("remembered route after nested dispatch = %q, want proxy-3 (outer route overwritten)", got)
	}
}

// CR-002/CR-004: память — только если снифф не дал имени и адрес не из FakeDNS.
func TestVupenRouteRecallAfterSniff(t *testing.T) {
	d := t083Dispatcher()
	d.fdns = t083FakeDNS{}
	ctx := t083CtxTo(50110, t083Dst, true)
	d.vupenRouteRemember(ctx, "proxy-3", internet.VupenRouteGeneration())
	content := session.ContentFromContext(ctx)

	if rctx := d.vupenRouteRecallAfterSniff(ctx, content, t083Dst, t083Dst); rctx.Value(vupenRouteMemKey{}) != "proxy-3" {
		t.Fatal("no domain, real IP: the memory must be used")
	}
	// Снифф дал имя и подменил назначение — имя точнее памяти.
	named := net.UDPDestination(net.DomainAddress("example.com"), 443)
	if rctx := d.vupenRouteRecallAfterSniff(ctx, content, t083Dst, named); rctx.Value(vupenRouteMemKey{}) != nil {
		t.Fatal("sniffed (overridden) domain must win over the memory")
	}
	// RouteOnly: назначение осталось IP, но имя уже в подсказке.
	hinted := &session.Content{}
	hinted.SetAttribute(vupenSniffDomainAttr, "example.com")
	if rctx := d.vupenRouteRecallAfterSniff(ctx, hinted, t083Dst, t083Dst); rctx.Value(vupenRouteMemKey{}) != nil {
		t.Fatal("a sniffed domain hint must win over the memory")
	}
	// FakeDNS: адрес из пула никогда не вспоминаем (иначе уйдёт наружу без домена).
	fake := net.UDPDestination(net.IPAddress([]byte{198, 18, 0, 7}), 443)
	fctx := t083CtxTo(50111, fake, true)
	d.vupenRouteRemember(fctx, "proxy-3", internet.VupenRouteGeneration())
	if rctx := d.vupenRouteRecallAfterSniff(fctx, session.ContentFromContext(fctx), fake, fake); rctx.Value(vupenRouteMemKey{}) != nil {
		t.Fatal("a FakeDNS IP must never be recalled")
	}
	if _, ok := d.vupenRouteRecall(fctx, fake); ok {
		t.Fatal("a FakeDNS IP must never be recalled (direct call)")
	}
}

// CR-005: платформенный forced-тег сильнее памяти.
func TestVupenRouteForcedTagBeatsMemory(t *testing.T) {
	d := t083Dispatcher()
	var viaMem, viaForced int
	d.ohm = &t083Ohm{m: map[string]outbound.Handler{
		"proxy-3": t083Recorder("proxy-3", &viaMem, nil),
		"forced":  t083Recorder("forced", &viaForced, nil),
		"direct":  &t083Handler{tag: "direct", typ: "xray.proxy.freedom.Config"},
	}}
	ctx := t083CtxTo(50120, t083Dst, true)
	d.vupenRouteRemember(ctx, "proxy-3", internet.VupenRouteGeneration())
	rctx, ok := d.vupenRouteRecall(ctx, t083Dst)
	if !ok {
		t.Fatal("not recalled")
	}
	rctx = session.SetForcedOutboundTagToContext(rctx, "forced")
	d.routedDispatch(rctx, &transport.Link{}, t083Dst)
	if viaForced != 1 || viaMem != 0 {
		t.Fatalf("forced=%d memory=%d", viaForced, viaMem)
	}
	// CR-103: платформенный тег не решение маршрутизации — не запоминается.
	fctx := session.SetForcedOutboundTagToContext(t083CtxTo(50121, t083Dst, true), "forced")
	d.routedDispatch(fctx, &transport.Link{}, t083Dst)
	if viaForced != 2 {
		t.Fatalf("forced handler calls = %d, want 2", viaForced)
	}
	if got := d.vupenRoutes.get(vupenRouteKey(fctx, t083Dst), time.Now()); got != "" {
		t.Fatalf("a platform-forced tag was remembered: %q", got)
	}
}

// Путь fromMemory через routedDispatch: PickRoute не вызывается; без памяти —
// обычная маршрутизация и запоминание.
func TestVupenRoutedDispatchFromMemory(t *testing.T) {
	d := t083Dispatcher()
	rt := &t083Router{tag: "direct"}
	d.router = rt
	var n int
	d.ohm.(*t083Ohm).m["proxy-3"] = t083Recorder("proxy-3", &n, nil)
	ctx := t083CtxTo(50130, t083Dst, true)
	d.vupenRouteRemember(ctx, "proxy-3", internet.VupenRouteGeneration())
	rctx, _ := d.vupenRouteRecall(ctx, t083Dst)
	d.routedDispatch(rctx, &transport.Link{}, t083Dst)
	if n != 1 || rt.calls != 0 {
		t.Fatalf("handler calls %d, PickRoute calls %d (want 1, 0)", n, rt.calls)
	}
	ctx2 := t083CtxTo(50131, t083Dst, true)
	rt.tag = "proxy-3"
	d.routedDispatch(ctx2, &transport.Link{}, t083Dst)
	if rt.calls != 1 || n != 2 {
		t.Fatalf("PickRoute calls %d, handler calls %d", rt.calls, n)
	}
	if _, ok := d.vupenRouteRecall(t083CtxTo(50131, t083Dst, true), t083Dst); !ok {
		t.Fatal("a routed sniffing flow must be remembered")
	}
}

// CR-007: запоминаем только потоки, которые просили снифф (не порт 53, не без снифа).
func TestVupenRouteRememberOnlySniffedFlows(t *testing.T) {
	d := t083Dispatcher()
	d.router = &t083Router{tag: "proxy-3"}
	var n int
	d.ohm.(*t083Ohm).m["proxy-3"] = t083Recorder("proxy-3", &n, nil)
	dns53 := net.UDPDestination(net.IPAddress([]byte{17, 1, 2, 3}), 53)
	for name, c := range map[string]struct {
		port uint16
		dst  net.Destination
		snif bool
	}{
		"no sniffing requested": {50140, t083Dst, false},
		"port 53 skips sniff":   {50141, dns53, true},
	} {
		ctx := t083CtxTo(c.port, c.dst, c.snif)
		d.routedDispatch(ctx, &transport.Link{}, c.dst)
		if k := vupenRouteKey(ctx, c.dst); d.vupenRoutes.get(k, time.Now()) != "" {
			t.Fatalf("%s: the flow must not be remembered", name)
		}
	}
	d.routedDispatch(t083CtxTo(50142, t083Dst, true), &transport.Link{}, t083Dst)
	if d.vupenRoutes.get(vupenRouteKey(t083CtxTo(50142, t083Dst, true), t083Dst), time.Now()) != "proxy-3" {
		t.Fatal("a sniffing flow must be remembered")
	}
}

// CR-003: поколение читается до PickRoute — если выбор узла сменился во время
// маршрутизации, запись устарела и следующий recall промахивается.
func TestVupenRouteRememberUsesGenerationBeforePick(t *testing.T) {
	d := t083Dispatcher()
	d.router = &t083Router{tag: "proxy-3", onPick: internet.VupenBumpRouteGeneration}
	var n int
	d.ohm.(*t083Ohm).m["proxy-3"] = t083Recorder("proxy-3", &n, nil)
	ctx := t083CtxTo(50150, t083Dst, true)
	d.routedDispatch(ctx, &transport.Link{}, t083Dst)
	if _, ok := d.vupenRouteRecall(t083CtxTo(50150, t083Dst, true), t083Dst); ok {
		t.Fatal("a decision made across a generation bump must not be recalled")
	}
}

// S3 + CR-006: баннер direct-miss и отсутствие DNS при догадке «куда пошёл бы по домену».
func TestVupenMaybeLogDirectMiss(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "miss.log")
	oldPath := vupenSniffMissLogPathCached
	vupenSniffMissLogPathCached = logPath
	t.Cleanup(func() { vupenSniffMissLogPathCached = oldPath })
	read := func() string { b, _ := os.ReadFile(logPath); return string(b) }

	proxy := &t083Handler{tag: "proxy-3", typ: "xray.proxy.vless.outbound.Config"}
	direct := &t083Handler{tag: "direct", typ: "xray.proxy.freedom.Config"}
	mkctx := func(miss, hint string) context.Context {
		ctx := t083CtxTo(50160, t083Dst, true)
		c := session.ContentFromContext(ctx)
		if miss != "" {
			c.SetAttribute(vupenSniffMissAttr, miss)
		}
		if hint != "" {
			c.SetAttribute(vupenSniffDomainAttr, hint)
		}
		return ctx
	}

	// Баннер: имя по правилам ушло бы напрямую, а поток ушёл в узел.
	d := t083Dispatcher()
	rt := &t083Router{tag: "direct"}
	d.router = rt
	ctx := mkctx("1", "apple.com")
	d.vupenMaybeLogDirectMiss(ctx, t083Dst, proxy)
	if !strings.Contains(read(), vupenDirectMissLogMarker) || !strings.Contains(read(), "apple.com") {
		t.Fatalf("banner missing: %q", read())
	}
	if rt.calls != 1 || rt.domains[0] != "apple.com" || !rt.skipDNS[0] {
		t.Fatalf("PickRoute calls=%d domains=%v skipDNS=%v (want SkipDNSResolve)", rt.calls, rt.domains, rt.skipDNS)
	}
	if session.ContentFromContext(ctx).SkipDNSResolve {
		t.Fatal("the flow's own Content must stay untouched")
	}
	// Остальное — без баннера.
	for name, c := range map[string]struct {
		ctx  context.Context
		h    outbound.Handler
		dest net.Destination
		tag  string
	}{
		"no sniff miss":    {mkctx("", "apple.com"), proxy, t083Dst, "direct"},
		"no domain hint":   {mkctx("1", ""), proxy, t083Dst, "direct"},
		"direct handler":   {mkctx("1", "apple.com"), direct, t083Dst, "direct"},
		"domain dest":      {mkctx("1", "apple.com"), proxy, net.UDPDestination(net.DomainAddress("a.com"), 443), "direct"},
		"domain via proxy": {mkctx("1", "apple.com"), proxy, t083Dst, "proxy-3"},
	} {
		if err := os.WriteFile(logPath, nil, 0o644); err != nil {
			t.Fatal(err)
		}
		d.router = &t083Router{tag: c.tag}
		d.vupenMaybeLogDirectMiss(c.ctx, c.dest, c.h)
		if read() != "" {
			t.Fatalf("%s: unexpected banner %q", name, read())
		}
	}
}

// CR-008: «notquic» — по sentinel-ошибке, а не по тексту.
func TestVupenQUICNotQUICBySentinel(t *testing.T) {
	for _, c := range []struct {
		err  error
		want string
	}{
		{quic.ErrQUICNotQUIC, "notquic"},
		{quic.ErrQUICNotInitial, "notquic"},
		{fmt.Errorf("wrapped: %w", quic.ErrQUICNotQUIC), "notquic"},
		{fmt.Errorf("not found"), "other"}, // раньше ловилось по префиксу «not »
	} {
		ctx := t083Ctx(1)
		vupenRecordQUICResult(ctx, nil, c.err)
		if got := session.ContentFromContext(ctx).Attribute(vupenQUICLastAttr); got != c.want {
			t.Fatalf("%v → %q, want %q", c.err, got, c.want)
		}
	}
}

// ── T-089: CR-102 — recall after sniff in Dispatch / DispatchLink ───────────

// t089ClientHello — ClientHello (как t083ClientHelloNoSNI), но с SNI, если name != "".
func t089ClientHello(name string) []byte {
	body := append([]byte{0x03, 0x03}, make([]byte, 32)...)
	body = append(body, 0x00, 0x00, 0x02, 0x13, 0x01, 0x01, 0x00)
	var ext []byte
	if name != "" {
		n := len(name)
		ext = append(ext, 0x00, 0x00, byte((n+5)>>8), byte(n+5), byte((n+3)>>8), byte(n+3), 0x00, byte(n>>8), byte(n))
		ext = append(ext, name...)
	}
	ext = append(ext, 0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04)
	pad := make([]byte, 1400)
	ext = append(ext, 0xfe, 0x0d, byte(len(pad)>>8), byte(len(pad)))
	ext = append(ext, pad...)
	body = append(body, byte(len(ext)>>8), byte(len(ext)))
	body = append(body, ext...)
	return append([]byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
}

// t089Run — поток со снифом QUIC и уже запомненным маршрутом proxy-3; роутер
// отправляет в direct. Возвращает, кто принял поток, и что видел PickRoute.
func t089Run(t *testing.T, viaDispatch bool, name string, port uint16) (tag string, router *t083Router) {
	t.Helper()
	d := t083Dispatcher()
	router = &t083Router{tag: "direct"}
	d.router = router
	got := make(chan string, 1)
	rec := func(tag string) *t083Handler {
		return &t083Handler{tag: tag, typ: "xray.proxy.vless.outbound.Config", onDispatch: func(context.Context, *transport.Link) { got <- tag }}
	}
	d.ohm = &t083Ohm{m: map[string]outbound.Handler{"proxy-3": rec("proxy-3"), "direct": rec("direct")}}

	ctx := t083CtxTo(port, t083Dst, true)
	session.ContentFromContext(ctx).SniffingRequest.OverrideDestinationForProtocol = []string{"quic"}
	d.vupenRouteRemember(ctx, "proxy-3", internet.VupenRouteGeneration())

	ch := t089ClientHello(name)
	half := len(ch) / 2
	pkts := [][]byte{t083Initial(t, 0, ch[:half], 0), t083Initial(t, half, ch[half:], 1)}
	if viaDispatch {
		link, err := d.Dispatch(ctx, t083Dst)
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range pkts {
			if err := link.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(p)}); err != nil {
				t.Fatal(err)
			}
		}
	} else {
		r, w := pipe.New(pipe.WithoutSizeLimit())
		for _, p := range pkts {
			if err := w.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(p)}); err != nil {
				t.Fatal(err)
			}
		}
		if err := d.DispatchLink(ctx, t083Dst, &transport.Link{Reader: r, Writer: w}); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case tag = <-got:
	case <-time.After(5 * time.Second):
		t.Fatal("no handler received the flow")
	}
	return tag, router
}

func TestVupenRouteRecallAfterSniffInDispatch(t *testing.T) {
	for name, viaDispatch := range map[string]bool{"Dispatch": true, "DispatchLink": false} {
		viaDispatch := viaDispatch
		t.Run(name+"/domain sniffed: memory not used", func(t *testing.T) {
			tag, rt := t089Run(t, viaDispatch, "example.com", 50200)
			rt.mu.Lock()
			defer rt.mu.Unlock()
			if rt.calls != 1 || len(rt.domains) != 1 || rt.domains[0] != "example.com" {
				t.Fatalf("PickRoute calls=%d domains=%v, want one call with example.com", rt.calls, rt.domains)
			}
			if tag != "direct" {
				t.Fatalf("flow went to %q, want the router's choice direct, not the memory", tag)
			}
		})
		t.Run(name+"/unrecognised payload: memory used", func(t *testing.T) {
			tag, rt := t089Run(t, viaDispatch, "", 50201)
			rt.mu.Lock()
			defer rt.mu.Unlock()
			if rt.calls != 0 {
				t.Fatalf("PickRoute called %d times, want 0 (memory must be used)", rt.calls)
			}
			if tag != "proxy-3" {
				t.Fatalf("flow went to %q, want the remembered proxy-3", tag)
			}
		})
	}
}
