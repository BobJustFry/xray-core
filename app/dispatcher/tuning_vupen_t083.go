package dispatcher

import (
	"container/list"
	"context"
	stderrors "errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/protocol/quic"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/outbound"
	routing_session "github.com/xtls/xray-core/features/routing/session"
	"github.com/xtls/xray-core/transport/internet"
)

// Vupen (T-083, ядро 81): снифф QUIC и маршрутизация без имени
// (docs/project/plans/ANALYSIS-sniff-quic.md, S0, S3, S4).

// ── S0: итоги снифа QUIC по потокам ─────────────────────────────────────────

// vupenQUICLastAttr — последний ответ снифера QUIC в этом потоке (атрибут Content).
const vupenQUICLastAttr = "vupen_quic_last"

var vupenQUICStats struct {
	ok, noSNI, notFirst, notQUIC, needMore, other atomic.Uint64
}

// vupenRecordQUICResult — снифер QUIC ответил (из обёртки в sniffer.go).
func vupenRecordQUICResult(ctx context.Context, res SniffResult, err error) {
	content := session.ContentFromContext(ctx)
	if content == nil {
		return
	}
	reason := "other"
	switch {
	case err == nil && res != nil && res.Domain() != "":
		reason = "ok"
	case stderrors.Is(err, quic.ErrQUICNoSNI):
		reason = "nosni"
	case stderrors.Is(err, quic.ErrQUICNotFirstInitial):
		reason = "notfirst"
	case stderrors.Is(err, protocol.ErrProtoNeedMoreData):
		reason = "more"
	case stderrors.Is(err, quic.ErrQUICNotQUIC), stderrors.Is(err, quic.ErrQUICNotInitial):
		reason = "notquic" // not quic / not initial packet (T-087 CR-008: by sentinel)
	}
	content.SetAttribute(vupenQUICLastAttr, reason)
}

// vupenCountQUICFlow — поток закончил снифф: посчитать итог QUIC (если снифер участвовал).
func vupenCountQUICFlow(ctx context.Context) {
	content := session.ContentFromContext(ctx)
	if content == nil {
		return
	}
	switch content.Attribute(vupenQUICLastAttr) {
	case "":
		return
	case "ok":
		vupenQUICStats.ok.Add(1)
	case "nosni":
		vupenQUICStats.noSNI.Add(1)
	case "notfirst":
		vupenQUICStats.notFirst.Add(1)
	case "notquic":
		vupenQUICStats.notQUIC.Add(1)
	case "more":
		vupenQUICStats.needMore.Add(1)
	default:
		vupenQUICStats.other.Add(1)
	}
}

func vupenQUICStatsString() string {
	return fmt.Sprintf("quic[ok=%d nosni=%d notfirst=%d notquic=%d more=%d other=%d]",
		vupenQUICStats.ok.Load(), vupenQUICStats.noSNI.Load(), vupenQUICStats.notFirst.Load(),
		vupenQUICStats.notQUIC.Load(), vupenQUICStats.needMore.Load(), vupenQUICStats.other.Load())
}

// vupenSniffGaps — паузы между приходами данных за снифф (мс), для строки тайм-аута:
// повторы iPhone через 250/500/1000 мс видны сразу.
func vupenSniffGaps(trace *vupenSniffTrace) string {
	if trace == nil || len(trace.arrivals) == 0 {
		return "dt=—"
	}
	parts := make([]string, 0, len(trace.arrivals))
	prev := time.Duration(0)
	for _, at := range trace.arrivals {
		parts = append(parts, strconv.FormatInt((at-prev).Milliseconds(), 10))
		prev = at
	}
	return "dt=" + strings.Join(parts, ",") + "ms"
}

// noteArrival — данные в буфере снифа выросли.
func (t *vupenSniffTrace) noteArrival() {
	if t.start.IsZero() || len(t.arrivals) >= 8 {
		return
	}
	t.arrivals = append(t.arrivals, time.Since(t.start))
}

// ── S3: честный direct-miss ─────────────────────────────────────────────────

const vupenNoDomainLogMarker = "[Vupen routing] no-domain:"

// vupenIsDirectHandler — outbound отправляет напрямую (freedom) или в никуда (blackhole).
func vupenHandlerKind(h outbound.Handler) string {
	if h == nil || h.ProxySettings() == nil {
		return ""
	}
	t := h.ProxySettings().Type
	switch {
	case strings.HasSuffix(t, "freedom.Config"):
		return "direct"
	case strings.HasSuffix(t, "blackhole.Config"):
		return "block"
	}
	return "proxy"
}

// vupenMaybeLogDirectMiss — снифф имени не дал, поток ушёл в узел (не direct).
// Баннер (маркер direct-miss) — только для настоящих кандидатов: известное
// ядру имя этого потока по правилам ушло бы напрямую. Остальное — строка Info
// без баннера: по одному IP правило по домену и не могло сработать.
func (d *DefaultDispatcher) vupenMaybeLogDirectMiss(ctx context.Context, destination net.Destination, h outbound.Handler) {
	content := session.ContentFromContext(ctx)
	if content == nil || content.Attribute(vupenSniffMissAttr) != "1" || destination.Address.Family().IsDomain() {
		return
	}
	if vupenHandlerKind(h) != "proxy" {
		return
	}
	tag := h.Tag()
	hint := content.Attribute(vupenSniffDomainAttr)
	if hint != "" && d.router != nil {
		if dt := d.vupenRouteTagForDomain(ctx, hint); dt != "" && vupenHandlerKind(d.ohm.GetHandler(dt)) == "direct" {
			detail := strings.Join([]string{
				"домен не попал в маршрут (снифф без итога)",
				vupenSniffMissDomainForLog(ctx),
				destination.String() + " → [" + tag + "], по домену было бы [" + dt + "]",
			}, ", ")
			vupenAppendSniffRoutingMissLog(vupenDirectMissLogMarker + " " + detail)
			errors.LogWarning(ctx, vupenDirectMissLogMarker, " ", detail)
			return
		}
	}
	errors.LogInfo(ctx, vupenNoDomainLogMarker, " домен не распознан (без имени в ClientHello или поток без начала), маршрут по IP: ",
		destination.String(), " → [", tag, "]")
}

// vupenRouteTagForDomain — куда маршрутизатор отправил бы этот поток с именем domain.
func (d *DefaultDispatcher) vupenRouteTagForDomain(ctx context.Context, domain string) string {
	obs := session.OutboundsFromContext(ctx)
	if len(obs) == 0 {
		return ""
	}
	ob := *obs[len(obs)-1]
	ob.RouteTarget = net.Destination{Network: ob.Target.Network, Address: net.DomainAddress(domain), Port: ob.Target.Port}
	rctx := session.ContextWithOutbounds(ctx, []*session.Outbound{&ob})
	// T-087 CR-006: only for a log line — PickRoute must not trigger DNS (IPIfNonMatch).
	// Shallow copy of Content: the original flow keeps its own flag.
	var c session.Content
	if cur := session.ContentFromContext(ctx); cur != nil {
		c = *cur
	}
	c.SkipDNSResolve = true
	rctx = session.ContextWithContent(rctx, &c)
	route, err := d.router.PickRoute(routing_session.AsRoutingContext(rctx))
	if err != nil {
		return ""
	}
	return route.GetOutboundTag()
}

// ── S4: память маршрута для повторов того же UDP-потока ─────────────────────

var (
	// VupenRouteMemoryTTL / VupenRouteMemoryMax — сколько помнить поток
	// src:port → dst:port (с последнего повтора) и сколько потоков помнить.
	VupenRouteMemoryTTL = 60 * time.Second
	VupenRouteMemoryMax = 512
)

type vupenRouteEntry struct {
	key   string
	tag   string
	until time.Time
	gen   uint64
}

// vupenRouteMemory — недавние решения маршрута для UDP-потоков (на экземпляр
// диспетчера: новый конфиг — новая память). Повтор того же потока (новая
// UDP-сессия TUN после простоя, повтор QUIC без начала) идёт тем же outbound'ом
// сразу, без снифа: иначе он без имени уходил по IP в другой узел. Решения
// прежнего поколения (смена сети, узла АВТО, перелив, настройка Apple) не берутся.
type vupenRouteMemory struct {
	mu  sync.Mutex
	m   map[string]*list.Element
	lru *list.List
}

func newVupenRouteMemory() *vupenRouteMemory {
	return &vupenRouteMemory{m: map[string]*list.Element{}, lru: list.New()}
}

// vupenRouteMemKey — ключ в ctx. Нет значения: поток ещё не маршрутизировался.
// Есть значение (даже пустое): routedDispatch уже отработал для этого ctx — память
// использована один раз и не должна течь во вложенный диспатч (loopback outbound →
// DispatchLink с тем же ctx): ни recall, ни remember там не делаются (T-087 CR-001).
type vupenRouteMemKey struct{}

func vupenRouteKey(ctx context.Context, destination net.Destination) string {
	if destination.Network != net.Network_UDP || !destination.Address.Family().IsIP() {
		return ""
	}
	in := session.InboundFromContext(ctx)
	if in == nil || !in.Source.IsValid() {
		return ""
	}
	return in.Source.NetAddr() + ">" + destination.NetAddr()
}

func (m *vupenRouteMemory) get(key string, now time.Time) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	el, ok := m.m[key]
	if !ok {
		return ""
	}
	e := el.Value.(*vupenRouteEntry)
	if now.After(e.until) || e.gen != internet.VupenRouteGeneration() {
		m.lru.Remove(el)
		delete(m.m, key)
		return ""
	}
	e.until = now.Add(VupenRouteMemoryTTL)
	m.lru.MoveToFront(el)
	return e.tag
}

// put — gen это поколение, прочитанное ДО PickRoute (T-087 CR-003): если выбор узла
// сменился во время маршрутизации, запись уже устарела и при чтении промахнётся.
func (m *vupenRouteMemory) put(key, tag string, gen uint64, now time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if el, ok := m.m[key]; ok {
		e := el.Value.(*vupenRouteEntry)
		e.tag, e.until, e.gen = tag, now.Add(VupenRouteMemoryTTL), gen
		m.lru.MoveToFront(el)
		return
	}
	for m.lru.Len() >= max(1, VupenRouteMemoryMax) {
		old := m.lru.Back()
		m.lru.Remove(old)
		delete(m.m, old.Value.(*vupenRouteEntry).key)
	}
	m.m[key] = m.lru.PushFront(&vupenRouteEntry{key: key, tag: tag, until: now.Add(VupenRouteMemoryTTL), gen: gen})
}

func (m *vupenRouteMemory) size() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lru.Len()
}

// vupenIsFakeIP — адрес из пула FakeDNS: по нему имя домена известно только движку
// FakeDNS, память маршрута к такому адресу не применяется (T-087 CR-002).
func (d *DefaultDispatcher) vupenIsFakeIP(addr net.Address) bool {
	fk, ok := d.fdns.(dns.FakeDNSEngineRev0)
	return ok && fk.IsIPInIPPool(addr)
}

// vupenRouteRecall — этот UDP-поток уже был недавно: контекст с запомненным
// outbound'ом и true. Вызывается ПОСЛЕ снифа и только если он не дал имени
// (vupenRouteRecallAfterSniff). Не работает во вложенном диспатче и для fake-IP.
func (d *DefaultDispatcher) vupenRouteRecall(ctx context.Context, destination net.Destination) (context.Context, bool) {
	if d.vupenRoutes == nil || ctx.Value(vupenRouteMemKey{}) != nil {
		return ctx, false
	}
	if d.vupenIsFakeIP(destination.Address) {
		return ctx, false
	}
	key := vupenRouteKey(ctx, destination)
	if key == "" {
		return ctx, false
	}
	tag := d.vupenRoutes.get(key, time.Now())
	if tag == "" || d.ohm.GetHandler(tag) == nil {
		return ctx, false
	}
	return context.WithValue(ctx, vupenRouteMemKey{}, tag), true
}

// vupenRouteRecallAfterSniff — снифф закончен. Память берётся, только если он не дал
// имени (current всё ещё IP, подсказки домена нет): имя всегда точнее памяти (T-087 CR-002).
// origin — исходный адрес назначения (до подмены на домен).
func (d *DefaultDispatcher) vupenRouteRecallAfterSniff(ctx context.Context, content *session.Content, origin, current net.Destination) context.Context {
	if current.Address.Family().IsDomain() {
		return ctx
	}
	if content != nil && content.Attribute(vupenSniffDomainAttr) != "" {
		return ctx
	}
	rctx, _ := d.vupenRouteRecall(ctx, origin)
	return rctx
}

// vupenRouteMemoryHandler — outbound из памяти маршрута (для routedDispatch);
// tag прочитан routedDispatch из ctx один раз.
func (d *DefaultDispatcher) vupenRouteMemoryHandler(ctx context.Context, destination net.Destination, tag string) outbound.Handler {
	if tag == "" {
		return nil
	}
	h := d.ohm.GetHandler(tag)
	if h != nil {
		errors.LogInfo(ctx, "[Vupen route-mem] same UDP flow as before: taking detour [", tag, "] for [", destination, "]")
	}
	return h
}

// vupenRouteWanted — поток запрашивал снифф (не порт-53/DoT/резолвер): только такие
// запоминаем (T-087 CR-007).
func vupenRouteWanted(content *session.Content, origin net.Destination) bool {
	return content != nil && content.SniffingRequest.Enabled && !vupenShouldSkipSniff(origin)
}

// vupenRouteRemember — запомнить решение для этого UDP-потока; gen — поколение
// маршрутов, прочитанное до PickRoute.
func (d *DefaultDispatcher) vupenRouteRemember(ctx context.Context, tag string, gen uint64) {
	if d.vupenRoutes == nil || tag == "" {
		return
	}
	obs := session.OutboundsFromContext(ctx)
	if len(obs) == 0 {
		return
	}
	if key := vupenRouteKey(ctx, obs[len(obs)-1].OriginalTarget); key != "" {
		d.vupenRoutes.put(key, tag, gen, time.Now())
	}
}
