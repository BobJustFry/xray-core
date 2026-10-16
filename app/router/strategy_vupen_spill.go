package router

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/errors"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"

	"google.golang.org/protobuf/reflect/protoreflect"
)

// Ядро 77 (АВТО 4.1, D-12, D-14, D-18, D-21; ADR-0001 §4.3, §4.4 (3)–(4), §9, §13):
// перелив REG → LTE.
//
//   - Только на сотовой: тип сети берётся у эпохи ядра 74 (VupenSetUplink), и на
//     Wi-Fi (в том числе раздаче с телефона), проводной, прочей, неизвестной сети и
//     без сети перелив запрещён жёстко, даже если vupenSpill.uplink их перечисляет.
//   - Только после полного неудачного поиска по REG («ничего не работает»), не
//     чаще раза в VupenSpillMinGap. Пока перелито, PickOutbound REG отдаёт выбор
//     LTE-балансировщика (у него свой «держать текущий»: свой initial и поиск с
//     проверкой 64 КБ — кандидаты LTE проверяются только при переливе).
//   - Возврат сразу: при любой смене сети вердикт «обычный мёртв» сбрасывается,
//     новые соединения идут в REG; пока перелито — раз в VupenLteRegularRecheck
//     лёгкая проверка VupenLteRegularRecheckN обычных (последний рабочий + лучшие
//     по прошлым замерам): HEAD, затем 24 КБ через ответивший — прошёл → REG.
//   - Неверный vupenSpill: ядро работает, перелив выключен, одно предупреждение.
var (
	VupenSpillMinGap           = 60 * time.Second
	VupenLteRegularRecheck     = 5 * time.Minute
	VupenLteRegularRecheckN    = 3
	vupenUplinkKind            = internet.VupenUplinkKind
	vupenCloseConnsWhenStable  = internet.VupenCloseConnsWhenStable
	vupenSpillAllowedUplinks   = []string{"cellular", "wifi", "wired", "other", "none"}
	vupenSpillOnlyOnUplinkKind = "cellular"
)

// vupenSpill — настройки и состояние перелива балансировщика.
type vupenSpill struct {
	targetTag string
	cellular  bool   // vupenSpill.uplink содержит cellular
	invalid   string // причина, по которой перелив выключен ("" — настройка верна)
	target    atomic.Pointer[Balancer]
	spilled   atomic.Bool

	// Только в горутине обработчика.
	lastSpillAt time.Time
	stopRecheck func() bool
	cancelClose func() // отмена ждущего закрытия соединений LTE (перелили снова)
}

var vupenSpillWarned sync.Map // balancer tag → предупреждение уже было

func newVupenSpillConfig(br *BalancingRule) *vupenSpill {
	cfg := br.GetVupenSpill()
	if cfg == nil {
		return nil
	}
	sp := &vupenSpill{targetTag: cfg.GetBalancerTag()}
	var ignored []string
	for _, u := range cfg.GetUplink() {
		switch {
		case u == vupenSpillOnlyOnUplinkKind:
			sp.cellular = true
		case slices.Contains(vupenSpillAllowedUplinks, u):
			ignored = append(ignored, u)
		default:
			sp.invalid = fmt.Sprintf("uplink %q is not a network type", u)
		}
	}
	switch {
	case sp.invalid != "":
	case sp.targetTag == "":
		sp.invalid = "balancerTag is empty"
	case sp.targetTag == br.GetTag():
		sp.invalid = "balancerTag is the balancer itself"
	}
	if len(ignored) > 0 && sp.invalid == "" {
		vupenSpillWarnOnce(br.GetTag()+":ignored", fmt.Sprintf(
			"[vupen] config warning: vupenSpill of %s: uplink %v ignored — spill to LTE only on cellular (D-21)",
			br.GetTag(), ignored))
	}
	return sp
}

func vupenSpillWarnOnce(key, msg string) {
	if _, loaded := vupenSpillWarned.LoadOrStore(key, true); !loaded {
		errors.LogWarning(context.Background(), msg)
	}
}

// vupenLinkSpill — после сборки всех балансировщиков найти цель перелива.
func vupenLinkSpill(balancers map[string]*Balancer) {
	for tag, b := range balancers {
		if b == nil || b.vupen == nil || b.vupen.spill == nil {
			continue
		}
		sp := b.vupen.spill
		if sp.invalid == "" {
			t := balancers[sp.targetTag]
			switch {
			case t == nil:
				sp.invalid = fmt.Sprintf("balancerTag %q is not a balancer", sp.targetTag)
			case t.vupen == nil:
				sp.invalid = fmt.Sprintf("balancer %q has no vupenSticky", sp.targetTag)
			case t.vupen.spill != nil:
				// Один уровень: цель перелива сама не переливает (иначе цепочки и
				// циклы REG → LTE → … → REG).
				sp.invalid = fmt.Sprintf("balancer %q has its own vupenSpill (one level only)", sp.targetTag)
			default:
				sp.target.Store(t)
				t.vupen.spillTargetOf.Store(true)
			}
		}
		if sp.invalid != "" {
			vupenSpillWarnOnce(tag+":invalid", fmt.Sprintf(
				"[vupen] config warning: vupenSpill of %s: %s → spill to LTE off (D-21)", tag, sp.invalid))
		}
	}
}

// spillTarget — куда отдать выбор сейчас (nil — выбирает сам балансировщик).
// Жёсткий запрет: не сотовая — никогда, что бы ни было в состоянии.
func (s *vupenSticky) spillTarget() *Balancer {
	sp := s.spill
	if sp == nil || !sp.spilled.Load() || vupenUplinkKind() != vupenSpillOnlyOnUplinkKind {
		return nil
	}
	return sp.target.Load()
}

// trySpill — поиск по REG ничего не нашёл: перелить в LTE, если можно.
func (s *vupenSticky) trySpill(reason string) bool {
	sp := s.spill
	if sp == nil {
		return false
	}
	blocked := ""
	switch kind := vupenUplinkKind(); {
	case sp.invalid != "" || sp.target.Load() == nil:
		blocked = "config: " + sp.invalid
	case !sp.cellular:
		blocked = "vupenSpill.uplink has no cellular"
	case kind != vupenSpillOnlyOnUplinkKind:
		blocked = "uplink " + kind // D-21: на Wi-Fi/проводной/неизвестной — никогда
	case !sp.lastSpillAt.IsZero() && vupenStickyNow().Sub(sp.lastSpillAt) < VupenSpillMinGap:
		blocked = fmt.Sprintf("last spill %s ago (limit %s)", vupenStickyNow().Sub(sp.lastSpillAt).Round(time.Second), VupenSpillMinGap)
	}
	s.setReport(func(r *vupenStickyReport) { r.spillBlocked = blocked })
	if blocked != "" {
		errors.LogWarning(s.logCtx(), "[spill] ", s.balancer, ": no spill (", blocked, ")")
		return false
	}
	// CR-603: перелив ставится один раз — уже перелито, счётчики не трогаем.
	if !sp.spilled.CompareAndSwap(false, true) {
		return true
	}
	sp.lastSpillAt = vupenStickyNow()
	if sp.cancelClose != nil {
		sp.cancelClose() // снова на LTE до закрытия его соединений — не закрываем
		sp.cancelClose = nil
	}
	if t := sp.target.Load(); t != nil && t.vupen != nil {
		t.vupen.feeders.Add(1)
		// CR-501: цель снова в работе; CR-602: флаг — на случай полной очереди.
		t.vupen.wakePending.Store(true)
		t.vupen.send(vupenStickyEvent{kind: "wake"})
	}
	if s.stopRetry != nil {
		s.stopRetry()
		s.stopRetry = nil
	}
	s.setReport(func(r *vupenStickyReport) { r.nextSearchAt = time.Time{} })
	s.setReport(func(r *vupenStickyReport) {
		r.spills++
		r.lastSwitch = vupenStickyMark{at: vupenStickyNow(), from: s.current, to: sp.targetTag, reason: "spill"}
	})
	errors.LogWarning(s.logCtx(), "[spill] ", s.balancer, " dead after search (", reason, ") → ", sp.targetTag, " (uplink=cellular)")
	s.scheduleRecheck()
	return true
}

func (s *vupenSticky) scheduleRecheck() {
	sp := s.spill
	if sp.stopRecheck != nil {
		sp.stopRecheck()
	}
	sp.stopRecheck = vupenStickyAfter(VupenLteRegularRecheck, func() { s.send(vupenStickyEvent{kind: "lte-recheck"}) })
}

// unspill — вернуть выбор в REG (смена сети или обычный ожил).
func (s *vupenSticky) unspill(reason string) bool {
	sp := s.spill
	if sp == nil || !sp.spilled.CompareAndSwap(true, false) {
		return false
	}
	if t := sp.target.Load(); t != nil && t.vupen != nil {
		t.vupen.feeders.Add(-1)
		t.vupen.send(vupenStickyEvent{kind: "sleep"}) // CR-501: без перелива LTE не ищет
	}
	errors.LogWarning(s.logCtx(), "[spill] return → ", s.balancer, " (", reason, ")")
	s.setReport(func(r *vupenStickyReport) { r.returns++ })
	return true
}

// onUnspilledByNetwork — в обработчике после возврата по смене сети: таймер
// лёгкой проверки больше не нужен; поиск по REG — когда сеть устоится (9 с),
// а если события не будет — по графику.
func (s *vupenSticky) onUnspilledByNetwork() {
	sp := s.spill
	if sp != nil && sp.stopRecheck != nil {
		sp.stopRecheck()
		sp.stopRecheck = nil
	}
	// CR-502: при любом возврате — закрыть соединения LTE, когда сеть устоится 9 с
	// (мигание с возвратом к прежней сети отменяет общую чистку эпохи).
	s.closeLTEConns()
	if s.getPhase() == vupenPhaseNoWorking {
		s.scheduleRetry(false)
	}
}

// dormant — цель перелива, в которую сейчас никто не переливает (или сеть не
// сотовая): поиск и повторы не идут (CR-501; кандидаты LTE — только при переливе).
func (s *vupenSticky) dormant() bool {
	return s.spillTargetOf.Load() && (s.feeders.Load() <= 0 || vupenUplinkKind() != vupenSpillOnlyOnUplinkKind)
}

// lteRecheck — пока перелито: лёгкая проверка обычных (D-18 п. 15).
func (s *vupenSticky) lteRecheck() {
	sp := s.spill
	if sp == nil || !sp.spilled.Load() {
		return
	}
	obs := s.observatory()
	if obs == nil {
		return
	}
	defer func() {
		if sp.spilled.Load() {
			s.scheduleRecheck()
		}
	}()
	if obs.VupenStickyAsleep() {
		return
	}
	cands, _ := s.b.SelectOutbounds()
	var pool []string
	for _, t := range cands {
		if !obs.VupenStickyExcluded(t) {
			pool = append(pool, t)
		}
	}
	// Последний рабочий + лучшие по прошлым замерам.
	var picks []string
	if s.current != "" && slices.Contains(pool, s.current) {
		picks = append(picks, s.current)
	}
	_, all := s.order(obs, pool)
	for _, t := range all {
		if len(picks) >= VupenLteRegularRecheckN {
			break
		}
		if !slices.Contains(picks, t) {
			picks = append(picks, t)
		}
	}
	if len(picks) == 0 {
		return
	}
	obs.VupenStickyProbe(picks)
	alive, _ := s.order(obs, picks)
	// Последний рабочий — первым, если ответил.
	if s.current != "" && slices.Contains(alive, s.current) {
		alive = append([]string{s.current}, slices.DeleteFunc(alive, func(t string) bool { return t == s.current })...)
	}
	for _, tag := range alive {
		if obs.VupenStickyCheck(tag) == vupenStickyOK {
			if s.unspill(tag + " verified") {
				if sp.stopRecheck != nil {
					sp.stopRecheck()
					sp.stopRecheck = nil
				}
				s.holdBecause(tag, "return")
				s.closeLTEConns()
			}
			return
		}
	}
	errors.LogWarning(s.logCtx(), fmt.Sprintf("[spill] %s: recheck of %d regular, %d answered — still on %s",
		s.balancer, len(picks), len(alive), sp.targetTag))
}

// closeLTEConns — возврат в REG без смены сети: открытые соединения пула LTE
// закрываются, когда сеть стабильна 9 с (сразу, если уже) — D-14 п. 3, D-18.
// При возврате по смене сети их и так закрывает эпоха (они прежней сети).
func (s *vupenSticky) closeLTEConns() {
	sp := s.spill
	t := sp.target.Load()
	if t == nil {
		return
	}
	selectors := append([]string(nil), t.selectors...)
	if sp.cancelClose != nil {
		sp.cancelClose()
	}
	sp.cancelClose = vupenCloseConnsWhenStable(func(tag string) bool {
		for _, sel := range selectors {
			if strings.HasPrefix(tag, sel) {
				return true
			}
		}
		return false
	}, "lte-return")
}

// ── состояние для 2.6 (VupenAutoState) ──────────────────────────────────────

// vupenStickyMark — событие для отчёта.
type vupenStickyMark struct {
	at               time.Time
	kind, detail     string
	from, to, reason string
}

// vupenStickyReport — то, что балансировщик отдаёт наружу (под stateMu).
type vupenStickyReport struct {
	current      string
	failedChecks int // проверок подряд не прошло в этом эпизоде (0 — всё хорошо)
	lastFailure  vupenStickyMark
	lastSwitch   vupenStickyMark
	spills       int
	returns      int
	spillBlocked string
	// Ядро 78 (VupenAutoState).
	since        time.Time       // когда взят текущий узел
	startVerdict string          // итог проверки initial при старте: ok | failed | unknown; "" — не было
	nextSearchAt time.Time       // следующий повтор поиска (ничего не работает); нуль — не назначен
	alive        int             // живых по пробам последнего поиска
	searched     bool            // поиск уже был
	lastSignal   vupenStickyMark // последний признак отказа: dial | freeze | manual
	network      string          // сеть устройства по последней проверке: up | down | unknown; "" — не проверялась
	routeCheck   vupenRouteMark  // последний check VupenCheckRoute (для heal)
	lastRoute    vupenStickyMark // последний итог VupenCheckRoute (kind = режим, detail = вердикт)
}

func (s *vupenSticky) setReport(f func(r *vupenStickyReport)) {
	s.stateMu.Lock()
	f(&s.report)
	s.stateMu.Unlock()
}

// vupenAutoState — состояние «держать текущий» для VupenAutoState (2.6).
// «Сервер не отвечает, ищу другой» — Searching && FailedChecks ≥ 1;
// «Нет рабочих серверов» — NoWorking (D-25/D-27).
type vupenAutoState struct {
	Balancer     string
	Tier         string // regular | lte
	Phase        string // new | checking | holding | searching | no-working
	Current      string // тег узла, через который идут новые соединения
	Host         string
	Port         uint32
	Spilled      bool
	Searching    bool
	NoWorking    bool
	FailedChecks int
	LastFailure  vupenStickyMark
	LastSwitch   vupenStickyMark
	Spills       int
	Returns      int
	SpillBlocked string
	// Ядро 78: кто сейчас выбирает (REG или LTE при переливе) и его подробности.
	Serving      string
	Since        time.Time
	StartVerdict string
	NextSearchAt time.Time
	LastSignal   vupenStickyMark
	Network      string
	RegularAlive int // -1 — поиска ещё не было
	LteAlive     int // -1 — поиска ещё не было или перелива нет в конфиге
	LastRoute    vupenStickyMark
}

func (s *vupenSticky) state() vupenAutoState {
	s.stateMu.Lock()
	r := s.report
	s.stateMu.Unlock()
	st := vupenAutoState{
		Balancer: s.balancer, Tier: "regular", Phase: s.getPhase().String(), Current: r.current,
		FailedChecks: r.failedChecks, LastFailure: r.lastFailure, LastSwitch: r.lastSwitch,
		Spills: r.spills, Returns: r.returns, SpillBlocked: r.spillBlocked,
		Serving: s.balancer, Since: r.since, StartVerdict: r.startVerdict, NextSearchAt: r.nextSearchAt,
		LastSignal: r.lastSignal, Network: r.network, RegularAlive: -1, LteAlive: -1, LastRoute: r.lastRoute,
	}
	if r.searched {
		st.RegularAlive = r.alive
	}
	if s.spill != nil {
		if t := s.spill.target.Load(); t != nil && t.vupen != nil {
			t.vupen.stateMu.Lock()
			if t.vupen.report.searched {
				st.LteAlive = t.vupen.report.alive
			}
			t.vupen.stateMu.Unlock()
		}
	}
	if p := s.view.Load(); p != nil && st.Current == "" {
		st.Current = *p
	}
	phase := s.getPhase()
	st.Searching = phase == vupenPhaseSearching || phase == vupenPhaseChecking
	st.NoWorking = phase == vupenPhaseNoWorking
	b := s.b
	if t := s.spillTarget(); t != nil && t.vupen != nil {
		lte := t.vupen.state()
		st.Tier, st.Spilled = "lte", true
		st.Current, st.Phase, st.Searching, st.NoWorking = lte.Current, lte.Phase, lte.Searching, lte.NoWorking
		st.Serving, st.Since, st.NextSearchAt, st.FailedChecks = lte.Balancer, lte.Since, lte.NextSearchAt, lte.FailedChecks
		if vupenNewer(lte.LastSignal, st.LastSignal) {
			st.LastSignal = lte.LastSignal
		}
		if vupenNewer(lte.LastFailure, st.LastFailure) {
			st.LastFailure = lte.LastFailure
		}
		if lte.LastSwitch.at.After(st.LastSwitch.at) { // при равенстве — перелив REG
			st.LastSwitch = lte.LastSwitch
		}
		if vupenNewer(lte.LastRoute, st.LastRoute) {
			st.LastRoute = lte.LastRoute
		}
		if lte.Network != "" {
			st.Network = lte.Network
		}
		b = t
	}
	st.Host, st.Port = vupenNodeAddr(b, st.Current)
	return st
}

// vupenNewer — a не старше b (при равенстве — a: событие того, кто выбирает сейчас).
func vupenNewer(a, b vupenStickyMark) bool { return !a.at.IsZero() && !a.at.Before(b.at) }

// vupenNodeAddr — адрес и порт сервера outbound'а tag (из его настроек).
func vupenNodeAddr(b *Balancer, tag string) (string, uint32) {
	if b == nil || b.ohm == nil || tag == "" {
		return "", 0
	}
	h := b.ohm.GetHandler(tag)
	if h == nil || h.ProxySettings() == nil {
		return "", 0
	}
	inst, err := h.ProxySettings().GetInstance()
	if err != nil {
		return "", 0
	}
	return vupenFirstEndpoint(inst.ProtoReflect(), 0)
}

// vupenFirstEndpoint — первый адрес сервера и порт рядом с ним (поле "port").
func vupenFirstEndpoint(m protoreflect.Message, depth int) (string, uint32) {
	if depth > 6 || !m.IsValid() {
		return "", 0
	}
	var host string
	var port uint32
	m.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		if fd.Kind() != protoreflect.MessageKind || fd.IsMap() {
			return true
		}
		if !fd.IsList() {
			if ipd, ok := v.Message().Interface().(*xnet.IPOrDomain); ok {
				if a := ipd.AsAddress(); a != nil {
					host = a.String()
					if pf := m.Descriptor().Fields().ByName("port"); pf != nil && pf.Kind() == protoreflect.Uint32Kind {
						port = uint32(m.Get(pf).Uint())
					}
					return false
				}
			}
			host, port = vupenFirstEndpoint(v.Message(), depth+1)
			return host == ""
		}
		l := v.List()
		for i := 0; i < l.Len() && host == ""; i++ {
			host, port = vupenFirstEndpoint(l.Get(i).Message(), depth+1)
		}
		return host == ""
	})
	return strings.TrimSpace(host), port
}
