package router

import (
	"context"
	"fmt"
	"net"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/app/observatory"
	"github.com/xtls/xray-core/common/errors"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/extension"
	"github.com/xtls/xray-core/transport/internet"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// Ядро 75 (АВТО 4.1, D-16, D-18, D-21; ADR-0001 §4.4, §9, §13): «держать текущий».
//
// Включается полем балансировщика vupenSticky (тип стратегии панели не меняется).
// Без поля у балансировщика vupen == nil и PickOutbound идёт прежним кодом.
//
//   - Узел выбирается один раз и держится, пока работает. Медленный, но
//     работающий узел не меняется; замеры не «протухают» для выбора.
//   - Старт: vupenSticky.initial (тег последнего рабочего узла) и одна проверка
//     24 КБ через него; пока она идёт — трафик в initial. Не прошла и сеть у
//     устройства есть — узел исключён на 15 мин и поиск. Тега нет / нет в пуле —
//     сразу поиск.
//   - Поиск: разовый раунд HEAD-проб по неисключённым узлам пула, порядок —
//     стратегией панели, проверка 64 КБ (ядро 71) не больше
//     VupenStickySearchMaxChecks узлов, по возможности из разных /24 или доменов;
//     переход только на проверенный.
//   - Ничего не работает: повтор по VupenStickyRetry (30 с, 1, 2, затем 5 мин),
//     и сразу, когда новая сеть устоялась (эпоха сети ядра 74).
//   - Пока узел не подтверждён (поиск, «ничего не работает»): fallbackTag, если он
//     не исключён, иначе временный кандидат — первый неисключённый узел пула в
//     порядке стратегии. Пустой тег не возвращается.
//
// Признаки отказа (П1/П2/П5), перелив в LTE и экспорты — подшаги 2.4–2.6; сюда
// они придут через vupenSticky.requestCheck.
var (
	// VupenStickyRetry — паузы повторного поиска, пока ничего не работает;
	// последняя повторяется (D-18 п. 14).
	VupenStickyRetry = []time.Duration{30 * time.Second, time.Minute, 2 * time.Minute, 5 * time.Minute}
	// VupenStickySearchMaxChecks — сколько узлов один поиск проверяет загрузкой 64 КБ
	// (ADR-0001 §4.4 (6) В4). Значение ещё может поменять владелец.
	VupenStickySearchMaxChecks = 3

	vupenStickyAfter = func(d time.Duration, f func()) (stop func() bool) {
		return time.AfterFunc(d, f).Stop
	}

	// Ядро 76: признаки «текущий не работает» (ADR-0001 §4.4 (2), §13). Признак
	// только запускает проверку текущего (24 КБ + сеть); сам узел не меняет.
	//
	// П1: VupenStickyFailDials неудачных соединений подряд к текущему узлу за
	// VupenStickyFailWindow, без единого ответа узла между ними.
	VupenStickyFailDials  = 3
	VupenStickyFailWindow = 10 * time.Second
	// П2: сторож заморозки (уже с фильтром «два соединения за 30 с») — не чаще
	// VupenStickyFreezeEvery на узел.
	VupenStickyFreezeEvery = time.Minute
	// Признаки не считаются VupenStickySignalNetGrace после смены сети (эпоха
	// ядра 74) и во сне.
	VupenStickySignalNetGrace = 10 * time.Second

	vupenStickyNow = time.Now
)

// vupenStickySignalSource — обсерватория, которая сообщает признаки отказа узлов
// (burst, ядро 76). Без неё признаков нет — остаётся только старт и поиск.
type vupenStickySignalSource interface {
	VupenStickyListen(f func(tag, kind string, ok bool, detail string)) func()
}

// vupenStickySignals — счётчики признаков текущего узла (из горутин соединений).
type vupenStickySignals struct {
	mu           sync.Mutex
	tag          string
	fails        []time.Time
	lastFreeze   time.Time
	netChangedAt time.Time
}

// Итоги проверок обсерватории (app/observatory/burst, tuning_vupen_sticky.go).
const (
	vupenStickyOK     = "ok"
	vupenStickyFailed = "failed"
	vupenNetUp        = "up"
	vupenNetDown      = "down"
)

// vupenStickyObservatory — что нужно от burst-обсерватории (ядро 75).
type vupenStickyObservatory interface {
	GetObservation(ctx context.Context) (proto.Message, error)
	VupenStickyProbe(tags []string)
	VupenStickyVerify(tag string) string
	VupenStickyCheck(tag string) string
	VupenStickyNetwork() string
	VupenStickyExcluded(tag string) bool
	VupenStickyExclude(tag, reason string)
	VupenStickyAsleep() bool
}

type vupenStickyPhase int32

const (
	vupenPhaseNew vupenStickyPhase = iota
	vupenPhaseChecking
	vupenPhaseHolding
	vupenPhaseSearching
	vupenPhaseNoWorking
)

func (p vupenStickyPhase) String() string {
	return [...]string{"new", "checking", "holding", "searching", "no-working"}[p]
}

type vupenStickyEvent struct {
	kind   string // start | check | search | retry | net-stable | current-excluded | wake | sleep | heal …
	reason string
	heal   *vupenHealReq // kind "heal" (ядро 78, VupenCheckRoute heal; ядро 79 — и switch)
}

type vupenSticky struct {
	b        *Balancer
	balancer string // тег балансировщика — для журнала
	initial  string

	ctx context.Context
	obs atomic.Pointer[vupenStickyObservatory]

	view  atomic.Pointer[string] // что отдаёт PickOutbound
	phase atomic.Int32

	startOnce sync.Once
	stopOnce  sync.Once
	events    chan vupenStickyEvent
	stopCh    chan struct{}
	runWorker func() // go s.loop(); в тестах — ничего (события разбирает тест)
	life      sync.Mutex
	stopped   bool   // под life
	unsub     func() // под life

	// Только в горутине обработчика.
	current      string
	retryIdx     int
	stopRetry    func() bool
	excludedSent atomic.Bool
	keys         map[string]string

	// Ядро 76: признаки отказа и склейка проверок (CR-205 (c)): пока проверка
	// стоит в очереди или идёт, новые признаки её не дублируют.
	signals      vupenStickySignals
	checkPending atomic.Bool
	unsubSignals func() // под life

	// Ядро 77: перелив REG → LTE (strategy_vupen_spill.go); nil — без vupenSpill.
	spill *vupenSpill
	// Ядро 77 (CR-501): этот балансировщик — цель перелива; feeders — сколько
	// балансировщиков сейчас в него переливают.
	spillTargetOf atomic.Bool
	feeders       atomic.Int32
	// CR-602: перелив разбудил цель; если событие wake не влезло в очередь,
	// обработчик цели увидит флаг на следующем событии.
	wakePending atomic.Bool
	// Ядро 77: состояние для 2.6 (VupenAutoState).
	stateMu sync.Mutex
	report  vupenStickyReport
	// Ядро 79 (VupenCheckRoute(switch), D-42): узлы, с которых пользователь ушёл
	// кнопкой «Сменить сервер», по порядку ухода (только в горутине обработчика).
	// Без срока и без исключения: только порядок перебора. visitedReset — сеть
	// сменилась (эпоха ядра 74): список очищается при следующем switch.
	visited      []string
	visitedReset atomic.Bool
}

func newVupenSticky(br *BalancingRule, b *Balancer) *vupenSticky {
	s := &vupenSticky{
		b:        b,
		balancer: br.GetTag(),
		initial:  br.GetVupenSticky().GetInitial(),
		events:   make(chan vupenStickyEvent, 16),
		stopCh:   make(chan struct{}),
		keys:     map[string]string{},
		spill:    newVupenSpillConfig(br),
	}
	s.runWorker = func() { go s.loop() }
	return s
}

func (s *vupenSticky) injectContext(ctx context.Context) {
	s.ctx = ctx
	if core.FromContext(ctx) == nil {
		return
	}
	err := core.OptionalFeatures(ctx, func(o extension.Observatory) error {
		if so, ok := o.(vupenStickyObservatory); ok {
			s.obs.Store(&so)
		} else {
			errors.LogWarning(ctx, "[sticky] ", s.balancer, ": the observatory cannot check nodes — holding without checks")
		}
		return nil
	})
	if err != nil {
		errors.LogWarningInner(ctx, err, "[sticky] ", s.balancer, ": no observatory")
	}
}

func (s *vupenSticky) observatory() vupenStickyObservatory {
	if p := s.obs.Load(); p != nil {
		return *p
	}
	return nil
}

func (s *vupenSticky) logCtx() context.Context {
	if s.ctx != nil {
		return s.ctx
	}
	return context.Background()
}

func (s *vupenSticky) publish(tag string) { s.view.Store(&tag) }

func (s *vupenSticky) setPhase(p vupenStickyPhase) { s.phase.Store(int32(p)) }

func (s *vupenSticky) getPhase() vupenStickyPhase { return vupenStickyPhase(s.phase.Load()) }

// pick — горячий путь: атомарное чтение, без блокировок (кроме проверки
// исключения у текущего узла).
func (s *vupenSticky) pick(cands []string) string {
	s.startOnce.Do(func() { s.start(cands) })
	if p := s.view.Load(); p != nil && *p != "" && slices.Contains(cands, *p) {
		tag := *p
		if s.getPhase() == vupenPhaseHolding {
			if obs := s.observatory(); obs != nil && obs.VupenStickyExcluded(tag) {
				// Текущий исключён (проверка ядра 71 подтвердила заморозку): ищем.
				if s.excludedSent.CompareAndSwap(false, true) && !s.send(vupenStickyEvent{kind: "current-excluded"}) {
					s.excludedSent.Store(false) // очередь полна — попробуем на следующем соединении
				}
				return s.fallbackPick(cands)
			}
		}
		return tag
	}
	return s.fallbackPick(cands)
}

// send — поставить событие в очередь; false — очередь полна (событие отброшено).
func (s *vupenSticky) send(ev vupenStickyEvent) bool {
	select {
	case s.events <- ev:
		return true
	default:
		return false
	}
}

func (s *vupenSticky) start(cands []string) {
	if s.observatory() == nil {
		// Нечем проверять: держим initial (или резервный выбор) без проверок.
		errors.LogWarning(s.logCtx(), "[sticky] ", s.balancer, ": no observatory with node checks — holding without checks")
		if s.initial != "" && slices.Contains(cands, s.initial) {
			s.publish(s.initial)
		} else {
			s.publish(s.fallbackPick(cands))
		}
		s.setPhase(vupenPhaseHolding)
		return
	}
	if s.initial != "" && slices.Contains(cands, s.initial) {
		s.setPhase(vupenPhaseChecking)
		s.publish(s.initial)
		s.send(vupenStickyEvent{kind: "check", reason: "start"})
	} else {
		if s.initial != "" {
			errors.LogWarning(s.logCtx(), "[sticky] ", s.balancer, ": initial ", s.initial,
				" is not in the pool → search")
		}
		s.setPhase(vupenPhaseSearching)
		s.publish(s.fallbackPick(cands))
		s.send(vupenStickyEvent{kind: "search", reason: "no initial"})
	}
	s.life.Lock()
	defer s.life.Unlock()
	if s.stopped {
		return // ядро уже закрыли: ни подписки, ни обработчика
	}
	s.unsub = internet.VupenNetEpochSubscribe(func(ev internet.VupenNetEvent) {
		switch ev {
		case internet.VupenNetStable:
			s.send(vupenStickyEvent{kind: "net-stable"})
		case internet.VupenNetChanged:
			s.signals.mu.Lock()
			s.signals.netChangedAt = vupenStickyNow()
			s.signals.fails = nil
			s.signals.mu.Unlock()
			s.visitedReset.Store(true)                                 // ядро 79: перебор switch — заново
			s.setReport(func(r *vupenStickyReport) { r.network = "" }) // ядро 78: сеть новая — не проверена
			// Ядро 77: сменилась сеть — вердикт «обычный мёртв» сброшен сразу:
			// новые соединения идут в REG (R4, D-12).
			if s.unspill("network changed") {
				s.send(vupenStickyEvent{kind: "net-changed"})
			}
		}
	})
	if src, ok := s.observatory().(vupenStickySignalSource); ok {
		s.unsubSignals = src.VupenStickyListen(s.onSignal)
	}
	s.runWorker()
}

// onSignal — признак от обсерватории (горутины соединений; быстро, без блокировок
// надолго). Считается только для текущего узла, вне окна смены сети и не во сне.
func (s *vupenSticky) onSignal(tag, kind string, ok bool, detail string) {
	if s.getPhase() != vupenPhaseHolding {
		return
	}
	p := s.view.Load()
	if p == nil || *p != tag {
		return
	}
	now := vupenStickyNow()
	sig := &s.signals
	sig.mu.Lock()
	if sig.tag != tag {
		sig.tag, sig.fails, sig.lastFreeze = tag, nil, time.Time{}
	}
	if kind == "dial" && ok {
		sig.fails = nil
		sig.mu.Unlock()
		return
	}
	if !sig.netChangedAt.IsZero() && now.Sub(sig.netChangedAt) < VupenStickySignalNetGrace {
		sig.mu.Unlock()
		return
	}
	if obs := s.observatory(); obs != nil && obs.VupenStickyAsleep() {
		sig.mu.Unlock()
		return
	}
	reason := ""
	switch kind {
	case "dial":
		kept := sig.fails[:0]
		for _, at := range sig.fails {
			if now.Sub(at) <= VupenStickyFailWindow {
				kept = append(kept, at)
			}
		}
		sig.fails = append(kept, now)
		if len(sig.fails) >= VupenStickyFailDials {
			sig.fails = nil
			reason = fmt.Sprintf("signal dial: %d failed connections in %s (%s)", VupenStickyFailDials, VupenStickyFailWindow, detail)
		}
	case "freeze":
		if sig.lastFreeze.IsZero() || now.Sub(sig.lastFreeze) >= VupenStickyFreezeEvery {
			sig.lastFreeze = now
			reason = "signal freeze: " + detail
		}
	}
	sig.mu.Unlock()
	if reason != "" {
		s.setReport(func(r *vupenStickyReport) {
			r.lastSignal = vupenStickyMark{at: now, kind: kind, detail: tag + ": " + detail}
		})
		if s.requestCheck(reason) {
			errors.LogWarning(s.logCtx(), "[sticky] ", s.balancer, ": ", reason, " on ", tag, " → check")
		}
	}
}

// requestCheck — проверить текущий узел (признаки отказа 2.4, проверка 2.6).
// Склеивается: пока проверка в очереди или идёт, новая не ставится (false).
func (s *vupenSticky) requestCheck(reason string) bool {
	if !s.checkPending.CompareAndSwap(false, true) {
		return false
	}
	if !s.send(vupenStickyEvent{kind: "check", reason: reason}) {
		s.checkPending.Store(false)
		return false
	}
	return true
}

func (s *vupenSticky) stop() {
	s.stopOnce.Do(func() {
		s.life.Lock()
		s.stopped = true
		unsub, unsubSignals := s.unsub, s.unsubSignals
		s.life.Unlock()
		close(s.stopCh)
		if unsub != nil {
			unsub()
		}
		if unsubSignals != nil {
			unsubSignals()
		}
	})
}

func (s *vupenSticky) loop() {
	defer func() {
		if s.stopRetry != nil {
			s.stopRetry()
		}
		if s.spill != nil && s.spill.stopRecheck != nil {
			s.spill.stopRecheck()
		}
	}()
	for {
		select {
		case <-s.stopCh:
			return
		case ev := <-s.events:
			s.handle(ev)
		}
	}
}

func (s *vupenSticky) handle(ev vupenStickyEvent) {
	select {
	case <-s.stopCh:
		return
	default:
	}
	// CR-602: перелив разбудил цель, а событие wake могло не влезть в очередь.
	if s.wakePending.Swap(false) {
		s.onWake()
	}
	// CR-501: цель перелива без перелива не ищет и не повторяет.
	if s.dormant() {
		switch ev.kind {
		case "search", "retry", "net-stable", "current-excluded":
			return
		}
	}
	switch ev.kind {
	case "sleep":
		if s.dormant() && s.stopRetry != nil {
			s.stopRetry()
			s.stopRetry = nil
		}
	case "wake":
		// Разобрано выше по флагу wakePending (CR-602).
	case "heal":
		if ev.heal != nil {
			if ev.heal.q.Mode == vupenRouteSwitchMode {
				ev.heal.reply <- s.switchRoute(ev.heal)
			} else {
				ev.heal.reply <- s.healRoute(ev.heal)
			}
		}
	case "check":
		defer s.checkPending.Store(false)
		switch s.getPhase() {
		case vupenPhaseChecking:
			s.checkCurrent(s.initial, ev.reason)
		case vupenPhaseHolding:
			s.checkCurrent(s.current, ev.reason)
		}
	case "search":
		s.search(ev.reason)
	case "retry":
		if s.getPhase() == vupenPhaseNoWorking {
			s.search("retry")
		}
	case "net-stable":
		if s.getPhase() == vupenPhaseNoWorking && !s.spilledNow() {
			s.retryIdx = 0
			s.search("network settled")
		}
	case "net-changed":
		s.onUnspilledByNetwork()
	case "lte-recheck":
		s.lteRecheck()
	case "current-excluded":
		if s.getPhase() == vupenPhaseHolding {
			cur := s.current
			s.search("current " + cur + " excluded")
		}
	}
}

func (s *vupenSticky) spilledNow() bool { return s.spill != nil && s.spill.spilled.Load() }

// onWake — цель перелива снова в работе: ничего рабочего не было — искать сразу.
func (s *vupenSticky) onWake() {
	if !s.dormant() && s.getPhase() == vupenPhaseNoWorking {
		s.retryIdx = 0
		s.search("spill")
	}
}

func (s *vupenSticky) hold(tag string) { s.holdBecause(tag, "check") }

func (s *vupenSticky) holdBecause(tag, reason string) {
	s.setReport(func(r *vupenStickyReport) {
		now := vupenStickyNow()
		if r.current != tag {
			r.lastSwitch = vupenStickyMark{at: now, from: r.current, to: tag, reason: reason}
			r.since = now
		} else if r.since.IsZero() {
			r.since = now
		}
		r.current = tag
		r.failedChecks = 0
		r.nextSearchAt = time.Time{}
	})
	s.current = tag
	s.retryIdx = 0
	if s.stopRetry != nil {
		s.stopRetry()
		s.stopRetry = nil
	}
	s.excludedSent.Store(false)
	s.publish(tag)
	s.setPhase(vupenPhaseHolding)
}

// checkCurrent — 24 КБ через tag; провал + сеть есть → исключить и искать.
func (s *vupenSticky) checkCurrent(tag, reason string) {
	obs := s.observatory()
	if obs == nil || tag == "" {
		return
	}
	verdict := obs.VupenStickyCheck(tag)
	if reason == "start" {
		s.setReport(func(r *vupenStickyReport) { r.startVerdict = verdict })
	}
	switch verdict {
	case vupenStickyOK:
		errors.LogWarning(s.logCtx(), "[sticky] ", s.balancer, ": ", reason, " ", tag, " check ok")
		s.setReport(func(r *vupenStickyReport) { r.network = vupenNetUp })
		s.hold(tag)
		return
	case vupenStickyFailed:
	default:
		// «Не поняли» (HTTP ≠ 200, ошибка сразу): узел не трогаем.
		errors.LogWarning(s.logCtx(), "[sticky] ", s.balancer, ": ", reason, " ", tag, " check inconclusive → keep")
		s.hold(tag)
		return
	}
	s.setReport(func(r *vupenStickyReport) {
		r.failedChecks++
		r.lastFailure = vupenStickyMark{at: vupenStickyNow(), kind: "check", detail: tag + ": " + reason}
	})
	devNet := obs.VupenStickyNetwork()
	s.setReport(func(r *vupenStickyReport) { r.network = devNet })
	switch devNet {
	case vupenNetUp:
		errors.LogWarning(s.logCtx(), "[sticky] ", s.balancer, ": ", tag,
			" check failed (net ok) → excluded 15m, search ", s.balancer)
		obs.VupenStickyExclude(tag, "24 KB check failed ("+reason+")")
		s.search(reason + ": " + tag + " failed")
	case vupenNetDown:
		errors.LogWarning(s.logCtx(), "[sticky] ", s.balancer, ": ", tag,
			" check failed, but the device has no network → keep")
		s.hold(tag)
	default:
		errors.LogWarning(s.logCtx(), "[sticky] ", s.balancer, ": ", tag,
			" check failed, network state unknown → keep")
		s.hold(tag)
	}
}

// search — поиск по пулу: пробы → порядок стратегии → до N проверок 64 КБ.
func (s *vupenSticky) search(reason string) { s.searchN(reason, VupenStickySearchMaxChecks) }

// searchN — поиск с пределом проверок maxChecks (VupenCheckRoute: maxSwitches);
// возвращает, сколько узлов проверено загрузкой.
func (s *vupenSticky) searchN(reason string, maxChecks int) int {
	obs := s.observatory()
	if obs == nil {
		return 0
	}
	cands, err := s.b.SelectOutbounds()
	if err != nil {
		cands = nil
	}
	if obs.VupenStickyAsleep() {
		// Во сне поиск запрещён: попробуем по графику.
		s.setPhase(vupenPhaseNoWorking)
		s.publish(s.fallbackPick(cands))
		s.scheduleRetry(false)
		errors.LogWarning(s.logCtx(), "[sticky] ", s.balancer, ": search postponed (asleep)")
		return 0
	}
	s.setPhase(vupenPhaseSearching)
	s.publish(s.fallbackPick(cands))
	var pool []string
	for _, t := range cands {
		if !obs.VupenStickyExcluded(t) {
			pool = append(pool, t)
		}
	}
	obs.VupenStickyProbe(pool)
	alive, _ := s.order(obs, pool)
	s.setReport(func(r *vupenStickyReport) { r.alive, r.searched = len(alive), true })
	picks := vupenStickyDiverse(alive, s.nodeKey, maxChecks)
	for i, tag := range picks {
		if obs.VupenStickyVerify(tag) == vupenStickyOK {
			from := s.current
			errors.LogWarning(s.logCtx(), fmt.Sprintf("[sticky] %s: search (%s): %d probed, %d alive, %s verified → switch (from %q)",
				s.balancer, reason, len(pool), len(alive), tag, from))
			s.setReport(func(r *vupenStickyReport) { r.network = vupenNetUp })
			s.holdBecause(tag, "search")
			return i + 1
		}
		s.setReport(func(r *vupenStickyReport) {
			r.failedChecks++
			r.lastFailure = vupenStickyMark{at: vupenStickyNow(), kind: "verify", detail: tag}
		})
	}
	errors.LogWarning(s.logCtx(), fmt.Sprintf("[sticky] %s: search (%s): %d probed, %d alive, %d checked → nothing works",
		s.balancer, reason, len(pool), len(alive), len(picks)))
	s.setPhase(vupenPhaseNoWorking)
	s.publish(s.fallbackPick(cands))
	// Ядро 77: на сотовой — перелив в LTE (если можно); иначе — повтор по графику.
	if s.trySpill(reason) {
		return len(picks)
	}
	s.scheduleRetry(true)
	return len(picks)
}

func (s *vupenSticky) scheduleRetry(advance bool) {
	if s.stopRetry != nil {
		s.stopRetry()
	}
	i := s.retryIdx
	if i >= len(VupenStickyRetry) {
		i = len(VupenStickyRetry) - 1
	}
	d := VupenStickyRetry[i]
	if advance && s.retryIdx < len(VupenStickyRetry)-1 {
		s.retryIdx++
	}
	s.stopRetry = vupenStickyAfter(d, func() { s.send(vupenStickyEvent{kind: "retry"}) })
	s.setReport(func(r *vupenStickyReport) { r.nextSearchAt = vupenStickyNow().Add(d) })
	errors.LogWarning(s.logCtx(), "[sticky] ", s.balancer, ": next search in ", d)
}

// fallbackPick — пока узел не подтверждён: fallbackTag, если он не исключён,
// иначе первый неисключённый в порядке стратегии; пустым не бывает, пока есть кандидаты.
func (s *vupenSticky) fallbackPick(cands []string) string {
	obs := s.observatory()
	excluded := func(t string) bool { return obs != nil && obs.VupenStickyExcluded(t) }
	fb := s.b.fallbackTag
	if fb != "" && !excluded(fb) && (len(cands) == 0 || slices.Contains(cands, fb)) {
		return fb
	}
	var all []string
	if obs != nil {
		_, all = s.order(obs, cands)
	} else {
		all = cands
	}
	for _, t := range all {
		if !excluded(t) {
			return t
		}
	}
	if fb != "" {
		return fb
	}
	if len(cands) > 0 {
		return cands[0]
	}
	return ""
}

// order — кандидаты в порядке стратегии панели: alive — живые по последним
// замерам (их проверяем), all — живые, затем остальные в порядке конфига.
func (s *vupenSticky) order(obs vupenStickyObservatory, cands []string) (alive, all []string) {
	if ll, ok := s.b.strategy.(*LeastLoadStrategy); ok && ll.observer != nil {
		nodes := ll.getNodes(cands)
		kept := nodes
		if ll.settings.MaxRTT == 0 {
			kept = vupenLeastLoadDropSlow(nodes)
		}
		for _, n := range kept {
			alive = append(alive, n.Tag)
		}
		for _, n := range nodes {
			if !slices.Contains(alive, n.Tag) {
				alive = append(alive, n.Tag)
			}
		}
	} else {
		type st struct {
			tag   string
			delay int64
			pos   int
		}
		var live []st
		if res, err := obs.GetObservation(s.logCtx()); err == nil {
			if r, ok := res.(*observatory.ObservationResult); ok {
				for _, v := range r.Status {
					if pos := slices.Index(cands, v.OutboundTag); pos >= 0 && v.Alive {
						live = append(live, st{v.OutboundTag, v.Delay, pos})
					}
				}
			}
		}
		sort.SliceStable(live, func(i, j int) bool {
			if live[i].delay != live[j].delay {
				return live[i].delay < live[j].delay
			}
			return live[i].pos < live[j].pos
		})
		for _, v := range live {
			alive = append(alive, v.tag)
		}
	}
	all = append(all, alive...)
	for _, t := range cands {
		if !slices.Contains(all, t) {
			all = append(all, t)
		}
	}
	return alive, all
}

// nodeKey — «соседство» узла: /24 для IPv4, /48 для IPv6, домен узла; иначе сам тег.
func (s *vupenSticky) nodeKey(tag string) string {
	if k, ok := s.keys[tag]; ok {
		return k
	}
	k := vupenNodeKey(s.b, tag)
	s.keys[tag] = k
	return k
}

func vupenNodeKey(b *Balancer, tag string) string {
	if b == nil || b.ohm == nil {
		return "tag:" + tag
	}
	h := b.ohm.GetHandler(tag)
	if h == nil || h.ProxySettings() == nil {
		return "tag:" + tag
	}
	inst, err := h.ProxySettings().GetInstance()
	if err != nil {
		return "tag:" + tag
	}
	addr := vupenFirstAddress(inst.ProtoReflect(), 0)
	if addr == nil {
		return "tag:" + tag
	}
	return vupenAddrKey(addr)
}

// vupenAddrKey — /24 для IPv4, /48 для IPv6, домен — как есть (в нижнем регистре).
func vupenAddrKey(addr xnet.Address) string {
	switch addr.Family() {
	case xnet.AddressFamilyIPv4:
		ip := addr.IP()
		return fmt.Sprintf("ip4:%d.%d.%d", ip[0], ip[1], ip[2])
	case xnet.AddressFamilyIPv6:
		prefix := make(net.IP, net.IPv6len)
		copy(prefix, addr.IP()[:6])
		return "ip6:" + prefix.String()
	default:
		return "dom:" + strings.ToLower(addr.Domain())
	}
}

// vupenFirstAddress — первый адрес сервера (xray.common.net.IPOrDomain) в настройках outbound'а.
func vupenFirstAddress(m protoreflect.Message, depth int) xnet.Address {
	if depth > 6 || !m.IsValid() {
		return nil
	}
	if ipd, ok := m.Interface().(*xnet.IPOrDomain); ok {
		if a := ipd.AsAddress(); a != nil {
			return a
		}
		return nil
	}
	var found xnet.Address
	m.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		if fd.Kind() != protoreflect.MessageKind {
			return true
		}
		switch {
		case fd.IsList():
			l := v.List()
			for i := 0; i < l.Len() && found == nil; i++ {
				found = vupenFirstAddress(l.Get(i).Message(), depth+1)
			}
		case fd.IsMap():
		default:
			found = vupenFirstAddress(v.Message(), depth+1)
		}
		return found == nil
	})
	return found
}

// vupenStickyDiverse — до max узлов из ordered, по возможности с разными key
// (ТСПУ часто замораживает целый хостинг); недостающих добираем по порядку.
func vupenStickyDiverse(ordered []string, key func(string) string, max int) []string {
	if max <= 0 {
		return nil
	}
	var picks []string
	seen := map[string]bool{}
	for _, t := range ordered {
		if len(picks) == max {
			return picks
		}
		if k := key(t); !seen[k] {
			seen[k] = true
			picks = append(picks, t)
		}
	}
	for _, t := range ordered {
		if len(picks) == max {
			break
		}
		if !slices.Contains(picks, t) {
			picks = append(picks, t)
		}
	}
	return picks
}

// vupenPickOutbound — PickOutbound балансировщика с vupenSticky.
func (b *Balancer) vupenPickOutbound() (string, error) {
	candidates, err := b.SelectOutbounds()
	if err != nil {
		if b.fallbackTag != "" {
			return b.fallbackTag, nil
		}
		return "", err
	}
	if o := b.override.Get(); o != "" {
		return o, nil
	}
	// Ядро 77: перелито (и сеть сотовая) — выбирает LTE-балансировщик.
	if t := b.vupen.spillTarget(); t != nil {
		return t.PickOutbound()
	}
	if tag := b.vupen.pick(candidates); tag != "" {
		return tag, nil
	}
	if b.fallbackTag != "" {
		return b.fallbackTag, nil
	}
	return "", errors.New("balancing strategy returns empty tag")
}

// vupenStopReplacedSticky — после ReloadRules остановить обработчики балансировщиков,
// которых больше нет в новом наборе (при добавлении правил старые переносятся как есть).
func vupenStopReplacedSticky(old, cur map[string]*Balancer) {
	for tag, b := range old {
		if b != nil && b.vupen != nil && cur[tag] != b {
			b.vupen.stop()
		}
	}
}

// vupenStopSticky — ядро закрывается: остановить обработчики «держать текущий».
func vupenStopSticky(balancers map[string]*Balancer) {
	for _, b := range balancers {
		if b != nil && b.vupen != nil {
			b.vupen.stop()
		}
	}
}
