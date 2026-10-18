package router

import (
	"context"
	"fmt"
	"time"

	"github.com/xtls/xray-core/app/observatory/burst"
	"github.com/xtls/xray-core/common/errors"
)

// Ядро 83 (T-102): смена сети не ждёт идущего поиска (разбор лога тестера, iPhone,
// ядро 82: поиск по REG, начатый в Wi-Fi, шёл 2 минуты после перехода в сотовую,
// держал обработчик, его проверки в БС заморозили три рабочих узла).
//
//   - Каждый поиск помнит эпоху сети, в которой начат (CR-001). Сменилась — пробы и
//     проверки прерываются («search aborted: epoch changed»), обработчик свободен.
//   - Пока класс новой сотовой сети не определён (пауза VupenNetClassSettle), поиски,
//     повторы и проверки откладываются; класс определяется первым, затем отложенное
//     выполняется (поиск по REG — только если сеть не БС).
//   - Эпоха сверяется перед каждой пробой и проверкой (CR-002); замеры прежней сети
//     burst забывает на первой пробе в новой эпохе.
//   - Проверка, прошедшая через смену сети, не замораживает узел (CR-003); заморозки,
//     поставленные в сети, ставшей БС, снимаются при смене сети и конце БС.

// vupenStickyCtxObservatory — обсерватория, чьи пробы и проверки прерываются.
type vupenStickyCtxObservatory interface {
	VupenStickyProbeCtx(ctx context.Context, tags []string)
	VupenStickyVerifyCtx(ctx context.Context, tag string, hold func() bool) string
}

// vupenStickyUnfreezer — обсерватория умеет снимать заморозки, поставленные с момента since.
type vupenStickyUnfreezer interface {
	VupenStickyUnfreezeSince(since time.Time) []string
}

// vupenStickyScopedUnfreezer — то же, но только для узлов пула балансировщика
// (T-108, CR-004: узлы чужого пула, например LTE, не трогаем).
type vupenStickyScopedUnfreezer interface {
	VupenStickyUnfreezeTags(since time.Time, tags []string) []string
}

// vupenStickyCheckCtxObservatory — проверка 24 КБ, которую можно прервать (T-108, CR-002).
type vupenStickyCheckCtxObservatory interface {
	VupenStickyCheckCtx(ctx context.Context, tag string) string
}

// vupenStickyRouteCtxObs — то же для heal (проверка с параметрами) и быстрых проб switch.
type vupenStickyRouteCtxObs interface {
	VupenStickyCheckWithCtx(ctx context.Context, tag string, opt burst.VupenCheckOptions) burst.VupenCheckResult
	VupenStickyQuickProbeCtx(ctx context.Context, tags []string, timeout time.Duration, deadline time.Time,
		each func(tag string, rtt time.Duration, ok bool) bool) int
}

// vupenStickyUnknown — «не поняли» (как burst.VupenStickyUnknown).
const vupenStickyUnknown = "unknown"

// vupenQueueWaitWarn — дольше этого событие в очереди — аномалия, попадает в журнал
// предупреждением; обычное ожидание пишется на уровне Debug (T-108, CR-006).
var vupenQueueWaitWarn = time.Second

// vupenSearchPoll — как часто идущий поиск сверяет эпоху сети сам (дополнительно к
// событию смены сети).
var vupenSearchPoll = 100 * time.Millisecond

// vupenSearchRun — один идущий поиск.
type vupenSearchRun struct {
	epoch  uint64
	ctx    context.Context
	cancel context.CancelFunc
}

// aborted — поиск надо бросить: сменилась эпоха или ядро останавливается.
func (r *vupenSearchRun) aborted() bool {
	if r.ctx.Err() != nil {
		return true
	}
	if vupenNetEpochNow() != r.epoch {
		r.cancel()
		return true
	}
	return false
}

func (s *vupenSticky) beginSearch(epoch uint64) *vupenSearchRun {
	ctx, cancel := context.WithCancel(context.Background())
	run := &vupenSearchRun{epoch: epoch, ctx: ctx, cancel: cancel}
	s.searchMu.Lock()
	s.searchRun = run
	s.searchMu.Unlock()
	poll := vupenSearchPoll // читается здесь, не в горутине: тест подменяет его между запусками
	go func() {
		t := time.NewTicker(poll)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-s.stopCh:
				cancel()
				return
			case <-t.C:
				if vupenNetEpochNow() != epoch {
					cancel()
					return
				}
			}
		}
	}()
	return run
}

func (s *vupenSticky) endSearch(run *vupenSearchRun) {
	run.cancel()
	s.searchMu.Lock()
	if s.searchRun == run {
		s.searchRun = nil
	}
	s.searchMu.Unlock()
}

// cancelSearch — сеть сменилась: идущий поиск (если есть) бросить.
func (s *vupenSticky) cancelSearch() {
	s.searchMu.Lock()
	run := s.searchRun
	s.searchMu.Unlock()
	if run != nil {
		run.cancel()
	}
}

// vupenUntil — f в горутине; прервали раньше — ok=false (результат выбрасывается).
func vupenUntil[T any](ctx context.Context, f func() T) (v T, ok bool) {
	ch := make(chan T, 1)
	go func() { ch <- f() }()
	select {
	case v = <-ch:
		return v, true
	case <-ctx.Done():
		return v, false
	}
}

// probeCtx — раунд проб; false — прервали.
func (s *vupenSticky) probeCtx(run *vupenSearchRun, obs vupenStickyObservatory, pool []string) bool {
	if co, ok := obs.(vupenStickyCtxObservatory); ok {
		co.VupenStickyProbeCtx(run.ctx, pool)
	} else {
		vupenUntil(run.ctx, func() struct{} { obs.VupenStickyProbe(pool); return struct{}{} })
	}
	return !run.aborted()
}

// verifyCtx — проверка 64 КБ; ok=false — прервали (итог не годится ни как успех, ни как провал).
func (s *vupenSticky) verifyCtx(run *vupenSearchRun, obs vupenStickyObservatory, tag string) (verdict string, ok bool) {
	if co, isCtx := obs.(vupenStickyCtxObservatory); isCtx {
		verdict = co.VupenStickyVerifyCtx(run.ctx, tag, s.whitelistClassNow)
	} else {
		verdict, _ = vupenUntil(run.ctx, func() string { return obs.VupenStickyVerify(tag) })
	}
	return verdict, !run.aborted()
}

// whitelistClassNow — в текущей эпохе сеть определена как БС.
func (s *vupenSticky) whitelistClassNow() bool {
	class, _ := s.netClassNow()
	return class == vupenNetClassWhitelist
}

// searchAborted — поиск брошен из-за смены сети: новый ставится в очередь (она
// пройдёт через откладывание, пока определяется класс сети).
func (s *vupenSticky) searchAborted(reason, step string, run *vupenSearchRun, started time.Time, checked int) int {
	select {
	case <-s.stopCh:
		return checked
	default:
	}
	errors.LogWarning(s.logCtx(), fmt.Sprintf("[sticky] %s: search aborted: epoch changed (%s; %s; epoch %d → %d, uplink %s, ran %s, %d checked)",
		s.balancer, reason, step, run.epoch, vupenNetEpochNow(), vupenUplinkKind(), time.Since(started).Round(time.Millisecond), checked))
	s.setPhase(vupenPhaseSearching)
	if !s.send(vupenStickyEvent{kind: "search", reason: "restart after network change"}) {
		// Очередь полна: не терять поиск — повтор по графику.
		s.setPhase(vupenPhaseNoWorking)
		s.scheduleRetry(false)
	}
	return checked
}

// ── откладывание событий, пока определяется класс сети ──────────────────────

func vupenDeferrable(kind string) bool {
	switch kind {
	case "search", "retry", "current-excluded", "check":
		return true
	}
	return false
}

// netClassSettling — сотовая сеть только что сменилась, класс ещё не определён.
func (s *vupenSticky) netClassSettling() bool {
	if s.spill == nil {
		return false
	}
	c := &s.netcls
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.settling
}

// deferEvent — true: событие отложено до класса сети.
func (s *vupenSticky) deferEvent(ev vupenStickyEvent) bool {
	if !vupenDeferrable(ev.kind) || !s.netClassSettling() {
		return false
	}
	s.deferred = append(s.deferred, ev)
	errors.LogWarning(s.logCtx(), "[sticky] ", s.balancer, ": ", ev.kind, " (", ev.reason, ") deferred until the network class is known")
	return true
}

// flushDeferred — выполнить отложенное (класс известен или ждать больше нечего).
func (s *vupenSticky) flushDeferred() {
	if len(s.deferred) == 0 || s.netClassSettling() {
		return
	}
	list := s.deferred
	s.deferred = nil
	seen := map[string]bool{}
	for _, ev := range list {
		key := ev.kind
		if key == "retry" || key == "current-excluded" {
			key = "search" // один поиск вместо нескольких
		}
		if seen[key] {
			if ev.kind == "check" {
				s.checkPending.Store(false)
			}
			continue
		}
		seen[key] = true
		s.handle(ev)
	}
}

// ── журнал очереди ──────────────────────────────────────────────────────────

// noteDequeued — журнал ожидания в очереди: обычное событие — Debug (строка на каждое
// событие засоряла журнал), только затянувшееся (>= vupenQueueWaitWarn) — Warning.
func (s *vupenSticky) noteDequeued(ev vupenStickyEvent) {
	if ev.at.IsZero() {
		return
	}
	waited := time.Since(ev.at)
	msg := fmt.Sprintf("[sticky] %s: event %s (%s) waited %s in the queue, epoch %d, uplink %s",
		s.balancer, ev.kind, ev.reason, waited.Round(time.Millisecond), vupenNetEpochNow(), vupenUplinkKind())
	if waited >= vupenQueueWaitWarn {
		errors.LogWarning(s.logCtx(), msg)
		return
	}
	errors.LogDebug(s.logCtx(), msg)
}

// checkCtx — проверка 24 КБ, прерываемая вместе с run; прервана — unknown.
func (s *vupenSticky) checkCtx(run *vupenSearchRun, obs vupenStickyObservatory, tag string) string {
	if co, ok := obs.(vupenStickyCheckCtxObservatory); ok {
		return co.VupenStickyCheckCtx(run.ctx, tag)
	}
	v, ok := vupenUntil(run.ctx, func() string { return obs.VupenStickyCheck(tag) })
	if !ok {
		return vupenStickyUnknown
	}
	return v
}

// checkWithCtx — то же с параметрами (heal); прервана — unknown.
func (s *vupenSticky) checkWithCtx(run *vupenSearchRun, ro vupenStickyRouteObs, tag string, opt burst.VupenCheckOptions) burst.VupenCheckResult {
	if co, ok := ro.(vupenStickyRouteCtxObs); ok {
		return co.VupenStickyCheckWithCtx(run.ctx, tag, opt)
	}
	res, ok := vupenUntil(run.ctx, func() burst.VupenCheckResult { return ro.VupenStickyCheckWith(tag, opt) })
	if !ok {
		return burst.VupenCheckResult{Verdict: vupenStickyUnknown, Detail: "aborted"}
	}
	return res
}

// ── заморозки БС ────────────────────────────────────────────────────────────

// noteWhitelist — запомнить, с какого момента сеть была БС (заморозки с этого момента
// снимаются, когда БС кончится или сеть сменится).
func (s *vupenSticky) noteWhitelist() {
	s.signals.mu.Lock()
	since := s.signals.netChangedAt
	s.signals.mu.Unlock()
	ns := int64(1) // сеть не менялась с запуска: БС была всё время
	if !since.IsZero() {
		ns = since.UnixNano()
	}
	s.whitelistSince.CompareAndSwap(0, ns)
}

// unfreezeWhitelistEra — БС кончилась или сеть сменилась: узлы, замороженные за время
// БС (и поиском, начатым до неё), снова годятся.
//
// Вызывается только из обработчика событий: снимок пула (SelectOutbounds) и обращение к
// обсерватории не должны блокировать колбэк смены сети (см. queueUnfreezeWhitelistEra).
func (s *vupenSticky) unfreezeWhitelistEra(why string) {
	s.unfreezeEraSince(s.whitelistSince.Swap(0), why)
}

// queueUnfreezeWhitelistEra — то же из onNetEvent (горутина VupenSetUplink / таймера, колбэки
// не должны блокироваться): здесь только атомарно забираем отметку эпохи БС и ставим событие
// в очередь, снятие заморозок выполнит обработчик (T-110, CR-104). Очередь полна — отметка
// возвращается (если новой БС за это время не было) и снимется при следующем случае.
// Крайний случай: пока очередь полна, старые заморозки остаются до следующей эры БС или
// смены сети (приемлемо: узлы всё равно перепроверяются, поведение не меняется).
func (s *vupenSticky) queueUnfreezeWhitelistEra(why string) {
	ns := s.whitelistSince.Swap(0)
	if ns == 0 {
		return
	}
	if !s.send(vupenStickyEvent{kind: "unfreeze-era", reason: why, eraSince: ns}) {
		s.whitelistSince.CompareAndSwap(0, ns)
	}
}

func (s *vupenSticky) unfreezeEraSince(ns int64, why string) {
	if ns == 0 {
		return
	}
	obs := s.observatory()
	if obs == nil {
		return
	}
	// T-108, CR-004: только заморозки проверки 64 КБ (она, а не исключения по настоящей
	// причине, ставит frozenAt) и только узлы пула этого балансировщика. Начало эпохи —
	// смена сети, а не момент, когда БС определена: проверки поиска, шедшие во время
	// определения класса, замораживали узлы раньше момента определения.
	var tags []string
	switch u := obs.(type) {
	case vupenStickyScopedUnfreezer:
		cands, err := s.b.SelectOutbounds()
		if err != nil || len(cands) == 0 {
			return
		}
		tags = u.VupenStickyUnfreezeTags(time.Unix(0, ns), cands)
	case vupenStickyUnfreezer:
		tags = u.VupenStickyUnfreezeSince(time.Unix(0, ns))
	}
	if len(tags) > 0 {
		errors.LogWarning(s.logCtx(), "[sticky] ", s.balancer, ": unfroze ", tags, " (frozen during the whitelist era; ", why, ")")
	}
}
