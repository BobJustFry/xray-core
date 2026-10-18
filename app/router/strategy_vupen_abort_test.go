package router

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/transport/internet"
)

// Ядро 83 (T-108): остаток замечаний ревью T-104 (CR-002, CR-004, CR-006).

func waitHung(t *testing.T, eo *epochObs, what string) {
	t.Helper()
	select {
	case got := <-eo.hung:
		if got != what {
			t.Fatalf("hung %q, want %q", got, what)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("%s did not start", what)
	}
}

// CR-002: проверка 24 КБ текущего узла (до 6 с, с запасным файлом дольше) бросается при
// смене сети, как поиск: обработчик свободен, оборванная загрузка не исключает узел, проверка
// ставится заново (checkPending держится).
func testCheckCurrentAborts(t *testing.T, viaEvent bool) {
	old := vupenSearchPoll
	if viaEvent {
		vupenSearchPoll = time.Hour // прерывает только событие смены сети
	}
	t.Cleanup(func() { vupenSearchPoll = old })
	r, f, eo := epochRig(t)
	t.Cleanup(eo.closeRelease)
	r.reg.initial = "p-1"
	eo.blockCheck = true
	r.pick() // старт: проверка initial в очереди
	done := make(chan struct{})
	go func() { r.drain(); close(done) }()
	waitHung(t, eo, "check")
	f.newEpoch() // сеть сменилась во время загрузки 24 КБ
	changedAt := time.Now()
	if viaEvent {
		r.kind = "cellular"
		r.reg.onNetEvent(internet.VupenNetChanged)
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("the handler is still blocked in the 24 KB check of the previous network")
	}
	if took := time.Since(changedAt); took > 2*time.Second {
		t.Fatalf("check abort took %s", took)
	}
	if len(r.obs.excluded) != 0 {
		t.Fatalf("an aborted check must not exclude a node: %v", r.obs.excluded)
	}
	// Брошенная проверка поставлена заново (сразу или после определения класса сети) и
	// выполнена; отменённая загрузка в счётчик завершённых проверок не попадает.
	r.reg.netClassOnChanged()
	r.ncSettle()
	r.drain()
	if n := r.obs.checkCount(); n != 1 {
		t.Fatalf("the aborted check must be re-queued and run again, completed checks=%d", n)
	}
	if r.reg.checkPending.Load() || len(r.obs.excluded) != 0 {
		t.Fatalf("after the re-check: pending=%v excluded=%v", r.reg.checkPending.Load(), r.obs.excluded)
	}
	if st := r.reg.getPhase(); st != vupenPhaseHolding {
		t.Fatalf("phase %v, want holding (node kept)", st)
	}
}

func TestVupenCheckCurrentAbortsOnEpochPoll(t *testing.T)  { testCheckCurrentAborts(t, false) }
func TestVupenCheckCurrentAbortsOnEpochEvent(t *testing.T) { testCheckCurrentAborts(t, true) }

// CR-002: heal — проверка текущего бросается при смене сети: Unknown, узел не исключён,
// соединения не закрыты, проверка поставлена заново.
func TestVupenHealCheckAbortsOnEpochChange(t *testing.T) {
	r, f, eo := epochRig(t)
	t.Cleanup(eo.closeRelease)
	r.pick()
	r.drain()
	if r.reg.getPhase() != vupenPhaseHolding {
		t.Fatalf("phase %v", r.reg.getPhase())
	}
	eo.blockRoute = true
	h := &vupenHealReq{q: vupenRouteReq{V: 1, Mode: vupenRouteHealMode, Reason: "foreground"}, reply: make(chan vupenRouteResp, 1)}
	got := make(chan vupenRouteResp, 1)
	go func() { got <- r.reg.healRoute(h) }()
	waitHung(t, eo, "route")
	f.newEpoch()
	select {
	case resp := <-got:
		if resp.Verdict != vupenRouteUnknown || resp.Closed != 0 {
			t.Fatalf("aborted heal: %+v", resp)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("heal is still blocked in the check of the previous network")
	}
	r.obs.mu.Lock()
	excl, closed := len(r.obs.excludedFor), len(r.obs.closedTags)
	r.obs.mu.Unlock()
	if excl != 0 || closed != 0 || len(r.obs.excluded) != 0 {
		t.Fatalf("an aborted heal must not exclude or close: excludedFor=%d closed=%d excluded=%v", excl, closed, r.obs.excluded)
	}
	if !r.reg.checkPending.Load() || len(r.reg.events)+len(r.reg.deferred) == 0 {
		t.Fatal("the aborted heal check must be re-queued")
	}
}

// CR-002: switch (до 12 с) бросается при смене сети: быстрые пробы и проверки 64 КБ
// прерываются, итог Unknown, ничего не исключено, поиск ставится заново.
//
// T-110 (CR-101): был рабочий prev — он остаётся (фаза Holding, выдача не уходит на запасной),
// проверка ставится заново; не было (noWorking) — прежнее поведение: Searching и поиск заново.
func testSwitchAborts(t *testing.T, stage string, noWorking bool) {
	r, f, eo := epochRig(t)
	t.Cleanup(eo.closeRelease)
	r.pick()
	r.drain()
	if r.reg.getPhase() != vupenPhaseHolding {
		t.Fatalf("phase %v", r.reg.getPhase())
	}
	prev := r.pick()
	if noWorking {
		r.reg.setPhase(vupenPhaseNoWorking) // рабочих не было и до запроса: prev == ""
	}
	for len(eo.started) > 0 { // проверки установочного поиска
		<-eo.started
	}
	if stage == "quick" {
		eo.blockQuick = true // замеров нет: быстрые пробы висят
	} else {
		eo.block = true // проверка 64 КБ висит до отмены
		r.obs.mu.Lock()
		r.obs.recent = map[string]time.Duration{"p-1": 10 * time.Millisecond, "p-2": 20 * time.Millisecond, "p-3": 30 * time.Millisecond}
		r.obs.recentAge = map[string]time.Duration{}
		r.obs.mu.Unlock()
	}
	h := &vupenHealReq{q: vupenRouteReq{V: 1, Mode: vupenRouteSwitchMode, Reason: "manual"}, reply: make(chan vupenRouteResp, 1)}
	got := make(chan vupenRouteResp, 1)
	go func() { got <- r.reg.switchRoute(h) }()
	if stage == "quick" {
		waitHung(t, eo, "quick")
	} else {
		select {
		case <-eo.started:
		case <-time.After(5 * time.Second):
			t.Fatal("the verify did not start")
		}
	}
	f.newEpoch()
	select {
	case resp := <-got:
		if resp.Verdict != vupenRouteUnknown {
			t.Fatalf("aborted switch: %+v", resp)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("switch is still blocked in the search of the previous network")
	}
	if len(r.obs.excluded) != 0 {
		t.Fatalf("nothing is excluded: %v", r.obs.excluded)
	}
	if len(r.reg.visited) != 0 {
		t.Fatalf("an aborted switch leaves the visited list alone: %v", r.reg.visited)
	}
	if len(r.reg.events)+len(r.reg.deferred) == 0 {
		t.Fatal("the search must be re-queued")
	}
	queued := func(kind string) bool {
		for _, ev := range append(append([]vupenStickyEvent(nil), r.reg.deferred...), drainEvents(r.reg)...) {
			if ev.kind == kind {
				return true
			}
		}
		return false
	}
	if noWorking {
		if ph := r.reg.getPhase(); ph != vupenPhaseSearching {
			t.Fatalf("no working node before the switch: phase %v, want searching", ph)
		}
		if !queued("search") {
			t.Fatal("no working node: the search must be re-queued")
		}
		return
	}
	if ph := r.reg.getPhase(); ph != vupenPhaseHolding {
		t.Fatalf("an aborted switch with a working node: phase %v, want holding", ph)
	}
	if got := r.pick(); got != prev {
		t.Fatalf("the published route moved to %q, want the working %q", got, prev)
	}
	if !r.reg.checkPending.Load() || !queued("check") {
		t.Fatal("a re-check of the kept node must be queued")
	}
}

// drainEvents — забрать события из очереди, не выполняя их.
func drainEvents(s *vupenSticky) []vupenStickyEvent {
	var out []vupenStickyEvent
	for {
		select {
		case ev := <-s.events:
			out = append(out, ev)
		default:
			return out
		}
	}
}

func TestVupenSwitchAbortsInQuickProbe(t *testing.T) { testSwitchAborts(t, "quick", false) }
func TestVupenSwitchAbortsInVerify(t *testing.T)     { testSwitchAborts(t, "verify", false) }
func TestVupenSwitchAbortsWithoutWorkingNode(t *testing.T) {
	testSwitchAborts(t, "quick", true)
	testSwitchAborts(t, "verify", true)
}

// CR-004: конец БС снимает заморозки только узлов пула этого балансировщика (LTE-узлы,
// замороженные за время БС по настоящей причине, остаются).
func TestVupenWhitelistEraUnfreezeIsScopedToThePool(t *testing.T) {
	r, f, eo := epochRig(t)
	f.whitelist()
	r.pick()
	r.drain()
	f.normal()
	if !r.reg.whitelistEnded("test") {
		t.Fatal("whitelistEnded")
	}
	if len(eo.unfreezeTags) != 1 {
		t.Fatalf("unfreeze calls: %v", eo.unfreezeTags)
	}
	if got := strings.Join(eo.unfreezeTags[0], ","); got != "p-1,p-2,p-3" {
		t.Fatalf("unfreeze scope %q, want the REG pool only (no LTE nodes)", got)
	}
}

type logCapture struct {
	mu   sync.Mutex
	msgs []string
}

func (c *logCapture) Handle(m log.Message) {
	c.mu.Lock()
	c.msgs = append(c.msgs, m.String())
	c.mu.Unlock()
}

func captureLog(t *testing.T) *logCapture {
	t.Helper()
	c := &logCapture{}
	log.RegisterHandler(c)
	t.Cleanup(func() { log.RegisterHandler(log.NewLogger(log.CreateStdoutLogWriter())) })
	return c
}

func (c *logCapture) lines(contains string) []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []string
	for _, m := range c.msgs {
		if strings.Contains(m, contains) {
			out = append(out, m)
		}
	}
	return out
}

// CR-006: ожидание в очереди — не Warning; Warning только у затянувшегося (аномалия).
func TestVupenQueueWaitLogLevel(t *testing.T) {
	c := captureLog(t)
	r := newStickyRig(t, "p-1", "p-1", "p-1", "p-2")
	r.s.noteDequeued(vupenStickyEvent{kind: "check", reason: "fresh", at: time.Now()})
	for _, m := range c.lines("waited") {
		if strings.Contains(m, "[Warning]") {
			t.Fatalf("an ordinary queue wait must not be a Warning: %s", m)
		}
	}
	r.s.noteDequeued(vupenStickyEvent{kind: "check", reason: "stuck", at: time.Now().Add(-5 * time.Second)})
	warn := 0
	for _, m := range c.lines("waited") {
		if strings.Contains(m, "[Warning]") && strings.Contains(m, "stuck") {
			warn++
		}
	}
	if warn != 1 {
		t.Fatalf("a wait of 5 s is an anomaly and must be a Warning: %v", c.lines("waited"))
	}
}

// CR-006: удачный поиск — одна итоговая строка (не две).
func TestVupenSuccessfulSearchLogsOneSummaryLine(t *testing.T) {
	c := captureLog(t)
	r, _, _ := epochRig(t)
	r.pick()
	r.drain()
	if r.reg.getPhase() != vupenPhaseHolding {
		t.Fatalf("phase %v", r.reg.getPhase())
	}
	if n := len(c.lines("search end")); n != 0 {
		t.Fatalf("no separate 'search end' line: %v", c.lines("search end"))
	}
	sum := c.lines("verified → switch")
	if len(sum) != 1 {
		t.Fatalf("a successful search logs one summary line, got %d: %v", len(sum), sum)
	}
	if !strings.Contains(sum[0], "epoch") || !strings.Contains(sum[0], "ran ") {
		t.Fatalf("the summary line keeps the epoch and duration: %s", sum[0])
	}
}

// T-110 (CR-103): лёгкая проверка обычных при переливе (24 КБ, до ~6 с) бросается при смене
// сети: обработчик свободен, итог из прежней сети ни возврат, ни исключение; перелив остался,
// повтор по графику стоит, следующая проверка уже в новой сети возвращает в REG.
func TestVupenLteRecheckAbortsOnEpochChange(t *testing.T) {
	f := installNetClassFake(t)
	f.normal()
	r := newSpillRig(t, []string{"cellular"}, []string{"p-1", "p-2", "p-3", "p-4", "p-5"}, []string{"lte-1", "lte-2"})
	eo := newEpochObs(r.obs)
	t.Cleanup(eo.closeRelease)
	eo.after = r.obs.VupenStickyVerify // исходы проверок 64 КБ — по таблице regDeadLteAlive
	var so vupenStickyObservatory = eo
	r.reg.obs.Store(&so)
	r.lte.obs.Store(&so)
	regDeadLteAlive(r)
	r.reg.current = "p-4" // последний рабочий
	r.pick()
	r.drain()
	r.pick()
	r.drain()
	if !r.reg.spilledNow() {
		t.Fatal("setup: spilled")
	}
	r.obs.mu.Lock()
	r.obs.check["p-4"] = vupenStickyOK
	r.obs.delay["p-4"] = 5
	r.obs.mu.Unlock()
	eo.blockCheck = true
	r.clock.Advance(VupenLteRegularRecheck)
	done := make(chan struct{})
	go func() { r.drain(); close(done) }()
	waitHung(t, eo, "check")
	f.newEpoch() // сеть сменилась во время проверки 24 КБ
	changedAt := time.Now()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("the handler is still blocked in the 24 KB recheck of the previous network")
	}
	if took := time.Since(changedAt); took > 2*time.Second {
		t.Fatalf("recheck abort took %s", took)
	}
	if !r.reg.spilledNow() {
		t.Fatal("an aborted recheck must neither return to REG nor unspill")
	}
	if r.obs.excluded["p-4"] {
		t.Fatalf("an aborted recheck must not exclude the node: %v", r.obs.excluded)
	}
	// Повтор по графику стоит и в новой сети (проверка проходит) возвращает в REG.
	r.clock.Advance(VupenLteRegularRecheck)
	r.drain()
	if r.reg.spilledNow() {
		t.Fatalf("the next recheck is rescheduled and returns to REG: %+v", r.reg.state())
	}
}

// T-110 (CR-104): смена сети (колбэк VupenSetUplink / таймера) не берёт снимок пула и не
// ходит в обсерватории: снятие заморозок эпохи БС выполняет обработчик событий.
func TestVupenWhitelistEraUnfreezeRunsOnTheLoop(t *testing.T) {
	r, f, eo := epochRig(t)
	f.whitelist()
	r.pick()
	r.drain()
	if r.reg.whitelistSince.Load() == 0 {
		t.Fatal("whitelist era not noted")
	}
	r.reg.onNetEvent(internet.VupenNetChanged)
	eo.mu.Lock()
	n := len(eo.unfreeze)
	eo.mu.Unlock()
	if n != 0 {
		t.Fatalf("the notifier callback must not unfreeze (pool snapshot + observatory call): %d calls", n)
	}
	if r.reg.whitelistSince.Load() != 0 {
		t.Fatal("the era mark is taken atomically in the callback")
	}
	r.drain()
	eo.mu.Lock()
	tags := eo.unfreezeTags
	eo.mu.Unlock()
	if len(tags) != 1 || strings.Join(tags[0], ",") != "p-1,p-2,p-3" {
		t.Fatalf("the loop must unfreeze the REG pool once: %v", tags)
	}
}

// T-110 (CR-104): очередь полна — отметка эры БС не теряется (снимется при конце БС или при следующей смене сети — отметку забирает тот, кто успел первым).
func TestVupenWhitelistEraUnfreezeKeptWhenQueueFull(t *testing.T) {
	r, f, eo := epochRig(t)
	f.whitelist()
	r.pick()
	r.drain()
	since := r.reg.whitelistSince.Load()
	if since == 0 {
		t.Fatal("whitelist era not noted")
	}
	for r.reg.send(vupenStickyEvent{kind: "wake"}) {
	}
	r.reg.queueUnfreezeWhitelistEra("network changed")
	if got := r.reg.whitelistSince.Load(); got != since {
		t.Fatalf("era mark %d after a dropped event, want %d kept", got, since)
	}
	r.drain()
	eo.mu.Lock()
	n := len(eo.unfreeze)
	eo.mu.Unlock()
	if n != 0 {
		t.Fatalf("nothing queued, nothing unfrozen: %d", n)
	}
}
