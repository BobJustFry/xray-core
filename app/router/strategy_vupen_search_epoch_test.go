package router

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/observatory/burst"
	"github.com/xtls/xray-core/transport/internet"
)

// Ядро 83 (T-102): смена сети и идущий поиск (лог тестера, iPhone, ядро 82).

// epochObs — обсерватория с прерываемыми пробами и проверками (как настоящая).
type epochObs struct {
	*stickyFakeObs
	mu       sync.Mutex
	block    bool                    // проверка висит, пока не отменят контекст (долгая загрузка 64 КБ в БС)
	after    func(tag string) string // итог проверки (если не block)
	onCheck  func(tag string) string // итог проверки 24 КБ
	started  chan string             // какие проверки 64 КБ начались
	nVerify  int
	unfreeze []time.Time
	// T-108 (CR-002/004): проверки 24 КБ и быстрые пробы, висящие до отмены контекста
	// (или release); пул, для которого запрошено снятие заморозок.
	blockCheck, blockRoute, blockQuick bool
	hung                               chan string // что зависло (check | route | quick)
	release                            chan struct{}
	unfreezeTags                       [][]string
}

func newEpochObs(base *stickyFakeObs) *epochObs {
	return &epochObs{stickyFakeObs: base, started: make(chan string, 32), hung: make(chan string, 32), release: make(chan struct{})}
}

// hang — висеть, пока не отменят контекст (или не откроют release); так выглядит
// загрузка, оборванная сменой сети: «провал».
func (o *epochObs) hang(ctx context.Context, what string) {
	o.hung <- what
	select {
	case <-ctx.Done():
	case <-o.release:
	case <-time.After(10 * time.Second):
	}
}

// oneShot — взвести блокировку один раз (повторная проверка после отмены уже не виснет).
func (o *epochObs) oneShot(flag *bool) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	v := *flag
	*flag = false
	return v
}

func (o *epochObs) closeRelease() {
	select {
	case <-o.release:
	default:
		close(o.release)
	}
}

func (o *epochObs) VupenStickyCheckCtx(ctx context.Context, tag string) string {
	if o.oneShot(&o.blockCheck) {
		o.hang(ctx, "check")
		return vupenStickyFailed
	}
	return o.VupenStickyCheck(tag)
}

func (o *epochObs) VupenStickyCheckWithCtx(ctx context.Context, tag string, opt burst.VupenCheckOptions) burst.VupenCheckResult {
	if o.oneShot(&o.blockRoute) {
		o.hang(ctx, "route")
		return burst.VupenCheckResult{Verdict: vupenStickyFailed, Kind: "error", Detail: "cut"}
	}
	return o.stickyFakeObs.VupenStickyCheckWith(tag, opt)
}

func (o *epochObs) VupenStickyQuickProbeCtx(ctx context.Context, tags []string, timeout time.Duration, deadline time.Time,
	each func(tag string, rtt time.Duration, ok bool) bool) int {
	if o.oneShot(&o.blockQuick) {
		o.hang(ctx, "quick")
		return 0
	}
	return o.stickyFakeObs.VupenStickyQuickProbe(tags, timeout, deadline, each)
}

func (o *epochObs) VupenStickyProbeCtx(ctx context.Context, tags []string) {
	o.stickyFakeObs.VupenStickyProbe(tags)
}

func (o *epochObs) VupenStickyVerifyCtx(ctx context.Context, tag string, hold func() bool) string {
	o.mu.Lock()
	o.nVerify++
	block, after := o.block, o.after
	o.mu.Unlock()
	o.stickyFakeObs.mu.Lock()
	o.stickyFakeObs.verifies = append(o.stickyFakeObs.verifies, tag)
	o.stickyFakeObs.mu.Unlock()
	o.started <- tag
	if block {
		<-ctx.Done()
		return vupenStickyFailed // худший случай: оборванная загрузка выглядит как провал
	}
	if after != nil {
		return after(tag)
	}
	return vupenStickyOK
}

func (o *epochObs) VupenStickyCheck(tag string) string {
	if o.oneShot(&o.blockCheck) { // не прерываемая проверка: висит, пока не откроют release
		o.hang(context.Background(), "check")
		return vupenStickyFailed
	}
	o.mu.Lock()
	f := o.onCheck
	o.mu.Unlock()
	if f != nil {
		return f(tag)
	}
	return o.stickyFakeObs.VupenStickyCheck(tag)
}

func (o *epochObs) VupenStickyUnfreezeTags(since time.Time, tags []string) []string {
	o.mu.Lock()
	o.unfreeze = append(o.unfreeze, since)
	o.unfreezeTags = append(o.unfreezeTags, tags)
	o.mu.Unlock()
	return []string{"p-x"}
}

func (o *epochObs) verifyCount() int { o.mu.Lock(); defer o.mu.Unlock(); return o.nVerify }

func epochRig(t *testing.T) (*spillRig, *ncFake, *epochObs) {
	t.Helper()
	f := installNetClassFake(t)
	f.normal()
	r := newSpillRig(t, []string{"cellular"}, []string{"p-1", "p-2", "p-3"}, []string{"lte-1", "lte-2"})
	eo := newEpochObs(r.obs)
	var so vupenStickyObservatory = eo
	r.reg.obs.Store(&so)
	r.lte.obs.Store(&so)
	r.alive(map[string]int64{"p-1": 10, "p-2": 20, "p-3": 30, "lte-1": 40, "lte-2": 50})
	return r, f, eo
}

// CR-001: проверка идёт в БС и не кончается; сеть сменилась (Wi-Fi → сотовая-БС).
// Поиск брошен сразу, REG больше не проверяется, перелив в LTE — по результату
// определения класса, а не по концу поиска. viaEvent — прервать событием смены сети;
// иначе — только сверкой эпохи самим поиском.
func testSearchAbortsOnEpochChange(t *testing.T, viaEvent bool) {
	old := vupenSearchPoll
	if viaEvent {
		vupenSearchPoll = time.Hour // прерывает только событие
	}
	t.Cleanup(func() { vupenSearchPoll = old })
	r, f, eo := epochRig(t)
	eo.block = true
	r.pick() // старт без initial: определение класса и поиск
	done := make(chan struct{})
	go func() { r.drain(); close(done) }()
	select {
	case <-eo.started:
	case <-time.After(5 * time.Second):
		t.Fatal("the REG verify did not start")
	}
	f.whitelist() // новая сеть — БС
	f.newEpoch()
	changedAt := time.Now()
	if viaEvent {
		r.kind = "cellular"
		r.reg.onNetEvent(internet.VupenNetChanged)
	} else {
		r.reg.netClassOnChanged()
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("the handler is still blocked in the search of the previous network")
	}
	if took := time.Since(changedAt); took > 2*time.Second {
		t.Fatalf("search abort took %s", took)
	}
	if n := eo.verifyCount(); n != 1 {
		t.Fatalf("no more REG verifies after the change, got %d", n)
	}
	if len(r.reg.deferred) != 1 {
		t.Fatalf("the restarted search must wait for the network class: deferred=%v", r.reg.deferred)
	}
	if ncRegExcluded(r) {
		t.Fatalf("the aborted verify must not exclude a node: %v", r.obs.excluded)
	}
	r.ncSettle() // 1.5 с: класс сети — БС → перелив, поиска по REG нет
	if !r.reg.spilledNow() {
		t.Fatal("whitelist → spill to LTE right after the settle")
	}
	if n := eo.verifyCount(); n != 1 {
		t.Fatalf("no REG verify during the whitelist, got %d", n)
	}
	if ncRegExcluded(r) || len(r.reg.deferred) != 0 {
		t.Fatalf("excluded=%v deferred=%v", r.obs.excluded, r.reg.deferred)
	}
}

func TestVupenSearchAbortsOnEpochChangeEvent(t *testing.T) { testSearchAbortsOnEpochChange(t, true) }
func TestVupenSearchAbortsOnEpochChangePoll(t *testing.T)  { testSearchAbortsOnEpochChange(t, false) }

// CR-001/CR-002: эпоха сверяется перед каждой проверкой; итог проверки, начатой в
// прежней сети, не считается ни успехом, ни провалом; после определения класса
// поиск идёт заново (пробы заново).
func TestVupenSearchEpochCheckedBeforeEachVerify(t *testing.T) {
	r, f, eo := epochRig(t)
	first := true
	eo.after = func(tag string) string {
		if first {
			first = false
			f.newEpoch() // сеть сменилась во время первой проверки
			return vupenStickyFailed
		}
		return vupenStickyOK
	}
	r.pick()
	for eo.verifyCount() == 0 {
		select {
		case ev := <-r.reg.events:
			r.reg.handle(ev)
		default:
			t.Fatal("no search was started")
		}
	}
	if n := eo.verifyCount(); n != 1 {
		t.Fatalf("the second verify must not start in the new epoch, got %d verifies", n)
	}
	if len(r.reg.events) == 0 {
		t.Fatal("the aborted search must queue a restart")
	}
	r.reg.stateMu.Lock()
	failed := r.reg.report.failedChecks
	r.reg.stateMu.Unlock()
	if failed != 0 || r.obs.excluded["p-1"] {
		t.Fatalf("a verify that crossed a network change is not a failure: failedChecks=%d excluded=%v", failed, r.obs.excluded)
	}
	r.obs.mu.Lock()
	probesBefore := len(r.obs.probes)
	r.obs.mu.Unlock()
	r.reg.netClassOnChanged()
	r.ncSettle()
	r.drain()
	r.obs.mu.Lock()
	probesAfter := len(r.obs.probes)
	r.obs.mu.Unlock()
	if probesAfter <= probesBefore {
		t.Fatalf("the restarted search must probe again (alive list of the previous network is stale): %d → %d", probesBefore, probesAfter)
	}
	if got := r.reg.getPhase(); got != vupenPhaseHolding {
		t.Fatalf("phase %v, want holding after the restarted search", got)
	}
}

// CR-003: 24 КБ провалилась, но сеть сменилась за время проверки — узел не исключается
// на 15 минут; проверка повторяется и проходит.
func TestVupenCheckFailedAcrossNetworkChangeDoesNotExclude(t *testing.T) {
	r, f, eo := epochRig(t)
	r.reg.initial = "p-1"
	n := 0
	eo.onCheck = func(tag string) string {
		n++
		if n == 1 {
			f.newEpoch()
			return vupenStickyFailed
		}
		return vupenStickyOK
	}
	r.pick()
	r.drain()
	if r.obs.excluded["p-1"] {
		t.Fatal("a check failed in another epoch must not exclude the node")
	}
	if n != 2 || r.reg.getPhase() != vupenPhaseHolding {
		t.Fatalf("checks=%d phase=%v, want 2 checks and holding", n, r.reg.getPhase())
	}
}

// CR-003: заморозки БС снимаются — при смене сети и при конце БС; без БС ничего не снимается.
func TestVupenWhitelistEraUnfreezes(t *testing.T) {
	r, f, eo := epochRig(t)
	r.reg.onNetEvent(internet.VupenNetChanged)
	if len(eo.unfreeze) != 0 {
		t.Fatalf("no whitelist era → nothing to unfreeze: %v", eo.unfreeze)
	}
	f.whitelist()
	r.pick()
	r.drain()
	if !r.reg.spilledNow() || r.reg.whitelistSince.Load() == 0 {
		t.Fatalf("whitelist spill expected, since=%d", r.reg.whitelistSince.Load())
	}
	// Конец БС (иностранные снова отвечают).
	f.normal()
	if !r.reg.whitelistEnded("test") {
		t.Fatal("whitelistEnded")
	}
	if len(eo.unfreeze) != 1 {
		t.Fatalf("unfreeze at the end of the whitelist: %v since=%d", eo.unfreeze, r.reg.whitelistSince.Load())
	}
	// Возврат в Wi-Fi / другая сеть: событие смены тоже снимает.
	f.whitelist()
	r.reg.netcls.mu.Lock()
	r.reg.netcls.class = ""
	r.reg.netcls.mu.Unlock()
	r.reg.spillWhitelist("test")
	if r.reg.whitelistSince.Load() == 0 {
		t.Fatal("whitelist era not noted")
	}
	r.reg.onNetEvent(internet.VupenNetChanged)
	r.drain() // T-110 (CR-104): снимает обработчик событий, не колбэк
	if len(eo.unfreeze) != 2 || r.reg.whitelistSince.Load() != 0 {
		t.Fatalf("unfreeze at the network change: %v", eo.unfreeze)
	}
}

// Журнал: очередь считает отброшенные события.
func TestVupenStickyCountsDroppedEvents(t *testing.T) {
	r := newStickyRig(t, "p-1", "p-1", "p-1", "p-2")
	for i := 0; i < cap(r.s.events)+5; i++ {
		r.s.send(vupenStickyEvent{kind: "retry", reason: "fill"})
	}
	if got := r.s.dropped.Load(); got < 5 {
		t.Fatalf("dropped %d, want >= 5", got)
	}
	ev := <-r.s.events
	if ev.at.IsZero() {
		t.Fatal("events must carry the queue time")
	}
}

// CR-001 (T-105): ожидание класса сети оборвано возвратом в Wi-Fi (netClassOnChanged без
// нового ожидания), других событий нет — отложенные проверка и поиск всё равно
// выполняются, checkPending сбрасывается.
func TestVupenDeferredEventsRunWhenSettleCancelled(t *testing.T) {
	r, f, eo := epochRig(t)
	r.pick()
	r.drain()
	if got := r.reg.getPhase(); got != vupenPhaseHolding {
		t.Fatalf("phase %v, want holding before the network change", got)
	}
	// Ушли с базового Wi-Fi в сотовую: идёт ожидание класса сети.
	f.newEpoch()
	r.kind = "cellular"
	r.reg.netClassOnChanged()
	if !r.reg.netClassSettling() {
		t.Fatal("cellular change must start the settle wait")
	}
	// За время ожидания: проверка и перезапуск поиска откладываются.
	if !r.reg.requestCheck("test") {
		t.Fatal("requestCheck refused")
	}
	if !r.reg.send(vupenStickyEvent{kind: "search", reason: "restart after network change"}) {
		t.Fatal("search event not queued")
	}
	r.drain()
	if len(r.reg.deferred) != 2 || !r.reg.checkPending.Load() {
		t.Fatalf("check and search must be deferred: deferred=%v checkPending=%v", r.reg.deferred, r.reg.checkPending.Load())
	}
	checksBefore, verifiesBefore := len(r.obs.checks), eo.verifyCount()
	// Вернулись в базовый Wi-Fi: «моргание» без VupenNetStable, перелива нет, событий больше нет.
	f.newEpoch()
	r.kind = "wifi"
	r.reg.netClassOnChanged()
	r.drain()
	if n := len(r.reg.deferred); n != 0 {
		t.Fatalf("deferred events stuck after the settle was cancelled: %v", r.reg.deferred)
	}
	if r.reg.checkPending.Load() {
		t.Fatal("checkPending stuck: requestCheck would refuse every signal")
	}
	if len(r.obs.checks) <= checksBefore {
		t.Fatal("the deferred check did not run")
	}
	if eo.verifyCount() <= verifiesBefore {
		t.Fatal("the deferred search did not run")
	}
	if got := r.reg.getPhase(); got != vupenPhaseHolding {
		t.Fatalf("phase %v, want holding after the deferred search", got)
	}
	if !r.reg.requestCheck("after") {
		t.Fatal("requestCheck must accept signals again")
	}
	r.drain()
}

// CR-003 (T-105): повторная проверка «сеть сменилась во время проверки» держит
// checkPending (новая проверка от сигнала не ставится, пока она в очереди) и сбрасывает
// его после своего выполнения.
func TestVupenCheckRequeueKeepsPending(t *testing.T) {
	r, f, eo := epochRig(t)
	r.reg.initial = "p-1"
	n := 0
	eo.onCheck = func(tag string) string {
		n++
		if n == 1 {
			f.newEpoch()
			return vupenStickyFailed
		}
		return vupenStickyOK
	}
	r.pick() // старт: проверка initial поставлена в очередь
	for i := 0; i < 10 && n == 0; i++ {
		select {
		case ev := <-r.reg.events:
			r.reg.handle(ev)
		default:
		}
	}
	if n != 1 {
		t.Fatalf("first check not run: %d", n)
	}
	if len(r.reg.events) == 0 {
		t.Fatal("the re-check must be queued")
	}
	if r.reg.requestCheck("duplicate") {
		t.Fatal("a signal check must not be queued while the re-check is pending")
	}
	r.drain()
	if n != 2 || r.reg.checkPending.Load() || r.reg.getPhase() != vupenPhaseHolding {
		t.Fatalf("checks=%d pending=%v phase=%v", n, r.reg.checkPending.Load(), r.reg.getPhase())
	}
}
