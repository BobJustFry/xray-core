package router

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/observatory"
	"github.com/xtls/xray-core/app/observatory/burst"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/transport/internet"

	"google.golang.org/protobuf/proto"
)

// ── fakes ───────────────────────────────────────────────────────────────────

type stickyFakeOhm struct {
	outbound.Manager
	tags []string
}

func (m *stickyFakeOhm) Select(selectors []string) []string     { return append([]string(nil), m.tags...) }
func (m *stickyFakeOhm) GetHandler(tag string) outbound.Handler { return nil }

type stickyFakeObs struct {
	mu       sync.Mutex
	delay    map[string]int64 // alive nodes and their delay; absent = not alive
	check    map[string]string
	verify   map[string]string
	network  string
	asleep   bool
	excluded map[string]bool
	probes   [][]string
	checks   []string
	verifies []string
	listener func(tag, kind string, ok bool, detail string)
	// Ядро 78 (VupenCheckRoute): итоги проверки с параметрами, исключения на срок, закрытия.
	route       map[string]burst.VupenCheckResult
	routeChecks []string
	routeOpts   []burst.VupenCheckOptions
	excludedFor map[string]time.Duration
	closedTags  []string
}

func (f *stickyFakeObs) VupenStickyListen(fn func(tag, kind string, ok bool, detail string)) func() {
	f.mu.Lock()
	f.listener = fn
	f.mu.Unlock()
	return func() {
		f.mu.Lock()
		f.listener = nil
		f.mu.Unlock()
	}
}

// emit — признак от «обсерватории» (как из горутины соединения).
func (f *stickyFakeObs) emit(tag, kind string, ok bool) {
	f.mu.Lock()
	fn := f.listener
	f.mu.Unlock()
	if fn != nil {
		fn(tag, kind, ok, "test")
	}
}

func (f *stickyFakeObs) checkCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.checks)
}

func newStickyFakeObs() *stickyFakeObs {
	return &stickyFakeObs{delay: map[string]int64{}, check: map[string]string{}, verify: map[string]string{},
		network: vupenNetUp, excluded: map[string]bool{}}
}

func (f *stickyFakeObs) GetObservation(ctx context.Context) (proto.Message, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r := &observatory.ObservationResult{}
	for tag, d := range f.delay {
		r.Status = append(r.Status, &observatory.OutboundStatus{OutboundTag: tag, Alive: !f.excluded[tag], Delay: d})
	}
	return r, nil
}
func (f *stickyFakeObs) VupenStickyProbe(tags []string) {
	f.mu.Lock()
	f.probes = append(f.probes, append([]string(nil), tags...))
	f.mu.Unlock()
}
func (f *stickyFakeObs) VupenStickyVerify(tag string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.verifies = append(f.verifies, tag)
	v := f.verify[tag]
	if v == "" {
		v = vupenStickyFailed
	}
	if v == vupenStickyFailed {
		f.excluded[tag] = true
	}
	return v
}
func (f *stickyFakeObs) VupenStickyCheck(tag string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.checks = append(f.checks, tag)
	if v := f.check[tag]; v != "" {
		return v
	}
	return vupenStickyOK
}
func (f *stickyFakeObs) VupenStickyNetwork() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.network
}
func (f *stickyFakeObs) VupenStickyExcluded(tag string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.excluded[tag]
}
func (f *stickyFakeObs) VupenStickyExclude(tag, reason string) {
	f.mu.Lock()
	f.excluded[tag] = true
	f.mu.Unlock()
}
func (f *stickyFakeObs) VupenStickyAsleep() bool { f.mu.Lock(); defer f.mu.Unlock(); return f.asleep }

type stickyTimer struct {
	at      time.Time
	f       func()
	stopped bool
	fired   bool
}

type stickyClock struct {
	mu     sync.Mutex
	now    time.Time
	timers []*stickyTimer
}

func (c *stickyClock) After(d time.Duration, f func()) func() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := &stickyTimer{at: c.now.Add(d), f: f}
	c.timers = append(c.timers, t)
	return func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		if t.fired || t.stopped {
			return false
		}
		t.stopped = true
		return true
	}
}

func (c *stickyClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	var due []*stickyTimer
	for _, t := range c.timers {
		if !t.fired && !t.stopped && !t.at.After(c.now) {
			t.fired = true
			due = append(due, t)
		}
	}
	c.mu.Unlock()
	for _, t := range due {
		t.f()
	}
}

// pendingIn — длительности живых таймеров от «сейчас».
func (c *stickyClock) pendingIn() []time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	var p []time.Duration
	for _, t := range c.timers {
		if !t.fired && !t.stopped {
			p = append(p, t.at.Sub(c.now))
		}
	}
	return p
}

type stickyRig struct {
	t     *testing.T
	s     *vupenSticky
	b     *Balancer
	obs   *stickyFakeObs
	clock *stickyClock
}

// newStickyRig — балансировщик REG с vupenSticky над узлами tags; события
// разбирает тест (drain), таймеры — фальшивые часы.
func newStickyRig(t *testing.T, initial, fallback string, tags ...string) *stickyRig {
	t.Helper()
	clock := &stickyClock{now: time.Unix(1_800_000_000, 0)}
	old, oldNow := vupenStickyAfter, vupenStickyNow
	vupenStickyAfter = clock.After
	vupenStickyNow = func() time.Time {
		clock.mu.Lock()
		defer clock.mu.Unlock()
		return clock.now
	}
	t.Cleanup(func() { vupenStickyAfter, vupenStickyNow = old, oldNow })
	b := &Balancer{selectors: []string{"p"}, strategy: &LeastPingStrategy{}, ohm: &stickyFakeOhm{tags: tags}, fallbackTag: fallback}
	s := newVupenSticky(&BalancingRule{Tag: "REG", VupenSticky: &VupenSticky{Initial: initial}}, b)
	b.vupen = s
	obs := newStickyFakeObs()
	var so vupenStickyObservatory = obs
	s.obs.Store(&so)
	s.runWorker = func() {}
	t.Cleanup(s.stop)
	return &stickyRig{t: t, s: s, b: b, obs: obs, clock: clock}
}

func (r *stickyRig) pick() string {
	r.t.Helper()
	tag, err := r.b.PickOutbound()
	if err != nil {
		r.t.Fatal(err)
	}
	return tag
}

// drain — разобрать все события в очереди (как горутина обработчика).
func (r *stickyRig) drain() {
	for {
		select {
		case ev := <-r.s.events:
			r.s.handle(ev)
		default:
			return
		}
	}
}

func (r *stickyRig) alive(delays map[string]int64) {
	r.obs.mu.Lock()
	r.obs.delay = delays
	r.obs.mu.Unlock()
}

func (r *stickyRig) expectPhase(p vupenStickyPhase) {
	r.t.Helper()
	if got := r.s.getPhase(); got != p {
		r.t.Fatalf("phase %v, want %v", got, p)
	}
}

// ── tests ───────────────────────────────────────────────────────────────────

// Старт: пока идёт проверка initial — трафик в initial; прошла — держим его, даже
// если по замерам другой узел быстрее, и не ищем ни по сети, ни по таймерам.
func TestVupenStickyHoldsSlowButWorkingNode(t *testing.T) {
	r := newStickyRig(t, "p-slow", "p-slow", "p-fast", "p-slow")
	r.alive(map[string]int64{"p-fast": 10, "p-slow": 900})
	if got := r.pick(); got != "p-slow" {
		t.Fatalf("while checking initial: %q", got)
	}
	r.expectPhase(vupenPhaseChecking)
	r.drain()
	r.expectPhase(vupenPhaseHolding)
	r.s.send(vupenStickyEvent{kind: "net-stable"})
	r.s.send(vupenStickyEvent{kind: "retry"})
	r.drain()
	r.clock.Advance(time.Hour)
	r.drain()
	for i := 0; i < 50; i++ {
		if got := r.pick(); got != "p-slow" {
			t.Fatalf("pick %d: %q, the working slow node must be kept", i, got)
		}
	}
	if len(r.obs.probes) != 0 || len(r.obs.verifies) != 0 {
		t.Fatalf("no probing while the current node works: probes=%v verifies=%v", r.obs.probes, r.obs.verifies)
	}
	if !slices.Equal(r.obs.checks, []string{"p-slow"}) {
		t.Fatalf("one 24 KB check of initial expected, got %v", r.obs.checks)
	}
}

// initial не прошёл 24 КБ, сеть есть → исключён, поиск по остальным; переход
// только на узел, прошедший 64 КБ.
func TestVupenStickyInitialFailedNetworkUpSearches(t *testing.T) {
	r := newStickyRig(t, "p-1", "p-1", "p-1", "p-2", "p-3", "p-4")
	r.alive(map[string]int64{"p-1": 50, "p-2": 20, "p-3": 30, "p-4": 40})
	r.obs.check["p-1"] = vupenStickyFailed
	r.obs.verify["p-2"] = vupenStickyFailed
	r.obs.verify["p-3"] = vupenStickyOK
	r.pick()
	r.drain()
	if !r.obs.excluded["p-1"] {
		t.Fatal("failed initial must be excluded")
	}
	if len(r.obs.probes) != 1 || slices.Contains(r.obs.probes[0], "p-1") {
		t.Fatalf("one probe round without the excluded node: %v", r.obs.probes)
	}
	if !slices.Equal(r.obs.verifies, []string{"p-2", "p-3"}) {
		t.Fatalf("verification in strategy order until the first pass: %v", r.obs.verifies)
	}
	r.expectPhase(vupenPhaseHolding)
	if got := r.pick(); got != "p-3" {
		t.Fatalf("pick %q, want the verified p-3", got)
	}
}

// Провал проверки без сети у устройства (или с неизвестным состоянием сети) —
// узел не меняется и не исключается; «не поняли» — тоже.
func TestVupenStickyKeepsNodeWithoutNetworkOrOnInconclusiveCheck(t *testing.T) {
	for _, c := range []struct{ check, network string }{
		{vupenStickyFailed, vupenNetDown},
		{vupenStickyFailed, "unknown"},
		{"unknown", vupenNetUp},
	} {
		r := newStickyRig(t, "p-1", "p-1", "p-1", "p-2")
		r.alive(map[string]int64{"p-1": 50, "p-2": 20})
		r.obs.check["p-1"] = c.check
		r.obs.network = c.network
		r.pick()
		r.drain()
		r.expectPhase(vupenPhaseHolding)
		if got := r.pick(); got != "p-1" || r.obs.excluded["p-1"] || len(r.obs.probes) != 0 {
			t.Fatalf("%+v: pick=%q excluded=%v probes=%v", c, got, r.obs.excluded["p-1"], r.obs.probes)
		}
	}
}

// Нет initial / тег не из пула → сразу поиск; до его конца — fallbackTag.
func TestVupenStickyNoOrUnknownInitialSearchesAtOnce(t *testing.T) {
	for _, initial := range []string{"", "proxy-gone"} {
		r := newStickyRig(t, initial, "p-2", "p-1", "p-2")
		r.alive(map[string]int64{"p-1": 10, "p-2": 20})
		r.obs.verify["p-1"] = vupenStickyOK
		if got := r.pick(); got != "p-2" {
			t.Fatalf("initial %q: before the search ends traffic goes to fallbackTag, got %q", initial, got)
		}
		r.expectPhase(vupenPhaseSearching)
		r.drain()
		if len(r.obs.checks) != 0 {
			t.Fatalf("initial %q: no 24 KB check without a valid initial: %v", initial, r.obs.checks)
		}
		if got := r.pick(); got != "p-1" {
			t.Fatalf("initial %q: after the search %q, want p-1", initial, got)
		}
	}
}

// Пока узел не подтверждён: fallbackTag, если он не тот, что отказал; иначе
// временный кандидат — первый неисключённый в порядке стратегии. Пустым не бывает.
func TestVupenStickyProvisionalWhileNotConfirmed(t *testing.T) {
	r := newStickyRig(t, "p-1", "p-1", "p-1", "p-2", "p-3")
	r.alive(map[string]int64{"p-1": 5, "p-2": 30, "p-3": 20})
	r.obs.check["p-1"] = vupenStickyFailed
	r.pick()
	// Обработчик исключит p-1 и начнёт поиск: смотрим, что публикуется в ходе.
	var during string
	r.obs.mu.Lock()
	r.obs.verify["p-3"] = "unknown" // «не поняли» — не исключён
	r.obs.verify["p-2"] = vupenStickyFailed
	r.obs.mu.Unlock()
	r.drain()
	during = r.pick()
	if during != "p-3" {
		t.Fatalf("fallbackTag p-1 failed: want the first non-excluded node in strategy order (p-3), got %q", during)
	}
	r.expectPhase(vupenPhaseNoWorking)
	// Все исключены — всё равно не пусто.
	r.obs.mu.Lock()
	r.obs.excluded["p-2"], r.obs.excluded["p-3"] = true, true
	r.obs.mu.Unlock()
	if got := r.pick(); got == "" {
		t.Fatal("never an empty tag")
	}
}

// Ничего не работает: повтор 30 с → 1 → 2 → 5 → 5 мин; каждый повтор проверяет
// следующие узлы (провалившиеся исключены).
func TestVupenStickyRetrySchedule(t *testing.T) {
	tags := []string{"p-1", "p-2", "p-3", "p-4", "p-5", "p-6", "p-7", "p-8", "p-9", "p-10", "p-11", "p-12", "p-13", "p-14", "p-15"}
	r := newStickyRig(t, "", "", tags...)
	delays := map[string]int64{}
	for i, tag := range tags {
		delays[tag] = int64(10 + i)
	}
	r.alive(delays)
	r.pick()
	r.drain()
	r.expectPhase(vupenPhaseNoWorking)
	want := []time.Duration{30 * time.Second, time.Minute, 2 * time.Minute, 5 * time.Minute, 5 * time.Minute}
	for i, d := range want {
		p := r.clock.pendingIn()
		if len(p) != 1 || p[0] != d {
			t.Fatalf("retry %d: pending %v, want [%v]", i, p, d)
		}
		r.clock.Advance(d)
		r.drain()
	}
	// 6 поисков по 15 узлам: p-1..p-3, p-4..p-6, … — по три, без повторов; шестому
	// проверять уже некого (все исключены на 15 мин).
	if len(r.obs.verifies) != 15 || r.obs.verifies[3] != "p-4" || r.obs.verifies[6] != "p-7" {
		t.Fatalf("each search checks the next three: %v", r.obs.verifies)
	}
	seen := map[string]bool{}
	for _, v := range r.obs.verifies[:15] {
		if seen[v] {
			t.Fatalf("a failed node was checked again within its exclusion: %v", r.obs.verifies)
		}
		seen[v] = true
	}
}

// Сеть устоялась (эпоха ядра 74), а ничего не работает — поиск сразу, график сначала.
func TestVupenStickyNetworkSettledRetriesAtOnce(t *testing.T) {
	r := newStickyRig(t, "", "", "p-1", "p-2", "p-3", "p-4", "p-5", "p-6", "p-7")
	r.alive(map[string]int64{"p-1": 10, "p-2": 20, "p-3": 30, "p-4": 40, "p-5": 50, "p-6": 60, "p-7": 70})
	r.pick()
	r.drain() // nothing works, retry in 30 s
	r.clock.Advance(30 * time.Second)
	r.drain() // second failure, retry in 1 min
	if p := r.clock.pendingIn(); len(p) != 1 || p[0] != time.Minute {
		t.Fatalf("pending %v, want [1m]", p)
	}
	r.obs.mu.Lock()
	r.obs.verify["p-7"] = vupenStickyOK
	r.obs.mu.Unlock()
	// p-7 ещё не исключён: найдётся на сетевом событии без ожидания минуты.
	r.s.send(vupenStickyEvent{kind: "net-stable"})
	r.drain()
	if got := r.pick(); got != "p-7" {
		t.Fatalf("net-stable must search at once: pick %q", got)
	}
	if p := r.clock.pendingIn(); len(p) != 0 {
		t.Fatalf("retry timer must be stopped after success: %v", p)
	}
}

// CR-204: «сеть устоялась» после неудачного поиска — график снова с 30 с.
func TestVupenStickyNetworkSettledResetsRetryPause(t *testing.T) {
	tags := []string{"p-1", "p-2", "p-3", "p-4", "p-5", "p-6", "p-7", "p-8", "p-9", "p-10", "p-11", "p-12"}
	r := newStickyRig(t, "", "", tags...)
	delays := map[string]int64{}
	for i, tag := range tags {
		delays[tag] = int64(10 + i)
	}
	r.alive(delays)
	r.pick()
	r.drain() // fail → 30 s
	r.clock.Advance(30 * time.Second)
	r.drain() // fail → 1 min
	r.clock.Advance(time.Minute)
	r.drain() // fail → 2 min
	if p := r.clock.pendingIn(); len(p) != 1 || p[0] != 2*time.Minute {
		t.Fatalf("before the network event: %v", p)
	}
	r.s.send(vupenStickyEvent{kind: "net-stable"})
	r.drain() // fails again (p-10..p-12)
	r.expectPhase(vupenPhaseNoWorking)
	if p := r.clock.pendingIn(); len(p) != 1 || p[0] != 30*time.Second {
		t.Fatalf("after a failed search on a settled network the pause restarts at 30 s: %v", p)
	}
}

// CR-205 (c): очередь полна — событие об исключении не теряется навсегда.
func TestVupenStickyExcludedEventRetriedWhenQueueFull(t *testing.T) {
	r := newStickyRig(t, "p-1", "p-1", "p-1", "p-2")
	r.alive(map[string]int64{"p-1": 10, "p-2": 20})
	r.pick()
	r.drain()
	for r.s.send(vupenStickyEvent{kind: "filler"}) {
	}
	r.obs.mu.Lock()
	r.obs.excluded["p-1"] = true
	r.obs.mu.Unlock()
	r.pick()
	if r.s.excludedSent.Load() {
		t.Fatal("a dropped event must not block the next attempt")
	}
	r.drain()
	r.pick()
	found := false
	for len(r.s.events) > 0 {
		if ev := <-r.s.events; ev.kind == "current-excluded" {
			found = true
		}
	}
	if !found {
		t.Fatal("current-excluded must be sent once the queue has room")
	}
}

// CR-205 (a): остановлен до старта — ни подписки, ни обработчика.
func TestVupenStickyStopBeforeStart(t *testing.T) {
	r := newStickyRig(t, "p-1", "p-1", "p-1")
	started := false
	r.s.runWorker = func() { started = true }
	r.s.stop()
	r.pick()
	r.s.life.Lock()
	unsub := r.s.unsub
	r.s.life.Unlock()
	if started || unsub != nil {
		t.Fatalf("stopped sticky started: worker=%v subscribed=%v", started, unsub != nil)
	}
}

// CR-205 (b): ReloadRules останавливает обработчики заменённых балансировщиков.
func TestVupenStickyReloadStopsReplaced(t *testing.T) {
	ohm := &stickyFakeOhm{tags: []string{"p-1"}}
	r := &Router{ctx: context.Background(), ohm: ohm}
	r.rules.Store(new([]*Rule))
	r.balancers.Store(&map[string]*Balancer{})
	cfg := &Config{BalancingRule: []*BalancingRule{{Tag: "REG", OutboundSelector: []string{"p"},
		Strategy: "random", VupenSticky: &VupenSticky{Initial: "p-1"}}}}
	if err := r.ReloadRules(cfg, false); err != nil {
		t.Fatal(err)
	}
	first := (*r.balancers.Load())["REG"].vupen
	if err := r.ReloadRules(cfg, false); err != nil {
		t.Fatal(err)
	}
	select {
	case <-first.stopCh:
	default:
		t.Fatal("the replaced balancer's sticky worker must be stopped")
	}
	second := (*r.balancers.Load())["REG"].vupen
	select {
	case <-second.stopCh:
		t.Fatal("the new balancer must keep running")
	default:
	}
	second.stop()
}

// Во сне поиск не идёт — переносится по графику.
func TestVupenStickyNoSearchWhileAsleep(t *testing.T) {
	r := newStickyRig(t, "", "p-1", "p-1", "p-2")
	r.alive(map[string]int64{"p-1": 10, "p-2": 20})
	r.obs.asleep = true
	r.pick()
	r.drain()
	if len(r.obs.probes) != 0 || len(r.obs.verifies) != 0 {
		t.Fatal("no search while asleep")
	}
	if p := r.clock.pendingIn(); len(p) != 1 || p[0] != 30*time.Second {
		t.Fatalf("postponed search: %v", p)
	}
	r.obs.mu.Lock()
	r.obs.asleep = false
	r.obs.verify["p-1"] = vupenStickyOK
	r.obs.mu.Unlock()
	r.clock.Advance(30 * time.Second)
	r.drain()
	if got := r.pick(); got != "p-1" {
		t.Fatalf("search after wake: %q", got)
	}
}

// Текущий узел исключили (заморозка ядра 71 подтверждена) — он больше не выбор, поиск.
func TestVupenStickyCurrentExcludedSearches(t *testing.T) {
	r := newStickyRig(t, "p-1", "p-1", "p-1", "p-2")
	r.alive(map[string]int64{"p-1": 10, "p-2": 20})
	r.obs.verify["p-2"] = vupenStickyOK
	r.pick()
	r.drain()
	r.obs.mu.Lock()
	r.obs.excluded["p-1"] = true
	r.obs.mu.Unlock()
	if got := r.pick(); got == "p-1" {
		t.Fatal("an excluded current node must not get new connections")
	}
	r.drain()
	if got := r.pick(); got != "p-2" {
		t.Fatalf("pick after search %q", got)
	}
}

// Не больше VupenStickySearchMaxChecks за поиск, по возможности из разных подсетей.
func TestVupenStickyDiverse(t *testing.T) {
	key := map[string]string{"a": "1.2.3", "b": "1.2.3", "c": "1.2.3", "d": "5.6.7", "e": "9.9.9"}
	got := vupenStickyDiverse([]string{"a", "b", "c", "d", "e"}, func(t string) string { return key[t] }, 3)
	if fmt.Sprint(got) != "[a d e]" {
		t.Fatalf("diverse %v", got)
	}
	got = vupenStickyDiverse([]string{"a", "b", "c", "d"}, func(t string) string { return key[t] }, 3)
	if fmt.Sprint(got) != "[a d b]" {
		t.Fatalf("fill in order when not enough subnets: %v", got)
	}
	if len(vupenStickyDiverse([]string{"a"}, func(string) string { return "" }, 0)) != 0 {
		t.Fatal("max 0 = no checks")
	}
}

// CR-203: /48 для IPv6 (ключ не пустой, разные /48 — разные ключи).
func TestVupenAddrKey(t *testing.T) {
	a := vupenAddrKey(net.ParseAddress("2001:db8:1::1"))
	b := vupenAddrKey(net.ParseAddress("2001:db8:1:ffff::2"))
	c := vupenAddrKey(net.ParseAddress("2001:db8:2::1"))
	if a == "ip6:" || a == "ip6:<nil>" || a != b || a == c {
		t.Fatalf("/48 keys: %q %q %q", a, b, c)
	}
	if k := vupenAddrKey(net.ParseAddress("203.0.113.7")); k != "ip4:203.0.113" {
		t.Fatalf("/24 key %q", k)
	}
	if k := vupenAddrKey(net.ParseAddress("Node.Example.com")); k != "dom:node.example.com" {
		t.Fatalf("domain key %q", k)
	}
}

func TestVupenFirstAddress(t *testing.T) {
	m := &protocol.ServerEndpoint{Address: net.NewIPOrDomain(net.ParseAddress("203.0.113.7")), Port: 443}
	a := vupenFirstAddress(m.ProtoReflect(), 0)
	if a == nil || a.String() != "203.0.113.7" {
		t.Fatalf("address %v", a)
	}
}

// Обработчик и подписка на эпоху сети останавливаются вместе с ядром.
func TestVupenStickyStopEndsWorker(t *testing.T) {
	r := newStickyRig(t, "p-1", "p-1", "p-1")
	done := make(chan struct{})
	r.s.runWorker = func() { go func() { r.s.loop(); close(done) }() }
	r.pick()
	r.s.stop()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("worker did not stop")
	}
}

// Повтор поиска запускает эпоха сети ядра 74: событие «сеть устоялась» приходит
// обработчику (настоящий VupenSetUplink, порог сокращён до 1 с).
func TestVupenStickyGetsNetworkSettledFromEpoch(t *testing.T) {
	old := internet.VupenNetChangeCloseStableSec
	internet.VupenNetChangeCloseStableSec = 1
	t.Cleanup(func() { internet.VupenNetChangeCloseStableSec = old })
	r := newStickyRig(t, "", "p-1", "p-1")
	r.pick() // start: subscribes
	r.drain()
	// Подписи уникальны на прогон: состояние эпохи общее на процесс (-count ≥ 2).
	run := time.Now().UnixNano()
	internet.VupenSetUplink("wifi", fmt.Sprintf("sticky-test-wifi-%d", run))
	internet.VupenSetUplink("cellular", fmt.Sprintf("sticky-test-cell-%d", run))
	deadline := time.After(5 * time.Second)
	for {
		select {
		case ev := <-r.s.events:
			if ev.kind == "net-stable" {
				return
			}
		case <-deadline:
			t.Fatal("no net-stable event from the network epoch")
		}
	}
}

// ── ядро 76: признаки отказа ────────────────────────────────────────────────

// holdingRig — держим p-1 (проверка initial прошла), признаки идут от «обсерватории».
func holdingRig(t *testing.T) *stickyRig {
	t.Helper()
	r := newStickyRig(t, "p-1", "p-1", "p-1", "p-2", "p-3")
	r.alive(map[string]int64{"p-1": 900, "p-2": 10, "p-3": 20})
	r.pick()
	r.drain()
	r.expectPhase(vupenPhaseHolding)
	if r.obs.checkCount() != 1 {
		t.Fatalf("start check: %v", r.obs.checks)
	}
	return r
}

// П1: 3 неудачных соединения подряд за 10 с — ровно одна проверка; проверка
// прошла — медленный рабочий узел остаётся.
func TestVupenStickyDialFailuresTriggerOneCheck(t *testing.T) {
	r := holdingRig(t)
	for i := 0; i < 3; i++ {
		r.obs.emit("p-1", "dial", false)
		r.clock.Advance(2 * time.Second)
	}
	r.drain()
	if n := r.obs.checkCount(); n != 2 {
		t.Fatalf("3 failures in 10 s → one check, got %d checks", n-1)
	}
	if got := r.pick(); got != "p-1" || len(r.obs.probes) != 0 {
		t.Fatalf("a check that passed keeps the node: pick %q probes %v", got, r.obs.probes)
	}
}

// П1: успех между неудачами, неудачи дольше окна, чужой узел — проверки нет.
func TestVupenStickyDialFailuresNeedAStreakInTheWindow(t *testing.T) {
	r := holdingRig(t)
	r.obs.emit("p-1", "dial", false)
	r.obs.emit("p-1", "dial", false)
	r.obs.emit("p-1", "dial", true) // узел ответил — серия прервана
	r.obs.emit("p-1", "dial", false)
	for i := 0; i < 3; i++ { // по одной раз в 6 с — в окно 10 с попадают две
		r.clock.Advance(6 * time.Second)
		r.obs.emit("p-1", "dial", false)
	}
	for i := 0; i < 10; i++ {
		r.obs.emit("p-2", "dial", false) // не текущий
	}
	r.drain()
	if n := r.obs.checkCount(); n != 1 {
		t.Fatalf("no check expected, got %d", n-1)
	}
}

// Признаки не считаются в окне смены сети и во сне.
func TestVupenStickySignalsIgnoredAfterNetChangeAndAsleep(t *testing.T) {
	r := holdingRig(t)
	r.s.signals.mu.Lock()
	r.s.signals.netChangedAt = vupenStickyNow()
	r.s.signals.mu.Unlock()
	for i := 0; i < 5; i++ {
		r.obs.emit("p-1", "dial", false)
	}
	r.obs.emit("p-1", "freeze", false)
	r.drain()
	if n := r.obs.checkCount(); n != 1 {
		t.Fatalf("network-change window: %d checks", n-1)
	}
	r.clock.Advance(VupenStickySignalNetGrace)
	r.obs.mu.Lock()
	r.obs.asleep = true
	r.obs.mu.Unlock()
	for i := 0; i < 5; i++ {
		r.obs.emit("p-1", "dial", false)
	}
	r.drain()
	if n := r.obs.checkCount(); n != 1 {
		t.Fatalf("asleep: %d checks", n-1)
	}
	r.obs.mu.Lock()
	r.obs.asleep = false
	r.obs.mu.Unlock()
	for i := 0; i < 3; i++ {
		r.obs.emit("p-1", "dial", false)
	}
	r.drain()
	if n := r.obs.checkCount(); n != 2 {
		t.Fatalf("after the window and awake: want one check, got %d", n-1)
	}
}

// CR-205 (c): поток признаков склеивается в одну проверку в очереди.
func TestVupenStickySignalFloodCoalesced(t *testing.T) {
	r := holdingRig(t)
	for i := 0; i < 1000; i++ {
		r.obs.emit("p-1", "dial", false)
	}
	if n := len(r.s.events); n != 1 {
		t.Fatalf("1000 failures → one queued check, queue %d", n)
	}
	r.drain()
	if n := r.obs.checkCount(); n != 2 {
		t.Fatalf("one check run, got %d", n-1)
	}
	// После проверки признаки снова могут её запросить.
	for i := 0; i < 3; i++ {
		r.obs.emit("p-1", "dial", false)
	}
	r.drain()
	if n := r.obs.checkCount(); n != 3 {
		t.Fatalf("a new streak after the check → next check, got %d", n-1)
	}
}

// П2: заморозка — проверка, не чаще раза в минуту на узел.
func TestVupenStickyFreezeSignalRateLimited(t *testing.T) {
	r := holdingRig(t)
	r.obs.emit("p-1", "freeze", false)
	r.drain()
	r.clock.Advance(30 * time.Second)
	r.obs.emit("p-1", "freeze", false)
	r.drain()
	if n := r.obs.checkCount(); n != 2 {
		t.Fatalf("one freeze check per minute, got %d", n-1)
	}
	r.clock.Advance(30 * time.Second)
	r.obs.emit("p-1", "freeze", false)
	r.drain()
	if n := r.obs.checkCount(); n != 3 {
		t.Fatalf("after a minute → next check, got %d", n-1)
	}
}

// Смена — только после проваленной проверки при живой сети.
func TestVupenStickySignalSwitchOnlyAfterFailedCheck(t *testing.T) {
	r := holdingRig(t)
	r.obs.mu.Lock()
	r.obs.check["p-1"] = vupenStickyFailed
	r.obs.network = vupenNetDown
	r.obs.mu.Unlock()
	for i := 0; i < 3; i++ {
		r.obs.emit("p-1", "dial", false)
	}
	r.drain()
	if got := r.pick(); got != "p-1" || len(r.obs.probes) != 0 {
		t.Fatalf("no network on the device: keep, got %q probes %v", got, r.obs.probes)
	}
	r.obs.mu.Lock()
	r.obs.network = vupenNetUp
	r.obs.verify["p-2"] = vupenStickyOK
	r.obs.mu.Unlock()
	for i := 0; i < 3; i++ {
		r.obs.emit("p-1", "dial", false)
	}
	r.drain()
	if got := r.pick(); got != "p-2" || !r.obs.excluded["p-1"] {
		t.Fatalf("failed check + network up → excluded and switched: pick %q excluded %v", got, r.obs.excluded["p-1"])
	}
}
