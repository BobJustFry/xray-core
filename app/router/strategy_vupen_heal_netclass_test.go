package router

import (
	"testing"
	"time"
)

// Ядро 86 (T-168): класс сети до поиска в пути heal приложения; повторная проверка после
// «нет сети» на сотовой в любой фазе.

// healHolding - ядро держит p-1 (старт в нормальной сети), счётчики пробников обнулены,
// класс сети устарел (старше VupenNetClassMinGap): heal должен спросить сеть заново.
func healHolding(t *testing.T) (*spillRig, *ncFake) {
	t.Helper()
	f := installNetClassFake(t)
	f.normal()
	r := newSpillRig(t, []string{"cellular"}, []string{"p-1", "p-2", "p-3"}, []string{"lte-1", "lte-2"})
	regDeadLteAlive(r)
	r.reg.initial = "p-1"
	r.pick()
	r.drain()
	if r.reg.getPhase() != vupenPhaseHolding || r.reg.current != "p-1" {
		t.Fatalf("setup: phase %v current %q", r.reg.getPhase(), r.reg.current)
	}
	r.obs.mu.Lock()
	r.obs.probes, r.obs.checks, r.obs.verifies = nil, nil, nil
	r.obs.network = vupenNetUp
	r.obs.mu.Unlock()
	r.clock.Advance(VupenNetClassMinGap + time.Second)
	r.drain()
	return r, f
}

func healReqNow() *vupenHealReq {
	return &vupenHealReq{q: vupenRouteReq{V: 1, Mode: vupenRouteHealMode, Reason: "foreground"}, reply: make(chan vupenRouteResp, 1)}
}

func (r *spillRig) excludedForCount() int {
	r.obs.mu.Lock()
	defer r.obs.mu.Unlock()
	return len(r.obs.excludedFor)
}

// (a) БС: heal узла, не прошедшего проверку, идёт в LTE без поиска по REG, узел не исключается.
func TestVupenHealNetClassWhitelistGoesToLteWithoutRegSweep(t *testing.T) {
	r, f := healHolding(t)
	f.whitelist()
	r.obs.setRoute("p-1", vupenStickyFailed, "stall")
	probesBefore := f.probes()
	resp := r.reg.healRoute(healReqNow())
	if resp.Verdict != vupenRouteSpilledLTE {
		t.Fatalf("whitelist heal: %+v", resp)
	}
	if !r.reg.spilledNow() || !r.reg.spill.byWhitelist.Load() {
		t.Fatal("whitelist spill expected")
	}
	if ncRegSearched(r) || ncRegProbed(r) {
		t.Fatalf("no REG probes/verifies on a whitelist: probes=%v verifies=%v", r.obs.probes, r.obs.verifies)
	}
	if r.excludedForCount() != 0 || r.obs.excluded["p-1"] {
		t.Fatal("the node must not be excluded on a whitelist")
	}
	if resp.Closed != 2 || len(r.obs.closedTags) != 1 || r.obs.closedTags[0] != "p-1" {
		t.Fatalf("connections of the dead node are closed: %+v %v", resp, r.obs.closedTags)
	}
	if got := f.probes() - probesBefore; got != 1 {
		t.Fatalf("exactly one netclass probe before the heal decision, %d", got)
	}
}

// (a) то же, когда ядро не держит узла (no-working): БС - сразу в LTE.
func TestVupenHealNetClassWhitelistFromNoWorking(t *testing.T) {
	r, f := healHolding(t)
	r.reg.setPhase(vupenPhaseNoWorking)
	f.whitelist()
	resp := r.reg.healRoute(healReqNow())
	if resp.Verdict != vupenRouteSpilledLTE || !r.reg.spilledNow() {
		t.Fatalf("no-working + whitelist: %+v", resp)
	}
	if ncRegSearched(r) || ncRegProbed(r) {
		t.Fatalf("no REG sweep: probes=%v verifies=%v", r.obs.probes, r.obs.verifies)
	}
}

// (b) normal / unknown / noNetwork: как раньше - узел исключён, поиск по REG идёт.
func TestVupenHealNetClassNonWhitelistBehavesAsBefore(t *testing.T) {
	for _, c := range []struct {
		name string
		set  func(f *ncFake)
	}{
		{"normal", func(f *ncFake) { f.normal() }},
		{"unknown", func(f *ncFake) { f.mu.Lock(); f.localErr = true; f.mu.Unlock() }},
		{"noNetwork", func(f *ncFake) { f.down() }},
	} {
		t.Run(c.name, func(t *testing.T) {
			r, f := healHolding(t)
			c.set(f)
			r.obs.setRoute("p-1", vupenStickyFailed, "stall")
			resp := r.reg.healRoute(healReqNow())
			if r.reg.spill.byWhitelist.Load() {
				t.Fatalf("%s must not be treated as a whitelist", c.name)
			}
			if r.excludedForCount() != 1 || !r.obs.excluded["p-1"] {
				t.Fatalf("%s: the failed node is excluded as before: %+v", c.name, resp)
			}
			if !ncRegSearched(r) {
				t.Fatalf("%s: the REG search runs as before: probes=%v", c.name, r.obs.probes)
			}
		})
	}
}

// Wi-Fi: класс не запрашивается (ожидания нет), heal как раньше.
func TestVupenHealNetClassSkippedOnWifi(t *testing.T) {
	r, f := healHolding(t)
	r.kind = "wifi"
	f.whitelist()
	r.obs.setRoute("p-1", vupenStickyFailed, "stall")
	before := f.probes()
	r.reg.healRoute(healReqNow())
	if f.probes() != before {
		t.Fatal("no direct probe on Wi-Fi")
	}
	if r.excludedForCount() != 1 || !ncRegSearched(r) {
		t.Fatal("Wi-Fi heal is unchanged: exclude and search")
	}
}

// Свежий класс (моложе VupenNetClassMinGap) берётся из памяти: лишних замеров в heal нет.
func TestVupenHealNetClassUsesFreshClass(t *testing.T) {
	r, f := healHolding(t)
	r.reg.netClassProbe("test") // normal, только что
	r.obs.setRoute("p-1", vupenStickyFailed, "stall")
	before := f.probes()
	r.reg.healRoute(healReqNow())
	if f.probes() != before {
		t.Fatalf("a fresh class is reused, probes %d → %d", before, f.probes())
	}
}

// ── повторная проверка после «нет сети» ──────────────────────────────────────

// retryHolding - узел держится, сеть сотовая, замер «нет сети» взвёл цепочку.
func retryHolding(t *testing.T) (*spillRig, *ncFake) {
	t.Helper()
	r, f := healHolding(t)
	f.down()
	r.reg.runNetClass("test")
	r.drain()
	if r.reg.getPhase() != vupenPhaseHolding {
		t.Fatalf("phase %v", r.reg.getPhase())
	}
	return r, f
}

func (r *spillRig) retryPending() []time.Duration {
	var out []time.Duration
	for _, d := range r.clock.pendingIn() {
		out = append(out, d)
	}
	return out
}

// (c) интервалы 30 с, 1, 2, 5, 5 мин; раньше срока проверки нет.
func TestVupenNetClassNoNetworkRearmsInHolding(t *testing.T) {
	r, f := retryHolding(t)
	base := f.probes()
	for i, d := range []time.Duration{30 * time.Second, time.Minute, 2 * time.Minute, 5 * time.Minute, 5 * time.Minute} {
		if p := r.retryPending(); len(p) == 0 || p[len(p)-1] != d {
			t.Fatalf("step %d: next re-probe in %v, want %v", i, p, d)
		}
		r.clock.Advance(d - time.Second)
		r.drain()
		if f.probes() != base+i {
			t.Fatalf("step %d: a probe before its time (%d)", i, f.probes()-base)
		}
		r.clock.Advance(time.Second)
		r.drain()
		if f.probes() != base+i+1 {
			t.Fatalf("step %d: exactly one probe expected, got %d", i, f.probes()-base-i)
		}
	}
	if r.reg.getPhase() != vupenPhaseHolding || r.reg.spilledNow() {
		t.Fatal("noNetwork re-probes change nothing about the node")
	}
}

// (c) смена сети (новая эпоха) снимает цепочку; устаревшее событие отбрасывается.
func TestVupenNetClassRetryCancelledByEpochChange(t *testing.T) {
	r, f := retryHolding(t)
	staleGen := r.reg.netcls.retryGen
	f.newEpoch()
	r.kind = "wifi"
	r.reg.netClassOnChanged()
	r.drain()
	before := f.probes()
	// событие, уже стоявшее в очереди к моменту смены сети
	r.reg.send(vupenStickyEvent{kind: "netclass", reason: vupenNetClassRetryReason, gen: staleGen})
	r.drain()
	r.clock.Advance(10 * time.Minute)
	r.drain()
	if f.probes() != before {
		t.Fatalf("no re-probe after the network changed: %d", f.probes()-before)
	}
	if r.reg.netcls.retryOn {
		t.Fatal("the chain must be off")
	}
}

// Сотовая → сотовая (новая эпоха): старая цепочка снята, новый замер заводит новую с 30 с.
func TestVupenNetClassRetryRestartsOnNewCellularNetwork(t *testing.T) {
	r, f := retryHolding(t)
	r.clock.Advance(30 * time.Second) // idx → 1 (следующая пауза 1 мин)
	r.drain()
	r.ncChange(f, "cellular")
	r.ncSettle() // замер в новой сети: снова «нет сети»
	p := r.retryPending()
	if len(p) != 1 || p[0] != 30*time.Second {
		t.Fatalf("a new network starts the backoff over: %v", p)
	}
}

// (d) Wi-Fi: «нет сети» цепочку не взводит.
func TestVupenNetClassNoNetworkOnWifiDoesNotRearm(t *testing.T) {
	r, f := healHolding(t)
	r.kind = "wifi"
	f.down()
	before := f.probes()
	r.reg.runNetClass("test")
	r.reg.netClassProbe("test")
	r.drain()
	r.clock.Advance(10 * time.Minute)
	r.drain()
	if f.probes() != before || r.reg.netcls.retryOn || len(r.retryPending()) != 0 {
		t.Fatalf("Wi-Fi: no probes and no timers: probes %d, pending %v", f.probes()-before, r.retryPending())
	}
}

// Уход с сотовой без смены эпохи (тип сети стал Wi-Fi): событие таймера снимает цепочку.
func TestVupenNetClassRetryStopsWhenUplinkLeavesCellular(t *testing.T) {
	r, f := retryHolding(t)
	r.kind = "wifi"
	before := f.probes()
	r.clock.Advance(30 * time.Second)
	r.drain()
	r.clock.Advance(10 * time.Minute)
	r.drain()
	if f.probes() != before || r.reg.netcls.retryOn {
		t.Fatalf("no probes off cellular, chain off=%v", !r.reg.netcls.retryOn)
	}
}

// (e) БС: повторная проверка находит БС - перелив в LTE, цепочка снята.
func TestVupenNetClassRetryFindsWhitelistAndStops(t *testing.T) {
	r, f := retryHolding(t)
	f.whitelist()
	r.clock.Advance(30 * time.Second)
	r.drain()
	if !r.reg.spilledNow() || !r.reg.spill.byWhitelist.Load() {
		t.Fatal("the re-probe saw a whitelist while holding a dead node: spill to LTE")
	}
	if ncRegSearched(r) {
		t.Fatal("no REG sweep")
	}
	before := f.probes()
	if r.reg.netcls.retryOn {
		t.Fatal("the chain must stop after a whitelist result")
	}
	r.clock.Advance(10 * time.Minute)
	r.drain()
	// дешёвая проверка перелива (lte-recheck) - отдельный график, не цепочка «нет сети»
	if got := f.probes() - before; got > 1 {
		t.Fatalf("at most the regular LTE recheck probes afterwards, %d", got)
	}
}

// (e) normal: цепочка снята, дальше проверок нет; узел остаётся.
func TestVupenNetClassRetryStopsAfterNormal(t *testing.T) {
	r, f := retryHolding(t)
	f.normal()
	r.clock.Advance(30 * time.Second)
	r.drain()
	before := f.probes()
	if r.reg.netcls.retryOn || len(r.retryPending()) != 0 {
		t.Fatalf("chain must stop: on=%v pending=%v", r.reg.netcls.retryOn, r.retryPending())
	}
	r.clock.Advance(10 * time.Minute)
	r.drain()
	if f.probes() != before || r.reg.getPhase() != vupenPhaseHolding || r.reg.current != "p-1" {
		t.Fatalf("no more probes, node kept: %d", f.probes()-before)
	}
}

// Остановка ядра снимает цепочку.
func TestVupenNetClassRetryStoppedWithTheCore(t *testing.T) {
	r, f := retryHolding(t)
	r.reg.stop()
	before := f.probes()
	r.clock.Advance(10 * time.Minute)
	r.drain()
	if f.probes() != before || r.reg.netcls.retryOn {
		t.Fatal("a stopped core does not re-probe")
	}
}

// noNetwork при отсутствии узла (no-working): цепочка и график поиска не удваивают замеры.
func TestVupenNetClassRetryNoWorkingNoDoubleProbes(t *testing.T) {
	r, f := healHolding(t)
	r.reg.setPhase(vupenPhaseNoWorking)
	f.down()
	r.reg.search("test") // вентиль: нет сети → график поиска (scheduleRetry)
	r.drain()
	base := f.probes()
	r.clock.Advance(30 * time.Second)
	r.drain()
	if got := f.probes() - base; got != 1 {
		t.Fatalf("one probe per interval, got %d", got)
	}
}
