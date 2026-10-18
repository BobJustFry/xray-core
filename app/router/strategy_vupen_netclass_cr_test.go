package router

import (
	"context"
	"net"
	"syscall"
	"testing"
	"time"
)

// T-093: регрессии по ревью ядра 82 (CR-001..CR-006).

func ncChecked(r *spillRig, tag string) bool {
	r.obs.mu.Lock()
	defer r.obs.mu.Unlock()
	for _, c := range r.obs.checks {
		if c == tag {
			return true
		}
	}
	return false
}

// CR-001: старт при БС — проверка initial пропущена (фаза checking). Уход на Wi-Fi снимает
// перелив; после net-stable узел проверяется, а мёртвый — исключается и заменяется.
func TestVupenNetClassStartWhitelistThenWifiChecksInitial(t *testing.T) {
	f := installNetClassFake(t)
	f.whitelist()
	r := newSpillRig(t, []string{"cellular"}, []string{"p-1", "p-2"}, []string{"lte-1", "lte-2"})
	regDeadLteAlive(r)
	r.alive(map[string]int64{"p-1": 10, "p-2": 20, "lte-1": 40, "lte-2": 50})
	r.obs.mu.Lock()
	r.obs.check["p-1"] = vupenStickyFailed
	r.obs.verify["p-2"] = vupenStickyOK
	r.obs.mu.Unlock()
	r.reg.initial = "p-1"
	r.pick()
	r.drain()
	if !r.reg.spilledNow() || r.reg.getPhase() != vupenPhaseChecking || ncChecked(r, "p-1") {
		t.Fatalf("start under whitelist: spilled, phase checking, nothing checked (phase %v)", r.reg.getPhase())
	}
	f.normal()
	r.ncChange(f, "wifi")
	if ncChecked(r, "p-1") {
		t.Fatal("the check waits for the settled network, not for the change")
	}
	r.reg.send(vupenStickyEvent{kind: "net-stable"})
	r.drain()
	if !ncChecked(r, "p-1") {
		t.Fatal("CR-001: after leaving the whitelist the initial node must be checked at net-stable")
	}
	if !r.obs.excluded["p-1"] {
		t.Fatal("dead initial node excluded")
	}
	r.expectHolding(t, "p-2")
}

// CR-001 (живой initial): проверка проходит — узел удерживается.
func TestVupenNetClassStartWhitelistThenWifiKeepsLiveInitial(t *testing.T) {
	f := installNetClassFake(t)
	f.whitelist()
	r := newSpillRig(t, []string{"cellular"}, []string{"p-1", "p-2"}, []string{"lte-1", "lte-2"})
	regDeadLteAlive(r)
	r.reg.initial = "p-1"
	r.pick()
	r.drain()
	f.normal()
	r.ncChange(f, "wifi")
	r.reg.send(vupenStickyEvent{kind: "net-stable"})
	r.drain()
	if !ncChecked(r, "p-1") {
		t.Fatal("initial checked")
	}
	r.expectHolding(t, "p-1")
}

// CR-001 (БС кончились, остались на сотовой): лёгкая проверка видит иностранные →
// возврат и проверка initial, а не поиск вслепую.
func TestVupenNetClassStartWhitelistThenEndsOnCellularChecksInitial(t *testing.T) {
	f := installNetClassFake(t)
	f.whitelist()
	r := newSpillRig(t, []string{"cellular"}, []string{"p-1", "p-2"}, []string{"lte-1", "lte-2"})
	regDeadLteAlive(r)
	r.reg.initial = "p-1"
	r.pick()
	r.drain()
	f.normal()
	r.clock.Advance(VupenLteRegularRecheck)
	r.drain()
	if r.reg.spilledNow() || !ncChecked(r, "p-1") {
		t.Fatalf("whitelist ended: unspilled and initial checked (spilled=%v)", r.reg.spilledNow())
	}
	r.expectHolding(t, "p-1")
}

// CR-002: «нет сети» замерено в момент подъёма сети (settle), к net-stable сеть есть —
// поиск идёт сразу. Два события net-stable идут подряд (поиск и netclass); каждое
// по отдельности тоже должно вести к поиску.
func TestVupenNetClassTransientNoNetworkAtSettleThenStableSearches(t *testing.T) {
	for _, withClassEvent := range []bool{false, true} {
		f := installNetClassFake(t)
		f.down()
		r := newSpillRig(t, []string{"cellular"}, []string{"p-1", "p-2"}, []string{"lte-1"})
		r.pick() // нет initial → поиск → вентиль: нет сети → NoWorking
		r.drain()
		if r.reg.getPhase() != vupenPhaseNoWorking || ncRegSearched(r) {
			t.Fatalf("setup: no network, no search (phase %v)", r.reg.getPhase())
		}
		r.ncChange(f, "cellular")
		r.ncSettle() // проба через 1,5 с: сеть ещё не поднялась
		if cls, _, _ := r.reg.netClassJSON(); cls != vupenNetClassNoNetwork {
			t.Fatalf("settle probe: %q", cls)
		}
		f.normal()
		r.alive(map[string]int64{"p-1": 10, "p-2": 20})
		r.obs.mu.Lock()
		r.obs.verify["p-1"] = vupenStickyOK
		r.obs.mu.Unlock()
		r.reg.send(vupenStickyEvent{kind: "net-stable"})
		if withClassEvent {
			r.reg.send(vupenStickyEvent{kind: "netclass", reason: "net-stable"})
		}
		r.drain()
		if !ncRegSearched(r) || r.reg.getPhase() != vupenPhaseHolding {
			t.Fatalf("CR-002 (class event %v): search must start at net-stable (phase %v)", withClassEvent, r.reg.getPhase())
		}
		r.expectHolding(t, "p-1")
	}
}

// CR-002: «нет сети» → «есть» без смены эпохи (замер по событию) при NoWorking — поиск сразу.
func TestVupenNetClassNoNetworkThenNormalWithoutEpochChangeSearches(t *testing.T) {
	f := installNetClassFake(t)
	f.down()
	r := newSpillRig(t, []string{"cellular"}, []string{"p-1", "p-2"}, []string{"lte-1"})
	r.pick()
	r.drain()
	if r.reg.getPhase() != vupenPhaseNoWorking {
		t.Fatalf("setup: %v", r.reg.getPhase())
	}
	f.normal()
	r.alive(map[string]int64{"p-1": 10, "p-2": 20})
	r.obs.mu.Lock()
	r.obs.verify["p-1"] = vupenStickyOK
	r.obs.mu.Unlock()
	r.reg.send(vupenStickyEvent{kind: "netclass", reason: "manual"})
	r.drain()
	if !ncRegSearched(r) {
		t.Fatal("the network is back: search at once, not on the retry schedule")
	}
	r.expectHolding(t, "p-1")
}

// CR-003: при «нет сети» повторы с нарастающей паузой — за 30 минут не больше девяти проб.
func TestVupenNetClassNoNetworkRetryBacksOff(t *testing.T) {
	f := installNetClassFake(t)
	f.down()
	r := newSpillRig(t, []string{"cellular"}, []string{"p-1"}, []string{"lte-1"})
	r.pick()
	r.drain()
	for i := 0; i < 30; i++ {
		r.clock.Advance(time.Minute)
		r.drain()
	}
	got := f.probes()
	if got >= 10 || got < 4 {
		t.Fatalf("CR-003: %d probes in 30 min, want 4..9", got)
	}
	if ncRegSearched(r) {
		t.Fatal("no REG search without a network")
	}
}

// CR-004: БС — только при трёх настоящих отказах иностранных; локальная ошибка сокета → unknown.
func TestVupenNetClassWhitelistNeedsThreeRealForeignFailures(t *testing.T) {
	installNetClassFake(t)
	mk := func(local map[string]bool, ok map[string]bool) {
		vupenNetClassConnect = func(ctx context.Context, hp string) (bool, error) {
			h, _, _ := net.SplitHostPort(hp)
			switch {
			case local[h]:
				return false, syscall.EACCES
			case ok[h]:
				return false, nil
			}
			return false, syscall.ECONNREFUSED
		}
	}
	yandex := map[string]bool{"77.88.8.8": true, "77.88.8.1": true, "77.88.8.88": true}
	mk(nil, yandex)
	if res := vupenNetClassRun(); res.class != vupenNetClassWhitelist {
		t.Fatalf("three real foreign failures + Yandex: %q", res.class)
	}
	mk(map[string]bool{"8.8.8.8": true}, yandex)
	if res := vupenNetClassRun(); res.class != vupenNetClassUnknown {
		t.Fatalf("one foreign failed locally: %q, want unknown (%s)", res.class, res.short())
	}
	mk(map[string]bool{"77.88.8.8": true}, nil)
	if res := vupenNetClassRun(); res.class != vupenNetClassUnknown {
		t.Fatalf("no answers and a local socket error: %q, want unknown", res.class)
	}
}
