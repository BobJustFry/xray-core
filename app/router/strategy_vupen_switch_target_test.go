package router

import (
	"slices"
	"strings"
	"testing"
	"time"
)

// Ядро 89 (D-71): VupenCheckRoute(switch) с target — тап по узлу во вкладке «Серверы» в АВТО.

// pressTarget — switch с целью.
func pressTarget(t *testing.T, rt *Router, target string) vupenRouteResp {
	t.Helper()
	return press(t, rt, `,"target":"`+target+`"`)
}

// Цель жива: одна проверка 24 КБ (как heal) только цели, переход без перезапуска,
// соединения прежнего закрыты, никто не исключён, VupenAutoState — новый текущий.
func TestVupenCheckRouteSwitchTargetAlive(t *testing.T) {
	r, rt := switchRig(t)
	s := r.s
	resp := pressTarget(t, rt, "p-3")
	if resp.Verdict != vupenRouteSwitched || resp.From != "p-1" || resp.To != "p-3" || resp.Tried != 1 || resp.Balancer != "REG" || resp.Closed != 2 {
		t.Fatalf("switch to target: %+v", resp)
	}
	if r.s != s || rt.balancers.Load() == nil || (*rt.balancers.Load())["REG"].vupen != s {
		t.Fatal("the balancer was replaced (restart)")
	}
	if got := r.s.viewTag(); got != "p-3" || r.s.getPhase() != vupenPhaseHolding {
		t.Fatalf("new connections via %q, phase %v", got, r.s.getPhase())
	}
	excluded, _, closed, verifies, _ := r.obs.snapshot()
	if len(excluded) != 0 || !slices.Equal(closed, []string{"p-1"}) || len(verifies) != 0 || len(r.obs.quickBatches()) != 0 {
		t.Fatalf("excluded %v closed %v verifies %v quick %v", excluded, closed, verifies, r.obs.quickBatches())
	}
	r.obs.mu.Lock()
	checks := slices.Clone(r.obs.routeChecks)
	r.obs.mu.Unlock()
	if !slices.Equal(checks, []string{"p-3"}) {
		t.Fatalf("24 KB checks %v, want only the target", checks)
	}
	st := autoState(t, rt)
	if st.Phase != "holding" || st.Current.Tag != "p-3" || st.Current.Balancer != "REG" || st.Notice != "" ||
		st.LastSwitch.From != "p-1" || st.LastSwitch.To != "p-3" || st.LastSwitch.Reason != "switch" ||
		st.LastCheckRoute.Verdict != vupenRouteSwitched {
		t.Fatalf("state: %+v", st)
	}
	// Без target после этого — прежний перебор по кругу (с p-3 на другой).
	if resp := press(t, rt, ""); resp.Verdict != vupenRouteSwitched || resp.From != "p-3" || resp.To == "p-3" {
		t.Fatalf("plain switch after target: %+v", resp)
	}
}

// Цель не прошла проверку (или «не поняли»): target_failed, текущий остаётся,
// цель не исключается, соединения не закрываются, это не провал текущего.
func TestVupenCheckRouteSwitchTargetDead(t *testing.T) {
	for _, v := range []string{vupenStickyFailed, vupenStickyUnknown} {
		r, rt := switchRig(t)
		r.obs.setRoute("p-2", v, "stall")
		resp := pressTarget(t, rt, "p-2")
		if resp.Verdict != vupenRouteTargetFailed || resp.From != "p-1" || resp.To != "p-1" || resp.Tried != 1 || resp.Kind != "stall" ||
			!strings.Contains(resp.Detail, "kept p-1") {
			t.Fatalf("%s: %+v", v, resp)
		}
		excluded, _, closed, _, _ := r.obs.snapshot()
		if len(excluded) != 0 || len(closed) != 0 || r.s.viewTag() != "p-1" {
			t.Fatalf("%s: excluded %v closed %v view %s", v, excluded, closed, r.s.viewTag())
		}
		st := autoState(t, rt)
		if st.Phase != "holding" || st.Current.Tag != "p-1" || st.FailedChecks != 0 || st.Notice != "" || st.LastSwitch.To == "p-2" {
			t.Fatalf("%s: state %+v", v, st)
		}
	}
}

// Неизвестный тег — not_in_pool без проверок; цель = текущий — switched без проверки;
// исключённая по провалу цель (D-42) — target_failed без проверки.
func TestVupenCheckRouteSwitchTargetNotInPoolCurrentExcluded(t *testing.T) {
	r, rt := switchRig(t)
	if resp := pressTarget(t, rt, "p-9"); resp.Verdict != vupenRouteNotInPool || resp.From != "p-1" || resp.Tried != 0 {
		t.Fatalf("unknown tag: %+v", resp)
	}
	if resp := pressTarget(t, rt, "p-1"); resp.Verdict != vupenRouteSwitched || resp.From != "p-1" || resp.To != "p-1" || resp.Tried != 0 || resp.Closed != 0 {
		t.Fatalf("target = current: %+v", resp)
	}
	r.obs.VupenStickyExclude("p-2", "test: dead")
	if resp := pressTarget(t, rt, "p-2"); resp.Verdict != vupenRouteTargetFailed || resp.To != "p-1" || resp.Tried != 0 {
		t.Fatalf("excluded target: %+v", resp)
	}
	if n := r.obs.routeCount(); n != 0 || r.s.viewTag() != "p-1" {
		t.Fatalf("no check expected: %d checks, view %s", n, r.s.viewTag())
	}
	_, _, closed, verifies, _ := r.obs.snapshot()
	if len(closed) != 0 || len(verifies) != 0 || len(r.obs.quickBatches()) != 0 {
		t.Fatalf("closed %v verifies %v quick %v", closed, verifies, r.obs.quickBatches())
	}
}

// target — только со switch; слишком длинный — bad request.
func TestVupenCheckRouteSwitchTargetBadRequest(t *testing.T) {
	r, rt := switchRig(t)
	for _, req := range []string{
		`{"v":1,"mode":"heal","target":"p-2"}`, `{"v":1,"mode":"check","target":"p-2"}`,
		`{"v":1,"mode":"switch","target":"` + strings.Repeat("x", vupenRouteMaxTarget+1) + `"}`,
	} {
		if resp := route(t, rt, req); resp.Verdict != vupenRouteUnknown || !strings.HasPrefix(resp.Detail, "bad request") {
			t.Fatalf("%.60s → %+v", req, resp)
		}
	}
	if n := r.obs.routeCount(); n != 0 || r.s.viewTag() != "p-1" {
		t.Fatalf("a bad request must not check anything: %d checks, view %s", n, r.s.viewTag())
	}
}

// Wi-Fi: REG держит p-1, цель из LTE — not_in_pool (другой ярус); запрос прямо в LTE
// (balancer=LTE) — тоже not_in_pool: LTE не на сотовой запрещён (D-21). LTE не тронут.
func TestVupenCheckRouteSwitchTargetOtherTierAndLteOnWifi(t *testing.T) {
	r := newSpillRig(t, []string{"cellular"}, []string{"p-1", "p-2"}, []string{"lte-1", "lte-2"})
	r.kind = "wifi"
	r.alive(map[string]int64{"p-1": 10, "p-2": 20, "lte-1": 40})
	r.obs.mu.Lock()
	r.obs.verify["p-1"] = vupenStickyOK
	r.obs.verify["lte-1"] = vupenStickyOK
	r.obs.mu.Unlock()
	r.pick()
	r.drain()
	if r.reg.getPhase() != vupenPhaseHolding || r.pick() != "p-1" {
		t.Fatalf("setup: %v %s", r.reg.getPhase(), r.pick())
	}
	rt := routerWith(map[string]*Balancer{"REG": r.regB, "LTE": r.lteB})
	go r.reg.loop()
	go r.lte.loop()
	if resp := pressTarget(t, rt, "lte-1"); resp.Verdict != vupenRouteNotInPool || resp.Balancer != "REG" || resp.Tried != 0 {
		t.Fatalf("LTE target via REG: %+v", resp)
	}
	resp := route(t, rt, `{"v":1,"mode":"switch","reason":"manual","balancer":"LTE","target":"lte-1"}`)
	if resp.Verdict != vupenRouteNotInPool || resp.Balancer != "LTE" || resp.Tried != 0 {
		t.Fatalf("LTE target on Wi-Fi: %+v", resp)
	}
	if r.reg.spilledNow() || r.touchedLTE() || r.pick() != "p-1" || r.obs.routeCount() != 0 {
		t.Fatalf("nothing changes: spilled=%v touchedLTE=%v pick=%s checks=%d", r.reg.spilledNow(), r.touchedLTE(), r.pick(), r.obs.routeCount())
	}
}

// Перелито (сотовая): выбирает LTE; цель из REG — not_in_pool, цель из LTE — switched
// внутри LTE, REG остаётся перелитым.
func TestVupenCheckRouteSwitchTargetWhileSpilled(t *testing.T) {
	r := newSpillRig(t, []string{"cellular"}, []string{"p-1", "p-2", "p-3"}, []string{"lte-1", "lte-2"})
	regDeadLteAlive(r)
	r.pick()
	r.drain()
	r.pick()
	r.drain()
	if got := r.pick(); got != "lte-2" || !r.reg.spilledNow() {
		t.Fatalf("setup: %s spilled=%v", got, r.reg.spilledNow())
	}
	r.obs.mu.Lock()
	r.obs.excluded["lte-1"] = false
	r.obs.mu.Unlock()
	rt := routerWith(map[string]*Balancer{"REG": r.regB, "LTE": r.lteB})
	go r.lte.loop()
	if resp := pressTarget(t, rt, "p-2"); resp.Verdict != vupenRouteNotInPool || resp.Balancer != "LTE" || resp.Tried != 0 {
		t.Fatalf("REG target while spilled: %+v", resp)
	}
	resp := pressTarget(t, rt, "lte-1")
	if resp.Verdict != vupenRouteSwitched || resp.Balancer != "LTE" || resp.From != "lte-2" || resp.To != "lte-1" || resp.Tried != 1 {
		t.Fatalf("LTE target while spilled: %+v", resp)
	}
	if !r.reg.spilledNow() || r.pick() != "lte-1" {
		t.Fatalf("still spilled, via lte-1: spilled=%v pick=%s", r.reg.spilledNow(), r.pick())
	}
}

// CR-002 (T-227): сеть сменилась во время проверки цели — unknown, текущий остаётся
// (Holding, выдача та же), цель не исключается, соединения не закрываются.
func TestVupenCheckRouteSwitchTargetAbortsOnEpochChange(t *testing.T) {
	r, f, eo := epochRig(t)
	t.Cleanup(eo.closeRelease)
	r.pick()
	r.drain()
	prev := r.pick()
	if r.reg.getPhase() != vupenPhaseHolding || prev == "" {
		t.Fatalf("setup: phase %v, current %q", r.reg.getPhase(), prev)
	}
	target := "p-3"
	if prev == target {
		target = "p-2"
	}
	eo.blockRoute = true // проверка 24 КБ цели висит до отмены
	h := &vupenHealReq{q: vupenRouteReq{V: 1, Mode: vupenRouteSwitchMode, Reason: "manual", Target: target}, reply: make(chan vupenRouteResp, 1)}
	got := make(chan vupenRouteResp, 1)
	go func() { got <- r.reg.switchRoute(h) }()
	waitHung(t, eo, "route")
	f.newEpoch()
	select {
	case resp := <-got:
		if resp.Verdict != vupenRouteUnknown || resp.From != prev || resp.To != prev || resp.Tried != 1 || resp.Closed != 0 ||
			!strings.Contains(resp.Detail, "network changed") || !strings.Contains(resp.Detail, "kept "+prev) {
			t.Fatalf("aborted switch to target: %+v", resp)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("switch to target is still blocked in the check of the previous network")
	}
	if r.reg.getPhase() != vupenPhaseHolding || r.reg.viewTag() != prev || r.pick() != prev {
		t.Fatalf("current node must be kept: phase %v view %q pick %q", r.reg.getPhase(), r.reg.viewTag(), r.pick())
	}
	r.obs.mu.Lock()
	excluded, excludedFor, closed := len(r.obs.excluded), len(r.obs.excludedFor), len(r.obs.closedTags)
	r.obs.mu.Unlock()
	if excluded != 0 || excludedFor != 0 || closed != 0 {
		t.Fatalf("an aborted target check must not exclude or close: excluded=%d excludedFor=%d closed=%d", excluded, excludedFor, closed)
	}
}

// CR-002 (T-227): рабочих не было — прошедшая проверку цель становится текущим
// (Holding), повтор поиска по графику снят (holdBecause останавливает таймер).
func TestVupenCheckRouteSwitchTargetWhenNoWorking(t *testing.T) {
	r := newStickyRig(t, "", "p-1", "p-1", "p-2")
	rt := routerWith(map[string]*Balancer{"REG": r.b})
	r.pick()
	r.drain()
	r.expectPhase(vupenPhaseNoWorking)
	if r.s.stopRetry == nil || len(r.clock.pendingIn()) == 0 || autoState(t, rt).Sticky.NextSearchAtMs == 0 {
		t.Fatalf("setup: the retry timer must be armed (pending %v)", r.clock.pendingIn())
	}
	pending := len(r.clock.pendingIn())
	go r.s.loop()
	resp := pressTarget(t, rt, "p-2")
	if resp.Verdict != vupenRouteSwitched || resp.From != "" || resp.To != "p-2" || resp.Tried != 1 || resp.Closed != 0 {
		t.Fatalf("switch to target with no working node: %+v", resp)
	}
	r.expectPhase(vupenPhaseHolding)
	if got := r.s.viewTag(); got != "p-2" {
		t.Fatalf("new connections via %q, want p-2", got)
	}
	if n := len(r.clock.pendingIn()); n != pending-1 {
		t.Fatalf("the retry timer must be stopped: %d live timers, was %d", n, pending)
	}
	st := autoState(t, rt)
	if st.Phase != "holding" || st.Current.Tag != "p-2" || st.NoWorking || st.Sticky.NextSearchAtMs != 0 ||
		st.LastSwitch.To != "p-2" || st.LastSwitch.Reason != "switch" {
		t.Fatalf("state: %+v", st)
	}
	r.obs.mu.Lock()
	checks := slices.Clone(r.obs.routeChecks)
	r.obs.mu.Unlock()
	if !slices.Equal(checks, []string{"p-2"}) {
		t.Fatalf("24 KB checks %v, want only the target", checks)
	}
}

// CR-002 (T-227): пока ядро само выбирает узел (new / поиск) — busy_searching и с target,
// цель не проверяется, второй поиск не ставится.
func TestVupenCheckRouteSwitchTargetBusySearching(t *testing.T) {
	r := newStickyRig(t, "", "p-1", "p-1", "p-2")
	rt := routerWith(map[string]*Balancer{"REG": r.b})
	if resp := pressTarget(t, rt, "p-2"); resp.Verdict != vupenRouteBusySearching || !strings.Contains(resp.Detail, "not chosen a node yet") {
		t.Fatalf("new: %+v", resp)
	}
	r.pick() // старт: поиск в очереди
	r.expectPhase(vupenPhaseSearching)
	start := time.Now()
	if resp := pressTarget(t, rt, "p-2"); resp.Verdict != vupenRouteBusySearching || !strings.Contains(resp.Detail, "searching") ||
		time.Since(start) > time.Second {
		t.Fatalf("searching: %+v", resp)
	}
	if n := len(r.s.events); n != 1 {
		t.Fatalf("only the start search is queued: %d events", n)
	}
	// И внутри обработчика (запрос прошёл до начала поиска).
	h := &vupenHealReq{q: vupenRouteReq{Mode: vupenRouteSwitchMode, Target: "p-2"}, reply: make(chan vupenRouteResp, 1)}
	if resp := r.s.switchRoute(h); resp.Verdict != vupenRouteBusySearching {
		t.Fatalf("handler: %+v", resp)
	}
	if n := r.obs.routeCount(); n != 0 {
		t.Fatalf("busy: the target must not be checked, %d checks", n)
	}
}
