package router

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/transport/internet"
)

// Ядро 79 (D-42): VupenCheckRoute(switch) — кнопка «Сменить сервер».

// switchRig — держим p-1 из p-1…p-3 (по замерам p-2 быстрее p-3, p-1 медленнее
// всех), все три проходят 64 КБ; обработчик работает по-настоящему.
func switchRig(t *testing.T) (*stickyRig, *Router) {
	t.Helper()
	r, rt := healRig(t)
	r.obs.mu.Lock()
	for _, tag := range []string{"p-1", "p-2", "p-3"} {
		r.obs.verify[tag] = vupenStickyOK
	}
	r.obs.mu.Unlock()
	return r, rt
}

// press — одно нажатие «Сменить сервер».
func press(t *testing.T, rt *Router, extra string) vupenRouteResp {
	t.Helper()
	return route(t, rt, `{"v":1,"mode":"switch","reason":"manual"`+extra+`}`)
}

// pressSeq — нажатия подряд; каждое должно сменить узел. Возвращает путь узлов.
func pressSeq(t *testing.T, r *stickyRig, rt *Router, n int) []string {
	t.Helper()
	path := []string{r.s.viewTag()}
	for i := 0; i < n; i++ {
		resp := press(t, rt, "")
		if resp.Verdict != vupenRouteSwitched || resp.From != path[len(path)-1] || resp.To == resp.From || resp.Balancer != "REG" {
			t.Fatalf("press %d after %v: %+v", i+1, path, resp)
		}
		if got := r.s.viewTag(); got != resp.To {
			t.Fatalf("press %d: new connections go via %q, want %q", i+1, got, resp.To)
		}
		path = append(path, resp.To)
	}
	return path
}

func (f *stickyFakeObs) snapshot() (excluded map[string]bool, excludedFor map[string]time.Duration, closed, verifies []string, probes [][]string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	excluded = map[string]bool{}
	for k, v := range f.excluded {
		if v {
			excluded[k] = true
		}
	}
	excludedFor = map[string]time.Duration{}
	for k, v := range f.excludedFor {
		excludedFor[k] = v
	}
	return excluded, excludedFor, slices.Clone(f.closedTags), slices.Clone(f.verifies), slices.Clone(f.probes)
}

// 3 рабочих узла: текущий не проверяется и не исключается, нажатия идут по
// кругу A→B→C→A→B (без A→B→A), соединения прежнего закрываются.
func TestVupenCheckRouteSwitchRotatesThree(t *testing.T) {
	r, rt := switchRig(t)
	checksBefore := r.obs.checkCount()
	path := pressSeq(t, r, rt, 4)
	if want := []string{"p-1", "p-2", "p-3", "p-1", "p-2"}; !slices.Equal(path, want) {
		t.Fatalf("path %v, want %v", path, want)
	}
	excluded, excludedFor, closed, _, _ := r.obs.snapshot()
	if len(excluded) != 0 || len(excludedFor) != 0 {
		t.Fatalf("switch must not exclude anything: %v %v", excluded, excludedFor)
	}
	if want := []string{"p-1", "p-2", "p-3", "p-1"}; !slices.Equal(closed, want) {
		t.Fatalf("closed %v, want %v", closed, want)
	}
	if r.obs.routeCount() != 0 || r.obs.checkCount() != checksBefore {
		t.Fatalf("the current node is not checked: route=%d checks=%v", r.obs.routeCount(), r.obs.checks)
	}
	st := autoState(t, rt)
	if st.Phase != "holding" || st.Current.Tag != "p-2" || st.LastSwitch.Reason != "switch" || st.LastSwitch.From != "p-1" ||
		st.LastCheckRoute.Mode != "switch" || st.LastCheckRoute.Verdict != vupenRouteSwitched || st.Notice != "" || st.FailedChecks != 0 {
		t.Fatalf("state: %+v", st)
	}
}

// 2 рабочих узла (p-3 не отвечает на пробы): A→B→A→B.
func TestVupenCheckRouteSwitchTwoPingPong(t *testing.T) {
	r, rt := switchRig(t)
	r.alive(map[string]int64{"p-1": 900, "p-2": 10})
	path := pressSeq(t, r, rt, 3)
	if want := []string{"p-1", "p-2", "p-1", "p-2"}; !slices.Equal(path, want) {
		t.Fatalf("path %v, want %v", path, want)
	}
	_, _, _, verifies, _ := r.obs.snapshot()
	if slices.Contains(verifies, "p-3") {
		t.Fatalf("a node that does not answer probes is not downloaded through: %v", verifies)
	}
}

// 1 рабочий узел: no_alternative, остаёмся на нём, ничего не закрыто и не исключено,
// «нет рабочих» нет; список перебора не меняется.
func TestVupenCheckRouteSwitchNoAlternative(t *testing.T) {
	r, rt := switchRig(t)
	r.alive(map[string]int64{"p-1": 900})
	resp := press(t, rt, "")
	if resp.Verdict != vupenRouteNoAlternative || resp.From != "p-1" || resp.To != "p-1" || resp.Tried != 0 || resp.Closed != 0 ||
		!strings.Contains(resp.Detail, "kept p-1") {
		t.Fatalf("switch: %+v", resp)
	}
	excluded, _, closed, _, _ := r.obs.snapshot()
	if len(excluded) != 0 || len(closed) != 0 || r.s.viewTag() != "p-1" {
		t.Fatalf("excluded %v closed %v view %s", excluded, closed, r.s.viewTag())
	}
	st := autoState(t, rt)
	if st.Phase != "holding" || st.NoWorking || st.Notice != "" || st.Current.Tag != "p-1" || st.LastCheckRoute.Verdict != vupenRouteNoAlternative {
		t.Fatalf("state: %+v", st)
	}

	// Другой отвечает на пробы, но 64 КБ не проходит: проверен, остаёмся (провал
	// кандидата — обычное исключение по провалу, текущий не трогаем).
	r.alive(map[string]int64{"p-1": 900, "p-2": 10})
	r.obs.mu.Lock()
	r.obs.verify["p-2"] = vupenStickyFailed
	r.obs.mu.Unlock()
	resp = press(t, rt, "")
	if resp.Verdict != vupenRouteNoAlternative || resp.Tried != 1 || resp.To != "p-1" {
		t.Fatalf("switch with a failing candidate: %+v", resp)
	}
	if st := autoState(t, rt); st.Phase != "holding" || st.FailedChecks != 0 || st.Notice != "" {
		t.Fatalf("a failing candidate is not a failure of the current node: %+v", st)
	}
	// Список не менялся: p-2 ожил — первое же нажатие идёт на него.
	r.obs.mu.Lock()
	r.obs.verify["p-2"] = vupenStickyOK
	r.obs.excluded["p-2"] = false
	r.obs.mu.Unlock()
	if resp := press(t, rt, ""); resp.Verdict != vupenRouteSwitched || resp.To != "p-2" {
		t.Fatalf("after recovery: %+v", resp)
	}
}

// Узел, исключённый по провалу (heal, сторож), не кандидат ни в первом круге, ни в следующем.
func TestVupenCheckRouteSwitchSkipsDeadExcluded(t *testing.T) {
	r, rt := switchRig(t)
	r.obs.VupenStickyExclude("p-3", "test: dead")
	path := pressSeq(t, r, rt, 3)
	if want := []string{"p-1", "p-2", "p-1", "p-2"}; !slices.Equal(path, want) {
		t.Fatalf("path %v, want %v", path, want)
	}
	_, _, _, verifies, probes := r.obs.snapshot()
	for _, p := range probes {
		if slices.Contains(p, "p-3") {
			t.Fatalf("an excluded node is probed: %v", probes)
		}
	}
	if slices.Contains(verifies, "p-3") {
		t.Fatalf("an excluded node is verified: %v", verifies)
	}
}

// maxSwitches ограничивает число проверок, closeConnections=false — ничего не закрывать.
func TestVupenCheckRouteSwitchOptions(t *testing.T) {
	r, rt := switchRig(t)
	r.obs.mu.Lock()
	r.obs.verify["p-2"] = vupenStickyFailed
	r.obs.mu.Unlock()
	resp := press(t, rt, `,"maxSwitches":1,"closeConnections":false`)
	if resp.Verdict != vupenRouteNoAlternative || resp.Tried != 1 {
		t.Fatalf("one check allowed: %+v", resp)
	}
	resp = press(t, rt, `,"closeConnections":false,"excludeMin":30`)
	if resp.Verdict != vupenRouteSwitched || resp.To != "p-3" || resp.Closed != 0 {
		t.Fatalf("switch: %+v", resp)
	}
	_, excludedFor, closed, _, _ := r.obs.snapshot()
	if len(closed) != 0 || excludedFor["p-1"] != 0 {
		t.Fatalf("closed %v, excludedFor %v", closed, excludedFor)
	}
}

// Смена сети (эпоха ядра 74) очищает список перебора.
func TestVupenCheckRouteSwitchNetworkChangeResetsRotation(t *testing.T) {
	r, rt := switchRig(t)
	if path := pressSeq(t, r, rt, 2); !slices.Equal(path, []string{"p-1", "p-2", "p-3"}) {
		t.Fatalf("path %v", path)
	}
	// Без смены сети третье нажатие ушло бы на p-1 (с него ушли раньше всех).
	run := time.Now().UnixNano()
	t.Cleanup(func() { internet.VupenSetUplink("wifi", fmt.Sprintf("switch-test-back-%d", run)) })
	// Первое сообщение процесса — не смена: две подписи подряд (уникальны на прогон).
	internet.VupenSetUplink("wifi", fmt.Sprintf("switch-test-wifi-%d", run))
	internet.VupenSetUplink("cellular", fmt.Sprintf("switch-test-cell-%d", run))
	if resp := press(t, rt, ""); resp.Verdict != vupenRouteSwitched || resp.To != "p-2" {
		t.Fatalf("after a network change the order starts over (strategy order): %+v", resp)
	}
}

// Рабочих не было и до запроса: поиск сразу; нашёлся — switched, нет — no_working.
func TestVupenCheckRouteSwitchWhenNoWorking(t *testing.T) {
	r := newStickyRig(t, "", "p-1", "p-1", "p-2")
	rt := routerWith(map[string]*Balancer{"REG": r.b})
	if resp := press(t, rt, ""); resp.Verdict != vupenRouteUnknown || !strings.Contains(resp.Detail, "not started") {
		t.Fatalf("not started: %+v", resp)
	}
	r.pick()
	r.drain()
	r.expectPhase(vupenPhaseNoWorking)
	go r.s.loop()
	if resp := press(t, rt, ""); resp.Verdict != vupenRouteNoWorking {
		t.Fatalf("still nothing: %+v", resp)
	}
	r.alive(map[string]int64{"p-2": 10})
	r.obs.mu.Lock()
	r.obs.verify["p-2"] = vupenStickyOK
	r.obs.mu.Unlock()
	if resp := press(t, rt, ""); resp.Verdict != vupenRouteSwitched || resp.To != "p-2" {
		t.Fatalf("found: %+v", resp)
	}
}

// Обработчик не успел — unknown через VupenCheckRouteHealWait, без зависания.
func TestVupenCheckRouteSwitchWaitBounded(t *testing.T) {
	r := holdingRig(t) // обработчик не запущен
	rt := routerWith(map[string]*Balancer{"REG": r.b})
	old := VupenCheckRouteHealWait
	VupenCheckRouteHealWait = 50 * time.Millisecond
	t.Cleanup(func() { VupenCheckRouteHealWait = old })
	if resp := press(t, rt, ""); resp.Verdict != vupenRouteUnknown || !strings.Contains(resp.Detail, "still switching") {
		t.Fatalf("switch: %+v", resp)
	}
}

// Без АВТО 4.1 в конфиге (нет vupenSticky) — unknown, ничего не происходит.
func TestVupenCheckRouteSwitchGated(t *testing.T) {
	plain := &Balancer{selectors: []string{"p"}, strategy: &LeastPingStrategy{}, ohm: &stickyFakeOhm{tags: []string{"p-1", "p-2"}}}
	rt := routerWith(map[string]*Balancer{"REG": plain})
	if resp := press(t, rt, ""); resp.Verdict != vupenRouteUnknown || !strings.Contains(resp.Detail, "no AUTO 4.1 balancer") {
		t.Fatalf("no sticky: %+v", resp)
	}
	r := holdingRig(t)
	rt = routerWith(map[string]*Balancer{"REG": r.b})
	for _, req := range []string{`{"v":1,"mode":"switch","maxSwitches":11}`, `{"v":1,"mode":"Switch"}`} {
		if resp := route(t, rt, req); resp.Verdict != vupenRouteUnknown || !strings.HasPrefix(resp.Detail, "bad request") {
			t.Fatalf("%s → %+v", req, resp)
		}
	}
}

// Сотовая, REG держит p-1, других рабочих в REG нет, LTE жив: no_alternative,
// перелива в LTE нет (switch не переливает никогда).
func TestVupenCheckRouteSwitchNeverSpills(t *testing.T) {
	r := newSpillRig(t, []string{"cellular"}, []string{"p-1", "p-2", "p-3"}, []string{"lte-1", "lte-2"})
	r.alive(map[string]int64{"p-1": 10, "lte-1": 40, "lte-2": 50})
	r.obs.mu.Lock()
	r.obs.verify["p-1"] = vupenStickyOK
	r.obs.verify["lte-1"] = vupenStickyOK
	r.obs.verify["lte-2"] = vupenStickyOK
	r.obs.mu.Unlock()
	r.pick()
	r.drain()
	if r.reg.getPhase() != vupenPhaseHolding || r.pick() != "p-1" {
		t.Fatalf("setup: %v %s", r.reg.getPhase(), r.pick())
	}
	rt := routerWith(map[string]*Balancer{"REG": r.regB, "LTE": r.lteB})
	go r.reg.loop()
	resp := press(t, rt, "")
	if resp.Verdict != vupenRouteNoAlternative || resp.Balancer != "REG" || resp.To != "p-1" {
		t.Fatalf("switch: %+v", resp)
	}
	if r.reg.spilledNow() || r.probedLTE() || r.pick() != "p-1" || r.reg.getPhase() != vupenPhaseHolding {
		t.Fatalf("no spill: spilled=%v probedLTE=%v pick=%s", r.reg.spilledNow(), r.probedLTE(), r.pick())
	}
}

// REG «нет рабочих» на Wi-Fi (перелив запрещён), потом сеть сотовая: switch ищет
// по REG, но не переливает; дальше — обычный повтор по графику.
func TestVupenCheckRouteSwitchNoWorkingDoesNotSpill(t *testing.T) {
	r := newSpillRig(t, []string{"cellular"}, []string{"p-1", "p-2"}, []string{"lte-1"})
	r.kind = "wifi"
	r.alive(map[string]int64{"lte-1": 40})
	r.obs.mu.Lock()
	r.obs.verify["lte-1"] = vupenStickyOK
	r.obs.mu.Unlock()
	r.pick()
	r.drain()
	if r.reg.getPhase() != vupenPhaseNoWorking || r.reg.spilledNow() {
		t.Fatalf("setup: %v spilled=%v", r.reg.getPhase(), r.reg.spilledNow())
	}
	r.kind = "cellular"
	rt := routerWith(map[string]*Balancer{"REG": r.regB, "LTE": r.lteB})
	go r.reg.loop()
	if resp := press(t, rt, ""); resp.Verdict != vupenRouteNoWorking || resp.Balancer != "REG" {
		t.Fatalf("switch: %+v", resp)
	}
	if r.reg.spilledNow() || r.probedLTE() {
		t.Fatalf("switch must not spill: spilled=%v probedLTE=%v", r.reg.spilledNow(), r.probedLTE())
	}
	if p := r.clock.pendingIn(); len(p) == 0 {
		t.Fatal("the regular retry stays scheduled")
	}
}

// Перелито: switch меняет узел внутри LTE (выбирает LTE), REG остаётся перелитым.
func TestVupenCheckRouteSwitchInsideLTE(t *testing.T) {
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
	r.obs.verify["lte-1"] = vupenStickyOK
	r.obs.excluded["lte-1"] = false
	r.obs.mu.Unlock()
	rt := routerWith(map[string]*Balancer{"REG": r.regB, "LTE": r.lteB})
	go r.lte.loop()
	resp := press(t, rt, "")
	if resp.Verdict != vupenRouteSwitched || resp.Balancer != "LTE" || resp.From != "lte-2" || resp.To != "lte-1" {
		t.Fatalf("switch: %+v", resp)
	}
	if !r.reg.spilledNow() || r.pick() != "lte-1" {
		t.Fatalf("still spilled, via lte-1: spilled=%v pick=%s", r.reg.spilledNow(), r.pick())
	}
}
