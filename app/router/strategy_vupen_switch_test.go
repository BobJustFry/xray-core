package router

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/transport/internet"
)

// Ядро 79–80 (D-42, D-43): VupenCheckRoute(switch) — кнопка «Сменить сервер».

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

// pressSeq — нажатия подряд; каждое должно сменить узел не больше чем за maxTried
// проверок 64 КБ. Возвращает путь узлов.
func pressSeq(t *testing.T, r *stickyRig, rt *Router, n, maxTried int) []string {
	t.Helper()
	path := []string{r.s.viewTag()}
	for i := 0; i < n; i++ {
		resp := press(t, rt, "")
		if resp.Verdict != vupenRouteSwitched || resp.From != path[len(path)-1] || resp.To == resp.From || resp.Balancer != "REG" ||
			resp.Tried < 1 || resp.Tried > maxTried {
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

func (f *stickyFakeObs) setRecent(m map[string]time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.recent = m
}

func flat(batches [][]string) []string {
	var all []string
	for _, b := range batches {
		all = append(all, b...)
	}
	return all
}

// Свежий кэш обсерватории: 4 нажатия A→B→C→A→B, по одной проверке 64 КБ на
// нажатие, ни раунда проб, ни быстрых проб; текущий не проверяется и не исключается.
func TestVupenCheckRouteSwitchRotatesThreeFromCache(t *testing.T) {
	r, rt := switchRig(t)
	r.obs.setRecent(map[string]time.Duration{"p-1": 900 * time.Millisecond, "p-2": 10 * time.Millisecond, "p-3": 20 * time.Millisecond})
	checksBefore := r.obs.checkCount()
	path := pressSeq(t, r, rt, 4, 1)
	if want := []string{"p-1", "p-2", "p-3", "p-1", "p-2"}; !slices.Equal(path, want) {
		t.Fatalf("path %v, want %v", path, want)
	}
	excluded, excludedFor, closed, verifies, probes := r.obs.snapshot()
	if len(excluded) != 0 || len(excludedFor) != 0 {
		t.Fatalf("switch must not exclude anything: %v %v", excluded, excludedFor)
	}
	if len(probes) != 0 || len(r.obs.quickBatches()) != 0 || len(verifies) != 4 {
		t.Fatalf("cache only: probes %v quick %v verifies %v", probes, r.obs.quickBatches(), verifies)
	}
	if want := []string{"p-1", "p-2", "p-3", "p-1"}; !slices.Equal(closed, want) {
		t.Fatalf("closed %v, want %v", closed, want)
	}
	if r.obs.routeCount() != 0 || r.obs.checkCount() != checksBefore {
		t.Fatalf("the current node is not checked: route=%d checks=%v", r.obs.routeCount(), r.obs.checks)
	}
	st := autoState(t, rt)
	if st.Phase != "holding" || st.Current.Tag != "p-2" || st.LastSwitch.Reason != "switch" || st.LastSwitch.From != "p-1" ||
		st.LastSwitch.To != "p-2" || st.LastSwitch.AtMs == 0 || st.LastCheckRoute.Mode != "switch" ||
		st.LastCheckRoute.Verdict != vupenRouteSwitched || st.Notice != "" || st.FailedChecks != 0 {
		t.Fatalf("state: %+v", st)
	}
}

// Кэша нет: быстрые пробы — одна пачка на нажатие, первый ответивший проверяется
// первым; полного раунда обсерватории нет.
func TestVupenCheckRouteSwitchRotatesThreeByQuickProbe(t *testing.T) {
	r, rt := switchRig(t)
	path := pressSeq(t, r, rt, 4, 1)
	if want := []string{"p-1", "p-2", "p-3", "p-1", "p-2"}; !slices.Equal(path, want) {
		t.Fatalf("path %v, want %v", path, want)
	}
	_, _, _, _, probes := r.obs.snapshot()
	if len(probes) != 0 {
		t.Fatalf("no observatory round: %v", probes)
	}
	// 1: [p-2 p-3]; 2: [p-3] (p-1 уже был); 3: свежих нет → круг заново [p-1 p-2]; 4: [p-2].
	got := fmt.Sprint(r.obs.quickBatches())
	if want := "[[p-2 p-3] [p-3] [p-1 p-2] [p-2]]"; got != want {
		t.Fatalf("quick probe batches %s, want %s", got, want)
	}
}

// 2 рабочих узла (p-3 молчит): A→B→A→B.
func TestVupenCheckRouteSwitchTwoPingPong(t *testing.T) {
	r, rt := switchRig(t)
	r.alive(map[string]int64{"p-1": 900, "p-2": 10})
	path := pressSeq(t, r, rt, 3, 1)
	if want := []string{"p-1", "p-2", "p-1", "p-2"}; !slices.Equal(path, want) {
		t.Fatalf("path %v, want %v", path, want)
	}
	_, _, _, verifies, _ := r.obs.snapshot()
	if slices.Contains(verifies, "p-3") {
		t.Fatalf("a node that does not answer is not downloaded through: %v", verifies)
	}
}

// Мёртвые не мешают: свежий провал в кэше — узел не пробуется вовсе; молчащий в
// пробе — не проверяется, выбирается ответивший.
func TestVupenCheckRouteSwitchDeadNodesDoNotBlock(t *testing.T) {
	r, rt := switchRig(t)
	r.obs.setRecent(map[string]time.Duration{"p-2": -1})
	r.obs.mu.Lock()
	r.obs.quickDelay = map[string]time.Duration{"p-3": 30 * time.Millisecond, "p-2": 10 * time.Millisecond}
	r.obs.mu.Unlock()
	resp := press(t, rt, "")
	if resp.Verdict != vupenRouteSwitched || resp.To != "p-3" || resp.Tried != 1 {
		t.Fatalf("switch: %+v", resp)
	}
	if b := flat(r.obs.quickBatches()); slices.Contains(b, "p-2") {
		t.Fatalf("a fresh failure is not probed again: %v", b)
	}
}

// Пачки по VupenSwitchProbeBatch: в первой никто не ответил — вторая; выбран
// первый ответивший второй пачки.
func TestVupenCheckRouteSwitchProbesInBatches(t *testing.T) {
	var tags []string
	for i := 1; i <= 20; i++ {
		tags = append(tags, fmt.Sprintf("p-%02d", i))
	}
	r := newStickyRig(t, "p-01", "p-01", tags...)
	r.pick()
	r.drain()
	r.expectPhase(vupenPhaseHolding)
	r.obs.mu.Lock()
	r.obs.quickDelay = map[string]time.Duration{"p-13": 40 * time.Millisecond, "p-12": 90 * time.Millisecond}
	r.obs.verify["p-12"], r.obs.verify["p-13"] = vupenStickyOK, vupenStickyOK
	r.obs.mu.Unlock()
	go r.s.loop()
	rt := routerWith(map[string]*Balancer{"REG": r.b})
	resp := press(t, rt, "")
	if resp.Verdict != vupenRouteSwitched || resp.To != "p-13" || resp.Tried != 1 {
		t.Fatalf("switch: %+v", resp)
	}
	b := r.obs.quickBatches()
	if len(b) != 2 || len(b[0]) != VupenSwitchProbeBatch || b[0][0] != "p-02" || b[1][0] != "p-10" {
		t.Fatalf("batches %v", b)
	}
}

// Кэш старше VupenSwitchCacheMaxAge или до смены сети — не годится: быстрые пробы.
func TestVupenCheckRouteSwitchStaleCacheFallsBackToProbe(t *testing.T) {
	r, rt := switchRig(t)
	r.obs.setRecent(map[string]time.Duration{"p-2": 10 * time.Millisecond, "p-3": 20 * time.Millisecond})
	r.obs.mu.Lock()
	r.obs.recentAge = map[string]time.Duration{"p-2": 6 * time.Minute, "p-3": 2 * time.Minute}
	r.obs.mu.Unlock()
	// Сеть сменилась минуту назад: замер p-3 (2 мин) — прежней сети.
	r.s.signals.mu.Lock()
	r.s.signals.netChangedAt = vupenStickyNow().Add(-time.Minute)
	r.s.signals.mu.Unlock()
	resp := press(t, rt, "")
	if resp.Verdict != vupenRouteSwitched || resp.To != "p-2" {
		t.Fatalf("switch: %+v", resp)
	}
	r.obs.mu.Lock()
	asks := slices.Clone(r.obs.recentAsks)
	r.obs.mu.Unlock()
	if len(asks) != 1 || asks[0] != time.Minute {
		t.Fatalf("cache age limited by the network change: %v", asks)
	}
	if b := r.obs.quickBatches(); len(b) != 1 || !slices.Equal(b[0], []string{"p-2", "p-3"}) {
		t.Fatalf("stale cache → quick probe: %v", b)
	}
}

// 1 рабочий узел: no_alternative, остаёмся на нём, ничего не закрыто и не
// исключено, «нет рабочих» нет; кандидат, не прошедший 64 КБ, — не провал текущего.
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
}

// Узел, исключённый по провалу (heal, сторож), не кандидат ни в кэше, ни в пробах.
func TestVupenCheckRouteSwitchSkipsDeadExcluded(t *testing.T) {
	r, rt := switchRig(t)
	r.obs.setRecent(map[string]time.Duration{"p-3": 5 * time.Millisecond})
	r.obs.VupenStickyExclude("p-3", "test: dead")
	path := pressSeq(t, r, rt, 3, 1)
	if want := []string{"p-1", "p-2", "p-1", "p-2"}; !slices.Equal(path, want) {
		t.Fatalf("path %v, want %v", path, want)
	}
	_, _, _, verifies, _ := r.obs.snapshot()
	if slices.Contains(flat(r.obs.quickBatches()), "p-3") || slices.Contains(verifies, "p-3") {
		t.Fatalf("an excluded node is probed or verified: %v %v", r.obs.quickBatches(), verifies)
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

// slowVerifyObs — проверка 64 КБ, которая идёт wait (замороженный узел).
type slowVerifyObs struct {
	*stickyFakeObs
	wait time.Duration
}

func (o *slowVerifyObs) VupenStickyVerify(tag string) string {
	time.Sleep(o.wait)
	return o.stickyFakeObs.VupenStickyVerify(tag)
}

// Бюджет switch: долгая проверка не держит ответ дольше VupenSwitchBudget; вышло
// время, а непроверенные остались — failed (CR-002), а не no_alternative.
func TestVupenCheckRouteSwitchBudget(t *testing.T) {
	r, rt := switchRig(t)
	old := VupenSwitchBudget
	VupenSwitchBudget = 100 * time.Millisecond
	t.Cleanup(func() { VupenSwitchBudget = old })
	var so vupenStickyObservatory = &slowVerifyObs{stickyFakeObs: r.obs, wait: 400 * time.Millisecond}
	r.s.obs.Store(&so)
	start := time.Now()
	resp := press(t, rt, "")
	if resp.Verdict != vupenRouteFailed || resp.Tried != 1 || resp.From != "p-1" || resp.To != "p-1" ||
		!strings.Contains(resp.Detail, "2 candidates unchecked") || time.Since(start) > 300*time.Millisecond {
		t.Fatalf("switch after %s: %+v", time.Since(start), resp)
	}
	if st := autoState(t, rt); st.Phase != "holding" || st.Current.Tag != "p-1" {
		t.Fatalf("stays on the current node: %+v", st)
	}
	time.Sleep(400 * time.Millisecond) // проверка в фоне доходит
}

// Пока ядро само выбирает узел (new / поиск при старте) — сразу busy_searching,
// второй поиск не ставится.
func TestVupenCheckRouteSwitchBusySearching(t *testing.T) {
	r := newStickyRig(t, "", "p-1", "p-1", "p-2")
	rt := routerWith(map[string]*Balancer{"REG": r.b})
	if resp := press(t, rt, ""); resp.Verdict != vupenRouteBusySearching || !strings.Contains(resp.Detail, "not chosen a node yet") {
		t.Fatalf("new: %+v", resp)
	}
	r.pick() // старт: поиск в очереди
	r.expectPhase(vupenPhaseSearching)
	start := time.Now()
	if resp := press(t, rt, ""); resp.Verdict != vupenRouteBusySearching || !strings.Contains(resp.Detail, "searching") ||
		time.Since(start) > time.Second {
		t.Fatalf("searching: %+v", resp)
	}
	if n := len(r.s.events); n != 1 {
		t.Fatalf("only the start search is queued: %d events", n)
	}
	// И внутри обработчика (запрос прошёл до начала поиска).
	h := &vupenHealReq{q: vupenRouteReq{Mode: vupenRouteSwitchMode}, reply: make(chan vupenRouteResp, 1)}
	if resp := r.s.switchRoute(h); resp.Verdict != vupenRouteBusySearching {
		t.Fatalf("handler: %+v", resp)
	}
}

// Итог, пришедший позже ожидания, виден в VupenAutoState: lastSwitch switch/from/to/atMs.
func TestVupenCheckRouteSwitchLateResultInAutoState(t *testing.T) {
	r := holdingRig(t) // обработчик не запущен
	rt := routerWith(map[string]*Balancer{"REG": r.b})
	r.obs.mu.Lock()
	r.obs.verify["p-2"] = vupenStickyOK
	r.obs.mu.Unlock()
	old := VupenCheckRouteHealWait
	VupenCheckRouteHealWait = 30 * time.Millisecond
	t.Cleanup(func() { VupenCheckRouteHealWait = old })
	if resp := press(t, rt, ""); resp.Verdict != vupenRouteUnknown || !strings.Contains(resp.Detail, "still switching") {
		t.Fatalf("switch: %+v", resp)
	}
	r.drain() // обработчик доходит до запроса позже
	st := autoState(t, rt)
	if st.Current.Tag != "p-2" || st.LastSwitch.Reason != "switch" || st.LastSwitch.From != "p-1" || st.LastSwitch.To != "p-2" ||
		st.LastSwitch.AtMs == 0 {
		t.Fatalf("late switch not visible: %+v", st.LastSwitch)
	}
}

// Смена сети (эпоха ядра 74) очищает список перебора.
func TestVupenCheckRouteSwitchNetworkChangeResetsRotation(t *testing.T) {
	r, rt := switchRig(t)
	if path := pressSeq(t, r, rt, 2, 1); !slices.Equal(path, []string{"p-1", "p-2", "p-3"}) {
		t.Fatalf("path %v", path)
	}
	// Без смены сети третье нажатие ушло бы на p-1 (с него ушли раньше всех).
	run := time.Now().UnixNano()
	t.Cleanup(func() { internet.VupenSetUplink("wifi", fmt.Sprintf("switch-test-back-%d", run)) })
	// Первое сообщение процесса — не смена: две подписи подряд (уникальны на прогон).
	internet.VupenSetUplink("wifi", fmt.Sprintf("switch-test-wifi-%d", run))
	internet.VupenSetUplink("cellular", fmt.Sprintf("switch-test-cell-%d", run))
	if resp := press(t, rt, ""); resp.Verdict != vupenRouteSwitched || resp.To != "p-2" {
		t.Fatalf("after a network change the order starts over: %+v", resp)
	}
}

// Рабочих не было и до запроса: быстрый поиск сразу; нашёлся — switched, нет — no_working.
func TestVupenCheckRouteSwitchWhenNoWorking(t *testing.T) {
	r := newStickyRig(t, "", "p-1", "p-1", "p-2")
	rt := routerWith(map[string]*Balancer{"REG": r.b})
	r.pick()
	r.drain()
	r.expectPhase(vupenPhaseNoWorking)
	go r.s.loop()
	if resp := press(t, rt, ""); resp.Verdict != vupenRouteNoWorking {
		t.Fatalf("still nothing: %+v", resp)
	}
	r.expectPhase(vupenPhaseNoWorking)
	r.alive(map[string]int64{"p-2": 10})
	r.obs.mu.Lock()
	r.obs.verify["p-2"] = vupenStickyOK
	r.obs.mu.Unlock()
	if resp := press(t, rt, ""); resp.Verdict != vupenRouteSwitched || resp.To != "p-2" {
		t.Fatalf("found: %+v", resp)
	}
	r.expectPhase(vupenPhaseHolding)
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

func (r *spillRig) touchedLTE() bool {
	if r.probedLTE() {
		return true
	}
	for _, tag := range flat(r.obs.quickBatches()) {
		if strings.HasPrefix(tag, "lte-") {
			return true
		}
	}
	return false
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
	if r.reg.spilledNow() || r.touchedLTE() || r.pick() != "p-1" || r.reg.getPhase() != vupenPhaseHolding {
		t.Fatalf("no spill: spilled=%v touchedLTE=%v pick=%s", r.reg.spilledNow(), r.touchedLTE(), r.pick())
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
	if r.reg.spilledNow() || r.touchedLTE() {
		t.Fatalf("switch must not spill: spilled=%v touchedLTE=%v", r.reg.spilledNow(), r.touchedLTE())
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
	if b := flat(r.obs.quickBatches()); slices.ContainsFunc(b, func(t string) bool { return strings.HasPrefix(t, "p-") }) {
		t.Fatalf("switch inside LTE does not touch REG: %v", b)
	}
}

// Круг заново строго с того, с кого ушли раньше всех: недавно ответивший (в кэше)
// и быстрый p-2 ждёт, пока ответит более давний p-1 — без C→B после B→C.
func TestVupenCheckRouteSwitchNextRoundKeepsOrder(t *testing.T) {
	r, rt := switchRig(t)
	if path := pressSeq(t, r, rt, 2, 1); !slices.Equal(path, []string{"p-1", "p-2", "p-3"}) {
		t.Fatalf("path %v", path)
	}
	r.obs.setRecent(map[string]time.Duration{"p-2": 10 * time.Millisecond}) // p-1 — без свежего замера
	r.obs.mu.Lock()
	r.obs.quickDelay = map[string]time.Duration{"p-1": 900 * time.Millisecond}
	r.obs.mu.Unlock()
	resp := press(t, rt, "")
	if resp.Verdict != vupenRouteSwitched || resp.To != "p-1" || resp.Tried != 1 {
		t.Fatalf("next round: %+v", resp)
	}
	if b := r.obs.quickBatches(); !slices.Equal(b[len(b)-1], []string{"p-1"}) {
		t.Fatalf("only p-1 is probed, p-2 comes from the cache: %v", b)
	}
}

// CR-001: после busy_searching приложение узнаёт итог по VupenAutoState —
// lastSwitch обновляет любой переход текущего узла с настоящей причиной.
func TestVupenCheckRouteSwitchBusyThenSearchResultInLastSwitch(t *testing.T) {
	r := newStickyRig(t, "", "p-1", "p-1", "p-2")
	rt := routerWith(map[string]*Balancer{"REG": r.b})
	r.alive(map[string]int64{"p-2": 10})
	r.obs.mu.Lock()
	r.obs.verify["p-2"] = vupenStickyOK
	r.obs.mu.Unlock()
	r.pick()
	if resp := press(t, rt, ""); resp.Verdict != vupenRouteBusySearching {
		t.Fatalf("switch: %+v", resp)
	}
	r.drain() // стартовый поиск
	st := autoState(t, rt)
	if st.Phase != "holding" || st.Current.Tag != "p-2" || st.LastSwitch.Reason != "search" || st.LastSwitch.To != "p-2" ||
		st.LastSwitch.AtMs == 0 {
		t.Fatalf("search result: %+v", st.LastSwitch)
	}
	// Проверка текущего не прошла → поиск сменил узел: reason "search" с from.
	r.alive(map[string]int64{"p-1": 20})
	r.obs.mu.Lock()
	r.obs.check["p-2"] = vupenStickyFailed
	r.obs.verify["p-1"] = vupenStickyOK
	r.obs.mu.Unlock()
	r.clock.Advance(time.Second)
	r.s.requestCheck("test")
	r.drain()
	st = autoState(t, rt)
	if st.Current.Tag != "p-1" || st.LastSwitch.Reason != "search" || st.LastSwitch.From != "p-2" || st.LastSwitch.To != "p-1" {
		t.Fatalf("failure search: %+v", st.LastSwitch)
	}
}
