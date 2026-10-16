package router

import (
	"encoding/json"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/observatory/burst"
	"github.com/xtls/xray-core/transport/internet"
)

// ── fake: то, что VupenCheckRoute просит у обсерватории (ядро 78) ───────────

func (f *stickyFakeObs) VupenStickyCheckWith(tag string, opt burst.VupenCheckOptions) burst.VupenCheckResult {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.routeChecks = append(f.routeChecks, tag)
	f.routeOpts = append(f.routeOpts, opt)
	if r, ok := f.route[tag]; ok {
		return r
	}
	v := f.check[tag]
	if v == "" {
		v = vupenStickyOK
	}
	r := burst.VupenCheckResult{Verdict: v, Detail: "fake " + v}
	if v != vupenStickyOK {
		r.Kind = "error"
	}
	return r
}

func (f *stickyFakeObs) VupenStickyExcludeFor(tag, reason string, d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.excluded[tag] = true
	if f.excludedFor == nil {
		f.excludedFor = map[string]time.Duration{}
	}
	f.excludedFor[tag] = d
}

func (f *stickyFakeObs) VupenStickyCloseConns(tag string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closedTags = append(f.closedTags, tag)
	return 2
}

// VupenStickyRecent — кэш замеров не старше maxAge (возраст — recentAge, по умолчанию 0).
func (f *stickyFakeObs) VupenStickyRecent(tags []string, maxAge time.Duration) map[string]time.Duration {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.recentAsks = append(f.recentAsks, maxAge)
	out := map[string]time.Duration{}
	for _, t := range tags {
		if d, ok := f.recent[t]; ok && f.recentAge[t] <= maxAge {
			out[t] = d
		}
	}
	return out
}

// VupenStickyQuickProbe — ответы по возрастанию задержки (quickDelay, иначе delay),
// затем провалы (узлы без задержки или с задержкой больше timeout) — в порядке пачки.
func (f *stickyFakeObs) VupenStickyQuickProbe(tags []string, timeout time.Duration, deadline time.Time,
	each func(tag string, rtt time.Duration, ok bool) bool) int {
	if timeout <= 0 {
		timeout = burst.VupenQuickProbeTimeout
	}
	f.mu.Lock()
	f.quick = append(f.quick, append([]string(nil), tags...))
	type ans struct {
		tag string
		d   time.Duration
	}
	var answers []ans
	var silent []string
	for _, t := range tags {
		d, ok := time.Duration(0), false
		if f.quickDelay != nil {
			d, ok = f.quickDelay[t]
		} else if ms, alive := f.delay[t]; alive && !f.excluded[t] {
			d, ok = time.Duration(ms)*time.Millisecond, true
		}
		if ok && d <= timeout {
			answers = append(answers, ans{t, d})
		} else {
			silent = append(silent, t)
		}
	}
	f.mu.Unlock()
	sort.SliceStable(answers, func(i, j int) bool { return answers[i].d < answers[j].d })
	n := 0
	for _, a := range answers {
		n++
		if each(a.tag, a.d, true) {
			return n
		}
	}
	for _, t := range silent {
		if each(t, 0, false) {
			return n
		}
	}
	return n
}

func (f *stickyFakeObs) quickBatches() [][]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.quick)
}

func (f *stickyFakeObs) setRoute(tag, verdict, kind string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.route == nil {
		f.route = map[string]burst.VupenCheckResult{}
	}
	f.route[tag] = burst.VupenCheckResult{Verdict: verdict, Kind: kind, Detail: "fake " + kind}
}

func (f *stickyFakeObs) routeCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.routeChecks)
}

func routerWith(balancers map[string]*Balancer) *Router {
	r := &Router{}
	r.balancers.Store(&balancers)
	return r
}

// route — VupenCheckRoute с разбором ответа.
func route(t *testing.T, r *Router, req string) vupenRouteResp {
	t.Helper()
	var resp vupenRouteResp
	if err := json.Unmarshal([]byte(r.VupenCheckRoute(req)), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.V != 1 {
		t.Fatalf("v=%d", resp.V)
	}
	return resp
}

// healRig — держим p-1 из p-1…p-3, обработчик работает по-настоящему (heal идёт через очередь).
func healRig(t *testing.T) (*stickyRig, *Router) {
	t.Helper()
	r := holdingRig(t)
	go r.s.loop()
	return r, routerWith(map[string]*Balancer{"REG": r.b})
}

// ── запрос ──────────────────────────────────────────────────────────────────

// Неверный запрос и «ядро не запущено» — verdict unknown + detail, без паники.
func TestVupenCheckRouteBadRequests(t *testing.T) {
	r := holdingRig(t)
	rt := routerWith(map[string]*Balancer{"REG": r.b})
	for _, req := range []string{
		``, `{`, `[]`, `{"v":1}`, `{"v":1,"mode":"fix"}`,
		`{"v":1,"mode":"check","bytes":-1}`, `{"v":1,"mode":"check","timeoutMs":600000}`,
		`{"v":1,"mode":"heal","maxSwitches":11}`, `{"v":1,"mode":"heal","excludeMin":-5}`,
		`{"v":1,"mode":"check","url":"http://vupen.fun/24k.bin"}`,
		`{"v":1,"mode":"check","url":"https://"}`,
		`{"v":1,"mode":"check","fallbackUrl":"https://speed.cloudflare.com/__down?bytes=24576"}`,
	} {
		resp := route(t, rt, req)
		if resp.Verdict != vupenRouteUnknown || !strings.HasPrefix(resp.Detail, "bad request") {
			t.Fatalf("%s → %+v", req, resp)
		}
	}
	if n := r.obs.routeCount(); n != 0 {
		t.Fatalf("a bad request must not check anything: %d checks", n)
	}
	var none *Router
	if resp := route(t, none, `{"v":1,"mode":"check"}`); resp.Verdict != vupenRouteUnknown || resp.Detail != "the core is not running" {
		t.Fatalf("no core: %+v", resp)
	}
	if resp := route(t, rt, `{"v":1,"mode":"check","balancer":"NOPE"}`); resp.Verdict != vupenRouteUnknown {
		t.Fatalf("unknown balancer: %+v", resp)
	}
}

// Параметры запроса доходят до проверки; нули — значения ядра.
func TestVupenCheckRouteOptions(t *testing.T) {
	r := holdingRig(t)
	rt := routerWith(map[string]*Balancer{"REG": r.b})
	route(t, rt, `{"v":1,"mode":"check","url":"https://vupen.fun/app/probe/24k.bin","fallbackUrl":"https://speed.cloudflare.com/__down?bytes=24576",
		"bytes":24576,"minStallMs":1500,"maxFirstByteMs":4000,"timeoutMs":6000,"reason":"foreground"}`)
	route(t, rt, `{"v":1,"mode":"check"}`)
	got := r.obs.routeOpts
	want := burst.VupenCheckOptions{URL: "https://vupen.fun/app/probe/24k.bin", FallbackURL: "https://speed.cloudflare.com/__down?bytes=24576",
		Bytes: 24576, Stall: 1500 * time.Millisecond, FirstByte: 4 * time.Second, Timeout: 6 * time.Second,
		Budget: VupenCheckRouteCheckBudget - burst.VupenNetCheckTimeout}
	if len(got) != 2 || got[0] != want || got[1] != (burst.VupenCheckOptions{Budget: want.Budget}) {
		t.Fatalf("options: %+v", got)
	}
}

// ── check ───────────────────────────────────────────────────────────────────

// check только проверяет: узел, исключения и соединения не трогаются.
func TestVupenCheckRouteCheckVerdicts(t *testing.T) {
	for _, c := range []struct {
		name, verdict, kind, net string
		want                     string
	}{
		{"ok", vupenStickyOK, "", vupenNetUp, vupenRouteOK},
		{"frozen, net up", vupenStickyFailed, "stall", vupenNetUp, vupenRouteFailed},
		{"failed, no network", vupenStickyFailed, "error", vupenNetDown, vupenRouteNetDown},
		{"failed, network unknown", vupenStickyFailed, "error", "unknown", vupenRouteUnknown},
		{"HTTP 404", "unknown", "http", vupenNetUp, vupenRouteUnknown},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := holdingRig(t)
			rt := routerWith(map[string]*Balancer{"REG": r.b})
			r.obs.setRoute("p-1", c.verdict, c.kind)
			r.obs.network = c.net
			resp := route(t, rt, `{"v":1,"mode":"check","reason":"foreground"}`)
			if resp.Verdict != c.want || resp.From != "p-1" || resp.Tried != 1 || resp.Kind != c.kind || resp.Balancer != "REG" {
				t.Fatalf("%+v", resp)
			}
			r.drain()
			if r.pick() != "p-1" || len(r.obs.excluded) != 0 || len(r.obs.closedTags) != 0 || r.s.getPhase() != vupenPhaseHolding {
				t.Fatalf("check must change nothing: pick=%s excluded=%v closed=%v", r.pick(), r.obs.excluded, r.obs.closedTags)
			}
		})
	}
}

// Ничего не работает: no_working (или network_down, если сети нет); поиск идёт — unknown.
func TestVupenCheckRouteCheckWhenNotHolding(t *testing.T) {
	r := newStickyRig(t, "", "p-1", "p-1", "p-2")
	rt := routerWith(map[string]*Balancer{"REG": r.b})
	if resp := route(t, rt, `{"v":1,"mode":"check"}`); resp.Verdict != vupenRouteUnknown {
		t.Fatalf("not started: %+v", resp)
	}
	r.pick() // старт: поиск
	if resp := route(t, rt, `{"v":1,"mode":"check"}`); resp.Verdict != vupenRouteUnknown || !strings.Contains(resp.Detail, "searching") {
		t.Fatalf("searching: %+v", resp)
	}
	r.drain() // никто не жив → no-working
	r.expectPhase(vupenPhaseNoWorking)
	if resp := route(t, rt, `{"v":1,"mode":"check"}`); resp.Verdict != vupenRouteNoWorking {
		t.Fatalf("no working: %+v", resp)
	}
	r.obs.network = vupenNetDown
	if resp := route(t, rt, `{"v":1,"mode":"check"}`); resp.Verdict != vupenRouteNetDown {
		t.Fatalf("no network: %+v", resp)
	}
	if r.obs.routeCount() != 0 {
		t.Fatal("no node to download through: nothing is checked")
	}
}

// ── heal ────────────────────────────────────────────────────────────────────

// Заморозка в check (встал посреди файла) → heal без повтора: исключить на 15 мин,
// закрыть соединения узла, перейти на проверенный.
func TestVupenCheckRouteHealSwitches(t *testing.T) {
	r, rt := healRig(t)
	r.obs.setRoute("p-1", vupenStickyFailed, "stall")
	r.obs.mu.Lock()
	r.obs.verify["p-2"] = vupenStickyOK
	r.obs.mu.Unlock()
	if resp := route(t, rt, `{"v":1,"mode":"check","reason":"foreground"}`); resp.Verdict != vupenRouteFailed {
		t.Fatalf("check: %+v", resp)
	}
	resp := route(t, rt, `{"v":1,"mode":"heal","reason":"foreground"}`)
	if resp.Verdict != vupenRouteSwitched || resp.From != "p-1" || resp.To != "p-2" || resp.Closed != 2 || resp.Tried != 1 {
		t.Fatalf("heal: %+v", resp)
	}
	r.obs.mu.Lock()
	defer r.obs.mu.Unlock()
	if len(r.obs.routeChecks) != 1 {
		t.Fatalf("a freeze pattern in check needs no second download: %v", r.obs.routeChecks)
	}
	if r.obs.excludedFor["p-1"] != 0 || !r.obs.excluded["p-1"] || len(r.obs.closedTags) != 1 || r.obs.closedTags[0] != "p-1" {
		t.Fatalf("excluded for the default term and its connections closed: %v %v", r.obs.excludedFor, r.obs.closedTags)
	}
	if got := r.s.viewTag(); got != "p-2" {
		t.Fatalf("new connections go via %q", got)
	}
}

// CR-703: отметка «встал» из check действует VupenCheckRouteSkipRecheckFor; позже
// heal снова качает узел (ожил — ok, ничего не меняем).
func TestVupenCheckRouteHealSkipExpires(t *testing.T) {
	r, rt := healRig(t)
	r.obs.setRoute("p-1", vupenStickyFailed, "stall")
	route(t, rt, `{"v":1,"mode":"check"}`)
	r.clock.Advance(VupenCheckRouteSkipRecheckFor + time.Second)
	r.obs.setRoute("p-1", vupenStickyOK, "")
	resp := route(t, rt, `{"v":1,"mode":"heal"}`)
	if resp.Verdict != vupenRouteOK || resp.Tried != 1 || r.obs.routeCount() != 2 || r.obs.VupenStickyExcluded("p-1") {
		t.Fatalf("a stale freeze mark must be re-checked: %+v checks=%d", resp, r.obs.routeCount())
	}
}

// Провал «ошибкой» в check — heal сначала проверяет тот же узел снова: ожил — ok, ничего не меняем.
func TestVupenCheckRouteHealRecheckRecovers(t *testing.T) {
	r, rt := healRig(t)
	r.obs.setRoute("p-1", vupenStickyFailed, "error")
	route(t, rt, `{"v":1,"mode":"check"}`)
	r.obs.setRoute("p-1", vupenStickyOK, "")
	resp := route(t, rt, `{"v":1,"mode":"heal"}`)
	if resp.Verdict != vupenRouteOK || resp.From != "p-1" || resp.Tried != 1 {
		t.Fatalf("heal: %+v", resp)
	}
	r.obs.mu.Lock()
	defer r.obs.mu.Unlock()
	if len(r.obs.routeChecks) != 2 || r.obs.excluded["p-1"] || len(r.obs.closedTags) != 0 {
		t.Fatalf("re-check, nothing excluded or closed: checks=%v excluded=%v closed=%v", r.obs.routeChecks, r.obs.excluded, r.obs.closedTags)
	}
}

// Параметры heal: excludeMin и closeConnections=false.
func TestVupenCheckRouteHealOptions(t *testing.T) {
	r, rt := healRig(t)
	r.obs.setRoute("p-1", vupenStickyFailed, "nostart")
	r.obs.mu.Lock()
	r.obs.verify["p-3"] = vupenStickyOK
	r.obs.mu.Unlock()
	route(t, rt, `{"v":1,"mode":"check"}`)
	resp := route(t, rt, `{"v":1,"mode":"heal","excludeMin":30,"closeConnections":false}`)
	if resp.Verdict != vupenRouteSwitched || resp.Closed != 0 {
		t.Fatalf("heal: %+v", resp)
	}
	r.obs.mu.Lock()
	defer r.obs.mu.Unlock()
	if r.obs.excludedFor["p-1"] != 30*time.Minute || len(r.obs.closedTags) != 0 {
		t.Fatalf("exclude %v, closed %v", r.obs.excludedFor, r.obs.closedTags)
	}
}

// heal: повтор провалился, но сети у устройства нет — узел не трогаем.
func TestVupenCheckRouteHealNetworkDownKeeps(t *testing.T) {
	r, rt := healRig(t)
	r.obs.setRoute("p-1", vupenStickyFailed, "error")
	resp := route(t, rt, `{"v":1,"mode":"check"}`)
	if resp.Verdict != vupenRouteFailed {
		t.Fatalf("check: %+v", resp)
	}
	r.obs.mu.Lock()
	r.obs.network = vupenNetDown
	r.obs.mu.Unlock()
	if resp := route(t, rt, `{"v":1,"mode":"heal"}`); resp.Verdict != vupenRouteNetDown {
		t.Fatalf("heal: %+v", resp)
	}
	if r.s.viewTag() != "p-1" || r.obs.VupenStickyExcluded("p-1") {
		t.Fatal("without network the node is kept")
	}
}

// Wi-Fi: все узлы пула не прошли — «нет рабочих».
func TestVupenCheckRouteHealNoWorking(t *testing.T) {
	r, rt := healRig(t)
	r.obs.setRoute("p-1", vupenStickyFailed, "stall")
	route(t, rt, `{"v":1,"mode":"check"}`)
	resp := route(t, rt, `{"v":1,"mode":"heal","maxSwitches":2}`)
	if resp.Verdict != vupenRouteNoWorking || resp.Tried != 2 {
		t.Fatalf("heal: %+v", resp)
	}
}

// Ядро само сменило узел между check и heal — switched, второй раз не лечим.
func TestVupenCheckRouteHealAlreadySwitched(t *testing.T) {
	r := holdingRig(t)
	rt := routerWith(map[string]*Balancer{"REG": r.b})
	r.obs.setRoute("p-1", vupenStickyFailed, "stall")
	route(t, rt, `{"v":1,"mode":"check"}`)
	r.s.holdBecause("p-3", "search") // сам нашёл другой
	go r.s.loop()
	resp := route(t, rt, `{"v":1,"mode":"heal"}`)
	if resp.Verdict != vupenRouteSwitched || resp.From != "p-1" || resp.To != "p-3" || len(r.obs.closedTags) != 0 {
		t.Fatalf("heal: %+v closed=%v", resp, r.obs.closedTags)
	}
}

// Обработчик не успел (или занят) — unknown через VupenCheckRouteHealWait, без зависания.
func TestVupenCheckRouteHealWaitBounded(t *testing.T) {
	r := holdingRig(t) // обработчик не запущен: события никто не разбирает
	rt := routerWith(map[string]*Balancer{"REG": r.b})
	old := VupenCheckRouteHealWait
	VupenCheckRouteHealWait = 50 * time.Millisecond
	t.Cleanup(func() { VupenCheckRouteHealWait = old })
	start := time.Now()
	resp := route(t, rt, `{"v":1,"mode":"heal"}`)
	if resp.Verdict != vupenRouteUnknown || !strings.Contains(resp.Detail, "still healing") || time.Since(start) > 2*time.Second {
		t.Fatalf("heal: %+v", resp)
	}
}

// Сотовая, REG мёртв после лечения — перелив в LTE (spilled_lte); лечится тот,
// кто выбирает сейчас: при переливе — LTE.
func TestVupenCheckRouteHealSpillsAndHealsLTE(t *testing.T) {
	r := newSpillRig(t, []string{"cellular"}, []string{"p-1", "p-2", "p-3"}, []string{"lte-1", "lte-2"})
	r.alive(map[string]int64{"p-1": 10, "p-2": 20, "p-3": 30, "lte-1": 40, "lte-2": 50})
	r.obs.mu.Lock()
	r.obs.verify["p-1"] = vupenStickyOK
	r.obs.verify["lte-1"] = vupenStickyOK
	r.obs.verify["lte-2"] = vupenStickyOK
	r.obs.mu.Unlock()
	r.pick()
	r.drain() // REG держит p-1
	if r.reg.getPhase() != vupenPhaseHolding || r.pick() != "p-1" {
		t.Fatalf("setup: %v %s", r.reg.getPhase(), r.pick())
	}
	rt := routerWith(map[string]*Balancer{"REG": r.regB, "LTE": r.lteB})
	r.obs.setRoute("p-1", vupenStickyFailed, "stall")
	route(t, rt, `{"v":1,"mode":"check"}`)
	go r.reg.loop()
	resp := route(t, rt, `{"v":1,"mode":"heal"}`)
	if resp.Verdict != vupenRouteSpilledLTE || resp.From != "p-1" || resp.Balancer != "REG" {
		t.Fatalf("heal: %+v", resp)
	}
	go r.lte.loop()
	deadline := time.Now().Add(2 * time.Second)
	for r.lte.getPhase() != vupenPhaseHolding && time.Now().Before(deadline) {
		r.pick()
		time.Sleep(5 * time.Millisecond)
	}
	if got := r.pick(); !strings.HasPrefix(got, "lte-") {
		t.Fatalf("spilled: %q", got)
	}
	// Теперь выбирает LTE: check идёт через его узел.
	resp = route(t, rt, `{"v":1,"mode":"check"}`)
	if resp.Balancer != "LTE" || !strings.HasPrefix(resp.From, "lte-") || resp.Verdict != vupenRouteOK {
		t.Fatalf("check while spilled: %+v", resp)
	}
}

// ── VupenAutoState ──────────────────────────────────────────────────────────

// Поля §13 на месте; ядро не запущено — active=false, без паники.
func TestVupenAutoStateShape(t *testing.T) {
	var none *Router
	var off map[string]any
	if err := json.Unmarshal([]byte(none.VupenAutoState()), &off); err != nil {
		t.Fatal(err)
	}
	if off["v"] != float64(1) || off["active"] != false || off["detail"] != "the core is not running" {
		t.Fatalf("not running: %v", off)
	}

	r := holdingRig(t)
	rt := routerWith(map[string]*Balancer{"REG": r.b})
	var m map[string]any
	if err := json.Unmarshal([]byte(rt.VupenAutoState()), &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"v", "uplink", "sig", "stableForMs", "tier", "regularAlive", "lteAlive", "sticky", "current",
		"noWorking", "pendingClose", "lastClose", "lastSwitch", "phase", "failedChecks", "spilled", "lastFailure", "notice", "network"} {
		if _, ok := m[k]; !ok {
			t.Fatalf("field %q missing: %v", k, m)
		}
	}
	sub := map[string][]string{
		"sticky":       {"since", "startVerdict", "searching", "nextSearchAtMs", "lastFailSignal"},
		"current":      {"balancer", "tag", "host", "port"},
		"pendingClose": {"atMs", "reason", "conns"},
		"lastClose":    {"atMs", "reason", "conns"},
		"lastSwitch":   {"atMs", "from", "to", "reason"},
	}
	for obj, keys := range sub {
		o, _ := m[obj].(map[string]any)
		for _, k := range keys {
			if _, ok := o[k]; !ok {
				t.Fatalf("%s.%s missing: %v", obj, k, o)
			}
		}
	}
	var st vupenAutoJSON
	_ = json.Unmarshal([]byte(rt.VupenAutoState()), &st)
	if !st.Active || st.Balancer != "REG" || st.Tier != "regular" || st.Phase != "holding" || st.Current.Tag != "p-1" ||
		st.Current.Balancer != "REG" || st.Sticky.StartVerdict != "ok" || st.Sticky.Since == 0 || st.Notice != "" || st.Network != "up" {
		t.Fatalf("state: %+v", st)
	}
}

func autoState(t *testing.T, rt *Router) vupenAutoJSON {
	t.Helper()
	var st vupenAutoJSON
	if err := json.Unmarshal([]byte(rt.VupenAutoState()), &st); err != nil {
		t.Fatal(err)
	}
	return st
}

// notice по D-27 / D-12 / D-14 п. 4: ищу другой → нет рабочих; нет сети; LTE.
func TestVupenAutoStateNotices(t *testing.T) {
	r := holdingRig(t)
	rt := routerWith(map[string]*Balancer{"REG": r.b})
	r.obs.mu.Lock()
	r.obs.check["p-1"] = vupenStickyFailed
	r.obs.mu.Unlock()
	// Проверка текущего не прошла, сеть есть: поиск. Состояние во время поиска —
	// подменой проверки 64 КБ (поиск идёт внутри handle).
	var during vupenAutoJSON
	r.obs.mu.Lock()
	r.obs.verify["p-2"] = vupenStickyFailed
	r.obs.mu.Unlock()
	hook := &noticeObs{stickyFakeObs: r.obs, onVerify: func() { during = autoState(t, rt) }}
	var so vupenStickyObservatory = hook
	r.s.obs.Store(&so)
	r.s.requestCheck("test")
	r.drain()
	if during.Notice != "searching" || during.FailedChecks < 1 || !during.Sticky.Searching {
		t.Fatalf("while searching after a failed check: %+v", during)
	}
	st := autoState(t, rt)
	if st.Notice != "no_working" || !st.NoWorking || st.Sticky.NextSearchAtMs == 0 || st.RegularAlive < 0 {
		t.Fatalf("nothing works: %+v", st)
	}
	r.obs.mu.Lock()
	r.obs.network = vupenNetDown
	r.obs.mu.Unlock()
	if resp := route(t, rt, `{"v":1,"mode":"check"}`); resp.Verdict != vupenRouteNetDown {
		t.Fatalf("check: %+v", resp)
	}
	if st := autoState(t, rt); st.Notice != "no_network" || st.Network != vupenNetDown {
		t.Fatalf("no network: %+v", st)
	}
}

// Проверка текущего не прошла, а сети у устройства нет: узел держим, notice "no_network".
func TestVupenAutoStateNoNetworkWhileHolding(t *testing.T) {
	r := holdingRig(t)
	rt := routerWith(map[string]*Balancer{"REG": r.b})
	r.obs.check["p-1"] = vupenStickyFailed
	r.obs.network = vupenNetDown
	r.s.requestCheck("test")
	r.drain()
	st := autoState(t, rt)
	if st.Phase != "holding" || st.Current.Tag != "p-1" || st.Notice != "no_network" || st.LastFailure.Kind != "check" {
		t.Fatalf("state: %+v", st)
	}
}

// noticeObs — обсерватория, которая даёт заглянуть в состояние посреди поиска.
type noticeObs struct {
	*stickyFakeObs
	onVerify func()
}

func (n *noticeObs) VupenStickyVerify(tag string) string {
	n.onVerify()
	return n.stickyFakeObs.VupenStickyVerify(tag)
}

// Перелито: tier lte, current — узел LTE с балансировщиком LTE, notice "lte".
func TestVupenAutoStateSpilled(t *testing.T) {
	r := newSpillRig(t, []string{"cellular"}, []string{"p-1", "p-2", "p-3"}, []string{"lte-1", "lte-2"})
	regDeadLteAlive(r)
	r.pick()
	r.drain()
	r.pick()
	r.drain()
	rt := routerWith(map[string]*Balancer{"REG": r.regB, "LTE": r.lteB})
	st := autoState(t, rt)
	if st.Balancer != "REG" || st.Tier != "lte" || !st.Spilled || st.Current.Balancer != "LTE" || st.Current.Tag != "lte-2" ||
		st.Notice != "lte" || st.Spills != 1 || st.LteAlive < 0 || st.LastSwitch.Reason != "spill" {
		t.Fatalf("spilled: %+v", st)
	}
}

// CR-705: платформа сообщила «сети нет» (uplink none) — notice "no_network" сразу,
// без проверки.
func TestVupenAutoStateNoNetworkByUplink(t *testing.T) {
	r := holdingRig(t)
	rt := routerWith(map[string]*Balancer{"REG": r.b})
	run := time.Now().Format("150405.000000")
	t.Cleanup(func() { internet.VupenSetUplink("wifi", "after-none-"+run) })
	internet.VupenSetUplink("none", "none-"+run)
	if st := autoState(t, rt); st.Uplink != "none" || st.Notice != "no_network" {
		t.Fatalf("uplink none: %+v", st)
	}
	internet.VupenSetUplink("wifi", "back-"+run)
	if st := autoState(t, rt); st.Notice != "" {
		t.Fatalf("network back: %+v", st)
	}
}

// Тип сети и эпоха — из transport/internet.
func TestVupenAutoStateUplink(t *testing.T) {
	r := holdingRig(t)
	rt := routerWith(map[string]*Balancer{"REG": r.b})
	sig := "auto-state-" + time.Now().Format("150405.000000")
	internet.VupenSetUplink("wifi", sig)
	st := autoState(t, rt)
	if st.Uplink != "wifi" || st.Sig != sig || st.Epoch == 0 {
		t.Fatalf("uplink: %+v", st)
	}
}
