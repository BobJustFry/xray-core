package router

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/transport/internet"
)

// spillRig — REG (p-*) с vupenSpill → LTE (lte-*), оба «держать текущий», общая
// фальшивая обсерватория, фальшивые часы и тип сети.
type spillRig struct {
	t        *testing.T
	reg, lte *vupenSticky
	regB     *Balancer
	lteB     *Balancer
	obs      *stickyFakeObs
	clock    *stickyClock
	kind     string
}

func newSpillRig(t *testing.T, uplink []string, regTags, lteTags []string) *spillRig {
	t.Helper()
	r := &spillRig{t: t, clock: &stickyClock{now: time.Unix(1_800_000_000, 0)}, kind: "cellular", obs: newStickyFakeObs()}
	oldAfter, oldNow, oldKind := vupenStickyAfter, vupenStickyNow, vupenUplinkKind
	vupenStickyAfter = r.clock.After
	vupenStickyNow = func() time.Time {
		r.clock.mu.Lock()
		defer r.clock.mu.Unlock()
		return r.clock.now
	}
	vupenUplinkKind = func() string { return r.kind }
	t.Cleanup(func() { vupenStickyAfter, vupenStickyNow, vupenUplinkKind = oldAfter, oldNow, oldKind })
	vupenSpillWarned.Range(func(k, _ any) bool { vupenSpillWarned.Delete(k); return true })

	r.regB = &Balancer{selectors: []string{"p"}, strategy: &LeastPingStrategy{}, ohm: &stickyFakeOhm{tags: regTags}}
	r.lteB = &Balancer{selectors: []string{"lte-"}, strategy: &LeastPingStrategy{}, ohm: &stickyFakeOhm{tags: lteTags}}
	r.reg = newVupenSticky(&BalancingRule{Tag: "REG", VupenSticky: &VupenSticky{},
		VupenSpill: &VupenSpill{BalancerTag: "LTE", Uplink: uplink}}, r.regB)
	r.lte = newVupenSticky(&BalancingRule{Tag: "LTE", VupenSticky: &VupenSticky{}}, r.lteB)
	r.regB.vupen, r.lteB.vupen = r.reg, r.lte
	var so vupenStickyObservatory = r.obs
	for _, s := range []*vupenSticky{r.reg, r.lte} {
		s.obs.Store(&so)
		s.runWorker = func() {}
		t.Cleanup(s.stop)
	}
	vupenLinkSpill(map[string]*Balancer{"REG": r.regB, "LTE": r.lteB})
	return r
}

func (r *spillRig) pick() string {
	r.t.Helper()
	tag, err := r.regB.PickOutbound()
	if err != nil {
		r.t.Fatal(err)
	}
	return tag
}

func (r *spillRig) drain() {
	for {
		select {
		case ev := <-r.reg.events:
			r.reg.handle(ev)
		case ev := <-r.lte.events:
			r.lte.handle(ev)
		default:
			return
		}
	}
}

// netChanged — как событие эпохи ядра 74 «сеть сменилась».
func (r *spillRig) netChanged(kind string) {
	r.kind = kind
	if r.reg.unspill("network changed") {
		r.reg.send(vupenStickyEvent{kind: "net-changed"})
	}
}

func (r *spillRig) probedLTE() bool {
	r.obs.mu.Lock()
	defer r.obs.mu.Unlock()
	for _, p := range r.obs.probes {
		for _, tag := range p {
			if strings.HasPrefix(tag, "lte-") {
				return true
			}
		}
	}
	return false
}

func regDeadLteAlive(r *spillRig) {
	r.alive(map[string]int64{"p-1": 10, "p-2": 20, "p-3": 30, "lte-1": 40, "lte-2": 50})
	r.obs.mu.Lock()
	r.obs.verify["lte-2"] = vupenStickyOK // lte-1 fails its 64 KB check
	r.obs.mu.Unlock()
}

func (r *spillRig) alive(d map[string]int64) {
	r.obs.mu.Lock()
	r.obs.delay = d
	r.obs.mu.Unlock()
}

// Сотовая: полный поиск по REG не нашёл рабочего → LTE; кандидаты LTE проверяются
// только при переливе и только проверенный получает трафик.
func TestVupenSpillOnCellularAfterFailedSearch(t *testing.T) {
	r := newSpillRig(t, []string{"cellular"}, []string{"p-1", "p-2", "p-3"}, []string{"lte-1", "lte-2"})
	regDeadLteAlive(r)
	if got := r.pick(); strings.HasPrefix(got, "lte-") {
		t.Fatalf("before the REG search: %q", got)
	}
	r.drain() // REG search: 3 checks fail → spill
	if !r.reg.spilledNow() {
		t.Fatal("cellular + REG dead after a full search → spill")
	}
	if r.probedLTE() {
		t.Fatal("LTE candidates must not be probed before the spill")
	}
	r.pick() // first LTE pick starts the LTE sticky (search)
	r.drain()
	if got := r.pick(); got != "lte-2" {
		t.Fatalf("spilled: traffic via the verified LTE node, got %q", got)
	}
	st := r.reg.state()
	if st.Tier != "lte" || !st.Spilled || st.Current != "lte-2" || st.Spills != 1 || st.LastSwitch.reason != "spill" {
		t.Fatalf("state: %+v", st)
	}
}

// Wi-Fi (и раздача с телефона — тоже wifi), проводная, прочая, нет сети,
// неизвестная — никогда, даже если vupenSpill.uplink их перечисляет (D-21).
func TestVupenSpillNeverOnNonCellular(t *testing.T) {
	for _, kind := range []string{"wifi", "wired", "other", "none", "unknown"} {
		r := newSpillRig(t, []string{"cellular", "wifi", "wired", "other", "none"}, []string{"p-1", "p-2"}, []string{"lte-1"})
		r.kind = kind
		regDeadLteAlive(r)
		r.pick()
		r.drain()
		if r.reg.spilledNow() || r.probedLTE() {
			t.Fatalf("%s: spilled to LTE", kind)
		}
		st := r.reg.state()
		if !st.NoWorking || st.Tier != "regular" || !strings.Contains(st.SpillBlocked, "uplink "+kind) {
			t.Fatalf("%s: «нет рабочих» on regular expected: %+v", kind, st)
		}
		if p := r.clock.pendingIn(); len(p) != 1 || p[0] != 30*time.Second {
			t.Fatalf("%s: regular retry schedule must go on: %v", kind, p)
		}
	}
}

// Жёсткий запрет и вживую: перелито, сеть стала Wi-Fi (событие ещё не дошло) —
// выбор уже не уходит в LTE.
func TestVupenSpillHardBlockOnWifiImmediately(t *testing.T) {
	r := newSpillRig(t, []string{"cellular"}, []string{"p-1"}, []string{"lte-1", "lte-2"})
	regDeadLteAlive(r)
	r.pick()
	r.drain()
	r.pick()
	r.drain()
	if got := r.pick(); got != "lte-2" {
		t.Fatalf("spilled: %q", got)
	}
	r.kind = "wifi"
	if got := r.pick(); strings.HasPrefix(got, "lte-") {
		t.Fatalf("on Wi-Fi the LTE pool must never get traffic, got %q", got)
	}
}

// Не чаще одного перелива в VupenSpillMinGap.
func TestVupenSpillMinGap(t *testing.T) {
	r := newSpillRig(t, []string{"cellular"}, []string{"p-1", "p-2", "p-3", "p-4", "p-5", "p-6", "p-7", "p-8", "p-9"}, []string{"lte-1", "lte-2"})
	d := map[string]int64{"lte-1": 1, "lte-2": 2}
	for i := 1; i <= 9; i++ {
		d["p-"+string(rune('0'+i))] = int64(10 * i)
	}
	r.alive(d)
	r.pick()
	r.drain()
	if !r.reg.spilledNow() {
		t.Fatal("first spill")
	}
	r.netChanged("cellular") // смена сотовой сети: возврат сразу
	r.drain()
	r.clock.Advance(10 * time.Second)
	r.reg.send(vupenStickyEvent{kind: "net-stable"})
	r.drain() // REG fails again 10 s after the spill → no spill (limit)
	if r.reg.spilledNow() {
		t.Fatal("a second spill within 60 s")
	}
	if st := r.reg.state(); !strings.Contains(st.SpillBlocked, "limit") {
		t.Fatalf("blocked by the limit: %+v", st)
	}
	r.clock.Advance(30 * time.Second) // retry 30 s → 40 s after the spill: still blocked
	r.drain()
	if r.reg.spilledNow() {
		t.Fatal("still within 60 s")
	}
	r.clock.Advance(time.Minute) // next retry (1 min) → 100 s after: allowed
	r.drain()
	if !r.reg.spilledNow() {
		t.Fatalf("after 60 s the spill is allowed again: %+v", r.reg.state())
	}
}

// Возврат при смене сети — сразу, новые соединения в REG; поиск по REG — когда
// сеть устоится.
func TestVupenSpillReturnOnNetworkChange(t *testing.T) {
	r := newSpillRig(t, []string{"cellular"}, []string{"p-1", "p-2"}, []string{"lte-1", "lte-2"})
	regDeadLteAlive(r)
	r.pick()
	r.drain()
	r.pick()
	r.drain()
	r.netChanged("wifi")
	if got := r.pick(); strings.HasPrefix(got, "lte-") {
		t.Fatalf("after a network change new connections go to REG at once, got %q", got)
	}
	r.drain()
	if st := r.reg.state(); st.Spilled || st.Returns != 1 || !st.NoWorking {
		t.Fatalf("state after return on Wi-Fi with REG dead: %+v", st)
	}
}

// Пока на LTE: раз в 5 мин лёгкая проверка трёх обычных (последний рабочий
// первым); 24 КБ прошла → REG сразу. Раньше 5 мин проверки нет.
func TestVupenSpillReturnOnRecheck(t *testing.T) {
	r := newSpillRig(t, []string{"cellular"}, []string{"p-1", "p-2", "p-3", "p-4", "p-5"}, []string{"lte-1", "lte-2"})
	regDeadLteAlive(r)    // p-1..p-3 fail their 64 KB checks → excluded for 15 min
	r.reg.current = "p-4" // последний рабочий
	r.pick()
	r.drain()
	r.pick()
	r.drain()
	checksBefore := r.obs.checkCount()
	r.obs.mu.Lock()
	r.obs.check["p-4"] = vupenStickyFailed
	r.obs.check["p-5"] = vupenStickyOK
	r.obs.delay["p-4"] = 5
	r.obs.delay["p-5"] = 60
	r.obs.mu.Unlock()
	r.clock.Advance(4 * time.Minute)
	r.drain()
	if !r.reg.spilledNow() || r.obs.checkCount() != checksBefore {
		t.Fatal("no regular re-check before 5 min")
	}
	r.clock.Advance(time.Minute)
	r.drain()
	if r.reg.spilledNow() {
		t.Fatalf("a regular node passed the 24 KB check → return: %+v", r.reg.state())
	}
	if got := r.pick(); got != "p-5" {
		t.Fatalf("returned to REG via the verified node, got %q", got)
	}
	r.obs.mu.Lock()
	probe := r.obs.probes[len(r.obs.probes)-1]
	checks := append([]string(nil), r.obs.checks[checksBefore:]...)
	r.obs.mu.Unlock()
	if len(probe) > VupenLteRegularRecheckN || probe[0] != "p-4" || checks[0] != "p-4" {
		t.Fatalf("light check: probe %v (≤%d, last working first), checks %v", probe, VupenLteRegularRecheckN, checks)
	}
	if st := r.reg.state(); st.Returns != 1 || st.LastSwitch.reason != "return" {
		t.Fatalf("state: %+v", st)
	}
}

// Неверный vupenSpill: перелив выключен, одно предупреждение, ядро работает.
func TestVupenSpillInvalidConfig(t *testing.T) {
	for _, c := range []struct {
		name   string
		target string
		uplink []string
		noLTE  bool
	}{
		{"empty balancerTag", "", []string{"cellular"}, false},
		{"unknown balancer", "NOPE", []string{"cellular"}, false},
		{"itself", "REG", []string{"cellular"}, false},
		{"unknown uplink value", "LTE", []string{"cellular", "satellite"}, false},
		{"target without vupenSticky", "LTE", []string{"cellular"}, true},
		{"no cellular in uplink", "LTE", []string{"wifi"}, false},
	} {
		r := newSpillRig(t, c.uplink, []string{"p-1"}, []string{"lte-1"})
		r.reg.spill = newVupenSpillConfig(&BalancingRule{Tag: "REG", VupenSpill: &VupenSpill{BalancerTag: c.target, Uplink: c.uplink}})
		if c.noLTE {
			r.lteB.vupen = nil
		}
		vupenLinkSpill(map[string]*Balancer{"REG": r.regB, "LTE": r.lteB})
		regDeadLteAlive(r)
		r.pick()
		r.drain()
		if r.reg.spilledNow() {
			t.Fatalf("%s: spilled", c.name)
		}
		if c.name != "no cellular in uplink" {
			if r.reg.spill.invalid == "" {
				t.Fatalf("%s: must be invalid", c.name)
			}
			if _, warned := vupenSpillWarned.Load("REG:invalid"); !warned {
				t.Fatalf("%s: one warning expected", c.name)
			}
		}
	}
}

// D-14 п. 3 / D-18: возврат в REG после лёгкой проверки (без смены сети) —
// закрыть соединения пула LTE (по 9 с правилу ядра 74); снова перелили до
// закрытия — отменить.
func TestVupenSpillReturnClosesLTEConnections(t *testing.T) {
	r := newSpillRig(t, []string{"cellular"}, []string{"p-1", "p-2", "p-3", "p-4", "p-5"}, []string{"lte-1", "lte-2"})
	type req struct {
		match     func(string) bool
		cancelled bool
	}
	var reqs []*req
	old := vupenCloseConnsWhenStable
	vupenCloseConnsWhenStable = func(match func(string) bool, reason string) func() {
		q := &req{match: match}
		reqs = append(reqs, q)
		return func() { q.cancelled = true }
	}
	t.Cleanup(func() { vupenCloseConnsWhenStable = old })
	regDeadLteAlive(r)
	r.pick()
	r.drain()
	r.pick()
	r.drain()
	r.obs.mu.Lock()
	r.obs.check["p-5"] = vupenStickyOK
	r.obs.delay["p-5"] = 60
	r.obs.mu.Unlock()
	r.clock.Advance(VupenLteRegularRecheck)
	r.drain()
	if r.reg.spilledNow() || len(reqs) != 1 {
		t.Fatalf("return after the light check must request closing LTE connections: spilled=%v requests=%d", r.reg.spilledNow(), len(reqs))
	}
	if !reqs[0].match("lte-1") || reqs[0].match("p-1") {
		t.Fatal("only the LTE pool's connections are closed")
	}
	// REG снова «мёртв» на той же сети → перелив (через 60 с) до закрытия: отменить.
	r.clock.Advance(VupenSpillMinGap)
	r.obs.mu.Lock()
	r.obs.check["p-5"] = vupenStickyFailed
	r.obs.mu.Unlock()
	r.reg.requestCheck("test")
	r.drain()
	if !r.reg.spilledNow() || !reqs[0].cancelled {
		t.Fatalf("a new spill before the close must cancel it: spilled=%v cancelled=%v", r.reg.spilledNow(), reqs[0].cancelled)
	}
}

func lteProbes(r *spillRig) int {
	r.obs.mu.Lock()
	defer r.obs.mu.Unlock()
	n := 0
	for _, p := range r.obs.probes {
		for _, tag := range p {
			if strings.HasPrefix(tag, "lte-") {
				n++
				break
			}
		}
	}
	return n
}

// CR-501: после возврата в REG LTE-балансировщик не ищет и не повторяет (ни по
// графику, ни на «сеть устоялась») — до следующего перелива.
func TestVupenSpillTargetDormantAfterReturn(t *testing.T) {
	r := newSpillRig(t, []string{"cellular"}, []string{"p-1", "p-2", "p-3", "p-4", "p-5", "p-6", "p-7"}, []string{"lte-1", "lte-2", "lte-3"})
	r.alive(map[string]int64{"p-1": 10, "p-2": 20, "p-3": 30, "p-4": 40, "p-5": 50, "p-6": 60, "p-7": 70, "lte-1": 1, "lte-2": 2, "lte-3": 3})
	r.obs.mu.Lock()
	for _, tag := range []string{"lte-1", "lte-2", "lte-3"} {
		r.obs.verify[tag] = "unknown" // LTE не отвечает внятно: узлы не исключаются, повтор их снова пробовал бы
	}
	r.obs.mu.Unlock()
	r.pick()
	r.drain() // REG dead → spill
	r.pick()
	r.drain() // LTE searches too: nothing works → its retry is scheduled
	if !r.reg.spilledNow() || lteProbes(r) == 0 || r.lte.getPhase() != vupenPhaseNoWorking {
		t.Fatalf("setup: spilled=%v lteProbes=%d ltePhase=%v", r.reg.spilledNow(), lteProbes(r), r.lte.getPhase())
	}
	r.netChanged("wifi")
	r.drain()
	before := lteProbes(r)
	r.clock.Advance(10 * time.Minute)
	r.lte.send(vupenStickyEvent{kind: "net-stable"})
	r.drain()
	if n := lteProbes(r); n != before {
		t.Fatalf("on Wi-Fi after the return the LTE pool was probed again (%d → %d)", before, n)
	}
}

// CR-502: возврат по смене сети тоже закрывает соединения LTE (когда сеть
// устоится 9 с) — на мигание с возвратом общая чистка эпохи отменяется.
func TestVupenSpillReturnOnNetworkChangeClosesLTE(t *testing.T) {
	r := newSpillRig(t, []string{"cellular"}, []string{"p-1", "p-2"}, []string{"lte-1", "lte-2"})
	calls := 0
	old := vupenCloseConnsWhenStable
	vupenCloseConnsWhenStable = func(match func(string) bool, reason string) func() {
		if match("lte-1") && !match("p-1") {
			calls++
		}
		return func() {}
	}
	t.Cleanup(func() { vupenCloseConnsWhenStable = old })
	regDeadLteAlive(r)
	r.pick()
	r.drain()
	r.netChanged("cellular")
	r.drain()
	if calls != 1 {
		t.Fatalf("return on a network change must request closing the LTE pool's connections, got %d", calls)
	}
}

// CR-503: возврат по настоящему событию эпохи ядра 74 (VupenSetUplink с другой
// подписью) — следующий выбор уже в REG.
func TestVupenSpillReturnOnRealUplinkChange(t *testing.T) {
	r := newSpillRig(t, []string{"cellular"}, []string{"p-1", "p-2"}, []string{"lte-1", "lte-2"})
	regDeadLteAlive(r)
	r.pick()
	r.drain()
	r.pick()
	r.drain()
	if got := r.pick(); got != "lte-2" {
		t.Fatalf("spilled: %q", got)
	}
	run := time.Now().UnixNano()
	internet.VupenSetUplink("cellular", fmt.Sprintf("spill-a-%d", run))
	internet.VupenSetUplink("cellular", fmt.Sprintf("spill-b-%d", run))
	if r.reg.spilledNow() {
		t.Fatal("a real network change must reset the spill at once")
	}
	if got := r.pick(); strings.HasPrefix(got, "lte-") {
		t.Fatalf("after the network change the next pick goes to REG, got %q", got)
	}
}

// CR-504: один уровень — цель перелива с собственным vupenSpill отвергается
// (в том числе цикл из двух).
func TestVupenSpillOneLevelOnly(t *testing.T) {
	mk := func(tag, target string) *Balancer {
		b := &Balancer{selectors: []string{tag}, strategy: &RandomStrategy{}, ohm: &stickyFakeOhm{}}
		rule := &BalancingRule{Tag: tag, VupenSticky: &VupenSticky{}}
		if target != "" {
			rule.VupenSpill = &VupenSpill{BalancerTag: target, Uplink: []string{"cellular"}}
		}
		b.vupen = newVupenSticky(rule, b)
		return b
	}
	vupenSpillWarned.Range(func(k, _ any) bool { vupenSpillWarned.Delete(k); return true })
	a, b, c := mk("A", "B"), mk("B", "C"), mk("C", "")
	vupenLinkSpill(map[string]*Balancer{"A": a, "B": b, "C": c})
	if a.vupen.spill.target.Load() != nil || !strings.Contains(a.vupen.spill.invalid, "one level") {
		t.Fatalf("A → B → C: A must be rejected: %q", a.vupen.spill.invalid)
	}
	if b.vupen.spill.target.Load() != c || b.vupen.spill.invalid != "" {
		t.Fatalf("B → C (C without its own spill) must be linked: %q", b.vupen.spill.invalid)
	}
	x, y := mk("X", "Y"), mk("Y", "X")
	vupenLinkSpill(map[string]*Balancer{"X": x, "Y": y})
	if x.vupen.spill.target.Load() != nil || y.vupen.spill.target.Load() != nil {
		t.Fatal("a two-balancer cycle must be rejected on both sides")
	}
}

// lteNoWorkingAfterSpill — сотовая: REG мёртв → перелив; LTE не отвечает внятно
// (узлы не исключаются) → у LTE тоже «ничего не работает».
func lteNoWorkingAfterSpill(t *testing.T) *spillRig {
	t.Helper()
	r := newSpillRig(t, []string{"cellular"}, []string{"p-1", "p-2", "p-3"}, []string{"lte-1", "lte-2"})
	r.alive(map[string]int64{"p-1": 10, "p-2": 20, "p-3": 30, "lte-1": 1, "lte-2": 2})
	r.obs.mu.Lock()
	for _, tag := range []string{"p-1", "p-2", "p-3", "lte-1", "lte-2"} {
		r.obs.verify[tag] = "unknown"
	}
	r.obs.mu.Unlock()
	r.pick()
	r.drain()
	r.pick()
	r.drain()
	if !r.reg.spilledNow() || r.lte.getPhase() != vupenPhaseNoWorking {
		t.Fatalf("setup: spilled=%v lte=%v", r.reg.spilledNow(), r.lte.getPhase())
	}
	return r
}

// CR-601 (а): LTE ничего не нашёл в первом переливе, вернулись в REG; второй
// перелив будит LTE — он ищет снова.
func TestVupenSpillWakesTargetOnRespill(t *testing.T) {
	r := lteNoWorkingAfterSpill(t)
	r.netChanged("wifi")
	r.drain()
	r.netChanged("cellular")
	r.drain()
	before := lteProbes(r)
	r.clock.Advance(5 * time.Minute) // REG retry → поиск → снова мёртв → перелив #2
	r.drain()
	if !r.reg.spilledNow() || r.reg.state().Spills != 2 {
		t.Fatalf("second spill expected: spilled=%v %+v", r.reg.spilledNow(), r.reg.state())
	}
	if n := lteProbes(r); n <= before {
		t.Fatalf("the second spill must wake LTE to search again (probes %d → %d)", before, n)
	}
}

// CR-601 (б): возврат по лёгкой проверке — LTE больше никто не кормит:
// feeders = 0, цель спит.
func TestVupenSpillReturnOnRecheckReleasesTarget(t *testing.T) {
	r := lteNoWorkingAfterSpill(t)
	if r.lte.feeders.Load() != 1 || r.lte.dormant() {
		t.Fatalf("spilled: feeders=%d dormant=%v", r.lte.feeders.Load(), r.lte.dormant())
	}
	r.obs.mu.Lock()
	r.obs.check["p-2"] = vupenStickyOK
	r.obs.check["p-1"] = vupenStickyFailed
	r.obs.check["p-3"] = vupenStickyFailed
	r.obs.mu.Unlock()
	r.clock.Advance(VupenLteRegularRecheck)
	r.drain()
	if r.reg.spilledNow() {
		t.Fatal("a regular node passed → return")
	}
	if r.lte.feeders.Load() != 0 || !r.lte.dormant() {
		t.Fatalf("after the return: feeders=%d dormant=%v", r.lte.feeders.Load(), r.lte.dormant())
	}
}

// CR-602: очередь цели полна, wake не влез — цель всё равно просыпается на
// следующем событии (флаг wakePending).
func TestVupenSpillWakeSurvivesFullQueue(t *testing.T) {
	r := lteNoWorkingAfterSpill(t)
	r.netChanged("wifi")
	r.drain()
	r.netChanged("cellular")
	r.drain()
	for r.lte.send(vupenStickyEvent{kind: "noop"}) {
	}
	before := lteProbes(r)
	r.clock.Advance(5 * time.Minute)
	for done := false; !done; { // только REG: перелив #2, wake в полную очередь LTE
		select {
		case ev := <-r.reg.events:
			r.reg.handle(ev)
		default:
			done = true
		}
	}
	if !r.reg.spilledNow() || !r.lte.wakePending.Load() {
		t.Fatalf("setup: spilled=%v wakePending=%v", r.reg.spilledNow(), r.lte.wakePending.Load())
	}
	r.drain()
	if n := lteProbes(r); n <= before {
		t.Fatalf("a lost wake event must not leave LTE asleep (probes %d → %d)", before, n)
	}
}

// CR-603: повторный trySpill при уже перелитом REG ничего не считает дважды.
func TestVupenSpillTrySpillOnce(t *testing.T) {
	r := lteNoWorkingAfterSpill(t)
	r.clock.Advance(2 * VupenSpillMinGap)
	if !r.reg.trySpill("again") {
		t.Fatal("already spilled: stays spilled")
	}
	if r.lte.feeders.Load() != 1 || r.reg.state().Spills != 1 {
		t.Fatalf("feeders=%d spills=%d — one spill counted twice", r.lte.feeders.Load(), r.reg.state().Spills)
	}
}
