package router

import (
	"context"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/transport/internet"
	"google.golang.org/protobuf/proto"
)

// Ядро 87 (T-189). Глобальная эпоха сети (internet.VupenNetState) в процессе тестов
// принадлежит другим тестам пакета; здесь снимок по умолчанию - «сеть устойчива, платформа
// ничего не сообщала», а нужное состояние тест задаёт сам (setNetSnapshot).
func init() {
	vupenNetSnapshot = func() internet.VupenNetInfo { return internet.VupenNetInfo{} }
}

func setNetSnapshot(t *testing.T, f func() internet.VupenNetInfo) {
	t.Helper()
	old := vupenNetSnapshot
	vupenNetSnapshot = f
	t.Cleanup(func() { vupenNetSnapshot = old })
}

// settlingNet - сеть сменилась (эпоха 5) stable назад.
func settlingNet(stable time.Duration) func() internet.VupenNetInfo {
	return func() internet.VupenNetInfo {
		return internet.VupenNetInfo{Active: true, Kind: "cellular", Epoch: 5, StableFor: stable}
	}
}

// verifyHookObs - обсерватория, которая в момент проверки 64 КБ или 24 КБ запускает хук
// (смотреть, что отдаёт PickOutbound, пока поиск идёт).
type verifyHookObs struct {
	*stickyFakeObs
	onVerify func(tag string)
	onCheck  func(tag string)
	onProbe  func()
	obsCalls atomic.Int32
}

func (o *verifyHookObs) VupenStickyProbe(tags []string) {
	o.stickyFakeObs.VupenStickyProbe(tags)
	if o.onProbe != nil {
		o.onProbe()
	}
}

func (o *verifyHookObs) GetObservation(ctx context.Context) (proto.Message, error) {
	o.obsCalls.Add(1)
	return o.stickyFakeObs.GetObservation(ctx)
}

func (o *verifyHookObs) VupenStickyVerify(tag string) string {
	if o.onVerify != nil {
		o.onVerify(tag)
	}
	return o.stickyFakeObs.VupenStickyVerify(tag)
}

func (o *verifyHookObs) VupenStickyCheck(tag string) string {
	if o.onCheck != nil {
		o.onCheck(tag)
	}
	return o.stickyFakeObs.VupenStickyCheck(tag)
}

func hookRig(t *testing.T, r *stickyRig) *verifyHookObs {
	t.Helper()
	h := &verifyHookObs{stickyFakeObs: r.obs}
	var so vupenStickyObservatory = h
	r.s.obs.Store(&so)
	return h
}

// ── A: во время поиска трафик не идёт в непроверенный узел ──────────────────

// Узел p-3 держали и проверили; поиск начался (например, сеть сменилась), p-3 не исключён:
// пока ищут, трафик остаётся на нём, а не на запасном p-1 (мёртвом) и не на самом быстром p-2.
func TestVupenSettleSearchKeepsLastAliveNode(t *testing.T) {
	r := newStickyRig(t, "p-3", "p-1", "p-1", "p-2", "p-3")
	r.alive(map[string]int64{"p-2": 5, "p-3": 40}) // p-1 (fallbackTag) молчит
	r.pick()
	r.drain() // старт: проверка 24 КБ p-3 прошла
	r.expectPhase(vupenPhaseHolding)
	var during []string
	h := hookRig(t, r)
	h.onVerify = func(string) { during = append(during, r.pick()) }
	r.obs.verify["p-2"] = vupenStickyOK
	r.s.send(vupenStickyEvent{kind: "search", reason: "test"})
	r.drain()
	if len(during) == 0 {
		t.Fatal("the search verified nothing")
	}
	for _, got := range during {
		if got != "p-3" {
			t.Fatalf("during the search traffic must stay on the last verified node p-3, got %q (all: %v)", got, during)
		}
	}
	if got := r.pick(); got != "p-2" {
		t.Fatalf("after the search: %q, want p-2", got)
	}
}

// Последний проверенный исключён (настоящий провал): трафик идёт в первый отвечавший на
// пробу узел, а не в мёртвый fallbackTag.
func TestVupenSettleSearchUsesPingAliveWhenLastAliveExcluded(t *testing.T) {
	r := newStickyRig(t, "p-3", "p-1", "p-1", "p-2", "p-3", "p-4")
	r.alive(map[string]int64{"p-2": 30, "p-4": 10, "p-3": 5}) // p-1 (fallbackTag) молчит
	r.obs.check["p-3"] = vupenStickyFailed
	r.obs.verify["p-4"] = vupenStickyFailed
	r.obs.verify["p-2"] = vupenStickyOK
	h := hookRig(t, r)
	var during []string
	h.onVerify = func(string) { during = append(during, r.pick()) }
	r.pick()
	r.drain()
	if !r.obs.excluded["p-3"] {
		t.Fatal("setup: the failed p-3 must be excluded")
	}
	if len(during) == 0 {
		t.Fatal("the search verified nothing")
	}
	for _, got := range during {
		if got == "p-1" || got == "p-3" {
			t.Fatalf("during the search traffic goes to an unverified silent/excluded node %q (all: %v)", got, during)
		}
	}
	if during[0] != "p-4" {
		t.Fatalf("the first ping-alive node in strategy order is p-4, got %v", during)
	}
	// T-192 (CR-703): p-4 провалил 64 КБ - пока проверяют p-2, трафик уже не на p-4.
	if len(during) < 2 || during[1] != "p-2" {
		t.Fatalf("after the interim p-4 failed the verify traffic must move to p-2, got %v", during)
	}
}

// Ничего не известно (нет ни проверенного, ни ответивших) - как раньше: fallbackTag.
func TestVupenSettleSearchFallsBackWhenNothingKnown(t *testing.T) {
	r := newStickyRig(t, "", "p-2", "p-1", "p-2")
	r.alive(map[string]int64{})
	if got := r.pick(); got != "p-2" {
		t.Fatalf("nothing is known: fallbackTag p-2, got %q", got)
	}
}

// ── C: поиск сменил узел - соединения временного и прежнего узлов закрыты ───

func TestVupenSettleSearchSwitchClosesInterimAndOldConnections(t *testing.T) {
	r := newStickyRig(t, "p-3", "p-1", "p-1", "p-2", "p-3", "p-4")
	r.alive(map[string]int64{"p-4": 10, "p-2": 30, "p-3": 5})
	r.obs.check["p-3"] = vupenStickyFailed // p-3 исключён, поиск
	r.obs.verify["p-4"] = vupenStickyFailed
	r.obs.verify["p-2"] = vupenStickyOK
	r.pick()
	r.drain()
	r.expectPhase(vupenPhaseHolding)
	if got := r.pick(); got != "p-2" {
		t.Fatalf("the search switched to %q, want p-2", got)
	}
	r.obs.mu.Lock()
	closed := slices.Clone(r.obs.closedTags)
	r.obs.mu.Unlock()
	slices.Sort(closed)
	if !slices.Equal(closed, []string{"p-3", "p-4"}) {
		t.Fatalf("connections of the old node p-3 and of the interim node p-4 must be closed, got %v", closed)
	}
}

// Новый узел совпал с временным - его соединения не трогаем.
func TestVupenSettleSearchSwitchKeepsConnectionsOfTheNewNode(t *testing.T) {
	r := newStickyRig(t, "p-3", "p-1", "p-1", "p-2", "p-3")
	r.alive(map[string]int64{"p-2": 10, "p-3": 5})
	r.obs.check["p-3"] = vupenStickyFailed
	r.obs.verify["p-2"] = vupenStickyOK
	r.pick()
	r.drain()
	r.obs.mu.Lock()
	closed := slices.Clone(r.obs.closedTags)
	r.obs.mu.Unlock()
	if !slices.Equal(closed, []string{"p-3"}) {
		t.Fatalf("only the old node p-3 is closed (p-2 is both interim and new), got %v", closed)
	}
}

// ── D: провал в окне смены сети не исключает узел ───────────────────────────

func TestVupenSettleFailureInsideWindowDoesNotExclude(t *testing.T) {
	r := newStickyRig(t, "p-1", "p-1", "p-1", "p-2")
	r.alive(map[string]int64{"p-1": 5, "p-2": 10})
	r.obs.check["p-1"] = vupenStickyFailed
	setNetSnapshot(t, settlingNet(3*time.Second))
	r.pick()
	r.drain()
	if r.obs.excluded["p-1"] || len(r.obs.verifies) != 0 || len(r.obs.probes) != 0 {
		t.Fatalf("failure inside the settle window: excluded=%v verifies=%v probes=%v", r.obs.excluded, r.obs.verifies, r.obs.probes)
	}
	r.expectPhase(vupenPhaseHolding)
	if got := r.pick(); got != "p-1" {
		t.Fatalf("the node is kept, got %q", got)
	}
	// Одна повторная проверка, когда окно кончится (3 с прошло, до 9 с - 6 с + запас).
	pending := r.clock.pendingIn()
	want := 6*time.Second + vupenSettleMargin
	if len(pending) != 1 || pending[0] != want {
		t.Fatalf("one re-check after the window (%v), got timers %v", want, pending)
	}
	// Сеть устоялась, проверка по-прежнему проваливается - теперь это настоящий провал.
	setNetSnapshot(t, func() internet.VupenNetInfo {
		return internet.VupenNetInfo{Active: true, Kind: "cellular", Epoch: 5, StableFor: 20 * time.Second}
	})
	r.clock.Advance(want)
	r.drain()
	if !r.obs.excluded["p-1"] {
		t.Fatalf("a failure on a stable network excludes the node as before; checks=%v", r.obs.checks)
	}
	if got := len(r.obs.checks); got != 2 {
		t.Fatalf("exactly one re-check: 2 checks in total, got %v", r.obs.checks)
	}
}

// Окно кончилось, пока ждали повторную проверку, и проверка прошла - узел цел, второй проверки нет.
func TestVupenSettleRecheckOkKeepsNode(t *testing.T) {
	r := newStickyRig(t, "p-1", "p-1", "p-1", "p-2")
	r.alive(map[string]int64{"p-1": 5, "p-2": 10})
	r.obs.check["p-1"] = vupenStickyFailed
	setNetSnapshot(t, settlingNet(2*time.Second))
	r.pick()
	r.drain()
	r.obs.mu.Lock()
	r.obs.check["p-1"] = vupenStickyOK
	r.obs.mu.Unlock()
	setNetSnapshot(t, settlingNet(30*time.Second))
	r.clock.Advance(20 * time.Second)
	r.drain()
	if r.obs.excluded["p-1"] || len(r.obs.checks) != 2 || len(r.clock.pendingIn()) != 0 {
		t.Fatalf("excluded=%v checks=%v timers=%v", r.obs.excluded, r.obs.checks, r.clock.pendingIn())
	}
	r.expectPhase(vupenPhaseHolding)
}

// Сеть сменилась ещё раз, пока ждали: повторная проверка ждёт конца нового окна, не проверяя.
func TestVupenSettleRecheckWaitsWhenNetworkChangedAgain(t *testing.T) {
	r := newStickyRig(t, "p-1", "p-1", "p-1", "p-2")
	r.alive(map[string]int64{"p-1": 5, "p-2": 10})
	r.obs.check["p-1"] = vupenStickyFailed
	setNetSnapshot(t, settlingNet(2*time.Second))
	r.pick()
	r.drain()
	setNetSnapshot(t, settlingNet(1*time.Second)) // новая смена
	r.clock.Advance(8 * time.Second)
	r.drain()
	if r.obs.excluded["p-1"] || len(r.obs.checks) != 1 {
		t.Fatalf("the re-check must wait for the new window: excluded=%v checks=%v", r.obs.excluded, r.obs.checks)
	}
	if p := r.clock.pendingIn(); len(p) != 1 || p[0] != 8*time.Second+vupenSettleMargin {
		t.Fatalf("a new wait for the rest of the window, got %v", p)
	}
}

// Чистильщик эпохи сети закрыл соединения проверки (net-change) - и «closed pipe» после него.
func TestVupenSettleNetChangeCloserDuringCheckIsNotAFailureOfTheNode(t *testing.T) {
	r := newStickyRig(t, "p-1", "p-1", "p-1", "p-2")
	r.alive(map[string]int64{"p-1": 5, "p-2": 10})
	r.obs.check["p-1"] = vupenStickyFailed
	h := hookRig(t, r)
	closedAt := time.Time{}
	setNetSnapshot(t, func() internet.VupenNetInfo {
		ni := internet.VupenNetInfo{Active: true, Kind: "cellular", Epoch: 5, StableFor: 30 * time.Second}
		if !closedAt.IsZero() {
			ni.LastClose = &internet.VupenNetClose{At: closedAt, Reason: "net-change", Conns: 8}
		}
		return ni
	})
	h.onCheck = func(string) { closedAt = vupenStickyNow().Add(time.Millisecond) } // чистильщик сработал внутри проверки
	r.pick()
	r.drain()
	if r.obs.excluded["p-1"] || len(r.obs.verifies) != 0 {
		t.Fatalf("closer during the check: excluded=%v verifies=%v", r.obs.excluded, r.obs.verifies)
	}
	if p := r.clock.pendingIn(); len(p) != 1 {
		t.Fatalf("a re-check is queued, got timers %v", p)
	}
}

// Настоящий провал на устойчивой сети - исключение и поиск, как раньше (контроль, что D не ослабляет).
func TestVupenSettleStableNetworkFailureStillExcludes(t *testing.T) {
	r := newStickyRig(t, "p-1", "p-1", "p-1", "p-2")
	r.alive(map[string]int64{"p-1": 5, "p-2": 10})
	r.obs.check["p-1"] = vupenStickyFailed
	r.obs.verify["p-2"] = vupenStickyOK
	setNetSnapshot(t, func() internet.VupenNetInfo {
		return internet.VupenNetInfo{Active: true, Kind: "wifi", Epoch: 5, StableFor: time.Hour,
			LastClose: &internet.VupenNetClose{At: vupenStickyNow().Add(-time.Hour), Reason: "net-change", Conns: 3}}
	})
	r.pick()
	r.drain()
	if !r.obs.excluded["p-1"] || r.s.current != "p-2" {
		t.Fatalf("excluded=%v current=%q", r.obs.excluded, r.s.current)
	}
	// Ядро 88 (D-70 п. 5): единственный таймер - повторная проверка нового узла через 12 с;
	// таймера повтора окна смены сети (settle re-check) по-прежнему нет.
	if p := r.clock.pendingIn(); len(p) != 1 || p[0] != VupenStickyPostSwitchRecheck {
		t.Fatalf("only the post-switch re-check may be pending on a real failure: %v", p)
	}
}

// Окно только после старта ядра (эпоха 1 - первая сообщённая сеть) окном смены не считается.
func TestVupenSettleFirstReportedNetworkIsNotAChange(t *testing.T) {
	r := newStickyRig(t, "p-1", "p-1", "p-1", "p-2")
	r.alive(map[string]int64{"p-1": 5, "p-2": 10})
	r.obs.check["p-1"] = vupenStickyFailed
	r.obs.verify["p-2"] = vupenStickyOK
	setNetSnapshot(t, func() internet.VupenNetInfo {
		return internet.VupenNetInfo{Active: true, Kind: "wifi", Epoch: 1, StableFor: time.Second}
	})
	r.pick()
	r.drain()
	if !r.obs.excluded["p-1"] {
		t.Fatal("a failed start check on the first reported network excludes the node as before")
	}
}

// checkRoute check в окне: приложению не «failed» (иначе позовёт heal и исключит), отметки для heal нет.
func TestVupenSettleCheckRouteInsideWindowIsNotFailed(t *testing.T) {
	r := holdingRig(t)
	r.obs.setRoute("p-1", vupenStickyFailed, vupenRouteFreezeStall)
	setNetSnapshot(t, settlingNet(4*time.Second))
	resp := r.s.checkRoute(vupenRouteReq{Mode: vupenRouteCheckMode, Reason: "foreground"})
	if resp.Verdict == vupenRouteFailed {
		t.Fatalf("a failure inside the settle window must not be reported as failed: %+v", resp)
	}
	r.s.stateMu.Lock()
	mark := r.s.report.routeCheck
	r.s.stateMu.Unlock()
	if mark.tag != "" || r.obs.excluded["p-1"] || len(r.clock.pendingIn()) != 1 {
		t.Fatalf("no heal mark, no exclusion, one re-check: mark=%+v excluded=%v timers=%v", mark, r.obs.excluded, r.clock.pendingIn())
	}
	// Устойчивая сеть - как раньше.
	setNetSnapshot(t, settlingNet(time.Hour))
	resp = r.s.checkRoute(vupenRouteReq{Mode: vupenRouteCheckMode, Reason: "foreground"})
	if resp.Verdict != vupenRouteFailed {
		t.Fatalf("a failure on a stable network is failed as before: %+v", resp)
	}
}

// heal в окне: провал не исключает узел и не ищет; heal на устойчивой сети исключает.
func TestVupenSettleHealInsideWindowKeepsNode(t *testing.T) {
	r, rt := healRig(t)
	r.obs.setRoute("p-1", vupenStickyFailed, vupenRouteNoStart)
	setNetSnapshot(t, settlingNet(4*time.Second))
	resp := route(t, rt, `{"v":1,"mode":"heal","reason":"foreground"}`)
	if r.obs.excluded["p-1"] || resp.Closed != 0 || !strings.Contains(resp.Detail, "settle window") {
		t.Fatalf("heal inside the window: excluded=%v %+v", r.obs.excluded, resp)
	}
	setNetSnapshot(t, settlingNet(time.Hour))
	resp = route(t, rt, `{"v":1,"mode":"heal","reason":"foreground"}`)
	if !r.obs.excluded["p-1"] {
		t.Fatalf("heal on a stable network excludes as before: %+v", resp)
	}
}

// «closed pipe» вскоре после закрытия соединений чистильщиком эпохи - его след; без закрытия или
// давно - нет; «never started» сам по себе (рисунок заморозки ТСПУ) в оправдание не годится.
func TestVupenSettleClosedPipeNeedsRecentCloser(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	old := vupenStickyNow
	vupenStickyNow = func() time.Time { return now }
	t.Cleanup(func() { vupenStickyNow = old })
	lc := func(ago time.Duration, reason string) func() internet.VupenNetInfo {
		return func() internet.VupenNetInfo {
			return internet.VupenNetInfo{Active: true, Epoch: 5, StableFor: time.Minute,
				LastClose: &internet.VupenNetClose{At: now.Add(-ago), Reason: reason, Conns: 8}}
		}
	}
	m := vupenNetMark{start: now}
	for _, c := range []struct {
		name   string
		snap   func() internet.VupenNetInfo
		detail string
		want   bool
	}{
		{"closed pipe 3s after the closer", lc(3*time.Second, "net-change"), "io: read/write on closed pipe", true},
		{"closed pipe long after the closer", lc(5*time.Minute, "net-change"), "io: read/write on closed pipe", false},
		{"closed pipe, closer was check-route", lc(3*time.Second, "check-route"), "io: read/write on closed pipe", false},
		{"nostart right after the closer", lc(3*time.Second, "net-change"), "the file never started in 1s", false},
		{"no closer at all", func() internet.VupenNetInfo {
			return internet.VupenNetInfo{Active: true, Epoch: 5, StableFor: time.Minute}
		}, "io: read/write on closed pipe", false},
	} {
		setNetSnapshot(t, c.snap)
		if _, got := m.disturbed(c.detail); got != c.want {
			t.Errorf("%s: disturbed=%v, want %v", c.name, got, c.want)
		}
	}
}

// ── T-192: CR-702, CR-703, CR-707 ───────────────────────────────────────────

// CR-702: узел исключили (24 КБ провал) - он больше не «последний проверенный»; когда
// исключение истекло и поиск идёт заново, трафик не возвращается на него.
func TestVupenSettleExpiredExclusionDoesNotRevive(t *testing.T) {
	r := newStickyRig(t, "p-3", "p-1", "p-1", "p-2", "p-3", "p-4")
	r.alive(map[string]int64{"p-2": 5, "p-4": 10, "p-3": 40})
	r.pick()
	r.drain() // 24 КБ p-3 прошла: он последний проверенный
	if p := r.s.lastAlive.Load(); p == nil || *p != "p-3" {
		t.Fatalf("setup: p-3 must be the last verified node, got %v", p)
	}
	r.obs.check["p-3"] = vupenStickyFailed
	r.s.send(vupenStickyEvent{kind: "check", reason: "test"})
	r.drain() // p-3 исключён, поиск: p-2 и p-4 не прошли 64 КБ -> ничего не работает
	if !r.obs.excluded["p-3"] {
		t.Fatal("setup: the failed p-3 must be excluded")
	}
	if p := r.s.lastAlive.Load(); p != nil {
		t.Fatalf("an excluded node must stop being the last verified one, got %q", *p)
	}
	// 15 минут прошли: исключения сняты, p-3 снова отвечает на пробы; повторный поиск.
	r.obs.mu.Lock()
	r.obs.excluded = map[string]bool{}
	r.obs.verify["p-2"], r.obs.verify["p-4"] = vupenStickyFailed, vupenStickyOK
	r.obs.mu.Unlock()
	var during []string
	hookRig(t, r).onVerify = func(string) { during = append(during, r.pick()) }
	r.s.send(vupenStickyEvent{kind: "search", reason: "retry"})
	r.drain()
	if len(during) == 0 {
		t.Fatal("the retry search verified nothing")
	}
	for _, got := range during {
		if got == "p-3" {
			t.Fatalf("the node whose exclusion expired must not be shown as verified, got %v", during)
		}
	}
}

// CR-702: последний проверенный узел не ответил на свежую пробу этого поиска - временным
// он не показывается.
func TestVupenSettleLastAliveMustAnswerTheFreshProbe(t *testing.T) {
	r := newStickyRig(t, "p-3", "p-1", "p-1", "p-2", "p-3")
	r.alive(map[string]int64{"p-2": 5, "p-3": 40})
	r.pick()
	r.drain() // p-3 проверен
	h := hookRig(t, r)
	h.onProbe = func() { r.alive(map[string]int64{"p-2": 5}) } // в новой сети p-3 молчит
	var during []string
	h.onVerify = func(string) { during = append(during, r.pick()) }
	r.obs.verify["p-2"] = vupenStickyOK
	r.s.send(vupenStickyEvent{kind: "search", reason: "test"})
	r.drain()
	if len(during) == 0 || during[0] != "p-2" {
		t.Fatalf("p-3 did not answer the fresh probe: traffic must be on p-2, got %v", during)
	}
}

// CR-703: временный узел отвечает на пробы, но не тянет 64 КБ - трафик переезжает на
// следующего ответившего, не ждёт конца поиска; соединения всех покинутых временных
// узлов закрываются при итоговой смене.
func TestVupenSettleInterimThatFailsVerifyIsReplaced(t *testing.T) {
	r := newStickyRig(t, "", "p-1", "p-1", "p-2", "p-4", "p-5")
	r.alive(map[string]int64{"p-4": 10, "p-2": 30, "p-5": 40}) // p-1 молчит
	r.obs.verify["p-4"], r.obs.verify["p-2"], r.obs.verify["p-5"] = vupenStickyFailed, vupenStickyFailed, vupenStickyOK
	var during []string
	hookRig(t, r).onVerify = func(string) { during = append(during, r.pick()) }
	r.pick()
	r.drain()
	if !slices.Equal(during, []string{"p-4", "p-2", "p-5"}) {
		t.Fatalf("traffic must follow the search: each failed interim is replaced, got %v", during)
	}
	if got := r.pick(); got != "p-5" {
		t.Fatalf("after the search: %q, want p-5", got)
	}
	r.obs.mu.Lock()
	closed := slices.Clone(r.obs.closedTags)
	r.obs.mu.Unlock()
	slices.Sort(closed)
	if !slices.Equal(closed, []string{"p-2", "p-4"}) {
		t.Fatalf("connections of both abandoned interim nodes must be closed, got %v", closed)
	}
}

// CR-707: пока текущий узел исключён, а обработчик ещё не начал поиск, соединения не
// запрашивают замеры и не сортируют узлы каждое: временный узел запомнен на 2 с.
func TestVupenSettleExcludedCurrentCachesTheInterimPick(t *testing.T) {
	r := newStickyRig(t, "p-3", "p-1", "p-1", "p-2", "p-3")
	r.alive(map[string]int64{"p-2": 5, "p-3": 40})
	r.pick()
	r.drain() // p-3 держим
	h := hookRig(t, r)
	r.obs.mu.Lock()
	r.obs.excluded["p-3"] = true // исключили извне, событие ещё в очереди
	r.obs.mu.Unlock()
	if got := r.pick(); got != "p-2" {
		t.Fatalf("first pick: %q, want the ping-alive p-2", got)
	}
	first := h.obsCalls.Load() // замер (и порядок стратегии) - один раз
	for i := 0; i < 50; i++ {
		if got := r.pick(); got != "p-2" {
			t.Fatalf("pick %d: %q, want the ping-alive p-2", i, got)
		}
	}
	if first == 0 || h.obsCalls.Load() != first {
		t.Fatalf("50 more connections must cost no observation: after the first %d, now %d", first, h.obsCalls.Load())
	}
	// запомненный узел исключили - пересчёт сразу, не ждём срока
	r.obs.mu.Lock()
	r.obs.excluded["p-2"] = true
	r.obs.mu.Unlock()
	if got := r.pick(); got == "p-2" || got == "p-3" {
		t.Fatalf("the cached node became excluded: got %q", got)
	}
	// срок записи вышел - пересчёт
	before := h.obsCalls.Load()
	r.clock.Advance(vupenInterimCacheTTL + time.Second)
	r.pick()
	if h.obsCalls.Load() == before {
		t.Fatal("an expired cache entry must be recomputed")
	}
}

// ── T-205: CR-811 ───────────────────────────────────────────────────────────

func interimRig(t *testing.T) *stickyRig {
	t.Helper()
	r := newStickyRig(t, "p-1", "p-4", "p-1", "p-2", "p-3", "p-4")
	r.alive(map[string]int64{"p-1": 900, "p-2": 5, "p-3": 10}) // замеры прежней сети: p-2 и p-3 живы
	r.pick()
	r.drain()
	r.expectPhase(vupenPhaseHolding)
	r.s.noteAlive("p-2") // и «последний проверенный» - тоже прежней сети
	return r
}

// CR-811: после смены сети узел, живой только в прежней сети, не достаётся новым соединениям
// ни как «последний проверенный», ни из старых замеров, ни из запомненного (2 с) выбора.
// Пока в этой сети никто не ответил - запасной выбор; ответил - берётся он.
func TestVupenSettlePickNeverReturnsTheOldNetworkNode(t *testing.T) {
	r := interimRig(t)
	r.obs.excluded["p-1"] = true // держимый узел исключён, обработчик ещё не искал
	if got := r.pick(); got != "p-2" {
		t.Fatalf("setup (no network change): the last verified node is the interim, got %q", got)
	}
	r.s.onNetEvent(internet.VupenNetChanged) // сеть сменилась; результаты обсерватории - ещё прежние
	for i := 0; i < 3; i++ {
		if got := r.pick(); got != "p-4" {
			t.Fatalf("pick %d after the network change: %q, want the fallback p-4 (never the old p-2/p-3)", i, got)
		}
	}
	if p := r.s.lastAlive.Load(); p != nil {
		t.Fatalf("lastAlive must be cleared on a network change, got %q", *p)
	}
	// В этой сети ответил p-3: он и берётся (запомненный p-4 живёт 2 с - ждём).
	r.clock.Advance(3 * time.Second)
	r.obs.setRecent(map[string]time.Duration{"p-3": 20 * time.Millisecond})
	if got := r.pick(); got != "p-3" {
		t.Fatalf("an answerer of this network must be used, got %q", got)
	}
}

// То же, но lastAlive записан уже после смены сети проверкой, начатой ещё в прежней (гонка):
// без замера этой сети он не годится.
func TestVupenSettlePickIgnoresLastAliveWithoutThisNetworkSample(t *testing.T) {
	r := interimRig(t)
	r.obs.excluded["p-1"] = true
	r.s.onNetEvent(internet.VupenNetChanged)
	r.s.noteAlive("p-2") // запоздавшая проверка прежней сети
	if got := r.pick(); got != "p-4" {
		t.Fatalf("a late last-verified mark of the old network must not be used, got %q", got)
	}
	r.clock.Advance(3 * time.Second)
	r.obs.setRecent(map[string]time.Duration{"p-2": 30 * time.Millisecond})
	if got := r.pick(); got != "p-2" {
		t.Fatalf("the same node answering in this network is fine, got %q", got)
	}
}

// Давно после смены сети (окно замеров прошло) поведение прежнее: ответившие по обсерватории.
func TestVupenSettlePickLongAfterNetworkChangeUsesObservation(t *testing.T) {
	r := interimRig(t)
	r.obs.excluded["p-1"] = true
	r.s.onNetEvent(internet.VupenNetChanged)
	r.clock.Advance(VupenSwitchCacheMaxAge + time.Minute)
	if got := r.pick(); got != "p-2" {
		t.Fatalf("after the window the observation is trusted again (fastest alive p-2), got %q", got)
	}
}
