package router

import (
	"context"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/observatory/burst"
	"github.com/xtls/xray-core/transport/internet"
)

// Ядро 88 (D-70, T-199): новый алгоритм поиска и повторная проверка после переключения.

// searchFake - обсерватория с пробами поиска ядра 88: ответы берутся из сценария (по
// порядку прихода), узлы вне переданного списка пропускаются.
type searchFake struct {
	*stickyFakeObs
	smu      sync.Mutex
	scripts  [][]vupenAnswer // сценарий n-го раунда проб (последний повторяется)
	calls    int
	ordered  [][]string
	wants    []int
	softs    []time.Duration
	recent   map[string]time.Duration
	ages     []time.Duration
	onStart  func()
	onAnswer func(tag string)
	onVerify func(tag string)
	cancels  int // сколько раз поиск отменял пробы, оставленные в фоне (CR-804)
}

func (f *searchFake) VupenStickyCancelSearchProbes() bool {
	f.smu.Lock()
	defer f.smu.Unlock()
	f.cancels++
	return true
}

func (f *searchFake) cancelCount() int {
	f.smu.Lock()
	defer f.smu.Unlock()
	return f.cancels
}

func (f *searchFake) VupenStickySearchProbeCtx(ctx context.Context, tags []string, want int, soft time.Duration,
	each func(tag string, rtt time.Duration)) burst.VupenSearchProbeResult {
	f.smu.Lock()
	i := f.calls
	f.calls++
	f.ordered = append(f.ordered, slices.Clone(tags))
	f.wants = append(f.wants, want)
	f.softs = append(f.softs, soft)
	var script []vupenAnswer
	if len(f.scripts) > 0 {
		script = f.scripts[min(i, len(f.scripts)-1)]
	}
	start, onAnswer := f.onStart, f.onAnswer
	f.smu.Unlock()
	if start != nil {
		start()
	}
	res := burst.VupenSearchProbeResult{Reason: burst.VupenSearchDone}
	for _, a := range script {
		if !slices.Contains(tags, a.tag) {
			continue
		}
		each(a.tag, a.rtt)
		res.Answered++
		if onAnswer != nil {
			onAnswer(a.tag)
		}
		if res.Answered >= want {
			res.Reason = burst.VupenSearchEnough
			break
		}
	}
	return res
}

func (f *searchFake) VupenStickyRecent(tags []string, maxAge time.Duration) map[string]time.Duration {
	f.smu.Lock()
	defer f.smu.Unlock()
	f.ages = append(f.ages, maxAge)
	return f.recent
}

func (f *searchFake) VupenStickyVerify(tag string) string {
	if f.onVerify != nil {
		f.onVerify(tag)
	}
	return f.stickyFakeObs.VupenStickyVerify(tag)
}

func newSearchTestRig(t *testing.T, fallback string, tags ...string) (*stickyRig, *searchFake) {
	t.Helper()
	r := newStickyRig(t, "", fallback, tags...)
	fo := &searchFake{stickyFakeObs: r.obs}
	var so vupenStickyObservatory = fo
	r.s.obs.Store(&so)
	return r, fo
}

// holdOn - узел держится и проходил проверку (как до смены сети).
func (r *stickyRig) holdOn(tag string) {
	r.s.current = tag
	r.s.publish(tag)
	r.s.setPhase(vupenPhaseHolding)
	r.s.noteAlive(tag)
}

func answers(pairs ...any) []vupenAnswer {
	var out []vupenAnswer
	for i := 0; i < len(pairs); i += 2 {
		out = append(out, vupenAnswer{pairs[i].(string), pairs[i+1].(time.Duration)})
	}
	return out
}

const ms = time.Millisecond

// Временный узел - первый, кто ответил на свежую пробу ЭТОГО поиска; узел из старых замеров
// (последний проверенный, «живой» по прежним данным) им не становится, как только есть
// свежий ответ. Проверка 85 КБ - на самом быстром из ответивших.
func TestVupenSearchInterimIsTheFirstFreshAnswerer(t *testing.T) {
	r, fo := newSearchTestRig(t, "n6", "n1", "n2", "n3", "n4", "n5", "n6")
	r.alive(map[string]int64{"n1": 5, "n2": 9}) // старые замеры: n1 и n2 живы и быстрее всех
	r.holdOn("n1")                              // последний проверенный; сейчас мёртв
	fo.scripts = [][]vupenAnswer{answers("n4", 80*ms, "n3", 30*ms, "n5", 50*ms)}
	r.obs.verify["n3"] = vupenStickyOK
	var views []string
	fo.onStart = func() { views = append(views, r.s.viewTag()) }
	fo.onAnswer = func(string) { views = append(views, r.s.viewTag()) }

	if n := r.s.searchN("test", VupenStickySearchMaxChecks); n != 1 {
		t.Fatalf("checked %d, want 1", n)
	}
	// До первого ответа - узел, на котором шёл трафик (выбор записан в отчёте T-199); после -
	// только первый ответивший n4, второй и третий ответы временный узел не меняют.
	if !slices.Equal(views, []string{"n1", "n4", "n4", "n4"}) {
		t.Fatalf("view during the search: %v", views)
	}
	if !slices.Equal(r.obs.verifies, []string{"n3"}) {
		t.Fatalf("85 KB check goes to the fastest answerer: %v", r.obs.verifies)
	}
	if r.s.viewTag() != "n3" || r.s.current != "n3" {
		t.Fatalf("view %q current %q, want n3", r.s.viewTag(), r.s.current)
	}
	if fo.wants[0] != 3 || fo.softs[0] != VupenSearchDeadline || VupenSearchDeadline != 3500*ms {
		t.Fatalf("round parameters: want %v soft %v", fo.wants, fo.softs)
	}
	if got := fo.ordered[0]; slices.Contains(got, "n6") != true || len(got) != 6 {
		t.Fatalf("the whole pool is probed: %v", got)
	}
}

// Узел, на котором шёл трафик, исключён (нужен поиск): до первого ответа берётся прежний
// запасной выбор, а не он.
func TestVupenSearchInterimBeforeAnswerSkipsExcludedView(t *testing.T) {
	r, fo := newSearchTestRig(t, "n6", "n1", "n2", "n6")
	r.holdOn("n1")
	r.obs.excluded["n1"] = true
	fo.scripts = [][]vupenAnswer{answers("n2", 10*ms)}
	r.obs.verify["n2"] = vupenStickyOK
	var first string
	fo.onStart = func() { first = r.s.viewTag() }
	r.s.searchN("test", 3)
	if first == "n1" || first == "" {
		t.Fatalf("an excluded node must not stay the interim: %q", first)
	}
}

// CR-801 (T-202): сразу после смены сети в результатах обсерватории лежит прежняя сеть. Узел,
// живой только там (и «последний проверенный»), не становится временным, пока нет свежего
// ответа: берётся запасной выбор.
func TestVupenSearchInterimNeverTakesAStaleAliveNode(t *testing.T) {
	r, fo := newSearchTestRig(t, "n6", "n1", "n2", "n3", "n6")
	r.alive(map[string]int64{"n2": 5, "n3": 9}) // прежняя сеть: n2 и n3 живы и быстрые
	r.holdOn("n1")
	r.s.noteAlive("n2") // и последний проверенный - тоже прежней сети
	r.obs.excluded["n1"] = true
	r.clock.Advance(time.Hour)
	r.s.signals.mu.Lock()
	r.s.signals.netChangedAt = r.clock.now.Add(-3 * time.Second)
	r.s.signals.mu.Unlock()
	fo.recent = nil // в этой сети ещё никто не отвечал
	fo.scripts = [][]vupenAnswer{answers("n3", 40*ms)}
	r.obs.verify["n3"] = vupenStickyOK
	var seen []string
	fo.onStart = func() { seen = append(seen, r.s.viewTag()) }
	fo.onAnswer = func(string) { seen = append(seen, r.s.viewTag()) }
	r.s.searchN("test", 3)
	if len(seen) == 0 || seen[0] != "n6" {
		t.Fatalf("interim before the first answer: %v, want the fallback n6 (never a stale n2/n3)", seen)
	}
	if fo.ages[0] != 3*time.Second {
		t.Fatalf("recency window for the interim %v, want 3s (since the network change)", fo.ages[0])
	}
}

// То же, но в этой сети кто-то уже отвечал на пробу: временный - самый быстрый из таких, а не
// узел из прежней сети.
func TestVupenSearchInterimPrefersAnswerersOfThisNetwork(t *testing.T) {
	r, fo := newSearchTestRig(t, "n6", "n1", "n2", "n3", "n4", "n6")
	r.alive(map[string]int64{"n2": 5})
	r.holdOn("n1")
	r.s.noteAlive("n2")
	r.obs.excluded["n1"] = true
	fo.recent = map[string]time.Duration{"n3": 70 * ms, "n4": 30 * ms, "n6": -1}
	fo.scripts = [][]vupenAnswer{answers("n4", 30*ms)}
	r.obs.verify["n4"] = vupenStickyOK
	var first string
	fo.onStart = func() { first = r.s.viewTag() }
	r.s.searchN("test", 3)
	if first != "n4" {
		t.Fatalf("interim %q, want n4 (fastest answerer of this network)", first)
	}
}

// CR-804 (T-202): пробы, оставленные в фоне, не переживают поиск: после него (переключил,
// не нашёл) обсерваторию просят их отменить - но не раньше конца проверки 85 КБ.
func TestVupenSearchCancelsBackgroundProbesWhenTheSearchEnds(t *testing.T) {
	r, fo := newSearchTestRig(t, "n6", "n1", "n2", "n3", "n6")
	r.holdOn("n1")
	fo.scripts = [][]vupenAnswer{answers("n3", 30*ms)}
	r.obs.verify["n3"] = vupenStickyOK
	atVerify := -1
	fo.onVerify = func(string) { atVerify = fo.cancelCount() }
	r.s.searchN("test", 3)
	if atVerify != 0 {
		t.Fatalf("the background probes were cancelled before the verify ended: %d", atVerify)
	}
	if fo.cancelCount() != 1 {
		t.Fatalf("cancels after a switch: %d, want 1", fo.cancelCount())
	}
	fo.scripts = append(fo.scripts, nil) // следующий поиск: никто не ответил
	r.s.searchN("again", 3)
	if fo.cancelCount() != 2 {
		t.Fatalf("cancels after NoWorking: %d, want 2", fo.cancelCount())
	}
}

// Один поиск - одна отмена и в цепочке «перепроверка -> один новый поиск».
func TestVupenSearchBackgroundCancelInRecheckChain(t *testing.T) {
	r, fo := switchedRig(t)
	r.obs.check["n3"] = vupenStickyFailed
	fo.scripts = append(fo.scripts, answers("n5", 40*ms))
	r.obs.verify["n5"] = vupenStickyOK
	r.clock.Advance(VupenStickyPostSwitchRecheck)
	r.drain()
	if fo.cancelCount() != 2 || fo.calls != 2 {
		t.Fatalf("cancels %d, rounds %d, want 2 and 2", fo.cancelCount(), fo.calls)
	}
}

// Самый быстрый не прошёл 85 КБ - следующий из ответивших; временный узел уходит с
// провалившегося на следующего из ответивших в этом поиске.
func TestVupenSearchNextAnswererOnVerifyFail(t *testing.T) {
	r, fo := newSearchTestRig(t, "n6", "n1", "n2", "n3", "n4", "n5", "n6")
	r.holdOn("n1")
	fo.scripts = [][]vupenAnswer{answers("n3", 30*ms, "n5", 50*ms, "n4", 80*ms)}
	r.obs.verify["n5"] = vupenStickyOK
	var views []string
	fo.onVerify = func(tag string) { views = append(views, tag+"@"+r.s.viewTag()) }

	if n := r.s.searchN("test", 3); n != 2 {
		t.Fatalf("checked %d, want 2", n)
	}
	if !slices.Equal(r.obs.verifies, []string{"n3", "n5"}) {
		t.Fatalf("verifies %v", r.obs.verifies)
	}
	if !slices.Equal(views, []string{"n3@n3", "n5@n5"}) {
		t.Fatalf("view at each verify: %v", views)
	}
	if r.s.current != "n5" || !r.obs.excluded["n3"] {
		t.Fatalf("current %q, excluded %v", r.s.current, r.obs.excluded)
	}
}

// Три проверки - предел: ни одна не прошла - «нет рабочих», повтор по графику.
func TestVupenSearchThreeChecksThenNoWorking(t *testing.T) {
	r, fo := newSearchTestRig(t, "n6", "n1", "n2", "n3", "n4", "n5", "n6")
	r.holdOn("n1")
	fo.scripts = [][]vupenAnswer{answers("n3", 30*ms, "n5", 50*ms, "n4", 80*ms)}
	if n := r.s.searchN("test", 3); n != 3 {
		t.Fatalf("checked %d, want 3", n)
	}
	if !slices.Equal(r.obs.verifies, []string{"n3", "n5", "n4"}) {
		t.Fatalf("verifies %v", r.obs.verifies)
	}
	r.expectPhase(vupenPhaseNoWorking)
	if !slices.Contains(r.clock.pendingIn(), 30*time.Second) {
		t.Fatalf("retry in 30s expected, pending %v", r.clock.pendingIn())
	}
	if slices.Contains(r.clock.pendingIn(), VupenStickyPostSwitchRecheck) {
		t.Fatal("no re-check without a switch")
	}
}

// Ответили меньше трёх (срок вышел): берём лучшего из ответивших.
func TestVupenSearchFewerThanThreeUsesWhoAnswered(t *testing.T) {
	r, fo := newSearchTestRig(t, "n6", "n1", "n2", "n3", "n6")
	r.holdOn("n1")
	fo.scripts = [][]vupenAnswer{answers("n2", 200*ms)}
	r.obs.verify["n2"] = vupenStickyOK
	if n := r.s.searchN("test", 3); n != 1 {
		t.Fatalf("checked %d", n)
	}
	if r.s.current != "n2" {
		t.Fatalf("current %q, want n2", r.s.current)
	}
}

// Никто не ответил: ни проверок, ни смены узла; запасной выбор и повтор по графику.
func TestVupenSearchNobodyAnswered(t *testing.T) {
	r, fo := newSearchTestRig(t, "n6", "n1", "n2", "n6")
	r.holdOn("n1")
	fo.scripts = [][]vupenAnswer{nil}
	if n := r.s.searchN("test", 3); n != 0 {
		t.Fatalf("checked %d", n)
	}
	r.expectPhase(vupenPhaseNoWorking)
	if len(r.obs.verifies) != 0 || r.s.viewTag() != "n6" {
		t.Fatalf("verifies %v, view %q (fallback expected)", r.obs.verifies, r.s.viewTag())
	}
	if !slices.Contains(r.clock.pendingIn(), 30*time.Second) {
		t.Fatalf("pending %v", r.clock.pendingIn())
	}
}

// Порядок проб: недавно ответившие (по возрастанию задержки), затем без замера, затем недавно
// не ответившие; первыми идут по одному узлу из каждой подсети. Давность замера - не старше
// последней смены сети (cacheMaxAge).
func TestVupenSearchProbeOrderRecentFirstAndDiverse(t *testing.T) {
	r, fo := newSearchTestRig(t, "n6", "n1", "n2", "n3", "n4", "n5", "n6")
	for tag, k := range map[string]string{"n1": "A", "n2": "A", "n3": "B", "n4": "B", "n5": "C", "n6": "C"} {
		r.s.keys[tag] = k
	}
	fo.recent = map[string]time.Duration{"n3": 40 * ms, "n5": 20 * ms, "n2": -1}
	r.holdOn("n1")
	r.obs.excluded["n1"] = true // в пул не входит
	r.s.searchN("test", 3)
	// хорошие: n5 (20), n3 (40); без замера: n4, n6; плохие: n2. Подсети - внутри групп
	// (CR-803): порядок групп не нарушается, недавно не ответивший n2 - последним.
	want := []string{"n5", "n3", "n4", "n6", "n2"}
	if !slices.Equal(fo.ordered[0], want) {
		t.Fatalf("probe order %v, want %v", fo.ordered[0], want)
	}
	if fo.ages[0] != VupenSwitchCacheMaxAge {
		t.Fatalf("recency window %v", fo.ages[0])
	}
}

// CR-803 (T-202): разные подсети - внутри каждой группы; недавно не ответивший узел из
// новой подсети не обгоняет недавно ответившего из уже виденной.
func TestVupenSearchProbeOrderDiversityStaysInsideGroups(t *testing.T) {
	r, fo := newSearchTestRig(t, "n6", "n1", "n2", "n3", "n4", "n5", "n6")
	for tag, k := range map[string]string{"n1": "A", "n2": "A", "n3": "B", "n4": "D", "n5": "C", "n6": "C"} {
		r.s.keys[tag] = k
	}
	// ответили: n1 (A), n2 (A), n3 (B); без замера: n5, n6 (обе C); не ответил: n4 (D, своя подсеть)
	fo.recent = map[string]time.Duration{"n1": 10 * ms, "n2": 20 * ms, "n3": 30 * ms, "n4": -1}
	r.holdOn("n1")
	r.s.searchN("test", 3)
	want := []string{"n1", "n3", "n2", "n5", "n6", "n4"}
	if !slices.Equal(fo.ordered[0], want) {
		t.Fatalf("probe order %v, want %v (one list diversity would give n4 before n2)", fo.ordered[0], want)
	}
}

// Замеры старше последней смены сети в порядке не участвуют.
func TestVupenSearchProbeOrderRecencyIgnoresPreviousNetwork(t *testing.T) {
	r, fo := newSearchTestRig(t, "n6", "n1", "n2", "n6")
	r.holdOn("n1")
	r.clock.Advance(time.Hour)
	r.s.signals.mu.Lock()
	r.s.signals.netChangedAt = r.clock.now.Add(-20 * time.Second)
	r.s.signals.mu.Unlock()
	r.s.searchN("test", 3)
	if fo.ages[0] != 20*time.Second {
		t.Fatalf("recency window %v, want 20s (time since the network change)", fo.ages[0])
	}
}

// ── повторная проверка после переключения ───────────────────────────────────

func switchedRig(t *testing.T) (*stickyRig, *searchFake) {
	t.Helper()
	r, fo := newSearchTestRig(t, "n6", "n1", "n2", "n3", "n4", "n5", "n6")
	r.holdOn("n1")
	fo.scripts = [][]vupenAnswer{answers("n3", 30*ms, "n5", 50*ms)}
	r.obs.verify["n3"] = vupenStickyOK
	r.s.searchN("test", 3)
	if r.s.current != "n3" {
		t.Fatalf("current %q", r.s.current)
	}
	if !slices.Contains(r.clock.pendingIn(), VupenStickyPostSwitchRecheck) || VupenStickyPostSwitchRecheck != 12*time.Second {
		t.Fatalf("re-check must be armed for 12s, pending %v", r.clock.pendingIn())
	}
	return r, fo
}

// Прошла: ничего не меняется, новых проверок и поисков нет (без цикла).
func TestVupenStickyPostSwitchRecheckPasses(t *testing.T) {
	r, fo := switchedRig(t)
	r.clock.Advance(VupenStickyPostSwitchRecheck)
	r.drain()
	if !slices.Equal(r.obs.checks, []string{"n3"}) {
		t.Fatalf("one 24 KB check of the new node expected: %v", r.obs.checks)
	}
	r.expectPhase(vupenPhaseHolding)
	if r.s.current != "n3" || fo.calls != 1 {
		t.Fatalf("current %q, probe rounds %d", r.s.current, fo.calls)
	}
	if len(r.clock.pendingIn()) != 0 {
		t.Fatalf("nothing may be re-armed: %v", r.clock.pendingIn())
	}
	r.clock.Advance(24 * time.Hour)
	r.drain()
	if len(r.obs.checks) != 1 || fo.calls != 1 {
		t.Fatalf("no loop: checks %v, rounds %d", r.obs.checks, fo.calls)
	}
}

// Провал: узел исключён, один новый поиск; он переключает на другой узел - новой проверки нет.
func TestVupenStickyPostSwitchRecheckFailsReSearchesOnce(t *testing.T) {
	r, fo := switchedRig(t)
	r.obs.check["n3"] = vupenStickyFailed
	fo.scripts = append(fo.scripts, answers("n5", 40*ms)) // второй раунд проб
	r.obs.verify["n5"] = vupenStickyOK
	r.clock.Advance(VupenStickyPostSwitchRecheck)
	r.drain()
	if !r.obs.excluded["n3"] {
		t.Fatal("the failed node must be excluded")
	}
	if fo.calls != 2 || r.s.current != "n5" {
		t.Fatalf("rounds %d, current %q", fo.calls, r.s.current)
	}
	r.expectPhase(vupenPhaseHolding)
	if len(r.clock.pendingIn()) != 0 {
		t.Fatalf("the search after a failed re-check must not arm another: %v", r.clock.pendingIn())
	}
	r.clock.Advance(time.Hour)
	r.drain()
	if !slices.Equal(r.obs.checks, []string{"n3"}) || fo.calls != 2 {
		t.Fatalf("no loop: checks %v rounds %d", r.obs.checks, fo.calls)
	}
}

// Провал и второй поиск тоже ничего не нашёл: «нет рабочих», повтор 30 с, 1, 2, 5 мин.
func TestVupenStickyPostSwitchRecheckFailsThenNoWorking(t *testing.T) {
	r, fo := switchedRig(t)
	r.obs.check["n3"] = vupenStickyFailed
	fo.scripts = append(fo.scripts, nil)
	r.clock.Advance(VupenStickyPostSwitchRecheck)
	r.drain()
	r.expectPhase(vupenPhaseNoWorking)
	if fo.calls != 2 || !slices.Equal(r.clock.pendingIn(), []time.Duration{30 * time.Second}) {
		t.Fatalf("rounds %d, pending %v", fo.calls, r.clock.pendingIn())
	}
	if r.s.recheckChain {
		t.Fatal("the chain flag must be reset")
	}
}

// Сеть не винит узел: проверка, брошенная сменой сети, узел не исключает.
func TestVupenStickyPostSwitchRecheckEpochChangeCancels(t *testing.T) {
	f := installNetClassFake(t)
	r, fo := switchedRig(t)
	r.obs.check["n3"] = vupenStickyFailed
	f.newEpoch() // сеть сменилась до срока (событие ядра ещё не дошло)
	r.clock.Advance(VupenStickyPostSwitchRecheck)
	r.drain()
	if len(r.obs.checks) != 0 || r.obs.excluded["n3"] || fo.calls != 1 {
		t.Fatalf("checks %v excluded %v rounds %d", r.obs.checks, r.obs.excluded, fo.calls)
	}
	r.expectPhase(vupenPhaseHolding)
}

// Событие смены сети снимает таймер; уже стоящее в очереди событие устарело.
func TestVupenStickyPostSwitchRecheckNetworkEventCancels(t *testing.T) {
	r, _ := switchedRig(t)
	r.s.recheck.mu.Lock()
	gen := r.s.recheck.gen
	r.s.recheck.mu.Unlock()
	r.s.onNetEvent(internet.VupenNetChanged)
	if slices.Contains(r.clock.pendingIn(), VupenStickyPostSwitchRecheck) {
		t.Fatalf("the timer must be stopped: %v", r.clock.pendingIn())
	}
	r.s.send(vupenStickyEvent{kind: "recheck", gen: gen}) // успело встать в очередь
	r.clock.Advance(time.Minute)
	r.drain()
	if slices.Contains(r.obs.checks, "n3") {
		t.Fatalf("a stale re-check ran: %v", r.obs.checks)
	}
}

// Узел сменился (другой поиск, ручная смена) - старая проверка не нужна.
func TestVupenStickyPostSwitchRecheckSkippedWhenNodeChanged(t *testing.T) {
	r, _ := switchedRig(t)
	r.s.holdBecause("n4", "switch")
	r.clock.Advance(VupenStickyPostSwitchRecheck)
	r.drain()
	if len(r.obs.checks) != 0 {
		t.Fatalf("checks %v", r.obs.checks)
	}
	r.expectPhase(vupenPhaseHolding)
	if r.s.current != "n4" {
		t.Fatalf("current %q", r.s.current)
	}
}

// Узел уже исключён (сторож, ручной провал) - повторно не проверяется и не ищется заново.
func TestVupenStickyPostSwitchRecheckSkippedWhenExcluded(t *testing.T) {
	r, fo := switchedRig(t)
	r.obs.excluded["n3"] = true
	r.clock.Advance(VupenStickyPostSwitchRecheck)
	r.drain()
	if len(r.obs.checks) != 0 || fo.calls != 1 {
		t.Fatalf("checks %v rounds %d", r.obs.checks, fo.calls)
	}
}

// Туннель остановлен - таймер снят, событий нет.
func TestVupenStickyPostSwitchRecheckStopsWithTheCore(t *testing.T) {
	r, _ := switchedRig(t)
	r.s.stop()
	if slices.Contains(r.clock.pendingIn(), VupenStickyPostSwitchRecheck) {
		t.Fatalf("pending %v", r.clock.pendingIn())
	}
	r.clock.Advance(time.Hour)
	r.drain()
	if len(r.obs.checks) != 0 {
		t.Fatalf("checks %v", r.obs.checks)
	}
}

// Новое переключение заменяет проверку: сработает только последняя.
func TestVupenStickyPostSwitchRecheckOnlyLastSwitch(t *testing.T) {
	r, fo := switchedRig(t)
	r.obs.excluded["n3"] = true
	r.clock.Advance(5 * time.Second)
	fo.scripts = append(fo.scripts, answers("n5", 10*ms))
	r.obs.verify["n5"] = vupenStickyOK
	r.s.searchN("again", 3) // второе переключение (поиск не из проверки) - своя проверка
	if r.s.current != "n5" {
		t.Fatalf("current %q", r.s.current)
	}
	r.clock.Advance(VupenStickyPostSwitchRecheck - 5*time.Second) // срок первой проверки
	r.drain()
	if len(r.obs.checks) != 0 {
		t.Fatalf("the first re-check was replaced: %v", r.obs.checks)
	}
	r.clock.Advance(5 * time.Second)
	r.drain()
	if !slices.Equal(r.obs.checks, []string{"n5"}) {
		t.Fatalf("checks %v", r.obs.checks)
	}
}
