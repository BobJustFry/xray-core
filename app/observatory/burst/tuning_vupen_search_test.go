package burst

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Ядро 88 (D-70, T-199): пробы поиска - 10 TCP + 1 UDP, остановка на трёх ответивших.

// searchRig - обсерватория без планировщика с подменённой пробой. Имена: "alive-N-<мс>" отвечает
// через <мс>, "dead-N" молчит до таймаута пробы или отмены, "u-..." - UDP-полоса.
type searchRig struct {
	hp                *HealthPing
	o                 *Observer
	tcpNow, tcpPeak   atomic.Int32
	udpNow, udpPeak   atomic.Int32
	started           sync.Map                         // tag → time.Time
	ctxs              sync.Map                         // tag → context.Context пробы
	onStart           atomic.Pointer[func(tag string)] // подменяется, пока фон ещё идёт
	mu                sync.Mutex
	finishedAfterStop []string
}

func peak(now, pk *atomic.Int32) func() {
	n := now.Add(1)
	for {
		p := pk.Load()
		if n <= p || pk.CompareAndSwap(p, n) {
			break
		}
	}
	return func() { now.Add(-1) }
}

func scanMs(s string, ms *int) bool {
	_, err := fmt.Sscanf(s, "%d", ms)
	return err == nil
}

func newSearchRig(t *testing.T, timeout time.Duration) *searchRig {
	t.Helper()
	r := &searchRig{}
	r.hp = newSleepTestPing()
	r.hp.Settings.Timeout = timeout
	r.hp.laneOf = func(tag string) string {
		if strings.HasPrefix(tag, "u-") {
			return vupenLaneUDP
		}
		return vupenLaneTCP
	}
	r.hp.vupenSearchPing = func(ctx context.Context, tag string, to time.Duration) (time.Duration, error) {
		if f := r.onStart.Load(); f != nil {
			(*f)(tag)
		}
		r.ctxs.Store(tag, ctx)
		r.started.Store(tag, time.Now())
		if strings.HasPrefix(tag, "u-") {
			defer peak(&r.udpNow, &r.udpPeak)()
		} else {
			defer peak(&r.tcpNow, &r.tcpPeak)()
		}
		var ms int
		if i := strings.Index(tag, "alive-"); i >= 0 && scanMs(tag[i+len("alive-"):], &ms) {
			select {
			case <-time.After(time.Duration(ms) * time.Millisecond):
				return time.Duration(ms) * time.Millisecond, nil
			case <-ctx.Done():
				return 0, ctx.Err()
			}
		}
		select {
		case <-time.After(to):
			return 0, errors.New("timeout")
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}
	r.o = &Observer{ctx: context.Background(), hp: r.hp}
	t.Cleanup(func() { r.waitIdle(t) })
	return r
}

// waitIdle - ждать, пока не выйдут все горутины проб (в том числе фоновые).
func (r *searchRig) waitIdle(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for r.hp.vupenSearchGoroutines.Load() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("search probe goroutines still running: %d", r.hp.vupenSearchGoroutines.Load())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

type searchAnswer struct {
	tag string
	rtt time.Duration
	at  time.Duration
}

func (r *searchRig) run(ctx context.Context, tags []string, want int, soft time.Duration) ([]searchAnswer, VupenSearchProbeResult, time.Duration) {
	start := time.Now()
	var got []searchAnswer
	res := r.o.VupenStickySearchProbeCtx(ctx, tags, want, soft, func(tag string, rtt time.Duration) {
		got = append(got, searchAnswer{tag, rtt, time.Since(start)})
	})
	return got, res, time.Since(start)
}

// Раунд кончается на третьем ответившем: 8 мёртвых узлов (таймаут пробы 5 с) рядом не
// задерживают, остальные пробы отменены и не доходят до таймаута.
func TestVupenSearchProbeStopsAtThreeAlive(t *testing.T) {
	r := newSearchRig(t, 5*time.Second)
	var tags []string
	for i := 0; i < 8; i++ {
		tags = append(tags, fmt.Sprintf("dead-%d", i))
	}
	// Живые стоят в первой волне из 10: порядок - дело вызывающего (недавно ответившие первыми).
	tags = append(tags[:2], append([]string{"alive-30", "alive-60", "alive-90", "alive-120"}, tags[2:]...)...)
	for i := 0; i < 10; i++ {
		tags = append(tags, fmt.Sprintf("dead-x%d", i))
	}
	got, res, took := r.run(context.Background(), tags, 3, 3500*time.Millisecond)
	if res.Reason != VupenSearchEnough || res.Answered != 3 || len(got) != 3 {
		t.Fatalf("result %+v answers %+v", res, got)
	}
	if took > time.Second {
		t.Fatalf("the round took %s, must not wait for the dead ones (timeout 5s)", took)
	}
	if got[0].tag != "alive-30" || got[1].tag != "alive-60" || got[2].tag != "alive-90" {
		t.Fatalf("answers in the order they came: %+v", got)
	}
	// Четвёртый живой (120 мс) уже отменён: его ответа в раунде нет, в результатах обсерватории - тоже.
	if rec := r.o.VupenStickyRecent([]string{"alive-120"}, time.Minute); len(rec) != 0 {
		t.Fatalf("cancelled probe recorded: %v", rec)
	}
	if rec := r.o.VupenStickyRecent([]string{"alive-30", "alive-60", "alive-90"}, time.Minute); len(rec) != 3 {
		t.Fatalf("answers not recorded: %v", rec)
	}
	// Очередь за первой волной не запускалась.
	if _, ok := r.started.Load("dead-x9"); ok {
		t.Fatal("the probes behind the first wave started although 3 had answered")
	}
}

// Не больше 10 TCP и 1 UDP проб одновременно; обе полосы идут сразу, UDP не ждёт TCP.
func TestVupenSearchProbeLanesCap(t *testing.T) {
	r := newSearchRig(t, 150*time.Millisecond)
	var tags []string
	for i := 0; i < 29; i++ {
		tags = append(tags, fmt.Sprintf("dead-%d", i))
	}
	tags = append(tags, "u-dead-1", "u-dead-2", "u-dead-3")
	got, res, took := r.run(context.Background(), tags, 3, 3500*time.Millisecond)
	if res.Reason != VupenSearchDone || len(got) != 0 || res.Finished != 32 {
		t.Fatalf("result %+v answers %+v", res, got)
	}
	if p := r.tcpPeak.Load(); p != 10 {
		t.Fatalf("TCP probes at once: peak %d, want 10", p)
	}
	if p := r.udpPeak.Load(); p != 1 {
		t.Fatalf("UDP probes at once: peak %d, want 1", p)
	}
	// 29 TCP по 10: три волны по 150 мс; 3 UDP по одному: три волны - параллельно, не после.
	if took < 400*time.Millisecond || took > 1500*time.Millisecond {
		t.Fatalf("took %s", took)
	}
	st, _ := r.started.Load("u-dead-1")
	if d := st.(time.Time).Sub(time.Now().Add(-took)); d > 100*time.Millisecond {
		t.Fatalf("UDP probe started %s after the round start", d)
	}
}

// Мёртвые не ответили, а UDP-узел ответил в своей полосе: он считается ответившим.
func TestVupenSearchProbeUDPLaneAnswers(t *testing.T) {
	r := newSearchRig(t, time.Second)
	tags := []string{"dead-1", "dead-2", "u-alive-40", "alive-80"}
	got, res, _ := r.run(context.Background(), tags, 3, 500*time.Millisecond)
	if res.Answered != 2 || len(got) != 2 || got[0].tag != "u-alive-40" {
		t.Fatalf("result %+v answers %+v", res, got)
	}
}

// Срок вышел, ответил один, двое медленнее: берём ответившего, остальные пробы
// доживают в фоне и пополняют замеры, но в раунд уже не попадают.
func TestVupenSearchProbeDeadlineUsesWhoAnswered(t *testing.T) {
	r := newSearchRig(t, 2*time.Second)
	tags := []string{"alive-20", "alive-600", "alive-700", "dead-1", "dead-2"}
	got, res, took := r.run(context.Background(), tags, 3, 250*time.Millisecond)
	if res.Reason != VupenSearchDeadline || res.Answered != 1 || len(got) != 1 || got[0].tag != "alive-20" {
		t.Fatalf("result %+v answers %+v", res, got)
	}
	if took < 200*time.Millisecond || took > 500*time.Millisecond {
		t.Fatalf("returned after %s, want about the soft deadline 250ms", took)
	}
	if res.Background != 4 {
		t.Fatalf("background probes %d, want 4", res.Background)
	}
	// Фон: медленные живые дошли и записались; вызывающий их уже не слышит (got не растёт).
	deadline := time.Now().Add(3 * time.Second)
	for {
		rec := r.o.VupenStickyRecent([]string{"alive-600", "alive-700"}, time.Minute)
		if len(rec) == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("background answers were not recorded: %v", rec)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(got) != 1 {
		t.Fatalf("each called after the return: %+v", got)
	}
}

// Срок вышел, а ответивших нет: ждать первого ответа (не NoWorking раньше времени).
func TestVupenSearchProbeDeadlineWithNoAnswerWaitsForTheFirst(t *testing.T) {
	r := newSearchRig(t, 2*time.Second)
	tags := []string{"dead-1", "alive-400", "alive-900"}
	got, res, took := r.run(context.Background(), tags, 3, 100*time.Millisecond)
	if res.Reason != VupenSearchDeadline || len(got) != 1 || got[0].tag != "alive-400" {
		t.Fatalf("result %+v answers %+v", res, got)
	}
	if took < 350*time.Millisecond || took > 800*time.Millisecond {
		t.Fatalf("returned after %s, want at the first answer (400ms)", took)
	}
}

// Никто не ответил: раунд кончается, когда кончились все пробы (дальше - путь «нет рабочих»).
func TestVupenSearchProbeNobodyAnswers(t *testing.T) {
	r := newSearchRig(t, 120*time.Millisecond)
	got, res, _ := r.run(context.Background(), []string{"dead-1", "dead-2", "dead-3"}, 3, 50*time.Millisecond)
	if res.Reason != VupenSearchDone || res.Answered != 0 || len(got) != 0 || res.Finished != 3 {
		t.Fatalf("result %+v answers %+v", res, got)
	}
}

// Отмена вызывающего (смена сети) обрывает пробы сразу и ничего не записывает.
func TestVupenSearchProbeCallerCancel(t *testing.T) {
	r := newSearchRig(t, 5*time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(80*time.Millisecond, cancel)
	got, res, took := r.run(ctx, []string{"dead-1", "dead-2", "alive-2000"}, 3, 3500*time.Millisecond)
	if res.Reason != VupenSearchCancelled || len(got) != 0 || took > time.Second {
		t.Fatalf("result %+v answers %+v took %s", res, got, took)
	}
	r.waitIdle(t)
}

// Смена эпохи сети бросает пробы, оставленные в фоне, и замеры прежней эпохи не пишутся.
func TestVupenSearchProbeEpochChangeDropsBackground(t *testing.T) {
	var epoch atomic.Uint64
	epoch.Store(7)
	old := vupenBurstEpochNow
	vupenBurstEpochNow = func() uint64 { return epoch.Load() }
	r := newSearchRig(t, 5*time.Second)
	t.Cleanup(func() {
		r.waitIdle(t)
		vupenBurstEpochNow = old
	})
	got, res, _ := r.run(context.Background(), []string{"alive-10", "alive-800", "dead-1"}, 3, 200*time.Millisecond)
	if res.Reason != VupenSearchDeadline || len(got) != 1 || res.Background != 2 {
		t.Fatalf("result %+v answers %+v", res, got)
	}
	epoch.Store(8) // сеть сменилась, пока фон ещё идёт
	r.waitIdle(t)  // фон бросили (эпоха), а не ждали таймаута 5 с
	if rec := r.o.VupenStickyRecent([]string{"alive-800"}, time.Minute); len(rec) != 0 {
		t.Fatalf("a result of the previous network was recorded: %v", rec)
	}
}

// leftoverRound - раунд, после которого в фоне остаются 14 мёртвых проб (10 в полёте).
func (r *searchRig) leftoverRound(t *testing.T) {
	t.Helper()
	tags := []string{"alive-20"}
	for i := 0; i < 14; i++ {
		tags = append(tags, fmt.Sprintf("dead-%d", i))
	}
	got, res, _ := r.run(context.Background(), tags, 3, 150*time.Millisecond)
	if res.Reason != VupenSearchDeadline || len(got) != 1 || res.Background != 14 {
		t.Fatalf("result %+v answers %+v", res, got)
	}
}

// CR-804: конец поиска отменяет оставленные в фоне пробы сразу (не ждёт таймаута 5 с), горутины
// выходят; ответ, полученный раньше, в замерах остаётся.
func TestVupenSearchProbeCancelStopsLeftovers(t *testing.T) {
	r := newSearchRig(t, 5*time.Second)
	r.leftoverRound(t)
	if p := r.tcpNow.Load(); p < 1 {
		t.Fatalf("no probe left in the background: %d", p)
	}
	start := time.Now()
	if !r.o.VupenStickyCancelSearchProbes() {
		t.Fatal("there was a background to cancel")
	}
	r.waitIdle(t)
	if took := time.Since(start); took > time.Second {
		t.Fatalf("leftovers needed %s to stop (probe timeout is 5s)", took)
	}
	if r.tcpNow.Load() != 0 {
		t.Fatalf("probes still in flight: %d", r.tcpNow.Load())
	}
	if r.o.VupenStickyCancelSearchProbes() {
		t.Fatal("a second cancel has nothing to cancel")
	}
	if rec := r.o.VupenStickyRecent([]string{"alive-20"}, time.Minute); len(rec) != 1 {
		t.Fatalf("the answer received before is gone: %v", rec)
	}
}

// CR-804: следующий раунд (новый поиск, лечение, перепроверка) начинается, когда пробы
// прежнего уже отменены: в полёте не больше 10+1 проб одного раунда.
func TestVupenSearchProbeNextRoundCancelsLeftovers(t *testing.T) {
	r := newSearchRig(t, 5*time.Second)
	r.leftoverRound(t)
	var notCancelled atomic.Int32
	hook := func(tag string) {
		if !strings.HasPrefix(tag, "alive-3") {
			return
		}
		r.ctxs.Range(func(k, v any) bool {
			if strings.HasPrefix(k.(string), "dead-") && v.(context.Context).Err() == nil {
				notCancelled.Add(1)
			}
			return true
		})
	}
	r.onStart.Store(&hook)
	got, res, _ := r.run(context.Background(), []string{"alive-30", "alive-35", "alive-40"}, 3, 3500*time.Millisecond)
	if res.Reason != VupenSearchEnough || len(got) != 3 {
		t.Fatalf("result %+v answers %+v", res, got)
	}
	if n := notCancelled.Load(); n != 0 {
		t.Fatalf("%d probes of the previous round were still alive when the next round started", n)
	}
	r.waitIdle(t)
	if r.tcpPeak.Load() > 10 {
		t.Fatalf("TCP peak %d, want <= 10", r.tcpPeak.Load())
	}
}

// Фон, закончившийся сам, ничего не оставляет: отменять нечего, горутин не осталось.
func TestVupenSearchProbeBackgroundFinishedByItself(t *testing.T) {
	r := newSearchRig(t, 120*time.Millisecond)
	got, res, _ := r.run(context.Background(), []string{"alive-10", "dead-1", "dead-2"}, 3, 30*time.Millisecond)
	if res.Reason != VupenSearchDeadline || len(got) != 1 {
		t.Fatalf("result %+v answers %+v", res, got)
	}
	r.waitIdle(t)
	if r.o.VupenStickyCancelSearchProbes() {
		t.Fatal("the background had finished; nothing to cancel")
	}
}
