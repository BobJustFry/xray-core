package burst

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet/tagged"
)

// vupenObsResetForTest — вентиль глобальный: без сброса тесты видят следы соседа.
func vupenObsResetForTest(t *testing.T, shortSleep, burstGap time.Duration) {
	oldShort, oldGap := VupenObservatoryShortSleep, VupenObservatoryWakeBurstMinGap
	VupenObservatoryShortSleep, VupenObservatoryWakeBurstMinGap = shortSleep, burstGap
	vupenObs.mu.Lock()
	vupenObs.active = true
	vupenObs.pausedAt = time.Time{}
	vupenObs.lastBurstAt = time.Time{}
	vupenObs.mu.Unlock()
	t.Cleanup(func() {
		VupenObservatoryShortSleep, VupenObservatoryWakeBurstMinGap = oldShort, oldGap
		vupenObs.mu.Lock()
		vupenObs.active = true
		vupenObs.pausedAt = time.Time{}
		vupenObs.lastBurstAt = time.Time{}
		vupenObs.mu.Unlock()
	})
}

func newSleepTestPing() *HealthPing {
	return NewHealthPing(context.Background(), nil, &HealthPingConfig{
		Interval:      int64(10 * time.Second),
		SamplingCount: 1,
		Timeout:       int64(200 * time.Millisecond),
		Destination:   "http://127.0.0.1:9/generate_204",
	})
}

// Во сне стартовая пачка не уходит: ядро могли поднять при спящем устройстве.
func TestVupenObservatoryPauseSkipsInitialBurst(t *testing.T) {
	vupenObsResetForTest(t, 10*time.Millisecond, time.Millisecond)
	var dials atomic.Int64
	oldDialer := tagged.Dialer
	tagged.Dialer = func(ctx context.Context, d routing.Dispatcher, dest net.Destination, tag string) (net.Conn, error) {
		dials.Add(1)
		return nil, errors.New("down")
	}
	defer func() { tagged.Dialer = oldDialer }()

	oldInit := VupenObservatoryInitialDelay
	VupenObservatoryInitialDelay = 10 * time.Millisecond
	defer func() { VupenObservatoryInitialDelay = oldInit }()

	VupenObservatoryPause("test")
	defer VupenObservatoryResume("test cleanup")

	h := newSleepTestPing()
	h.StartScheduler(func() ([]string, error) { return []string{"a", "b"}, nil })
	defer h.StopScheduler()

	time.Sleep(150 * time.Millisecond)
	if n := dials.Load(); n != 0 {
		t.Fatalf("во сне ушло %d проб, ожидалось 0", n)
	}
}

// Пробуждение: мёртвые снова опрашиваются, окно без записи провалов взведено,
// раунд просится сразу — и именно пачкой.
func TestVupenObservatoryResumeArmsWakeRound(t *testing.T) {
	vupenObsResetForTest(t, 10*time.Millisecond, time.Millisecond)
	h := newSleepTestPing()
	vupenObsRegister(h)
	defer vupenObsUnregister(h)

	h.access.Lock()
	h.deadSkip = map[string]int{"proxy-2": 5}
	h.access.Unlock()

	VupenObservatoryPause("test sleep")
	if VupenObservatoryActive() {
		t.Fatal("после паузы вентиль остался открытым")
	}
	time.Sleep(30 * time.Millisecond) // сон должен стать «настоящим»
	VupenObservatoryResume("test wake")
	if !VupenObservatoryActive() {
		t.Fatal("после пробуждения вентиль не открылся")
	}
	if !h.wakeBurst.Load() {
		t.Fatal("раунд после пробуждения не помечен как пачка")
	}
	select {
	case <-h.wakeSignal:
	default:
		t.Fatal("цикл не разбужен — раунд ждал бы тика")
	}
	h.access.Lock()
	dead := len(h.deadSkip)
	h.access.Unlock()
	if dead != 0 {
		t.Fatalf("счётчики мёртвых не сброшены: %d", dead)
	}
	if !h.vupenFailIgnored() {
		t.Fatal("окно без записи провалов не взведено")
	}
}

// Пауза отменяет идущий раунд: его результаты не должны попасть в статистику.
func TestVupenLongPauseCancelsRunningRound(t *testing.T) {
	vupenObsResetForTest(t, 10*time.Millisecond, time.Millisecond)
	h := newSleepTestPing()
	vupenObsRegister(h)
	defer vupenObsUnregister(h)

	roundCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stored := context.CancelFunc(cancel)
	h.cancelPending.Store(&stored)

	VupenObservatoryPause("test")
	defer VupenObservatoryResume("test cleanup")

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) && roundCtx.Err() == nil {
		time.Sleep(5 * time.Millisecond)
	}
	if roundCtx.Err() == nil {
		t.Fatal("затянувшаяся пауза не отменила идущий раунд")
	}
	if h.cancelPending.Load() != nil {
		t.Fatal("отменённый раунд остался висеть в cancelPending")
	}
}

// Главная защита от разряда батареи: iOS дёргает sleep/wake каждые несколько
// секунд, и такой цикл не должен ни гонять пачку, ни убивать идущий раунд.
func TestVupenShortSleepIsNotASleep(t *testing.T) {
	vupenObsResetForTest(t, time.Second, time.Millisecond)
	h := newSleepTestPing()
	vupenObsRegister(h)
	defer vupenObsUnregister(h)

	roundCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stored := context.CancelFunc(cancel)
	h.cancelPending.Store(&stored)
	h.access.Lock()
	h.deadSkip = map[string]int{"proxy-2": 5}
	h.access.Unlock()
	// Раунд только что прошёл: данные свежие, гонять пачку незачем.
	h.lastRoundAt.Store(time.Now().UnixNano())

	for i := 0; i < 5; i++ {
		VupenObservatoryPause("system sleep")
		time.Sleep(5 * time.Millisecond)
		VupenObservatoryResume("wake")
	}

	if !VupenObservatoryActive() {
		t.Fatal("вентиль остался закрытым")
	}
	if h.wakeBurst.Load() {
		t.Fatal("короткий цикл энергосбережения погнал пачку проб")
	}
	if roundCtx.Err() != nil {
		t.Fatal("короткая пауза отменила идущий раунд")
	}
	if h.vupenFailIgnored() {
		t.Fatal("короткая пауза взвела окно без записи провалов")
	}
	h.access.Lock()
	dead := len(h.deadSkip)
	h.access.Unlock()
	if dead == 0 {
		t.Fatal("короткая пауза сбросила счётчики мёртвых узлов")
	}
}

// Обратная сторона: если раунда давно не было, пачка нужна даже после короткого
// цикла. Иначе тики теряются, результаты истекают, и у балансировщика не остаётся
// ни одного живого узла — весь трафик уходит в fallbackTag (бандл 2026-09-19).
func TestVupenStaleDataWakesRoundEvenAfterShortSleep(t *testing.T) {
	vupenObsResetForTest(t, time.Minute, time.Millisecond)
	h := newSleepTestPing()
	vupenObsRegister(h)
	defer vupenObsUnregister(h)

	window := h.Settings.Interval * time.Duration(h.Settings.SamplingCount)
	h.lastRoundAt.Store(time.Now().Add(-2 * window).UnixNano())
	if !h.vupenRoundDataStale() {
		t.Fatal("раунд был давно, а данные не считаются протухающими")
	}

	VupenObservatoryPause("system sleep")
	time.Sleep(5 * time.Millisecond)
	VupenObservatoryResume("wake")

	if !h.wakeBurst.Load() {
		t.Fatal("протухшие данные не подняли раунд")
	}
}

// Даже настоящие пробуждения подряд не должны давать пачку чаще, чем раз в окно.
func TestVupenWakeBurstRateLimited(t *testing.T) {
	vupenObsResetForTest(t, 10*time.Millisecond, time.Minute)
	h := newSleepTestPing()
	vupenObsRegister(h)
	defer vupenObsUnregister(h)

	h.lastRoundAt.Store(time.Now().Add(-time.Hour).UnixNano())
	VupenObservatoryPause("system sleep")
	time.Sleep(30 * time.Millisecond)
	VupenObservatoryResume("wake")
	if !h.wakeBurst.Load() {
		t.Fatal("первое пробуждение не дало пачку")
	}
	h.wakeBurst.Store(false)

	VupenObservatoryPause("system sleep")
	time.Sleep(30 * time.Millisecond)
	VupenObservatoryResume("wake")
	if h.wakeBurst.Load() {
		t.Fatal("вторая пачка ушла внутри окна ограничения")
	}
}

// Провал во времени = процесс морозили. Сигнала сна на Windows нет, поэтому
// пробуждение ядро должно распознать само.
func TestVupenTimeGapCountsAsWake(t *testing.T) {
	vupenObsResetForTest(t, 10*time.Millisecond, time.Millisecond)
	h := newSleepTestPing()
	h.vupenNoteRoundStart(time.Minute)
	h.wakeBurst.Store(false)
	h.lastRoundAt.Store(time.Now().Add(-10 * time.Minute).UnixNano())

	h.vupenNoteRoundStart(time.Minute)
	if !h.wakeBurst.Load() {
		t.Fatal("провал во времени не распознан как пробуждение")
	}

	h.wakeBurst.Store(false)
	h.vupenNoteRoundStart(time.Minute)
	if h.wakeBurst.Load() {
		t.Fatal("обычный тик принят за пробуждение")
	}
}

// Пачка после пробуждения могла уйти в неподнятое радио: живых замеров нет, и
// раунд нужно повторить, не дожидаясь тика. В окне без записи провалов «мёртвых»
// не бывает — у неудачного узла просто нет результата.
func TestVupenNoLiveResults(t *testing.T) {
	h := newSleepTestPing()
	tags := []string{"a", "b"}
	if !h.vupenNoLiveResults(tags) {
		t.Fatal("пустые результаты приняты за живые")
	}
	h.PutResult("a", rttFailed)
	if !h.vupenNoLiveResults(tags) {
		t.Fatal("один провал принят за живой замер")
	}
	h.PutResult("b", 120*time.Millisecond)
	if h.vupenNoLiveResults(tags) {
		t.Fatal("живой замер не увиден")
	}
}

// Окно после пробуждения истекает само: дальше провалы снова записываются.
func TestVupenWakeGraceExpires(t *testing.T) {
	h := newSleepTestPing()
	if h.vupenFailIgnored() {
		t.Fatal("окно взведено без пробуждения")
	}
	h.wakeGraceUntil.Store(time.Now().Add(50 * time.Millisecond).UnixNano())
	if !h.vupenFailIgnored() {
		t.Fatal("окно не действует сразу после пробуждения")
	}
	time.Sleep(80 * time.Millisecond)
	if h.vupenFailIgnored() {
		t.Fatal("окно не истекло")
	}
}

// Сценарий бандла 2026-09-19 целиком: пауза съела плановый тик, данные протухли.
// Раунд обязан уйти на возобновлении, не дожидаясь следующего тика — иначе
// результаты истекут, у балансировщика не останется живых узлов и весь трафик
// уедет в fallbackTag.
func TestVupenStaleResumeRunsRoundWithoutWaitingForTick(t *testing.T) {
	// Сон заведомо «короткий»: проверяем именно протухание данных, а не длину паузы.
	vupenObsResetForTest(t, time.Hour, time.Millisecond)

	var dials atomic.Int64
	oldDialer := tagged.Dialer
	tagged.Dialer = func(ctx context.Context, d routing.Dispatcher, dest net.Destination, tag string) (net.Conn, error) {
		dials.Add(1)
		return nil, errors.New("down")
	}
	defer func() { tagged.Dialer = oldDialer }()

	oldInit := VupenObservatoryInitialDelay
	VupenObservatoryInitialDelay = 10 * time.Millisecond
	defer func() { VupenObservatoryInitialDelay = oldInit }()

	h := newSleepTestPing() // interval 10s × sampling 1 → окно и тик 10 с
	h.StartScheduler(func() ([]string, error) { return []string{"a", "b"}, nil })
	defer h.StopScheduler()
	time.Sleep(200 * time.Millisecond) // стартовая пачка отработала

	base := dials.Load()
	if base == 0 {
		t.Fatal("стартовая пачка не ушла — тест бессмысленный")
	}

	VupenObservatoryPause("system sleep")
	// Так выглядит пропущенный тик: последний раунд был давно.
	h.lastRoundAt.Store(time.Now().Add(-time.Minute).UnixNano())
	time.Sleep(20 * time.Millisecond)
	VupenObservatoryResume("wake")

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && dials.Load() == base {
		time.Sleep(10 * time.Millisecond)
	}
	if got := dials.Load(); got == base {
		t.Fatal("на протухших данных раунд не ушёл: балансировщик остался бы без замеров до тика")
	}
}
