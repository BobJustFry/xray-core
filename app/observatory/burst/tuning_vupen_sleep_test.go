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
func TestVupenPauseCancelsRunningRound(t *testing.T) {
	h := newSleepTestPing()
	vupenObsRegister(h)
	defer vupenObsUnregister(h)

	roundCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stored := context.CancelFunc(cancel)
	h.cancelPending.Store(&stored)

	VupenObservatoryPause("test")
	defer VupenObservatoryResume("test cleanup")

	if roundCtx.Err() == nil {
		t.Fatal("идущий раунд не отменён")
	}
	if h.cancelPending.Load() != nil {
		t.Fatal("отменённый раунд остался висеть в cancelPending")
	}
}

// Провал во времени = процесс морозили. Сигнала сна на Windows нет, поэтому
// пробуждение ядро должно распознать само.
func TestVupenTimeGapCountsAsWake(t *testing.T) {
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
