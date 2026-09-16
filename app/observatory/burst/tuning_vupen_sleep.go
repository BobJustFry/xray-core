package burst

import (
	"context"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/errors"
)

// Vupen (ядро 60): пробы балансировщика не идут, пока устройство спит или нет сети.
//
// Провалившаяся проба пишется в окно результатов как rttFailed и живёт
// `interval × sampling × 2` (у панели 10 минут). Во сне сети нет, и каждый плановый
// раунд кладёт каждому узлу провал: через `sampling` раундов `Alive = All != Fail`
// делает мёртвыми ВСЕ узлы разом, а ядро 55 мёртвый узел опрашивает в
// VupenObservatoryDeadBackoff раз реже — то есть возврат к нормальному опросу после
// сна занимал бы до десяти раундов. Живых нет → vupenLeastPingChoose возвращает
// пустой тег → балансировщик уходит в fallbackTag, первый узел списка. Снаружи это
// выглядит как «ротация идёт, а интернета нет».
//
// Что делаем:
//   - VupenObservatoryPause — новые раунды не начинаются, идущий отменяется;
//   - VupenObservatoryResume — счётчики мёртвых сбрасываются и пачка проб уходит
//     сразу, не дожидаясь тика (через полосы TCP×N / UDP×1, а не залпом);
//   - первые VupenObservatoryWakeGrace после пробуждения провалы не записываются:
//     радио ещё поднимается, а записанный провал живёт 10 минут;
//   - тик, пришедший много позже ожидаемого, сам считается пробуждением — процесс
//     замораживали (Windows: сигнала сна у нас там нет).
//
// Сигнал приходит снаружи: на Apple — из NE (`sleep`/`wake` и NWPathMonitor,
// см. PacketTunnelProvider). Платформы без сигнала живут на детекторе провала.
var (
	// VupenObservatoryWakeGrace — окно после пробуждения, в котором провалы не
	// записываются в результаты.
	VupenObservatoryWakeGrace = 20 * time.Second
	// VupenObservatoryGapFactor — тик позже ожидаемого во столько раз = мы спали.
	VupenObservatoryGapFactor = 2.0
)

// vupenObs — вентиль на все балансировщики процесса разом: их может быть
// несколько, а сон и сеть у устройства одни на всех.
var vupenObs = struct {
	mu     sync.Mutex
	active bool
	pings  map[*HealthPing]struct{}
}{
	active: true,
	pings:  make(map[*HealthPing]struct{}),
}

// VupenObservatoryPause — устройство уснуло или пропала сеть.
func VupenObservatoryPause(reason string) {
	vupenObs.mu.Lock()
	was := vupenObs.active
	vupenObs.active = false
	pings := vupenObsPingsLocked()
	vupenObs.mu.Unlock()
	errors.LogWarning(context.Background(),
		"[observatory] pause (", reason, ") balancers=", len(pings), " wasActive=", was)
	for _, h := range pings {
		h.vupenCancelRound()
	}
}

// VupenObservatoryResume — проснулись или вернулась сеть. Пачка уходит всегда, даже
// если паузы не было: после сна свежие замеры нужны сейчас, а не через тик.
func VupenObservatoryResume(reason string) {
	vupenObs.mu.Lock()
	was := vupenObs.active
	vupenObs.active = true
	pings := vupenObsPingsLocked()
	vupenObs.mu.Unlock()
	errors.LogWarning(context.Background(),
		"[observatory] resume (", reason, ") balancers=", len(pings), " wasActive=", was)
	for _, h := range pings {
		h.vupenAfterWake(reason)
	}
}

// VupenObservatoryActive — идут ли сейчас пробы (для лога и тестов).
func VupenObservatoryActive() bool {
	vupenObs.mu.Lock()
	defer vupenObs.mu.Unlock()
	return vupenObs.active
}

func vupenObsPingsLocked() []*HealthPing {
	list := make([]*HealthPing, 0, len(vupenObs.pings))
	for h := range vupenObs.pings {
		list = append(list, h)
	}
	return list
}

func vupenObsRegister(h *HealthPing) {
	vupenObs.mu.Lock()
	vupenObs.pings[h] = struct{}{}
	active := vupenObs.active
	vupenObs.mu.Unlock()
	if !active {
		// Ядро подняли во сне или без сети: раунды начнутся с пробуждением.
		errors.LogWarning(h.ctx, "[observatory] scheduler starts paused")
	}
}

func vupenObsUnregister(h *HealthPing) {
	vupenObs.mu.Lock()
	delete(vupenObs.pings, h)
	vupenObs.mu.Unlock()
}

// vupenCancelRound — отменить идущий раунд: его пробы просто не стартуют, а
// результаты дошедших не записываются (doCheck выходит по ctx.Done).
func (h *HealthPing) vupenCancelRound() {
	if c := h.cancelPending.Swap(nil); c != nil {
		(*c)()
	}
}

// vupenAfterWake — реакция на пробуждение: мёртвые узлы снова опрашиваются каждый
// раунд, ближайшие VupenObservatoryWakeGrace провалы не записываются, следующий
// раунд идёт пачкой и прямо сейчас.
func (h *HealthPing) vupenAfterWake(reason string) {
	h.access.Lock()
	h.deadSkip = nil
	h.access.Unlock()
	h.wakeGraceUntil.Store(time.Now().Add(VupenObservatoryWakeGrace).UnixNano())
	h.wakeBurst.Store(true)
	select {
	case h.wakeSignal <- struct{}{}:
	default:
	}
	errors.LogWarning(h.ctx, "[observatory] wake round (", reason, ")")
}

// vupenFailIgnored — провал сразу после пробуждения: не записываем.
func (h *HealthPing) vupenFailIgnored() bool {
	until := h.wakeGraceUntil.Load()
	return until > 0 && time.Now().UnixNano() < until
}

// vupenNoteRoundStart — засекает стенные часы начала раунда и ловит провал во
// времени. Стенные (Round(0) снимает монотонную составляющую) именно потому, что
// монотонные на Apple во сне не идут, а нам нужен реальный прошедший срок.
func (h *HealthPing) vupenNoteRoundStart(window time.Duration) {
	now := time.Now().Round(0)
	prev := h.lastRoundAt.Swap(now.UnixNano())
	if prev <= 0 || window <= 0 {
		return
	}
	gap := now.Sub(time.Unix(0, prev))
	if gap > time.Duration(float64(window)*VupenObservatoryGapFactor) {
		h.vupenAfterWake("time gap " + gap.Truncate(time.Second).String())
	}
}

// vupenTakeWakeSignal — съесть отложенный сигнал пробуждения: раунд всё равно
// начинается сейчас, и без этого цикл сразу пошёл бы на второй круг.
func (h *HealthPing) vupenTakeWakeSignal() {
	select {
	case <-h.wakeSignal:
	default:
	}
}
