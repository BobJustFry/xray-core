package burst

import (
	"context"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/errors"
)

// Vupen (ядро 61): пробы балансировщика не идут, пока устройство спит или нет сети.
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
//   - если пачка не нашла ни одного живого узла (ушла в неподнятое радио), она
//     повторяется через VupenObservatoryRetryDelay, а не через тик;
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
	// VupenObservatoryShortSleep — сон короче этого сном не считается.
	//
	// iOS 26 дёргает `sleep`/`wake` у расширения постоянно: бандл 2026-09-18 —
	// 160 циклов за 22 минуты, медиана 3,5 с. Каждый такой «сон» гнал пачку проб
	// по всем узлам и отменял идущий раунд: за 22 минуты завершились 15 раундов,
	// радио не простаивало ни секунды, телефон сел за ночь. Поэтому короткая
	// пауза только закрывает вентиль — без пачки, без сброса мёртвых и без
	// отмены идущего раунда.
	VupenObservatoryShortSleep = 60 * time.Second
	// VupenObservatoryWakeBurstMinGap — чаще этого пачку на пробуждение не гоняем,
	// каким бы ни был повод (сон, возврат сети, провал во времени).
	VupenObservatoryWakeBurstMinGap = 2 * time.Minute
)

// vupenObs — вентиль на все балансировщики процесса разом: их может быть
// несколько, а сон и сеть у устройства одни на всех.
var vupenObs = struct {
	mu     sync.Mutex
	active bool
	pings  map[*HealthPing]struct{}
	// Стенные часы: когда закрыли вентиль и когда последний раз гоняли пачку.
	pausedAt    time.Time
	lastBurstAt time.Time
	// Поколение паузы: отложенная отмена раунда не должна сработать после того,
	// как вентиль успели открыть и закрыть снова.
	pauseGen int64
}{
	active: true,
	pings:  make(map[*HealthPing]struct{}),
}

// VupenObservatoryPause — устройство уснуло или пропала сеть.
//
// Тихая операция: новые раунды не начинаются, но идущий живёт ещё
// VupenObservatoryShortSleep. Если к тому времени вентиль всё ещё закрыт — сон
// настоящий, раунд отменяется, и только тогда это попадает в лог.
func VupenObservatoryPause(reason string) {
	vupenObs.mu.Lock()
	if !vupenObs.active {
		vupenObs.mu.Unlock()
		return
	}
	vupenObs.active = false
	vupenObs.pausedAt = time.Now().Round(0)
	vupenObs.pauseGen++
	gen := vupenObs.pauseGen
	vupenObs.mu.Unlock()

	time.AfterFunc(VupenObservatoryShortSleep, func() {
		vupenObsCancelRoundsIfStillPaused(gen, reason)
	})
}

// vupenObsCancelRoundsIfStillPaused — пауза затянулась: это настоящий сон или
// долгая пропажа сети, идущий раунд можно отменять.
func vupenObsCancelRoundsIfStillPaused(gen int64, reason string) {
	vupenObs.mu.Lock()
	stale := vupenObs.active || vupenObs.pauseGen != gen
	pings := vupenObsPingsLocked()
	vupenObs.mu.Unlock()
	if stale {
		return
	}
	errors.LogWarning(context.Background(),
		"[observatory] paused (", reason, ") balancers=", len(pings))
	for _, h := range pings {
		if vupenObsDropIfDone(h) {
			continue
		}
		h.vupenCancelRound()
	}
}

// VupenObservatoryResume — проснулись или вернулась сеть.
//
// Пачка уходит, только если пауза была настоящей (дольше
// VupenObservatoryShortSleep) и с прошлой пачки прошло больше
// VupenObservatoryWakeBurstMinGap. Короткий цикл энергосбережения просто
// открывает вентиль: свежие замеры от него не появятся, а радио он будит.
func VupenObservatoryResume(reason string) {
	vupenObs.mu.Lock()
	was := vupenObs.active
	slept := time.Duration(0)
	if !was && !vupenObs.pausedAt.IsZero() {
		slept = time.Now().Round(0).Sub(vupenObs.pausedAt)
	}
	vupenObs.active = true
	pings := vupenObsPingsLocked()
	vupenObs.mu.Unlock()

	if !vupenObsTakeWakeBurstSlot(slept) {
		return
	}
	errors.LogWarning(context.Background(),
		"[observatory] resume (", reason, ") slept=", slept.Truncate(time.Second).String(),
		" balancers=", len(pings))
	for _, h := range pings {
		if vupenObsDropIfDone(h) {
			continue
		}
		h.vupenAfterWake(reason)
	}
}

// vupenObsTakeWakeBurstSlot — можно ли гнать пачку прямо сейчас. Отмеряет и сон,
// и промежуток с прошлой пачки; при разрешении сразу занимает слот.
func vupenObsTakeWakeBurstSlot(slept time.Duration) bool {
	if slept < VupenObservatoryShortSleep {
		return false
	}
	return vupenObsTakeWakeBurstSlotForced()
}

// vupenObsTakeWakeBurstSlotForced — то же, но без проверки длительности сна: для
// детектора провала во времени, где сна как события не было вовсе.
func vupenObsTakeWakeBurstSlotForced() bool {
	now := time.Now().Round(0)
	vupenObs.mu.Lock()
	defer vupenObs.mu.Unlock()
	if !vupenObs.lastBurstAt.IsZero() &&
		now.Sub(vupenObs.lastBurstAt) < VupenObservatoryWakeBurstMinGap {
		return false
	}
	vupenObs.lastBurstAt = now
	return true
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

// vupenObsDropIfDone — ядро этого балансировщика уже остановлено: чистим реестр
// сами, чтобы забытый StopScheduler не копил в нём мёртвые записи.
func vupenObsDropIfDone(h *HealthPing) bool {
	if h.ctx.Err() == nil {
		return false
	}
	vupenObsUnregister(h)
	return true
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

// vupenNoLiveResults — ни у одного узла раунда нет живого замера. В окне после
// пробуждения провалы не записываются, поэтому «мёртвых» тут не будет: у неудачного
// узла просто нет результата (`All == 0`), и отличить его от живого может только это.
func (h *HealthPing) vupenNoLiveResults(tags []string) bool {
	h.access.Lock()
	defer h.access.Unlock()
	for _, tag := range tags {
		r, ok := h.Results[tag]
		if !ok {
			continue
		}
		if s := r.getStatistics(); s.All > s.Fail {
			return false
		}
	}
	return true
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
	if gap <= time.Duration(float64(window)*VupenObservatoryGapFactor) {
		return
	}
	if !vupenObsTakeWakeBurstSlotForced() {
		return
	}
	h.vupenAfterWake("time gap " + gap.Truncate(time.Second).String())
}

// vupenTakeWakeSignal — съесть отложенный сигнал пробуждения: раунд всё равно
// начинается сейчас, и без этого цикл сразу пошёл бы на второй круг.
func (h *HealthPing) vupenTakeWakeSignal() {
	select {
	case <-h.wakeSignal:
	default:
	}
}
