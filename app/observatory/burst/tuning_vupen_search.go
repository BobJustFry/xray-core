package burst

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/errors"
)

// Ядро 88 (D-70, T-199): пробы поиска АВТО 4.1.
//
// Разбор журнала iOS 4.1.669 (ядро 87): после смены сети поиск ждал ответа от ВСЕХ 29 узлов
// 20,7 с (полосы: TCP ×3, UDP ×1, мёртвый узел держит слот до таймаута пробы 5 с).
// Для поиска теперь отдельная очередь проб, мимо полос плановых раундов и проверки 64/85 КБ
// (те остаются как были):
//
//   - одновременно не больше VupenSearchTCPProbes TCP-проб и VupenSearchUDPProbes UDP-проб
//     (транспорт узла определяет та же laneOf, что у полос); порядок в каждой очереди —
//     как передал вызывающий (недавно живые первыми, разные подсети — решает балансировщик);
//   - раунд обрывается, когда ответило want узлов (остальные пробы отменяются);
//   - не набралось want за soft от начала раунда, но кто-то уже ответил - вернуться с тем,
//     что есть; оставшиеся пробы доживают в фоне (их удачные ответы только пополняют
//     замеры обсерватории, нового поиска не запускают); никто не ответил - ждать первого
//     ответа или конца всех проб;
//   - таймаут одной пробы прежний (HealthPingSettings.Timeout, 5 с);
//   - фоновые пробы бросаются вместе с обсерваторией, при смене эпохи сети, в конце поиска,
//     который их оставил, и в начале следующего раунда проб (CR-804, T-202: иначе рядом с
//     проверкой 85 КБ и следующим поиском в полёте оказывалось 20+ проб - память iPhone);
//     замер, снятый в прежней эпохе, не записывается. Ответы, уже полученные фоном, в
//     замерах остаются.
var (
	VupenSearchTCPProbes = 10
	VupenSearchUDPProbes = 1
)

// vupenSearchEpochPoll - как часто фоновые пробы сверяют эпоху сети.
const vupenSearchEpochPoll = 100 * time.Millisecond

// Причины возврата VupenStickySearchProbeCtx.
const (
	VupenSearchEnough    = "enough"    // ответило want узлов
	VupenSearchDeadline  = "deadline"  // вышло soft, ответившие есть, остальные пробы - в фоне
	VupenSearchDone      = "done"      // все пробы кончились
	VupenSearchCancelled = "cancelled" // вызывающий отменил (смена сети, остановка)
)

// vupenSearchBG - отмена проб, оставленных в фоне одним раундом.
type vupenSearchBG struct{ cancel context.CancelFunc }

// vupenSetSearchBG запоминает фон раунда (прежний, если ещё идёт, отменяется).
func (h *HealthPing) vupenSetSearchBG(cancel context.CancelFunc) *vupenSearchBG {
	b := &vupenSearchBG{cancel}
	h.vupenSearchBGMu.Lock()
	old := h.vupenSearchBG
	h.vupenSearchBG = b
	h.vupenSearchBGMu.Unlock()
	if old != nil {
		old.cancel()
	}
	return b
}

// vupenClearSearchBG - фон b кончился сам.
func (h *HealthPing) vupenClearSearchBG(b *vupenSearchBG) {
	h.vupenSearchBGMu.Lock()
	if h.vupenSearchBG == b {
		h.vupenSearchBG = nil
	}
	h.vupenSearchBGMu.Unlock()
}

// vupenCancelSearchBG отменяет пробы, оставленные в фоне; true - было что отменять.
func (h *HealthPing) vupenCancelSearchBG() bool {
	h.vupenSearchBGMu.Lock()
	b := h.vupenSearchBG
	h.vupenSearchBG = nil
	h.vupenSearchBGMu.Unlock()
	if b == nil {
		return false
	}
	b.cancel()
	return true
}

// VupenStickyCancelSearchProbes - поиск кончился: пробы, оставленные им в фоне, отменить
// (CR-804). Уже записанные ответы остаются в замерах. true - что-то было отменено.
func (o *Observer) VupenStickyCancelSearchProbes() bool {
	if o.hp == nil {
		return false
	}
	if o.hp.vupenCancelSearchBG() {
		errors.LogInfo(o.hp.ctx, "[sticky] search probes left in the background cancelled")
		return true
	}
	return false
}

// VupenSearchProbeResult - итог раунда проб поиска.
type VupenSearchProbeResult struct {
	Reason     string
	Answered   int
	Finished   int // проб завершено к возврату (ответ или провал)
	Background int // проб осталось в фоне
}

type vupenSearchAnswer struct {
	tag string
	rtt time.Duration
	err error
}

// VupenStickySearchProbeCtx - пробы поиска по tags. each вызывается из горутины
// вызывающего на каждый ответ (после того, как замер записан в результаты); после возврата
// не вызывается. want <= 0 - без остановки по числу ответов; soft <= 0 - без срока.
func (o *Observer) VupenStickySearchProbeCtx(ctx context.Context, tags []string, want int, soft time.Duration,
	each func(tag string, rtt time.Duration)) VupenSearchProbeResult {
	if o.hp == nil || len(tags) == 0 {
		return VupenSearchProbeResult{Reason: VupenSearchDone}
	}
	if n, epoch := o.hp.vupenDropStaleResults(); n > 0 {
		errors.LogWarning(o.hp.ctx, "[sticky] ", n, " probe results of the previous network dropped (epoch ", epoch, ")")
	}
	return o.hp.vupenSearchProbe(ctx, tags, want, soft, each)
}

func (h *HealthPing) vupenSearchProbe(ctx context.Context, tags []string, want int, soft time.Duration,
	each func(tag string, rtt time.Duration)) VupenSearchProbeResult {
	h.vupenCancelSearchBG() // новый раунд: фон прежнего не должен копиться рядом с ним
	epoch := vupenBurstEpochNow()
	timeout := h.Settings.Timeout
	ping := h.vupenSearchPing
	if ping == nil {
		ping = h.vupenQuickPing
	}
	// Значения контекста ядра (диспетчер) берутся от обсерватории; отмена вызывающего
	// передаётся, пока он ждёт, и снимается, когда он ушёл, оставив пробы в фоне.
	bctx, bcancel := context.WithCancel(h.ctx)
	stopCaller := context.AfterFunc(ctx, bcancel)

	var tcpQ, udpQ []string
	for _, tag := range tags {
		lane := vupenLaneTCP
		if h.laneOf != nil {
			lane = h.laneOf(tag)
		}
		if lane == vupenLaneUDP {
			udpQ = append(udpQ, tag)
		} else {
			tcpQ = append(tcpQ, tag)
		}
	}

	ch := make(chan vupenSearchAnswer, len(tags)) // с запасом: пробы в фоне не блокируются
	done := make(chan struct{})
	var wg sync.WaitGroup
	spawn := func(q []string, slots int) {
		if len(q) == 0 {
			return
		}
		var next atomic.Int64
		for i := 0; i < min(max(1, slots), len(q)); i++ {
			wg.Add(1)
			h.vupenSearchGoroutines.Add(1)
			go func() {
				defer h.vupenSearchGoroutines.Add(-1)
				defer wg.Done()
				for bctx.Err() == nil {
					j := int(next.Add(1)) - 1
					if j >= len(q) {
						return
					}
					tag := q[j]
					rtt, err := ping(bctx, tag, timeout)
					if bctx.Err() != nil {
						return // отменено: обрыв замера не итог узла
					}
					if err == nil {
						if rtt <= 0 {
							rtt = time.Millisecond // часы Windows: быстрый ответ меряется как 0
						}
						// Замер, снятый в другой эпохе сети, не годится (смена сети отменяет
						// пробы с задержкой до vupenSearchEpochPoll).
						if vupenBurstEpochNow() == epoch {
							h.PutResult(tag, rtt)
						}
					}
					ch <- vupenSearchAnswer{tag, rtt, err}
				}
			}()
		}
	}
	spawn(tcpQ, VupenSearchTCPProbes)
	spawn(udpQ, VupenSearchUDPProbes)
	h.vupenSearchGoroutines.Add(2)
	go func() {
		defer h.vupenSearchGoroutines.Add(-1)
		wg.Wait()
		close(done)
		bcancel()
	}()
	go func() {
		defer h.vupenSearchGoroutines.Add(-1)
		t := time.NewTicker(vupenSearchEpochPoll)
		defer t.Stop()
		for {
			select {
			case <-bctx.Done():
				return
			case <-done:
				return
			case <-t.C:
				if vupenBurstEpochNow() != epoch {
					bcancel()
					return
				}
			}
		}
	}()

	var res VupenSearchProbeResult
	var timerC <-chan time.Time
	if soft > 0 {
		timer := time.NewTimer(soft)
		defer timer.Stop()
		timerC = timer.C
	}
	late := false // soft вышел, а ответивших не было: вернуться на первом же ответе
	handle := func(a vupenSearchAnswer) (stop string) {
		res.Finished++
		if a.err != nil {
			errors.LogInfo(h.ctx, "[sticky] search probe ", a.tag, ": ", a.err)
			return ""
		}
		res.Answered++
		each(a.tag, a.rtt)
		if want > 0 && res.Answered >= want {
			return VupenSearchEnough
		}
		if late {
			return VupenSearchDeadline
		}
		return ""
	}
	finish := func(reason string) VupenSearchProbeResult {
		res.Reason = reason
		switch reason {
		case VupenSearchEnough, VupenSearchCancelled:
			stopCaller()
			bcancel() // остальные пробы не нужны
		case VupenSearchDeadline:
			stopCaller() // пробы доживают в фоне, пока поиск не кончится (CR-804)
			res.Background = len(tags) - res.Finished
			select {
			case <-done: // все уже вышли
			default:
				bg := h.vupenSetSearchBG(bcancel)
				h.vupenSearchGoroutines.Add(1)
				go func() { // фон кончился сам - отмена не нужна
					defer h.vupenSearchGoroutines.Add(-1)
					<-done
					h.vupenClearSearchBG(bg)
				}()
			}
		}
		return res
	}
	for {
		select {
		case a := <-ch:
			if stop := handle(a); stop != "" {
				return finish(stop)
			}
		case <-timerC:
			timerC = nil
			if res.Answered > 0 {
				return finish(VupenSearchDeadline)
			}
			late = true
		case <-done:
			for {
				select {
				case a := <-ch:
					if stop := handle(a); stop != "" {
						return finish(stop)
					}
				default:
					if bctx.Err() != nil && ctx.Err() != nil {
						return finish(VupenSearchCancelled)
					}
					return finish(VupenSearchDone)
				}
			}
		case <-ctx.Done():
			return finish(VupenSearchCancelled)
		}
	}
}
