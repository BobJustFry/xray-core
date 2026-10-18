package burst

import (
	"context"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/transport/internet"
)

// Ядро 83 (T-102): поиск АВТО 4.1 и смена сети. Разбор лога тестера (iPhone, ядро 82):
// поиск, начатый в Wi-Fi, шёл и после перехода в сотовую, а его проверки 64 КБ в БС
// заморозили три рабочих узла на 15 минут.
//
//   - пробы и проверки поиска можно прервать (контекст вызывающего);
//   - проверка, у которой сменилась эпоха сети, не ставит ни заморозку, ни отметку
//     «проверен» (vupenTspuVerifyCtx);
//   - замеры прежней сети не участвуют в «живых» новой: при первой пробе в новой эпохе
//     замеры сбрасываются (CR-002);
//   - заморозки, поставленные в сети, которая оказалась БС, снимаются (CR-003).

// vupenBurstEpochNow — эпоха сети ядра 74 (подмена в тестах).
var vupenBurstEpochNow = func() uint64 { return internet.VupenNetState().Epoch }

// vupenMergeCtx — контекст, который отменяется с любым из двух.
func vupenMergeCtx(a, b context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(a)
	stop := context.AfterFunc(b, cancel)
	return ctx, func() {
		stop()
		cancel()
	}
}

// vupenDropStaleResults — замеры сняты в другой эпохе сети: забыть их. Вызывается в
// начале пробы поиска; замеры, снятые в этой эпохе, остаются.
func (h *HealthPing) vupenDropStaleResults() (dropped int, epoch uint64) {
	epoch = vupenBurstEpochNow()
	h.access.Lock()
	defer h.access.Unlock()
	if h.resultsEpoch == epoch {
		return 0, epoch
	}
	dropped = len(h.Results)
	h.Results = nil
	h.resultsEpoch = epoch
	return dropped, epoch
}

// VupenStickyProbeCtx — как VupenStickyProbe, но прерывается вместе с ctx; замеры
// прежней сети забываются (CR-002).
func (o *Observer) VupenStickyProbeCtx(ctx context.Context, tags []string) {
	if o.hp == nil || len(tags) == 0 {
		return
	}
	if n, epoch := o.hp.vupenDropStaleResults(); n > 0 {
		errors.LogWarning(o.hp.ctx, "[sticky] ", n, " probe results of the previous network dropped (epoch ", epoch, ")")
	}
	pctx, cancel := vupenMergeCtx(ctx, o.hp.ctx)
	defer cancel()
	o.hp.doCheck(pctx, tags, 0, 1)
}

// VupenStickyVerifyCtx — как VupenStickyVerify, но прерывается вместе с ctx; не ставит
// заморозку при смене сети за время проверки и пока hold() — true (БС).
func (o *Observer) VupenStickyVerifyCtx(ctx context.Context, tag string, hold func() bool) string {
	if o.hp == nil {
		return VupenStickyUnknown
	}
	return o.hp.vupenTspuVerifyNowCtx(ctx, tag, "search", hold, true)
}

// VupenStickyUnfreezeSince — снять заморозки, поставленные не раньше since (сеть,
// в которой они поставлены, оказалась БС или кончилась). Возвращает теги.
func (o *Observer) VupenStickyUnfreezeSince(since time.Time) []string {
	if o.hp == nil {
		return nil
	}
	h := o.hp
	now := time.Now()
	var tags []string
	h.tspu.mu.Lock()
	for tag, e := range h.tspu.m {
		if now.Before(e.frozenUntil) && !e.frozenAt.Before(since) {
			e.frozenUntil = time.Time{}
			e.frozenAt = time.Time{}
			tags = append(tags, tag)
		}
	}
	h.tspu.mu.Unlock()
	if len(tags) > 0 {
		errors.LogWarning(h.ctx, "[sticky] unfrozen (frozen in a network that was not representative): ", tags)
	}
	return tags
}
