package burst

import (
	"context"
	"io"
	"net/http"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/utils"
)

// Ядро 80 (D-43): быстрый поиск для VupenCheckRoute(switch), кнопка «Сменить сервер».
//
// Ядро 79 искало другой узел полным раундом обсерватории: пробы по всем узлам
// пула через полосы (TCP ×3, UDP ×1), мёртвые — до таймаута пробы. На iPhone
// владельца это 26–28 с на нажатие (n=32, alive=19), приложение ждало 15 с.
// Для switch — два помощника, плановые раунды, heal и сторож их не используют:
//
//   - VupenStickyRecent — последние замеры узлов из результатов обсерватории (кэш);
//   - VupenStickyQuickProbe — пробы сразу по всем переданным узлам параллельно,
//     мимо полос, каждая не дольше VupenQuickProbeTimeout; ответы отдаются по мере
//     прихода, первый подошедший останавливает остальные. Удачный ответ
//     записывается в результаты (как проба раунда), провал — нет: короткий предел
//     не повод считать узел мёртвым для плановых раундов.
var (
	VupenQuickProbeTimeout = 2500 * time.Millisecond
)

// VupenStickyRecent — последний замер каждого узла из tags, если он не старше
// maxAge: > 0 — узел ответил (задержка), < 0 — последняя проба провалилась.
// Узлов без свежего замера в ответе нет.
func (o *Observer) VupenStickyRecent(tags []string, maxAge time.Duration) map[string]time.Duration {
	out := map[string]time.Duration{}
	if o.hp == nil || maxAge <= 0 {
		return out
	}
	h := o.hp
	now := time.Now()
	h.access.Lock()
	defer h.access.Unlock()
	for _, tag := range tags {
		r := h.Results[tag]
		if r == nil || r.rtts == nil || r.idx < 0 {
			continue
		}
		last := r.rtts[r.idx]
		if last.value == rttUntested || last.time.IsZero() || now.Sub(last.time) > maxAge {
			continue
		}
		if last.value == rttFailed {
			out[tag] = -1
		} else if last.value > 0 {
			out[tag] = last.value
		}
	}
	return out
}

// VupenStickyQuickProbe — HEAD-пробы по всем tags одновременно, каждая не дольше
// timeout (0 — VupenQuickProbeTimeout). each получает итог каждой пробы по мере
// прихода (ok — узел ответил за rtt; !ok — ошибка или таймаут), в горутине
// вызывающего; each вернула true — остальные пробы отменяются. Возврат — все
// пробы кончились, наступил deadline (нуль — без него) или each вернула true.
// Итог — сколько узлов ответило.
func (o *Observer) VupenStickyQuickProbe(tags []string, timeout time.Duration, deadline time.Time,
	each func(tag string, rtt time.Duration, ok bool) bool) int {
	if o.hp == nil {
		return 0
	}
	return o.vupenQuickProbe(o.hp.ctx, tags, timeout, deadline, each)
}

func (o *Observer) vupenQuickProbe(parent context.Context, tags []string, timeout time.Duration, deadline time.Time,
	each func(tag string, rtt time.Duration, ok bool) bool) int {
	if o.hp == nil || len(tags) == 0 {
		return 0
	}
	h := o.hp
	if timeout <= 0 {
		timeout = VupenQuickProbeTimeout
	}
	var ctx context.Context
	var cancel context.CancelFunc
	if deadline.IsZero() {
		ctx, cancel = context.WithCancel(parent)
	} else {
		ctx, cancel = context.WithDeadline(parent, deadline)
	}
	defer cancel()
	type answer struct {
		tag string
		rtt time.Duration
		err error
	}
	ch := make(chan answer, len(tags)) // с запасом: после возврата пробы не блокируются
	for _, tag := range tags {
		go func(tag string) {
			rtt, err := h.vupenQuickPing(ctx, tag, timeout)
			ch <- answer{tag, rtt, err}
		}(tag)
	}
	answered := 0
	for range tags {
		select {
		case a := <-ch:
			if a.err != nil {
				if ctx.Err() != nil {
					return answered // отменили или вышел бюджет — остальное не нужно
				}
				errors.LogInfo(h.ctx, "[sticky] quick probe ", a.tag, ": ", a.err)
				if each(a.tag, 0, false) {
					return answered
				}
				continue
			}
			if a.rtt <= 0 {
				a.rtt = time.Millisecond // часы Windows: быстрый ответ меряется как 0
			}
			h.PutResult(a.tag, a.rtt)
			answered++
			if each(a.tag, a.rtt, true) {
				return answered
			}
		case <-ctx.Done():
			return answered
		}
	}
	return answered
}

// vupenQuickPing — одна проба через узел tag (тот же запрос, что у раундов).
func (h *HealthPing) vupenQuickPing(ctx context.Context, tag string, timeout time.Duration) (time.Duration, error) {
	client := newHTTPClient(ctx, h.dispatcher, tag, timeout)
	req, err := http.NewRequestWithContext(ctx, h.Settings.HttpMethod, h.Settings.Destination, nil)
	if err != nil {
		return 0, err
	}
	utils.TryDefaultHeadersWith(req.Header, "nav")
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	if h.Settings.HttpMethod == http.MethodGet {
		if _, err = io.Copy(io.Discard, resp.Body); err != nil {
			resp.Body.Close()
			return 0, err
		}
	}
	resp.Body.Close()
	return time.Since(start), nil
}
