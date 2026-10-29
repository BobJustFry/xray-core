package router

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/xtls/xray-core/app/observatory"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/transport/internet"
)

// Ядро 87 (T-189, бандл iOS 2026-10-29 14:22-14:23): провал проверки узла в окне
// «сеть только что сменилась» не вина узла.
//
// Wi-Fi → сотовая в 14:22:57, проверка 24 КБ пошла в 14:23:02 и в 14:23:06.7 (9 с
// устойчивой сети) её же соединения закрыл чистильщик эпохи сети (`closed 8
// connections (reason=net-change)`): «io: read/write on closed pipe» → провал →
// исправный узел исключён на 15 мин и начат поиск по 30 узлам, всё это время трафик
// шёл в мёртвый запасной. Правило: провал внутри окна (эпоха сети > 1, сеть не
// держится ещё VupenNetChangeCloseStableSec) или провал, пока чистильщик закрывал
// соединения, или «closed pipe» сразу после такого закрытия — не провал узла:
// узел не трогаем, ровно одна повторная проверка, когда сеть устоялась. Провал на
// устойчивой сети — как раньше.

// vupenSettleRecheckReason — причина повторной проверки после окна. Проверка с этой
// причиной второй раз не откладывается: её провал — настоящий.
const vupenSettleRecheckReason = "recheck after the network settled"

var (
	// vupenNetSnapshot — снимок эпохи сети (точка подмены для тестов).
	vupenNetSnapshot = internet.VupenNetState
	// vupenSettleMargin — запас после конца окна, прежде чем проверять заново.
	vupenSettleMargin = time.Second
	// vupenSettleCloseRecent — «closed pipe» не позже этого после закрытия
	// соединений чистильщиком считается его следом.
	vupenSettleCloseRecent = 20 * time.Second
)

// vupenNetMark — состояние эпохи сети в момент начала проверки.
type vupenNetMark struct {
	start    time.Time
	settling bool
}

func vupenSettleWindow() time.Duration {
	return time.Duration(internet.VupenNetChangeCloseStableSec) * time.Second
}

// vupenNetSettling — смена сети была в этом запуске ядра (эпоха > 1: первая сообщённая
// сеть — не смена) и ещё не продержалась окно.
func vupenNetSettling(ni internet.VupenNetInfo) bool {
	return ni.Active && ni.Epoch > 1 && (ni.Pending != nil || ni.StableFor < vupenSettleWindow())
}

func vupenNetMarkNow() vupenNetMark {
	return vupenNetMark{start: vupenStickyNow(), settling: vupenNetSettling(vupenNetSnapshot())}
}

// disturbed — провал проверки (detail — текст ошибки) вызван сменой сети, а не узлом.
// Возвращает причину для журнала.
func (m vupenNetMark) disturbed(detail string) (string, bool) {
	if m.settling {
		return "the check started inside the network settle window", true
	}
	ni := vupenNetSnapshot()
	if vupenNetSettling(ni) {
		return "the network settle window opened during the check", true
	}
	lc := ni.LastClose
	if lc == nil || !strings.Contains(lc.Reason, "net-change") {
		return "", false
	}
	if !lc.At.Before(m.start) {
		return "the network change closer closed connections during the check", true
	}
	d := strings.ToLower(detail)
	if strings.Contains(d, "closed pipe") && vupenStickyNow().Sub(lc.At) <= vupenSettleCloseRecent {
		return "closed pipe right after the network change closer ran", true
	}
	return "", false
}

// scheduleSettleRecheck — одна повторная проверка текущего узла, когда окно кончится.
// Вызывается из любой горутины; повторные вызовы пока таймер ждёт не множат проверки.
func (s *vupenSticky) scheduleSettleRecheck() {
	s.settleMu.Lock()
	defer s.settleMu.Unlock()
	if s.settleArmed {
		return
	}
	s.settleArmed = true
	wait := vupenSettleMargin + settleRecheckWait()
	s.settleStop = vupenStickyAfter(wait, func() {
		s.settleMu.Lock()
		s.settleArmed = false
		s.settleMu.Unlock()
		s.requestCheck(vupenSettleRecheckReason)
	})
	errors.LogWarning(s.logCtx(), "[sticky] ", s.balancer, ": re-check of the current node in ", wait, " (after the network settles)")
}

// settleRecheckWait — сколько осталось ждать до конца окна (0 — окно кончилось).
func settleRecheckWait() time.Duration {
	ni := vupenNetSnapshot()
	if !vupenNetSettling(ni) {
		return 0
	}
	if rest := vupenSettleWindow() - ni.StableFor; rest > 0 {
		return rest
	}
	return 0
}

func (s *vupenSticky) stopSettleRecheck() {
	s.settleMu.Lock()
	stop := s.settleStop
	s.settleStop, s.settleArmed = nil, false
	s.settleMu.Unlock()
	if stop != nil {
		stop()
	}
}

// settleKeep — провал проверки tag вызван сменой сети: узел не исключается, повторная
// проверка поставлена. false — провал настоящий (или это уже повторная проверка).
func (s *vupenSticky) settleKeep(m vupenNetMark, tag, reason, detail string) bool {
	if reason == vupenSettleRecheckReason {
		return false
	}
	why, ok := m.disturbed(detail)
	if !ok {
		return false
	}
	errors.LogWarning(s.logCtx(), fmt.Sprintf("[sticky] %s: %s %s check failed, but %s → not excluded, re-check after the network settles (%s)",
		s.balancer, reason, tag, why, detail))
	s.scheduleSettleRecheck()
	return true
}

// ── узел, который можно показывать, пока поиск не подтвердил новый (T-189, A) ────

// noteAlive — узел tag только что прошёл проверку (24 или 64 КБ).
func (s *vupenSticky) noteAlive(tag string) {
	if tag != "" {
		s.lastAlive.Store(&tag)
	}
}

// forgetAlive — узел tag провалил проверку или исключён: «последним проверенным» он
// больше не считается (T-192, CR-702). Иначе по истечении исключения (15 мин) поиск
// снова показал бы его как проверенный.
func (s *vupenSticky) forgetAlive(tag string) {
	if p := s.lastAlive.Load(); p != nil && *p == tag {
		s.lastAlive.CompareAndSwap(p, nil)
	}
}

// interimPick — во время поиска трафик идёт не в непроверенный узел: сначала узел,
// который проходил проверку последним (если он в пуле и не исключён), затем первый по
// порядку стратегии из тех, что отвечали на пробу; нет ни того ни другого — как раньше
// (fallbackPick: fallbackTag или первый неисключённый).
func (s *vupenSticky) interimPick(cands []string) string {
	return s.interimPickFresh(cands, false, nil)
}

// interimPickFresh — interimPick с уточнениями поиска (T-192): fresh — пробы этого поиска
// свежие, и последний проверенный узел обязан на них ответить (CR-702); skip — узлы,
// не прошедшие проверку 64 КБ в этом поиске (CR-703).
func (s *vupenSticky) interimPickFresh(cands []string, fresh bool, skip []string) string {
	obs := s.observatory()
	if obs == nil {
		return s.fallbackPick(cands)
	}
	p := s.lastAlive.Load()
	usable := p != nil && *p != "" && slices.Contains(cands, *p) && !slices.Contains(skip, *p) && !obs.VupenStickyExcluded(*p)
	if usable && !fresh {
		return *p
	}
	answered := map[string]bool{}
	if res, err := obs.GetObservation(s.logCtx()); err == nil {
		answered = vupenAnsweredTags(res)
	}
	if usable && answered[*p] {
		return *p
	}
	alive, _ := s.order(obs, cands)
	for _, t := range alive {
		if answered[t] && !obs.VupenStickyExcluded(t) && !slices.Contains(skip, t) {
			return t
		}
	}
	return s.fallbackPick(cands)
}

// vupenInterimCacheTTL — сколько pick() пользуется запомненным временным узлом.
const vupenInterimCacheTTL = 2 * time.Second

// vupenInterimMemo — результат interimPick для горячего пути pick() (T-192, CR-707).
type vupenInterimMemo struct {
	tag   string
	cands []string
	alive *string // lastAlive на момент расчёта (смена указателя = смена узла)
	at    time.Time
}

// interimPickCached — interimPick для pick(), пока текущий узел исключён, а обработчик ещё
// не начал поиск: без замера и сортировки на каждое соединение. Запись действует
// vupenInterimCacheTTL и сбрасывается, если изменились набор узлов, последний проверенный
// или запомненный узел исключили.
func (s *vupenSticky) interimPickCached(cands []string) string {
	now := vupenStickyNow()
	la := s.lastAlive.Load()
	s.interimMu.Lock()
	m := s.interimMemo
	s.interimMu.Unlock()
	if m != nil && m.alive == la && now.Sub(m.at) < vupenInterimCacheTTL && slices.Equal(m.cands, cands) {
		if obs := s.observatory(); obs != nil && !obs.VupenStickyExcluded(m.tag) {
			return m.tag
		}
	}
	tag := s.interimPick(cands)
	s.interimMu.Lock()
	s.interimMemo = &vupenInterimMemo{tag: tag, cands: slices.Clone(cands), alive: la, at: now}
	s.interimMu.Unlock()
	return tag
}

// vupenAnsweredTags — узлы, которые по последним замерам обсерватории живы.
func vupenAnsweredTags(res interface{}) map[string]bool {
	out := map[string]bool{}
	if r, ok := res.(*observatory.ObservationResult); ok {
		for _, v := range r.Status {
			if v.Alive {
				out[v.OutboundTag] = true
			}
		}
	}
	return out
}
