package router

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/xtls/xray-core/app/observatory/burst"
	"github.com/xtls/xray-core/common/errors"
)

// Ядро 88 (D-70, T-199): новый алгоритм поиска узла после смены сети и повторная проверка
// выбранного. Разбор журнала iOS 4.1.669 (ядро 87, 2026-11-02): поиск ждал ответа всех 29
// узлов 20,7 с (3 TCP-полосы × 5 с таймаута мёртвых), трафик 20 с шёл через мёртвый
// временный узел, найденный узел прошёл 85 КБ и замер, повторной проверки не было.
//
//  1. Пробы поиска - отдельная очередь (burst, tuning_vupen_search.go): 10 TCP и 1 UDP
//     одновременно; раунд обрывается, как только ответили VupenSearchStopAlive узлов;
//     не набралось за VupenSearchDeadline, но кто-то ответил - берём ответивших, остальные
//     пробы доживают в фоне. Порядок проб: недавно ответившие первыми, разные подсети.
//  2. Временный узел на время поиска - первый, кто ответил на свежую пробу ЭТОГО поиска.
//  3. 85 КБ проверяется на самом быстром из ответивших; не прошёл - на следующем из них.
//  4. Через VupenStickyPostSwitchRecheck после переключения новый узел проверяется ещё раз
//     (24 КБ, как проверка текущего): провал - исключение и один новый поиск.
var (
	// VupenSearchStopAlive - сколько ответивших хватает, чтобы закончить раунд проб.
	VupenSearchStopAlive = 3
	// VupenSearchDeadline - от начала раунда проб до решения «берём ответивших, сколько есть».
	VupenSearchDeadline = 3500 * time.Millisecond
	// VupenStickyPostSwitchRecheck - через сколько после переключения поиском новый узел
	// перепроверяется (D-70, вариант Б: 10-15 с).
	VupenStickyPostSwitchRecheck = 12 * time.Second
)

// vupenPostSwitchRecheckReason - причина проверки, которую ставит таймер после переключения.
const vupenPostSwitchRecheckReason = "post-switch re-check"

// vupenStickySearchProbeObs - обсерватория умеет пробы поиска ядра 88 (burst).
type vupenStickySearchProbeObs interface {
	VupenStickySearchProbeCtx(ctx context.Context, tags []string, want int, soft time.Duration,
		each func(tag string, rtt time.Duration)) burst.VupenSearchProbeResult
}

// vupenStickyRecentObs - последние замеры узлов (burst, tuning_vupen_switch.go).
type vupenStickyRecentObs interface {
	VupenStickyRecent(tags []string, maxAge time.Duration) map[string]time.Duration
}

// vupenAnswer - ответ узла на пробу этого поиска.
type vupenAnswer struct {
	tag string
	rtt time.Duration
}

// searchProbeOrder - порядок запуска проб поиска: ответившие недавно (в этой сети) - по
// возрастанию задержки, затем без замера - в порядке пула, затем недавно не ответившие.
// Разные подсети (nodeKey, как у проверок 64 КБ) - внутри каждой группы, а не поверх всего
// списка: порядок групп не нарушается (CR-803, T-202).
func (s *vupenSticky) searchProbeOrder(obs vupenStickyObservatory, pool []string) []string {
	ro, ok := obs.(vupenStickyRecentObs)
	if !ok {
		return vupenStickyDiverse(pool, s.nodeKey, len(pool))
	}
	recent := ro.VupenStickyRecent(pool, s.cacheMaxAge())
	var good, unknown, bad []string
	for _, t := range pool {
		switch d, seen := recent[t]; {
		case !seen:
			unknown = append(unknown, t)
		case d > 0:
			good = append(good, t)
		default:
			bad = append(bad, t)
		}
	}
	sort.SliceStable(good, func(i, j int) bool { return recent[good[i]] < recent[good[j]] })
	var ordered []string
	for _, group := range [][]string{good, unknown, bad} {
		ordered = append(ordered, vupenStickyDiverse(group, s.nodeKey, len(group))...)
	}
	return ordered
}

// probeSearch - раунд проб поиска ядра 88. answers - ответившие по возрастанию задержки;
// ok=false - раунд прервали (смена сети, остановка). Первый ответивший сразу становится
// временным узлом (D-70 п. 3); узел, с которого ушли, добавляется в left.
func (s *vupenSticky) probeSearch(run *vupenSearchRun, so vupenStickySearchProbeObs, obs vupenStickyObservatory,
	pool []string, left *[]string) (answers []vupenAnswer, ok bool) {
	started := time.Now()
	order := s.searchProbeOrder(obs, pool)
	first := ""
	res := so.VupenStickySearchProbeCtx(run.ctx, order, VupenSearchStopAlive, VupenSearchDeadline, func(tag string, rtt time.Duration) {
		answers = append(answers, vupenAnswer{tag, rtt})
		if first == "" && !obs.VupenStickyExcluded(tag) {
			first = tag
			if from := s.viewTag(); from != "" && from != tag {
				*left = append(*left, from)
			}
			s.publish(tag)
		}
	})
	sort.SliceStable(answers, func(i, j int) bool { return answers[i].rtt < answers[j].rtt })
	if run.aborted() {
		return answers, false
	}
	best := ""
	if len(answers) > 0 {
		best = fmt.Sprintf("%s %s", answers[0].tag, answers[0].rtt.Round(time.Millisecond))
	}
	errors.LogWarning(s.logCtx(), fmt.Sprintf("[sticky] %s: search probe: %s, %d answered of %d (%d finished, %d left in the background), first %q, fastest %s, ran %s",
		s.balancer, res.Reason, res.Answered, len(order), res.Finished, res.Background, first, best, time.Since(started).Round(time.Millisecond)))
	return answers, true
}

// nextFreshInterim - следующий из ответивших в этом поиске, кроме отказавших и исключённых;
// "" - нет такого (узел из старых замеров временным не берётся).
func nextFreshInterim(obs vupenStickyObservatory, answers []vupenAnswer, skip []string) string {
	for _, a := range answers {
		if !slices.Contains(skip, a.tag) && !obs.VupenStickyExcluded(a.tag) {
			return a.tag
		}
	}
	return ""
}

// searchInterim - временный узел до первого ответа на пробы поиска: узел, на котором шёл
// трафик, если он в пуле и не исключён (нового знания о других узлах нет); иначе - только
// узел, ответивший на пробу в ЭТОЙ сети (замеры не старше последней смены сети), самый
// быстрый из них; иначе fallbackPick. Замеры прежней сети и lastAlive сюда не входят:
// сразу после смены сети в результатах обсерватории ещё лежит прежняя сеть (она
// сбрасывается только в начале проб), и узел, живой там, нёс бы трафик до первого свежего
// ответа (CR-801, T-202; инцидент iOS 4.1.669).
func (s *vupenSticky) searchInterim(cands []string) string {
	obs := s.observatory()
	if obs == nil {
		return s.fallbackPick(cands)
	}
	if cur := s.viewTag(); cur != "" && slices.Contains(cands, cur) && !obs.VupenStickyExcluded(cur) {
		return cur
	}
	if ro, ok := obs.(vupenStickyRecentObs); ok {
		recent := ro.VupenStickyRecent(cands, s.cacheMaxAge())
		best := ""
		for _, t := range cands {
			if d := recent[t]; d > 0 && !obs.VupenStickyExcluded(t) && (best == "" || d < recent[best]) {
				best = t
			}
		}
		if best != "" {
			return best
		}
	}
	return s.fallbackPick(cands)
}

// vupenStickySearchCancelObs - обсерватория умеет отменять пробы поиска, оставленные в фоне.
type vupenStickySearchCancelObs interface {
	VupenStickyCancelSearchProbes() bool
}

// cancelSearchLeftovers - поиск кончился (переключил, не нашёл, брошен): пробы, оставленные им
// в фоне после срока, отменить (CR-804, T-202). Пока идёт проверка 85 КБ, они ещё работают и
// пополняют замеры; к следующему поиску, перепроверке или лечению в полёте их уже нет.
func (s *vupenSticky) cancelSearchLeftovers(obs vupenStickyObservatory) {
	if c, ok := obs.(vupenStickySearchCancelObs); ok {
		c.VupenStickyCancelSearchProbes()
	}
}

// ── повторная проверка после переключения (D-70 п. 5, вариант Б) ─────────────

// vupenRecheck - взведённая повторная проверка нового узла.
type vupenRecheck struct {
	mu    sync.Mutex
	gen   uint64
	tag   string
	epoch uint64
	stop  func() bool
}

// armPostSwitchRecheck - поиск переключил трафик на tag: через VupenStickyPostSwitchRecheck
// проверить его ещё раз. Одна проверка на переключение; переключение, сделанное поиском
// после провала такой проверки, новой не взводит (цепочка не зацикливается).
func (s *vupenSticky) armPostSwitchRecheck(tag string, epoch uint64) {
	if s.recheckChain || VupenStickyPostSwitchRecheck <= 0 {
		return
	}
	r := &s.recheck
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stop != nil {
		r.stop()
	}
	r.gen++
	gen := r.gen
	r.tag, r.epoch = tag, epoch
	r.stop = vupenStickyAfter(VupenStickyPostSwitchRecheck, func() {
		s.send(vupenStickyEvent{kind: "recheck", reason: vupenPostSwitchRecheckReason, gen: gen})
	})
	errors.LogWarning(s.logCtx(), "[sticky] ", s.balancer, ": ", tag, " will be re-checked in ", VupenStickyPostSwitchRecheck)
}

// cancelPostSwitchRecheck - проверку отменить (сеть сменилась, ядро останавливается).
func (s *vupenSticky) cancelPostSwitchRecheck() {
	r := &s.recheck
	r.mu.Lock()
	defer r.mu.Unlock()
	r.gen++ // событие, уже стоящее в очереди, устарело
	if r.stop != nil {
		r.stop()
		r.stop = nil
	}
	r.tag = ""
}

// postSwitchRecheckDue - проверку надо выполнить: она не устарела и условия те же, что при
// переключении (узел прежний и держится, эпоха сети та же, узел не исключён).
func (s *vupenSticky) postSwitchRecheckDue(gen uint64) (tag string, ok bool) {
	r := &s.recheck
	r.mu.Lock()
	tag, epoch, cur := r.tag, r.epoch, r.gen
	if gen == cur {
		r.stop = nil
		r.tag = "" // одна проверка на переключение
	}
	r.mu.Unlock()
	if gen != cur || tag == "" {
		return "", false
	}
	why := ""
	obs := s.observatory()
	switch {
	case obs == nil:
		why = "no observatory"
	case s.getPhase() != vupenPhaseHolding || s.current != tag:
		why = "the node changed"
	case vupenNetEpochNow() != epoch:
		why = "the network changed"
	case obs.VupenStickyExcluded(tag):
		why = "the node is already excluded"
	case obs.VupenStickyAsleep():
		why = "asleep"
	case s.whitelistHolds():
		why = "whitelist holds"
	}
	if why != "" {
		errors.LogWarning(s.logCtx(), "[sticky] ", s.balancer, ": re-check of ", tag, " skipped: ", why)
		return "", false
	}
	return tag, true
}

// runPostSwitchRecheck - событие "recheck" (горутина обработчика). Проверка - как у текущего
// узла (checkCurrent: 24 КБ; провал при живой сети - исключение и один новый поиск; брошенная
// сменой сети проверка узел не винит). Поиск после провала нового переключения не перепроверяет.
func (s *vupenSticky) runPostSwitchRecheck(gen uint64) {
	tag, ok := s.postSwitchRecheckDue(gen)
	if !ok {
		return
	}
	s.recheckChain = true
	defer func() { s.recheckChain = false }()
	s.checkCurrent(tag, vupenPostSwitchRecheckReason)
}
