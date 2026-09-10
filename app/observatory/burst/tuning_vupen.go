package burst

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync/atomic"
	"time"
)

// Vupen (ядро 52): burst-observatory на мобильном клиенте.
//
// Апстрим на старте стреляет пробами по ВСЕМ узлам балансировщика разом
// (doCheck с duration=0: все таймеры на 0) — в момент, когда ядро только
// поднялось. На iOS это 24 одновременных HTTP-проб через 24 outbound'а: узлы
// на xhttp/tls получали `io: read/write on closed pipe` через 0,4 с, а узлы на
// QUIC (hysteria) — `context deadline exceeded` через 5 с, потому что их
// рукопожатие целиком в user-space и не переживает такую пачку (см. норму
// «пинг hysteria в списке», iOS 00594: в одиночку 357–398 мс, в пачке 2,5–3,9 с
// или таймаут). Провалившийся узел считается мёртвым (`Alive = All != Fail`),
// пока не придёт следующая удачная проба, а следующая — случайная точка в
// ближайших interval×sampling секундах. Итог: после каждого старта и
// softRestart балансировщик 1–5 минут выбирает среди случайного подмножества
// узлов, переживших стартовую пачку, а hysteria — самые быстрые узлы владельца —
// не выбирается практически никогда.
//
// Что сделано:
//   - пробы идут через полосы: TCP-транспорты — до VupenObservatoryTCPLane
//     одновременно, UDP/QUIC-транспорты (hysteria, kcp, quic, wireguard, tuic) —
//     по одному; распределённые по времени пробы это не замедляет, а стартовую
//     пачку превращает в очередь;
//   - первый раунд начинается через VupenObservatoryInitialDelay после старта,
//     а не в ту же миллисекунду;
//   - узлы, провалившие стартовый раунд, перепроверяются через
//     VupenObservatoryRetryDelay, а не через случайные 0–300 с;
//   - по завершении раунда — одна строка `[observatory] round=…` с тем, что
//     видит leastPing (avg/fail/all по каждому узлу): раньше успешные пробы не
//     логировались вообще, и по vSupport нельзя было сказать, почему выбран тот
//     или иной узел.
var (
	VupenObservatoryInitialDelay = 2 * time.Second
	VupenObservatoryRetryDelay   = 20 * time.Second
	VupenObservatoryTCPLane      = 3
	VupenObservatoryUDPLane      = 1
	// Пока идёт QUIC-хендшейк UDP-пробы, TCP-пробы ждут не дольше этого:
	// в vSupport 2026-09-10 00:14 hysteria в observatory 536/618 мс при
	// параллельной TCP-полосе против 296–369 мс в одиночном пинге списка.
	VupenObservatoryUDPQuiet = 1500 * time.Millisecond
	// Ядро 55: узел без единой удачной пробы VupenObservatoryDeadStreak раундов
	// подряд опрашивается в VupenObservatoryDeadBackoff раз реже (proxy-2 с
	// домашней сети владельца: 56 таймаутов по 5 с за ночь — треть всех отказов).
	// Сбрасывается первой же удачной пробой и при старте ядра.
	VupenObservatoryDeadStreak  = 3
	VupenObservatoryDeadBackoff = 10
)

const (
	vupenLaneTCP = "tcp"
	vupenLaneUDP = "udp"
)

// vupenRetryHook — только для тестов: вызывается перед повторным раундом.
var vupenRetryHook func(tags []string)

// vupenLaneFor — полоса по имени транспорта (streamSettings.protocolName) и
// типу прокси (TypedMessage.Type outbound'а, напр. "xray.proxy.hysteria.Config").
func vupenLaneFor(streamProtocol string, proxyType string) string {
	switch strings.ToLower(strings.TrimSpace(streamProtocol)) {
	case "hysteria", "kcp", "mkcp", "quic":
		return vupenLaneUDP
	}
	t := strings.ToLower(proxyType)
	for _, k := range []string{"hysteria", "wireguard", "tuic"} {
		if strings.Contains(t, k) {
			return vupenLaneUDP
		}
	}
	return vupenLaneTCP
}

type vupenLanes struct {
	tcp chan struct{}
	udp chan struct{}
	// unix-наносекунды, до которых TCP-пробы уступают UDP-хендшейку; 0 — свободно.
	udpQuietUntil atomic.Int64
}

// vupenTCPYield — TCP-проба ждёт, пока UDP-хендшейк в тихом окне (не дольше
// VupenObservatoryUDPQuiet), либо до отмены раунда.
func (l *vupenLanes) vupenTCPYield(ctx context.Context) {
	until := l.udpQuietUntil.Load()
	if until == 0 {
		return
	}
	wait := time.Until(time.Unix(0, until))
	if wait <= 0 {
		return
	}
	if wait > VupenObservatoryUDPQuiet {
		wait = VupenObservatoryUDPQuiet
	}
	vupenSleep(ctx, wait)
}

// vupenUDPBegin/End — тихое окно на время хендшейка UDP-пробы.
func (l *vupenLanes) vupenUDPBegin() {
	l.udpQuietUntil.Store(time.Now().Add(VupenObservatoryUDPQuiet).UnixNano())
}

func (l *vupenLanes) vupenUDPEnd() { l.udpQuietUntil.Store(0) }

func newVupenLanes() *vupenLanes {
	return &vupenLanes{
		tcp: make(chan struct{}, max(1, VupenObservatoryTCPLane)),
		udp: make(chan struct{}, max(1, VupenObservatoryUDPLane)),
	}
}

func (l *vupenLanes) sem(lane string) chan struct{} {
	if lane == vupenLaneUDP {
		return l.udp
	}
	return l.tcp
}

// vupenAcquire ждёт слот полосы или отмены раунда.
func vupenAcquire(ctx context.Context, sem chan struct{}) bool {
	select {
	case sem <- struct{}{}:
		return true
	case <-ctx.Done():
		return false
	}
}

func vupenRelease(sem chan struct{}) { <-sem }

// vupenSleep — пауза, прерываемая отменой контекста.
func vupenSleep(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// vupenSkipDead — true, если узел мёртв VupenObservatoryDeadStreak подряд и его
// очередь опроса ещё не подошла (каждый VupenObservatoryDeadBackoff-й раунд).
func (h *HealthPing) vupenSkipDead(tag string) bool {
	h.access.Lock()
	defer h.access.Unlock()
	r, ok := h.Results[tag]
	if !ok {
		return false
	}
	s := r.getStatistics()
	if s.Fail < VupenObservatoryDeadStreak || s.All != s.Fail {
		delete(h.deadSkip, tag)
		return false
	}
	if h.deadSkip == nil {
		h.deadSkip = make(map[string]int)
	}
	h.deadSkip[tag]++
	return h.deadSkip[tag]%VupenObservatoryDeadBackoff != 0
}

// vupenFailedTags — узлы, у которых после раунда нет ни одной удачной пробы.
func (h *HealthPing) vupenFailedTags(tags []string) []string {
	h.access.Lock()
	defer h.access.Unlock()
	var failed []string
	for _, tag := range tags {
		r, ok := h.Results[tag]
		if !ok {
			continue
		}
		s := r.getStatistics()
		if s.All > 0 && s.All == s.Fail {
			failed = append(failed, tag)
		}
	}
	return failed
}

// vupenRoundSummary — одна строка на раунд: то, что видит leastPing.
// Формат: `tag=avgMs/fail/all`; `tag=dead` — ни одной удачной пробы.
func (h *HealthPing) vupenRoundSummary(kind string, tags []string) string {
	h.access.Lock()
	defer h.access.Unlock()
	sorted := append([]string(nil), tags...)
	sort.Strings(sorted)
	alive := 0
	var b strings.Builder
	for _, tag := range sorted {
		r, ok := h.Results[tag]
		if !ok {
			fmt.Fprintf(&b, " %s=none", tag)
			continue
		}
		s := r.getStatistics()
		if s.All == 0 || s.All == s.Fail {
			fmt.Fprintf(&b, " %s=dead(%d)", tag, s.Fail)
			continue
		}
		alive++
		fmt.Fprintf(&b, " %s=%d/%d/%d", tag, s.Average.Milliseconds(), s.Fail, s.All)
	}
	return fmt.Sprintf("[observatory] round=%s n=%d alive=%d:%s", kind, len(sorted), alive, b.String())
}
