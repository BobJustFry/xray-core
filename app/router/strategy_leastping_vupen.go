package router

import (
	"github.com/xtls/xray-core/app/observatory"
)

// Ядро 55: leastPing апстрима берёт строго минимальный RTT на каждое новое
// соединение. Ночь 2026-09-10 (597): 23 переключения за 2,5 ч между узлами с
// разницей 106…289 мс — шум, а каждое переключение меняет IP на выходе; плюс
// выборы при alive=2/2, 3/3 — сразу после рестарта, когда observatory собрала
// результаты по двум узлам из 25. У стратегии в Xray настроек нет вообще.
var (
	// VupenLeastPingHysteresis — менять узел, только если новый быстрее текущего
	// на эту долю (0.20 = на 20 %) или текущий умер.
	VupenLeastPingHysteresis = 0.20
	// VupenLeastPingMinObserved — не выбирать, пока observatory не покрыла хотя бы
	// эту долю кандидатов (пустая строка → fallbackTag балансировщика).
	//
	// Ядро 56: было 0.5. На 27 кандидатах половина набиралась 8 с после старта
	// (бандл 2026-09-11 10:16), и все эти секунды трафик шёл в fallbackTag, то
	// есть в первый узел списка, который у пользователя не поднимался. Четверть
	// плюс VupenLeastPingMinAlive режут окно до 2–3 с.
	VupenLeastPingMinObserved = 0.25
	// VupenLeastPingMinAlive — если живых замеров уже столько, выбираем сразу,
	// не дожидаясь доли покрытия: три живых узла лучше любого fallback.
	VupenLeastPingMinAlive = 3
)

type vupenLeastPingPick struct {
	tag   string
	delay int64
	alive int
	total int
}

// vupenLeastPingChoose — чистая функция выбора: без побочных эффектов, под тест.
func vupenLeastPingChoose(last string, candidates outboundList, status []*observatory.OutboundStatus, nCandidates int) vupenLeastPingPick {
	best := vupenLeastPingPick{delay: int64(99999999)}
	var lastDelay int64 = -1
	for _, v := range status {
		if !candidates.contains(v.OutboundTag) {
			continue
		}
		best.total++
		if v.Alive {
			best.alive++
		}
		if v.OutboundTag == last && v.Alive {
			lastDelay = v.Delay
		}
		if v.Alive && v.Delay < best.delay {
			best.tag = v.OutboundTag
			best.delay = v.Delay
		}
	}
	if best.tag == "" {
		return best
	}
	if nCandidates > 1 &&
		best.alive < VupenLeastPingMinAlive &&
		float64(best.total) < float64(nCandidates)*VupenLeastPingMinObserved {
		// Мало наблюдений — рано выбирать; балансировщик уйдёт в fallbackTag.
		return vupenLeastPingPick{alive: best.alive, total: best.total}
	}
	if last != "" && last != best.tag && lastDelay >= 0 {
		threshold := float64(lastDelay) * (1 - VupenLeastPingHysteresis)
		if float64(best.delay) > threshold {
			best.tag = last
			best.delay = lastDelay
		}
	}
	return best
}
