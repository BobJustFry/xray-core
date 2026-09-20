package router

import (
	"sync"
	"time"
)

// Vupen (ядро 63): leastLoad на мобильном клиенте.
//
// Апстрим берёт лучший узел по отклонению RTT на КАЖДОЕ новое соединение, без
// всякой инерции: пришли три свежие пробы — порядок поменялся, и следующее
// соединение уходит на другой узел, то есть на другой IP. Бандл 2026-09-19:
// за полчаса выбор гулял proxy-18 → proxy-17 → proxy-10 → proxy-26, а Telegram
// в это время пересоздавал сессию каждые несколько секунд и не мог подняться,
// хотя «интернет» в браузере работал — у него каждый запрос сам по себе.
//
// Для leastPing мы это уже лечили гистерезисом (ядро 55). Здесь то же самое:
// держимся текущего узла, пока он остаётся кандидатом и не хуже лучшего на
// VupenLeastLoadHysteresis. Панель клиенту не переписать, а leastLoad в чужих
// подписках встречается ровно так же часто, как leastPing.
var (
	// VupenLeastLoadHysteresis — менять узел, только если новый быстрее текущего
	// больше чем на эту долю (0.25 = на четверть).
	VupenLeastLoadHysteresis = 0.25
	// VupenLeastLoadMaxRatio — во сколько раз кандидат может быть медленнее самого
	// быстрого живого узла. Медленнее — не кандидат.
	//
	// leastLoad сортирует по РАЗБРОСУ задержки, а не по её величине: стабильный
	// узел на 900 мс обгоняет дёрганый на 300. Бандл 2026-09-20: балансировщик
	// выбирал узлы на 727, 607 и 579 мс, когда в том же раунде были 300 и 325.
	// Порог относительный — на равномерно медленной сети лучший тоже медленный, и
	// не отсеивается никто; абсолютный в такой ситуации выкосил бы весь пул.
	VupenLeastLoadMaxRatio = 2.0
	// VupenLeastLoadMinKeep — ниже этого числа кандидатов отсев не применяется
	// вовсе: пустой или почти пустой пул хуже медленного узла.
	VupenLeastLoadMinKeep = 3
)

// vupenLeastLoadState — текущий выбор стратегии; живёт рядом с ней.
type vupenLeastLoadState struct {
	mu   sync.Mutex
	last string
}

func (s *vupenLeastLoadState) get() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.last
}

// set возвращает true, если выбор сменился (для лога).
func (s *vupenLeastLoadState) set(tag string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	changed := s.last != tag
	s.last = tag
	return changed
}

// vupenLeastLoadChoose — какой узел отдать с учётом инерции.
//
// [qualified] — все прошедшие отбор узлы (отсортированы апстримом), [selects] —
// то, что выбрал сам leastLoad. Возвращает узел из [selects], либо текущий, если
// он всё ещё кандидат и разница не стоит смены IP. Чистая функция, под тест.
func vupenLeastLoadChoose(last string, qualified []*node, selects []*node) *node {
	if len(selects) == 0 {
		return nil
	}
	best := selects[0]
	if last == "" {
		return best
	}
	// Профиль мог попросить распределять нагрузку (`expected` > 1): пока текущий
	// узел в выбранном наборе, остаёмся на нём — набор для того и выбран.
	for _, n := range selects {
		if n.Tag == last {
			return n
		}
	}
	var cur *node
	for _, n := range qualified {
		if n.Tag == last {
			cur = n
			break
		}
	}
	if cur == nil {
		// Текущий узел больше не кандидат: умер, протухли замеры или его убрали
		// из подписки — держаться не за что.
		return best
	}
	if cur.CountAll > 0 && cur.CountFail > 0 && best.CountFail == 0 {
		// У текущего есть провалы, у лучшего — нет: это не шум, уходим.
		return best
	}
	if vupenRttBetterBy(best.RTTAverage, cur.RTTAverage, VupenLeastLoadHysteresis) {
		return best
	}
	return cur
}

// vupenLeastLoadDropSlow — убрать кандидатов, которые медленнее самого быстрого
// живого больше чем в VupenLeastLoadMaxRatio раз.
//
// Узлы без замера (RTTAverage = 0) не трогаем: судить о них нечем. Если после
// отсева осталось меньше VupenLeastLoadMinKeep, возвращаем исходный список.
func vupenLeastLoadDropSlow(nodes []*node) []*node {
	if len(nodes) <= VupenLeastLoadMinKeep {
		return nodes
	}
	best := time.Duration(0)
	for _, n := range nodes {
		if n.RTTAverage <= 0 {
			continue
		}
		if best == 0 || n.RTTAverage < best {
			best = n.RTTAverage
		}
	}
	if best <= 0 {
		return nodes
	}
	limit := time.Duration(float64(best) * VupenLeastLoadMaxRatio)
	kept := make([]*node, 0, len(nodes))
	for _, n := range nodes {
		if n.RTTAverage > limit {
			continue
		}
		kept = append(kept, n)
	}
	if len(kept) < VupenLeastLoadMinKeep {
		return nodes
	}
	return kept
}

// vupenRttBetterBy — [best] быстрее [cur] больше чем на долю [margin].
func vupenRttBetterBy(best, cur time.Duration, margin float64) bool {
	if cur <= 0 {
		return false
	}
	if best <= 0 {
		return true
	}
	return float64(best) < float64(cur)*(1-margin)
}
