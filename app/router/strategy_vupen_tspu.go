package router

// Vupen (ядро 71): уходить с рабочего узла только на проверенный на заморозку ТСПУ.
//
// Обсерватория (burst, tuning_vupen_tspu.go) проверяет лучших кандидатов загрузкой
// 64 КБ через узел. Пока новый «самый быстрый» не проверен, балансировщик
// остаётся на текущем узле и просит его проверить: иначе он уходил на узел,
// который проходит короткие пробы, но замерзает на настоящем трафике (бандл
// iPhone 2026-09-27 23:30:49). Замороженные узлы обсерватория и так отдаёт
// мёртвыми — это правило про тех, кого ещё не успели проверить.

// vupenTspuOracle — то, что умеет burst-обсерватория ядра 71. Другие обсерватории
// (или старое ядро) этого не реализуют — тогда правило не действует.
type vupenTspuOracle interface {
	VupenTspuVerified(tag string) bool
	VupenTspuRequestVerify(tag string)
}

// vupenVerifiedSwitch — окончательный выбор с учётом проверки.
//
// [last] — текущий узел, [lastAlive] — он ещё кандидат, [pick] — выбор стратегии,
// [ordered] — живые кандидаты в порядке предпочтения стратегии. Чистая функция:
// [verified] и [request] передаются снаружи.
func vupenVerifiedSwitch(last string, lastAlive bool, pick string, ordered []string,
	verified func(string) bool, request func(string)) string {
	if pick == "" || pick == last || verified(pick) {
		return pick
	}
	request(pick)
	if last != "" && lastAlive {
		// Текущий узел жив: держимся его, пока новый не проверен.
		return last
	}
	// Текущего нет (старт ядра, умер, заморожен): лучший из проверенных, если есть.
	for _, t := range ordered {
		if verified(t) {
			return t
		}
	}
	// Проверенных нет — выбора нет: берём лучшего, проверка уже заказана.
	return pick
}
