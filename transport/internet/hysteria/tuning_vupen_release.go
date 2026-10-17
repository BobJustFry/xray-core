package hysteria

import "github.com/xtls/xray-core/transport/internet"

// Vupen (T-075, CR-003): закрытый outbound освобождает свои клиенты Hysteria
// (transport/internet/tuning_vupen_release.go): ключ кэша — настройки потока
// outbound'а, поэтому временные ядра (пинг, проверка) иначе оставляли по записи
// с QUIC-соединением до очистки простоя. Регистрируется при создании manager.
//
// CR-101: под manager.Lock только выбираем и удаляем записи. Клиент держит свой
// замок всё рукопожатие (client.tcp/udp → dial, до 5–30 с с молчащим узлом);
// ждать его под manager.Lock значило бы остановить все Dial Hysteria в процессе
// и Handler.Close. Закрываем каждый клиент отдельно, когда его замок освободится.
func vupenReleaseHysteria(ss *internet.MemoryStreamConfig) {
	var closing []*client
	manager.Lock()
	for k, c := range manager.m {
		if k.MemoryStreamConfig == ss {
			delete(manager.m, k)
			closing = append(closing, c)
		}
	}
	manager.Unlock()
	for _, c := range closing {
		go vupenHysteriaClose(c)
	}
}

// vupenHysteriaClose — закрыть клиент, когда освободится его замок (подмена в тестах).
var vupenHysteriaClose = func(c *client) {
	c.Lock()
	defer c.Unlock()
	if c.status() != StatusNull {
		c.close()
	}
}
