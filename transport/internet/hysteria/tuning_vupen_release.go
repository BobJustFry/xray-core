package hysteria

import "github.com/xtls/xray-core/transport/internet"

// Vupen (T-075, CR-003): закрытый outbound освобождает свои клиенты Hysteria
// (transport/internet/tuning_vupen_release.go): ключ кэша — настройки потока
// outbound'а, поэтому временные ядра (пинг, проверка) иначе оставляли по записи
// с QUIC-соединением до очистки простоя. Регистрируется при создании manager.
func vupenReleaseHysteria(ss *internet.MemoryStreamConfig) {
	manager.Lock()
	defer manager.Unlock()
	for k, c := range manager.m {
		if k.MemoryStreamConfig != ss {
			continue
		}
		delete(manager.m, k)
		c.Lock()
		if c.status() != StatusNull {
			c.close()
		}
		c.Unlock()
	}
}
