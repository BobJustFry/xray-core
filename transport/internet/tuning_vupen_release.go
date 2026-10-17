package internet

import (
	"sync"
	"time"
)

// Vupen (T-075, аудит памяти T-071): кэши транспортов привязаны к outbound'у.
//
// gRPC (grpc/dial.go) и XHTTP (splithttp/dialer.go) держат клиентов в картах на
// весь процесс, ключ — (адрес, *MemoryStreamConfig). MemoryStreamConfig у
// каждого outbound'а свой, поэтому новый экземпляр ядра (перезапуск, пинг или
// проверка узла временным ядром) никогда не находит старую запись, а старая не
// удаляется никогда: gRPC — ~80 КБ, 5 горутин и открытое соединение на каждое
// временное ядро, XHTTP — ~36 КБ навсегда и соединение до 300 с простоя.
//
// Outbound при закрытии (app/proxyman/outbound Handler.Close) сообщает сюда свои
// настройки потока, транспорты закрывают и удаляют только записи с ними —
// соединения работающего ядра (другие указатели) не трогаются.

// VupenStreamReleaseRecheck — второй проход освобождения: соединение, которое
// outbound начал устанавливать за мгновение до Close (проверку «закрыт» оно уже
// прошло), создаёт запись в кэше чуть позже первого прохода (T-075, CR-001).
var VupenStreamReleaseRecheck = 10 * time.Second

var vupenStreamRelease struct {
	mu sync.Mutex
	fs []func(*MemoryStreamConfig)
}

// VupenRegisterStreamRelease — транспорт сообщает, как освободить свои записи
// для настроек потока (вызывается из init пакета транспорта).
func VupenRegisterStreamRelease(f func(*MemoryStreamConfig)) {
	vupenStreamRelease.mu.Lock()
	vupenStreamRelease.fs = append(vupenStreamRelease.fs, f)
	vupenStreamRelease.mu.Unlock()
}

// VupenReleaseStreamSettings — outbound с этими настройками потока закрыт:
// освободить сразу и ещё раз через VupenStreamReleaseRecheck.
func VupenReleaseStreamSettings(ss *MemoryStreamConfig) {
	if ss == nil {
		return
	}
	vupenReleaseStreamNow(ss)
	time.AfterFunc(VupenStreamReleaseRecheck, func() { vupenReleaseStreamNow(ss) })
}

func vupenReleaseStreamNow(ss *MemoryStreamConfig) {
	vupenStreamRelease.mu.Lock()
	fs := append([](func(*MemoryStreamConfig)){}, vupenStreamRelease.fs...)
	vupenStreamRelease.mu.Unlock()
	for _, f := range fs {
		f(ss)
	}
}
