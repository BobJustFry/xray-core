package splithttp

import (
	"context"
	"net"
	"time"

	"github.com/xtls/xray-core/transport/internet"
)

// Vupen (T-075): закрытый outbound освобождает свои клиенты XHTTP
// (transport/internet/tuning_vupen_release.go). Без этого globalDialerMap рос на
// каждое временное ядро (пинг, проверка узла) и каждый перезапуск: ~36 КБ
// навсегда плюс открытое HTTP/2-соединение до 300 с простоя.
func init() { internet.VupenRegisterStreamRelease(vupenReleaseXHTTP) }

// VupenXHTTPReleaseRecheck — соединения, занятые в момент закрытия outbound'а,
// закрываются, как только освободятся (повторный CloseIdleConnections).
var VupenXHTTPReleaseRecheck = 10 * time.Second

func vupenReleaseXHTTP(ss *internet.MemoryStreamConfig) {
	var closing []XmuxConn
	globalDialerAccess.Lock()
	// downloadSettings — свои записи у той же outbound'а (ключ — её настройки).
	down := ss.DownloadSettings
	for k, m := range globalDialerMap {
		if k.MemoryStreamConfig != ss && (down == nil || k.MemoryStreamConfig != down) {
			continue
		}
		delete(globalDialerMap, k)
		if m == nil {
			continue
		}
		for _, c := range m.xmuxClients {
			c.NotUsed.Store(true)
			closing = append(closing, c.XmuxConn)
		}
		m.xmuxClients = nil
	}
	globalDialerAccess.Unlock()
	for _, c := range closing {
		vupenCloseDialerClient(c)
	}
}

// vupenCloseDialerClient — закрыть клиента целиком: свободные соединения сразу,
// занятые — когда освободятся; соединения пула выгрузки (packet-up, HTTP/1.1).
func vupenCloseDialerClient(c XmuxConn) {
	d, ok := c.(*DefaultDialerClient)
	if !ok {
		return
	}
	d.closed.Store(true)
	if d.vupenKill != nil {
		d.vupenKill() // соединения, которые ещё устанавливаются (рукопожатие с молчащим узлом)
	}
	_ = d.Close() // HTTP/3
	if ci, ok := d.client.Transport.(interface{ CloseIdleConnections() }); ok {
		ci.CloseIdleConnections()
		time.AfterFunc(VupenXHTTPReleaseRecheck, ci.CloseIdleConnections)
	}
	if d.uploadRawPool != nil {
		for {
			v := d.uploadRawPool.Get()
			if v == nil {
				break
			}
			if conn, ok := v.(net.Conn); ok {
				_ = conn.Close()
			}
		}
	}
}

// vupenDialLife — контекст установления соединения, который отменяется и когда
// закрыт клиент (life). stop — снять связь, когда установление закончилось;
// сам контекст после этого не отменяем: установленное соединение (и то, что
// слои под ним могли к нему привязать) живёт, как раньше.
func vupenDialLife(ctx, life context.Context) (context.Context, func()) {
	ctx, cancel := context.WithCancel(ctx)
	unhook := context.AfterFunc(life, cancel)
	return ctx, func() { unhook() }
}

// VupenDialerPoolSize — записей в кэше XHTTP и клиентов в них (диагностика).
func VupenDialerPoolSize() (managers, clients int) {
	globalDialerAccess.Lock()
	defer globalDialerAccess.Unlock()
	for _, m := range globalDialerMap {
		managers++
		if m != nil {
			clients += len(m.xmuxClients)
		}
	}
	return managers, clients
}
