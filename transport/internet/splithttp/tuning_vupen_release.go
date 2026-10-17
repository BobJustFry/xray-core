package splithttp

import (
	"net"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
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

// vupenOwner — запись для downloadSettings принадлежит outbound'у, чьи
// настройки потока её создали (ключ у неё — streamSettings.DownloadSettings).
// Под globalDialerAccess.
var vupenOwner = map[dialerConf]*internet.MemoryStreamConfig{}

func vupenNoteOwner(dest xnet.Destination, ss, owner *internet.MemoryStreamConfig) {
	if ss == nil || owner == nil || ss == owner {
		return
	}
	globalDialerAccess.Lock()
	if _, ok := globalDialerMap[dialerConf{dest, ss}]; ok {
		vupenOwner[dialerConf{dest, ss}] = owner
	}
	globalDialerAccess.Unlock()
}

func vupenReleaseXHTTP(ss *internet.MemoryStreamConfig) {
	var closing []XmuxConn
	globalDialerAccess.Lock()
	for k, m := range globalDialerMap {
		if k.MemoryStreamConfig != ss && vupenOwner[k] != ss {
			continue
		}
		delete(globalDialerMap, k)
		delete(vupenOwner, k)
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
