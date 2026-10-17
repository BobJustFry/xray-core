package splithttp

import (
	"context"
	"net"
	"net/http"
	"os"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
)

type vupenFakeTransport struct{ idleClosed atomic.Int32 }

func (f *vupenFakeTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, net.ErrClosed
}
func (f *vupenFakeTransport) CloseIdleConnections() { f.idleClosed.Add(1) }

// Vupen (T-075): закрытый outbound освобождает свои записи XHTTP (и запись
// downloadSettings), чужие не трогает; клиенты закрываются.
func TestVupenReleaseXHTTPOnlyOwnEntries(t *testing.T) {
	// sync.Pool теряет элементы при сборке мусора — на время теста без сборок.
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	globalDialerAccess.Lock()
	saved := globalDialerMap
	globalDialerMap = map[dialerConf]*XmuxManager{}
	globalDialerAccess.Unlock()
	t.Cleanup(func() {
		globalDialerAccess.Lock()
		globalDialerMap = saved
		globalDialerAccess.Unlock()
	})
	mkClient := func() (*DefaultDialerClient, *vupenFakeTransport, net.Conn) {
		tr := &vupenFakeTransport{}
		c1, c2 := net.Pipe()
		t.Cleanup(func() { c2.Close() })
		pool := &sync.Pool{}
		pool.Put(&H1Conn{Conn: c1})
		return &DefaultDialerClient{client: &http.Client{Transport: tr}, uploadRawPool: pool}, tr, c2
	}
	a, down, b := &internet.MemoryStreamConfig{}, &internet.MemoryStreamConfig{}, &internet.MemoryStreamConfig{}
	dest := xnet.TCPDestination(xnet.LocalHostIP, 443)
	ca, tra, peerA := mkClient()
	cd, trd, _ := mkClient()
	cb, trb, _ := mkClient()
	put := func(ss *internet.MemoryStreamConfig, c *DefaultDialerClient) {
		m := NewXmuxManager(XmuxConfig{}, func() XmuxConn { return c })
		globalDialerMap[dialerConf{dest, ss}] = m
		m.GetXmuxClient(t.Context())
	}
	globalDialerAccess.Lock()
	put(a, ca)
	put(down, cd)
	put(b, cb)
	globalDialerAccess.Unlock()
	a.DownloadSettings = down // запись downloadSettings — того же outbound

	if m, c := VupenDialerPoolSize(); m != 3 || c != 3 {
		t.Fatalf("setup: %d managers, %d clients", m, c)
	}
	internet.VupenReleaseStreamSettings(a)

	if m, c := VupenDialerPoolSize(); m != 1 || c != 1 {
		t.Fatalf("after release: %d managers, %d clients, want 1/1", m, c)
	}
	if !ca.IsClosed() || !cd.IsClosed() || cb.IsClosed() {
		t.Fatalf("closed: a=%v down=%v b=%v", ca.IsClosed(), cd.IsClosed(), cb.IsClosed())
	}
	if tra.idleClosed.Load() != 1 || trd.idleClosed.Load() != 1 || trb.idleClosed.Load() != 0 {
		t.Fatalf("CloseIdleConnections: a=%d down=%d b=%d", tra.idleClosed.Load(), trd.idleClosed.Load(), trb.idleClosed.Load())
	}
	// Соединение пула выгрузки закрыто: собеседник видит конец.
	peerA.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := peerA.Read(make([]byte, 1)); err == nil || (os.IsTimeout(err) && !vupenRaceEnabled) {
		t.Fatal("the upload pool connection is still open")
	}
}

// CR-001: соединение, начатое за мгновение до Close, создаёт запись уже после
// первого прохода — второй проход (VupenStreamReleaseRecheck) её убирает.
func TestVupenReleaseXHTTPLateEntry(t *testing.T) {
	old := internet.VupenStreamReleaseRecheck
	internet.VupenStreamReleaseRecheck = 50 * time.Millisecond
	t.Cleanup(func() { internet.VupenStreamReleaseRecheck = old })
	ss := &internet.MemoryStreamConfig{ProtocolName: "splithttp", ProtocolSettings: &Config{Path: "/x"}}
	dest := xnet.TCPDestination(xnet.LocalHostIP, 1)
	before, _ := VupenDialerPoolSize()
	internet.VupenReleaseStreamSettings(ss)
	getHTTPClient(t.Context(), dest, ss) // опоздавшее соединение
	if m, _ := VupenDialerPoolSize(); m != before+1 {
		t.Fatalf("setup: %d managers, want %d", m, before+1)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if m, _ := VupenDialerPoolSize(); m == before {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	m, _ := VupenDialerPoolSize()
	t.Fatalf("the late entry stays: %d managers, want %d", m, before)
}

// CR-001: установление соединения обрывается, когда клиент закрыт; законченное — нет.
func TestVupenDialLife(t *testing.T) {
	life, kill := context.WithCancel(context.Background())
	ctx, stop := vupenDialLife(context.WithoutCancel(t.Context()), life)
	done, stop2 := vupenDialLife(context.Background(), life)
	stop2() // это установление уже закончилось
	kill()
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("in-flight dial context not cancelled by the client close")
	}
	stop()
	if done.Err() != nil {
		t.Fatal("a finished dial context must not be cancelled")
	}
}
