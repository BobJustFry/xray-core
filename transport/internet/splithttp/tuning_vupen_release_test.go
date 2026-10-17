package splithttp

import (
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"

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
	globalDialerAccess.Lock()
	saved, savedOwner := globalDialerMap, vupenOwner
	globalDialerMap, vupenOwner = map[dialerConf]*XmuxManager{}, map[dialerConf]*internet.MemoryStreamConfig{}
	globalDialerAccess.Unlock()
	t.Cleanup(func() {
		globalDialerAccess.Lock()
		globalDialerMap, vupenOwner = saved, savedOwner
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
	vupenNoteOwner(dest, down, a) // downloadSettings записи a

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
	if _, err := peerA.Read(make([]byte, 1)); err == nil {
		t.Fatal("the upload pool connection is still open")
	}
	globalDialerAccess.Lock()
	n := len(vupenOwner)
	globalDialerAccess.Unlock()
	if n != 0 {
		t.Fatalf("owner records left: %d", n)
	}
}
