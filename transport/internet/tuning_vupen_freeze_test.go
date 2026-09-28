package internet

import (
	"context"
	"io"
	stdnet "net"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
)

func TestVupenFreezeSuspicious(t *testing.T) {
	now := time.Now().UnixNano()
	silent := now - int64(VupenFreezeSilence) - 1
	fresh := now - int64(time.Second)
	cases := []struct {
		name               string
		sent, recv, since  int64
		want               bool
	}{
		{"silent after 16 KB", 12 << 10, 4 << 10, silent, true},
		{"nothing pending", 12 << 10, 4 << 10, 0, false},
		{"not silent long enough", 12 << 10, 4 << 10, fresh, false},
		{"too early: handshake only", 2 << 10, 5 << 10, silent, false},
		{"too late: a busy connection that paused", 300 << 10, 5 << 20, silent, false},
	}
	for _, c := range cases {
		if got := vupenFreezeSuspicious(c.sent, c.recv, c.since, now); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

type freezeHit struct {
	key        any
	tag        string
	sent, recv int64
}

// freezeTestHooks — сторож в тесте: короткая тишина, частый проход, свои хуки.
func freezeTestHooks(t *testing.T, watch bool) chan freezeHit {
	t.Helper()
	oldSilence, oldScan := VupenFreezeSilence, vupenFreezeScanEvery
	VupenFreezeSilence = 150 * time.Millisecond
	vupenFreezeScanEvery = 20 * time.Millisecond
	hits := make(chan freezeHit, 8)
	old := vupenFreezeHooks.Load()
	VupenSetFreezeHooks(&VupenFreezeHooks{
		Watch: func(ctx context.Context, tag string) any {
			if !watch {
				return nil
			}
			return "hp"
		},
		Suspect: func(key any, tag string, sent, recv int64) {
			hits <- freezeHit{key, tag, sent, recv}
		},
	})
	t.Cleanup(func() {
		VupenFreezeSilence, vupenFreezeScanEvery = oldSilence, oldScan
		vupenFreezeHooks.Store(old)
	})
	return hits
}

func freezeCtx(tag string) context.Context {
	return session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Tag: tag}})
}

var tcpDest = net.TCPDestination(net.DomainAddress("node.example"), 443)

// Узел под заморозкой: мы шлём 16 КБ, он всё читает (TCP-ACK), но не отвечает.
func TestVupenFreezeFiresOnceOnASilentConnection(t *testing.T) {
	hits := freezeTestHooks(t, true)
	client, server := stdnet.Pipe()
	defer server.Close()
	go func() { _, _ = io.Copy(io.Discard, server) }()
	c := vupenFreezeWrap(freezeCtx("proxy-7"), client, tcpDest)
	defer c.Close()
	if _, ok := c.(*vupenFreezeConn); !ok {
		t.Fatal("a watched outbound must be wrapped")
	}
	if _, err := c.Write(make([]byte, 16<<10)); err != nil {
		t.Fatal(err)
	}
	select {
	case h := <-hits:
		if h.tag != "proxy-7" || h.key != "hp" || h.sent != 16<<10 {
			t.Fatalf("unexpected hit: %+v", h)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a silent connection after 16 KB must be reported")
	}
	select {
	case h := <-hits:
		t.Fatalf("must fire once per connection, got a second hit %+v", h)
	case <-time.After(300 * time.Millisecond):
	}
}

// Живой узел отвечает на каждую запись — тревоги нет.
func TestVupenFreezeQuietWhenTheNodeAnswers(t *testing.T) {
	hits := freezeTestHooks(t, true)
	client, server := stdnet.Pipe()
	defer server.Close()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 4096)
		for {
			n, err := server.Read(buf)
			if err != nil {
				return
			}
			if _, err := server.Write(buf[:n]); err != nil {
				return
			}
		}
	}()
	c := vupenFreezeWrap(freezeCtx("proxy-10"), client, tcpDest)
	go func() { _, _ = io.Copy(io.Discard, c) }()
	for i := 0; i < 4; i++ {
		if _, err := c.Write(make([]byte, 4096)); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case h := <-hits:
		t.Fatalf("an answering node must not be reported: %+v", h)
	case <-time.After(500 * time.Millisecond):
	}
	c.Close()
	wg.Wait()
}

func TestVupenFreezeSkipsUnwatchedAndNonTCP(t *testing.T) {
	freezeTestHooks(t, false)
	client, server := stdnet.Pipe()
	defer server.Close()
	defer client.Close()
	if c := vupenFreezeWrap(freezeCtx("direct"), client, tcpDest); c != client {
		t.Fatal("an outbound the observatory does not watch must stay unwrapped")
	}
	freezeTestHooks(t, true)
	udp := net.UDPDestination(net.DomainAddress("node.example"), 443)
	if c := vupenFreezeWrap(freezeCtx("proxy-2"), client, udp); c != client {
		t.Fatal("UDP must stay unwrapped: the freeze is a TCP thing")
	}
	if c := vupenFreezeWrap(context.Background(), client, tcpDest); c != client {
		t.Fatal("no outbound in ctx — nothing to report against")
	}
}
