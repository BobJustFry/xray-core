package udphop

import (
	"context"
	goerrors "errors"
	stdnet "net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
)

type auto41Key struct{}

// Vupen (core 74, CR-102): a port hop opens its new socket with
// internet.VupenNetEpochContextFor(original) — tracked by the network epochs
// exactly when the original socket of an AUTO 4.1 instance is.
func TestVupenHopSocketTrackedLikeOriginal(t *testing.T) {
	internet.VupenSetNetEpochHooks(&internet.VupenNetEpochHooks{Auto41: func(ctx context.Context) bool {
		return ctx.Value(auto41Key{}) != nil
	}})
	t.Cleanup(func() { internet.VupenSetNetEpochHooks(nil) })
	internet.VupenSetUplink("cellular", "cellular:pdp_ip0")

	srv, err := stdnet.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	addr := srv.LocalAddr().(*stdnet.UDPAddr)
	dest := net.UDPDestination(net.IPAddress(addr.IP), net.Port(addr.Port))

	for _, auto41 := range []bool{true, false} {
		ctx := context.Background()
		if auto41 {
			ctx = context.WithValue(ctx, auto41Key{}, true)
		}
		raw, err := internet.DialSystem(ctx, dest, nil)
		if err != nil {
			t.Fatal(err)
		}
		pc, err := NewUDPHopConn(&Config{IntervalMin: 5, IntervalMax: 5, Local: true}, raw.(*internet.PacketConnWrapper).PacketConn)
		if err != nil {
			t.Fatal(err)
		}
		hc := pc.(*udpHopConn)
		hc.mu.Lock()
		hc.hop(&net.UDPAddr{IP: addr.IP, Port: addr.Port})
		cur := hc.cur
		hc.mu.Unlock()
		if cur == nil || cur == hc.conn {
			t.Fatal("hop did not open a new socket")
		}
		// VupenNetEpochContextFor returns plain context.Background() for an
		// untracked socket, a derived context for a tracked one.
		got := internet.VupenNetEpochContextFor(cur) != context.Background()
		if got != auto41 {
			t.Errorf("auto41=%v: hop socket tracked=%v", auto41, got)
		}
		pc.Close()
	}
}

// CR-106: the tracking decision is taken once, from the original socket, and
// survives network changes — after the first change has closed the original
// socket (and dropped its registry entry), new hop sockets are still tracked
// and closed by the next change. Real 9 s countdowns (~19 s).
func TestVupenHopTrackingSurvivesNetworkChanges(t *testing.T) {
	if testing.Short() {
		t.Skip("two real 9 s countdowns")
	}
	internet.VupenSetNetEpochHooks(&internet.VupenNetEpochHooks{Auto41: func(ctx context.Context) bool {
		return ctx.Value(auto41Key{}) != nil
	}})
	t.Cleanup(func() { internet.VupenSetNetEpochHooks(nil) })

	srv, err := stdnet.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	addr := srv.LocalAddr().(*stdnet.UDPAddr)
	dest := net.UDPDestination(net.IPAddress(addr.IP), net.Port(addr.Port))
	hopTo := &net.UDPAddr{IP: addr.IP, Port: addr.Port}

	internet.VupenSetUplink("wifi", "hop-wifi")
	raw, err := internet.DialSystem(context.WithValue(context.Background(), auto41Key{}, true), dest, nil)
	if err != nil {
		t.Fatal(err)
	}
	original := raw.(*internet.PacketConnWrapper).PacketConn
	pc, err := NewUDPHopConn(&Config{IntervalMin: 5, IntervalMax: 5, Local: true}, original)
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	hc := pc.(*udpHopConn)
	hop := func() net.PacketConn {
		hc.mu.Lock()
		defer hc.mu.Unlock()
		hc.hop(hopTo)
		return hc.cur
	}
	closed := func(c net.PacketConn) bool {
		_ = c.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
		_, _, err := c.ReadFrom(make([]byte, 16))
		return goerrors.Is(err, stdnet.ErrClosed)
	}
	sock1 := hop()

	// Change 1: wifi → cellular, 9 s stable → the wifi sockets are closed.
	internet.VupenSetUplink("cellular", "hop-cell")
	time.Sleep(9500 * time.Millisecond)
	if !closed(original) || !closed(sock1) {
		t.Fatal("change 1: wifi sockets not closed")
	}
	sock2 := hop()
	if internet.VupenNetEpochContextFor(sock2) == context.Background() {
		t.Fatal("hop socket opened after change 1 is not tracked")
	}

	// Change 2: cellular → wifi, 9 s stable → the cellular hop socket is closed.
	internet.VupenSetUplink("wifi", "hop-wifi")
	time.Sleep(9500 * time.Millisecond)
	if !closed(sock2) {
		t.Fatal("change 2: hop socket of the previous network not closed")
	}
}
