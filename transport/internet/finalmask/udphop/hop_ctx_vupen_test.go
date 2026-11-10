package udphop

import (
	"context"
	stdnet "net"
	"testing"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/finalmask"
)

// Vupen (T-221): udphop re-dials with the closure built from the FIRST dial
// ctx. When that request ctx is cancelled after the connection is up, every
// hop used to fail ("hop err"). Hops must keep the ctx values and drop only
// the cancellation; the first dial must still honour the caller's cancel.
func TestVupenHopSurvivesFirstDialCancel(t *testing.T) {
	srv, err := stdnet.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	addr := srv.LocalAddr().(*stdnet.UDPAddr)
	dest := net.UDPDestination(net.IPAddress(addr.IP), net.Port(addr.Port))

	dials := 0
	var lastCtx context.Context
	dialUDP := func(ctx context.Context, d net.Destination) (net.PacketConn, net.Addr, error) {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		dials++
		lastCtx = ctx
		c, err := internet.DialSystem(ctx, d, nil)
		if err != nil {
			return nil, nil, err
		}
		pw := c.(*net.PacketConnWrapper)
		return pw.PacketConn, pw.Dest, nil
	}
	fm := finalmask.NewFinalMask(nil, []finalmask.UDPMask{&Config{IntervalMin: 5, IntervalMax: 5, Local: true}}, nil, nil, dialUDP, nil)

	// The first dial still honours cancellation.
	dead, kill := context.WithCancel(context.Background())
	kill()
	if _, err := fm.DialUDP(dead, dest); err == nil {
		t.Fatal("first dial with a cancelled ctx must fail")
	}

	ctx, cancel := context.WithCancel(context.WithValue(context.Background(), auto41Key{}, "v"))
	conn, err := fm.DialUDP(ctx, dest)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	hc := conn.(*net.PacketConnWrapper).PacketConn.(*udpHopConn)
	hc.mu.Lock()
	first := hc.cur
	hc.mu.Unlock()
	before := dials

	cancel() // the original request is over; the connection lives on
	hc.hop()

	hc.mu.Lock()
	cur := hc.cur
	hc.mu.Unlock()
	if cur == first || dials != before+1 {
		t.Fatalf("hop after first-ctx cancel failed: new socket=%v dials %d->%d", cur != first, before, dials)
	}
	if lastCtx.Value(auto41Key{}) != "v" {
		t.Error("hop dial lost the ctx values")
	}
	if lastCtx.Err() != nil {
		t.Error("hop dial ctx must not carry the cancellation")
	}
}
