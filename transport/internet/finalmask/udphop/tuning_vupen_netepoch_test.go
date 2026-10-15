package udphop

import (
	"context"
	stdnet "net"
	"testing"

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
