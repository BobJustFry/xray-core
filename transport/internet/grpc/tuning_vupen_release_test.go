package grpc

import (
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
)

// Vupen (T-075): закрытый outbound освобождает только свои gRPC-клиенты.
func TestVupenReleaseGRPCOnlyOwnEntries(t *testing.T) {
	globalDialerAccess.Lock()
	saved := globalDialerMap
	globalDialerMap = map[dialerConf]*grpc.ClientConn{}
	globalDialerAccess.Unlock()
	t.Cleanup(func() {
		globalDialerAccess.Lock()
		globalDialerMap = saved
		globalDialerAccess.Unlock()
	})
	mk := func() *grpc.ClientConn {
		c, err := grpc.NewClient("passthrough:///127.0.0.1:1", grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	a, b := &internet.MemoryStreamConfig{}, &internet.MemoryStreamConfig{}
	d1 := net.TCPDestination(net.LocalHostIP, 1001)
	d2 := net.TCPDestination(net.LocalHostIP, 1002)
	ca1, ca2, cb := mk(), mk(), mk()
	globalDialerAccess.Lock()
	globalDialerMap[dialerConf{d1, a}] = ca1
	globalDialerMap[dialerConf{d2, a}] = ca2
	globalDialerMap[dialerConf{d1, b}] = cb
	globalDialerAccess.Unlock()

	internet.VupenReleaseStreamSettings(a) // через реестр, как Handler.Close

	if n := TransportPoolSize(); n != 1 {
		t.Fatalf("pool %d, want 1 (only b left)", n)
	}
	for _, c := range []*grpc.ClientConn{ca1, ca2} {
		if c.GetState() != connectivity.Shutdown {
			t.Fatalf("a client of the closed outbound is %v", c.GetState())
		}
	}
	if cb.GetState() == connectivity.Shutdown {
		t.Fatal("another outbound's client was closed")
	}
	internet.VupenReleaseStreamSettings(nil) // без паники
	_ = cb.Close()
}
