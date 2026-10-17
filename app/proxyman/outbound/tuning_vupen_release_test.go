package outbound_test

import (
	"context"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/proxyman"
	. "github.com/xtls/xray-core/app/proxyman/outbound"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	core "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/transport/internet"
	grpctransport "github.com/xtls/xray-core/transport/internet/grpc"
)

// Vupen (T-075, CR-001/CR-005): outbound с gRPC — соединение (неудачное) создаёт
// запись в кэше транспорта, Close её убирает, Dial после Close отказывает и
// записи не создаёт.
func TestVupenHandlerCloseReleasesGRPC(t *testing.T) {
	v, err := core.New(&core.Config{})
	if err != nil {
		t.Fatal(err)
	}
	v.AddFeature(outbound.Manager(new(Manager)))
	ctx := context.WithValue(context.Background(), xrayKey, v)
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{}})
	h, err := NewHandler(ctx, &core.OutboundHandlerConfig{
		Tag: "g",
		SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{StreamSettings: &internet.StreamConfig{
			ProtocolName: "grpc",
			TransportSettings: []*internet.TransportConfig{{
				ProtocolName: "grpc",
				Settings:     serial.ToTypedMessage(&grpctransport.Config{ServiceName: "vupen"}),
			}},
		}}),
		ProxySettings: serial.ToTypedMessage(&freedom.Config{}),
	})
	if err != nil {
		t.Fatal(err)
	}
	handler := h.(*Handler)
	before := grpctransport.TransportPoolSize()
	dctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	conn, _ := handler.Dial(dctx, net.TCPDestination(net.LocalHostIP, 1)) // никто не слушает
	if conn != nil {
		conn.Close()
	}
	if n := grpctransport.TransportPoolSize(); n != before+1 {
		t.Fatalf("setup: pool %d, want %d", n, before+1)
	}
	if err := handler.Close(); err != nil {
		t.Fatal(err)
	}
	if n := grpctransport.TransportPoolSize(); n != before {
		t.Fatalf("after Close: pool %d, want %d", n, before)
	}
	if _, err := handler.Dial(ctx, net.TCPDestination(net.LocalHostIP, 1)); err == nil {
		t.Fatal("Dial after Close must fail")
	}
	if n := grpctransport.TransportPoolSize(); n != before {
		t.Fatalf("Dial after Close created an entry: pool %d", n)
	}
}
