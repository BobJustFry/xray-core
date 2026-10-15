package router

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/app/observatory/burst"
	"github.com/xtls/xray-core/app/proxyman"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	"github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"

	"google.golang.org/protobuf/proto"
)

// vupenNetEpochInst — a core instance with the given router/observatory
// config; returns the context its features run with (it carries the instance).
func vupenNetEpochInst(t *testing.T, apps ...proto.Message) context.Context {
	t.Helper()
	cfg := &core.Config{App: []*serial.TypedMessage{
		serial.ToTypedMessage(&dispatcher.Config{}),
		serial.ToTypedMessage(&proxyman.OutboundConfig{}),
		serial.ToTypedMessage(&stats.Config{}),
	}}
	for _, a := range apps {
		cfg.App = append(cfg.App, serial.ToTypedMessage(a))
	}
	inst, err := core.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { inst.Close() })
	r, ok := inst.GetFeature(routing.RouterType()).(*Router)
	if !ok {
		t.Fatalf("router feature is %T", inst.GetFeature(routing.RouterType()))
	}
	return r.ctx
}

func TestVupenNetEpochAuto41(t *testing.T) {
	balancer := func(spill *VupenSpill, sticky *VupenSticky) *Config {
		return &Config{BalancingRule: []*BalancingRule{{
			Tag: "REG", OutboundSelector: []string{"proxy"}, Strategy: "leastping",
			VupenSpill: spill, VupenSticky: sticky,
		}}}
	}
	obs := func(onDemand bool) *burst.Config {
		return &burst.Config{SubjectSelector: []string{"proxy"}, PingConfig: &burst.HealthPingConfig{}, VupenOnDemand: onDemand}
	}
	cases := []struct {
		name string
		apps []proto.Message
		want bool
	}{
		// leastPing needs an observatory, so every case has one.
		{"panel balancer, no vupen fields", []proto.Message{balancer(nil, nil), obs(false)}, false},
		{"vupenSticky", []proto.Message{balancer(nil, &VupenSticky{Initial: "proxy-1"}), obs(false)}, true},
		{"vupenSpill", []proto.Message{balancer(&VupenSpill{BalancerTag: "LTE", Uplink: []string{"cellular"}}, nil), obs(false)}, true},
		{"vupenOnDemand only", []proto.Message{balancer(nil, nil), obs(true)}, true},
		{"router without balancers, no observatory", []proto.Message{&Config{}}, false},
	}
	for _, c := range cases {
		ctx := vupenNetEpochInst(t, c.apps...)
		if got := vupenNetEpochAuto41(ctx); got != c.want {
			t.Errorf("%s: Auto41 = %v, want %v", c.name, got, c.want)
		}
	}
	if vupenNetEpochAuto41(context.Background()) {
		t.Error("a context without a core instance must not be AUTO 4.1")
	}
}
