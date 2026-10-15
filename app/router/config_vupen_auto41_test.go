package router

// Vupen 4.1 AUTO, core step 2.1: the new BalancingRule fields (vupen_spill,
// vupen_sticky) are carried by the config only. Until the later sub-steps use
// them, BalancingRule.Build must produce the same Balancer with or without them.

import (
	"reflect"
	"testing"

	"github.com/xtls/xray-core/common/serial"

	"google.golang.org/protobuf/proto"
)

// vupenAuto41SameBalancer compares two built balancers field by field; proto
// settings are compared with proto.Equal (their internal state is not
// reflect-comparable between two unmarshals) and the leastLoad weight
// manager field by field (it holds a func).
func vupenAuto41SameBalancer(a, b *Balancer) bool {
	if !reflect.DeepEqual(a.selectors, b.selectors) || a.fallbackTag != b.fallbackTag ||
		a.ohm != b.ohm || !reflect.DeepEqual(&a.override, &b.override) ||
		reflect.TypeOf(a.strategy) != reflect.TypeOf(b.strategy) {
		return false
	}
	la, ok := a.strategy.(*LeastLoadStrategy)
	if !ok {
		return reflect.DeepEqual(a.strategy, b.strategy)
	}
	lb := b.strategy.(*LeastLoadStrategy)
	ca, cb := la.costs, lb.costs
	if len(ca.settings) != len(cb.settings) {
		return false
	}
	for i := range ca.settings {
		if !proto.Equal(ca.settings[i], cb.settings[i]) {
			return false
		}
	}
	// scaler is a func: compare the code pointer (the same closure in NewLeastLoadStrategy).
	return proto.Equal(la.settings, lb.settings) &&
		reflect.DeepEqual(ca.cache, cb.cache) && ca.defaultWeight == cb.defaultWeight &&
		reflect.ValueOf(ca.scaler).Pointer() == reflect.ValueOf(cb.scaler).Pointer() &&
		la.observer == lb.observer && la.ctx == lb.ctx && reflect.DeepEqual(&la.vupen, &lb.vupen)
}

func TestVupenAuto41BuildIgnoresNewFields(t *testing.T) {
	leastLoad := serial.ToTypedMessage(&StrategyLeastLoadConfig{Expected: 2, MaxRTT: 1e9, Tolerance: 0.3})
	for _, strategy := range []string{"", "random", "leastping", "leastload", "roundrobin"} {
		base := &BalancingRule{
			Tag:              "REG",
			OutboundSelector: []string{"proxy"},
			Strategy:         strategy,
			FallbackTag:      "proxy-1",
		}
		if strategy == "leastload" {
			base.StrategySettings = leastLoad
		}
		withVupen := &BalancingRule{
			Tag:              base.Tag,
			OutboundSelector: base.OutboundSelector,
			Strategy:         base.Strategy,
			StrategySettings: base.StrategySettings,
			FallbackTag:      base.FallbackTag,
			VupenSpill:       &VupenSpill{BalancerTag: "LTE", Uplink: []string{"cellular"}},
			VupenSticky:      &VupenSticky{Initial: "proxy-7"},
		}
		a, err := base.Build(nil, nil)
		if err != nil {
			t.Fatalf("%q: %v", strategy, err)
		}
		b, err := withVupen.Build(nil, nil)
		if err != nil {
			t.Fatalf("%q with vupen fields: %v", strategy, err)
		}
		if !vupenAuto41SameBalancer(a, b) {
			t.Fatalf("%q: Build differs with vupen fields:\n%#v\n%#v", strategy, a, b)
		}
	}

	bad := &BalancingRule{Tag: "b", OutboundSelector: []string{"p"}, Strategy: "vupensticky",
		VupenSticky: &VupenSticky{Initial: "x"}}
	if _, err := bad.Build(nil, nil); err == nil {
		t.Fatal("unknown strategy type must still be rejected")
	}
}
