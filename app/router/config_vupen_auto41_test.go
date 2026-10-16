package router

// Vupen 4.1 AUTO (cores 73/75; CR-002): BalancingRule.Build without the new
// fields builds exactly the balancer it built before them — vupen state is nil
// and every other field is the same. With vupenSticky the balancer gets the
// sticky state and nothing else changes; vupenSpill alone (2.5) does nothing yet.

import (
	"reflect"
	"testing"

	"github.com/xtls/xray-core/common/serial"

	"google.golang.org/protobuf/proto"
)

// vupenAuto41BalancerFields — every Balancer field and how this test compares
// it. A new field fails the test until it is listed here (CR-002).
var vupenAuto41BalancerFields = map[string]bool{
	"selectors": true, "strategy": true, "ohm": true, "fallbackTag": true, "override": true,
	"vupen": true, // asserted separately (nil without vupenSticky)
}

func TestVupenAuto41BalancerFieldsKnown(t *testing.T) {
	typ := reflect.TypeOf(Balancer{})
	for i := 0; i < typ.NumField(); i++ {
		if name := typ.Field(i).Name; !vupenAuto41BalancerFields[name] {
			t.Fatalf("Balancer has a new field %q: decide how a config without vupen fields keeps it unchanged and list it here", name)
		}
	}
	if typ.NumField() != len(vupenAuto41BalancerFields) {
		t.Fatalf("Balancer has %d fields, the test knows %d", typ.NumField(), len(vupenAuto41BalancerFields))
	}
}

// vupenAuto41SameBalancer compares every field except vupen; proto settings
// with proto.Equal (their internal state is not reflect-comparable between two
// unmarshals), the leastLoad weight manager field by field (it holds a func).
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

func TestVupenAuto41BuildVupenState(t *testing.T) {
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
		with := func(spill *VupenSpill, sticky *VupenSticky) *BalancingRule {
			return &BalancingRule{
				Tag: base.Tag, OutboundSelector: base.OutboundSelector, Strategy: base.Strategy,
				StrategySettings: base.StrategySettings, FallbackTag: base.FallbackTag,
				VupenSpill: spill, VupenSticky: sticky,
			}
		}
		a, err := base.Build(nil, nil)
		if err != nil {
			t.Fatalf("%q: %v", strategy, err)
		}
		if a.vupen != nil {
			t.Fatalf("%q: a balancer without vupen fields must have nil vupen state", strategy)
		}
		spillOnly, err := with(&VupenSpill{BalancerTag: "LTE", Uplink: []string{"cellular"}}, nil).Build(nil, nil)
		if err != nil {
			t.Fatalf("%q spill only: %v", strategy, err)
		}
		if spillOnly.vupen != nil || !vupenAuto41SameBalancer(a, spillOnly) {
			t.Fatalf("%q: vupenSpill alone must not change the balancer (2.5)", strategy)
		}
		sticky, err := with(nil, &VupenSticky{Initial: "proxy-7"}).Build(nil, nil)
		if err != nil {
			t.Fatalf("%q sticky: %v", strategy, err)
		}
		if sticky.vupen == nil || sticky.vupen.initial != "proxy-7" || sticky.vupen.balancer != "REG" || sticky.vupen.b != sticky {
			t.Fatalf("%q: vupenSticky must give sticky state for this balancer: %+v", strategy, sticky.vupen)
		}
		if !vupenAuto41SameBalancer(a, sticky) {
			t.Fatalf("%q: vupenSticky must not change the rest of the balancer", strategy)
		}
		empty, err := with(nil, &VupenSticky{}).Build(nil, nil)
		if err != nil || empty.vupen == nil || empty.vupen.initial != "" {
			t.Fatalf("%q: vupenSticky {} = sticky without initial (search at once): %v %+v", strategy, err, empty.vupen)
		}
	}

	bad := &BalancingRule{Tag: "b", OutboundSelector: []string{"p"}, Strategy: "vupensticky",
		VupenSticky: &VupenSticky{Initial: "x"}}
	if _, err := bad.Build(nil, nil); err == nil {
		t.Fatal("unknown strategy type must still be rejected")
	}
}

// Without vupen state PickOutbound takes the old path: the strategy decides.
func TestVupenAuto41PickWithoutStickyIsUnchanged(t *testing.T) {
	ohm := &stickyFakeOhm{tags: []string{"p-1", "p-2", "p-3"}}
	b := &Balancer{selectors: []string{"p"}, strategy: &RoundRobinStrategy{}, ohm: ohm}
	var got []string
	for i := 0; i < 4; i++ {
		tag, err := b.PickOutbound()
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, tag)
	}
	if want := []string{"p-1", "p-2", "p-3", "p-1"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("round robin without sticky: %v, want %v", got, want)
	}
}
