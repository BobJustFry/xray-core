package router

import (
	"testing"

	"github.com/xtls/xray-core/app/observatory"
)

type fakeOracle struct {
	verified  map[string]bool
	requested []string
}

func (f *fakeOracle) VupenTspuVerified(tag string) bool { return f.verified[tag] }
func (f *fakeOracle) VupenTspuRequestVerify(tag string) {
	f.requested = append(f.requested, tag)
}

func TestVupenVerifiedSwitch(t *testing.T) {
	cases := []struct {
		name      string
		last      string
		lastAlive bool
		pick      string
		ordered   []string
		verified  map[string]bool
		want      string
		requested bool
	}{
		{"same node — nothing to decide", "proxy-4", true, "proxy-4", []string{"proxy-4"}, nil, "proxy-4", false},
		{"switch to a verified node", "proxy-4", true, "proxy-10", []string{"proxy-10", "proxy-4"}, map[string]bool{"proxy-10": true}, "proxy-10", false},
		// Бандл 2026-09-27 23:30:49: proxy-7 стал «самым быстрым», но не проверен.
		{"stay while the new best is unverified", "proxy-4", true, "proxy-7", []string{"proxy-7", "proxy-4"}, nil, "proxy-4", true},
		{"current died: best verified among the rest", "proxy-4", false, "proxy-7", []string{"proxy-7", "proxy-10", "proxy-11"}, map[string]bool{"proxy-11": true}, "proxy-11", true},
		{"start of the core: nothing verified yet", "", false, "proxy-7", []string{"proxy-7", "proxy-10"}, nil, "proxy-7", true},
		{"fallback stays fallback", "proxy-4", true, "", nil, nil, "", false},
	}
	for _, c := range cases {
		o := &fakeOracle{verified: c.verified}
		got := vupenVerifiedSwitch(c.last, c.lastAlive, c.pick, c.ordered, o.VupenTspuVerified, o.VupenTspuRequestVerify)
		if got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
		if (len(o.requested) > 0) != c.requested {
			t.Errorf("%s: requested=%v, want request=%v", c.name, o.requested, c.requested)
		}
	}
}

func TestVupenLeastPingVerified(t *testing.T) {
	status := []*observatory.OutboundStatus{
		{OutboundTag: "proxy-7", Alive: true, Delay: 266},
		{OutboundTag: "proxy-4", Alive: true, Delay: 300},
		{OutboundTag: "proxy-10", Alive: true, Delay: 320},
		{OutboundTag: "proxy-8", Alive: false, Delay: 0},
	}
	cands := outboundList{"proxy-7", "proxy-4", "proxy-10", "proxy-8"}
	pick := vupenLeastPingPick{tag: "proxy-7", delay: 266, alive: 3, total: 4}

	o := &fakeOracle{}
	got := vupenLeastPingVerified("proxy-4", pick, cands, status, o)
	if got.tag != "proxy-4" || got.delay != 300 || len(o.requested) != 1 || o.requested[0] != "proxy-7" {
		t.Fatalf("stay on proxy-4 and ask to verify proxy-7: %+v %v", got, o.requested)
	}

	o = &fakeOracle{verified: map[string]bool{"proxy-10": true}}
	got = vupenLeastPingVerified("proxy-8", pick, cands, status, o)
	if got.tag != "proxy-10" || got.delay != 320 {
		t.Fatalf("current is dead: take the fastest verified one: %+v", got)
	}

	o = &fakeOracle{verified: map[string]bool{"proxy-7": true}}
	got = vupenLeastPingVerified("proxy-4", pick, cands, status, o)
	if got.tag != "proxy-7" || len(o.requested) != 0 {
		t.Fatalf("a verified best is taken as is: %+v", got)
	}
}
