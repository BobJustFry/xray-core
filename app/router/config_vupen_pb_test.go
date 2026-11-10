package router

import (
	"testing"

	"google.golang.org/protobuf/proto"
)

// Vupen: app/router/config.pb.go is regenerated on every upstream merge (no protoc in the
// fork toolchain). Our BalancingRule fields 100/101 must survive next to upstream's
// Config.script = 4; this test fails if a merge drops or renumbers them.
func TestVupenConfigPbFields(t *testing.T) {
	in := &Config{
		Script: "/tmp/route.lua",
		BalancingRule: []*BalancingRule{{
			Tag:         "auto",
			VupenSpill:  &VupenSpill{BalancerTag: "LTE", Uplink: []string{"wifi", "eth"}},
			VupenSticky: &VupenSticky{Initial: "node-7"},
		}},
	}
	b, err := proto.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out Config
	if err := proto.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(in, &out) {
		t.Fatalf("round trip mismatch: %v != %v", &out, in)
	}
	br := out.BalancingRule[0]
	if out.Script != "/tmp/route.lua" || br.VupenSpill.BalancerTag != "LTE" || br.VupenSticky.Initial != "node-7" {
		t.Fatalf("fields lost: %v", &out)
	}
	fields := (&BalancingRule{}).ProtoReflect().Descriptor().Fields()
	if n := fields.ByName("vupen_spill").Number(); n != 100 {
		t.Fatalf("vupen_spill number %d", n)
	}
	if n := fields.ByName("vupen_sticky").Number(); n != 101 {
		t.Fatalf("vupen_sticky number %d", n)
	}
	if n := (&Config{}).ProtoReflect().Descriptor().Fields().ByName("script").Number(); n != 4 {
		t.Fatalf("script number %d", n)
	}
}
