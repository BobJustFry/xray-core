package conf_test

// Vupen 4.1 AUTO, core step 2.1 (ADR-0001 sections 4.3, 4.4, 13): the config
// fields vupenSpill / vupenSticky (routing.balancers[]) and vupenOnDemand
// (burstObservatory). These tests pin that a config WITHOUT the new fields
// builds byte-for-byte the same core config as before the fields existed.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/observatory/burst"
	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common/serial"
	core "github.com/xtls/xray-core/core"
	. "github.com/xtls/xray-core/infra/conf"

	"google.golang.org/protobuf/proto"
)

// vupenAuto41LegacyJSON is a config in the shape the app builds today
// (two panel balancers, burst observatory), without any vupen* field.
const vupenAuto41LegacyJSON = `{
	"outbounds": [
		{"tag": "proxy-1", "protocol": "freedom"},
		{"tag": "proxy-2", "protocol": "freedom"},
		{"tag": "lte-proxy-1", "protocol": "freedom"},
		{"tag": "direct", "protocol": "freedom"}
	],
	"routing": {
		"domainStrategy": "AsIs",
		"rules": [
			{"port": "0-65535", "balancerTag": "REG"}
		],
		"balancers": [
			{
				"tag": "REG",
				"selector": ["proxy"],
				"strategy": {"type": "leastPing"},
				"fallbackTag": "proxy-1"
			},
			{
				"tag": "LTE",
				"selector": ["lte-"],
				"strategy": {
					"type": "leastLoad",
					"settings": {"expected": 2, "maxRTT": "1s", "tolerance": 0.3}
				},
				"fallbackTag": "lte-proxy-1"
			}
		]
	},
	"burstObservatory": {
		"subjectSelector": ["proxy", "lte-"],
		"pingConfig": {
			"destination": "https://www.gstatic.com/generate_204",
			"connectivity": "",
			"interval": "100s",
			"sampling": 3,
			"timeout": "5s"
		}
	}
}`

// vupenAuto41NewJSON is vupenAuto41LegacyJSON plus every new field, in the
// shape of the ADR-0001 section 13 contract.
const vupenAuto41NewJSON = `{
	"outbounds": [
		{"tag": "proxy-1", "protocol": "freedom"},
		{"tag": "proxy-2", "protocol": "freedom"},
		{"tag": "lte-proxy-1", "protocol": "freedom"},
		{"tag": "direct", "protocol": "freedom"}
	],
	"routing": {
		"domainStrategy": "AsIs",
		"rules": [
			{"port": "0-65535", "balancerTag": "REG"}
		],
		"balancers": [
			{
				"tag": "REG",
				"selector": ["proxy"],
				"strategy": {"type": "leastPing"},
				"fallbackTag": "proxy-1",
				"vupenSpill": {"balancerTag": "LTE", "uplink": ["cellular"]},
				"vupenSticky": {"initial": "proxy-2"}
			},
			{
				"tag": "LTE",
				"selector": ["lte-"],
				"strategy": {
					"type": "leastLoad",
					"settings": {"expected": 2, "maxRTT": "1s", "tolerance": 0.3}
				},
				"fallbackTag": "lte-proxy-1",
				"vupenSticky": {"initial": "lte-proxy-1"}
			}
		]
	},
	"burstObservatory": {
		"subjectSelector": ["proxy", "lte-"],
		"vupenOnDemand": true,
		"pingConfig": {
			"destination": "https://www.gstatic.com/generate_204",
			"connectivity": "",
			"interval": "100s",
			"sampling": 3,
			"timeout": "5s"
		}
	}
}`

// vupenAuto41LegacyGolden is sha256 of the deterministic wire encoding of the
// core config built from vupenAuto41LegacyJSON by the fork BEFORE step 2.1
// (fork HEAD 9b9df02b8dc6, branch vupen/full-26.9.9, core 72).
//
// If this test fails, first find the cause. Recapture the hash (run the test,
// copy "got") ONLY after confirming the change comes from an upstream merge
// (e.g. a new default field in an upstream config) and not from Vupen code:
// a Vupen change that alters a config without vupen* fields is a regression.
// Note the upstream commit next to the new hash.
const vupenAuto41LegacyGolden = "0a317ab6de604d61f65f2afb5ea3c2f5dc00d084e550251e06c0591b55e93089"

const vupenAuto41Ping = `"pingConfig":{"destination":"d","interval":"100s","sampling":3,"timeout":"5s"}`

func vupenAuto41Build(t *testing.T, s string) proto.Message {
	t.Helper()
	c := new(Config)
	if err := json.Unmarshal([]byte(s), c); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	pb, err := c.Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	return pb
}

func vupenAuto41Digest(t *testing.T, m proto.Message) string {
	t.Helper()
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func vupenAuto41ParseRouter(s string) (*router.Config, error) {
	c := new(RouterConfig)
	if err := json.Unmarshal([]byte(s), c); err != nil {
		return nil, err
	}
	return c.Build()
}

func vupenAuto41ParseBurst(s string) (*burst.Config, error) {
	c := new(BurstObservatoryConfig)
	if err := json.Unmarshal([]byte(s), c); err != nil {
		return nil, err
	}
	m, err := c.Build()
	if err != nil {
		return nil, err
	}
	return m.(*burst.Config), nil
}

// A config without the new fields builds exactly the same core config as core 72.
func TestVupenAuto41LegacyConfigUnchanged(t *testing.T) {
	got := vupenAuto41Digest(t, vupenAuto41Build(t, vupenAuto41LegacyJSON))
	again := vupenAuto41Digest(t, vupenAuto41Build(t, vupenAuto41LegacyJSON))
	if got != again {
		t.Fatalf("config build is not deterministic: %s vs %s", got, again)
	}
	if got != vupenAuto41LegacyGolden {
		t.Fatalf("legacy config changed: got %s, want %s", got, vupenAuto41LegacyGolden)
	}
}

// The new fields touch nothing else: the new-shape config with the vupen
// fields cleared builds byte-for-byte the legacy (core 72) config.
func TestVupenAuto41FieldsDoNotLeak(t *testing.T) {
	cfg := vupenAuto41Build(t, vupenAuto41NewJSON).(*core.Config)
	for i, app := range cfg.App {
		inst, err := app.GetInstance()
		if err != nil {
			t.Fatal(err)
		}
		switch m := inst.(type) {
		case *router.Config:
			for _, br := range m.BalancingRule {
				br.VupenSpill, br.VupenSticky = nil, nil
			}
			cfg.App[i] = serial.ToTypedMessage(m)
		case *burst.Config:
			m.VupenOnDemand = false
			cfg.App[i] = serial.ToTypedMessage(m)
		}
	}
	if got := vupenAuto41Digest(t, cfg); got != vupenAuto41LegacyGolden {
		t.Fatalf("new fields leak into the rest of the config: got %s, want %s", got, vupenAuto41LegacyGolden)
	}
}

// The new balancer fields reach the proto exactly as written.
func TestVupenAuto41BalancerFieldsParsed(t *testing.T) {
	got, err := vupenAuto41ParseRouter(`{
		"balancers": [
			{
				"tag": "REG",
				"selector": ["proxy"],
				"strategy": {"type": "leastPing"},
				"fallbackTag": "proxy-1",
				"vupenSpill": {"balancerTag": "LTE", "uplink": ["cellular"]},
				"vupenSticky": {"initial": "proxy-7"}
			},
			{
				"tag": "LTE",
				"selector": ["lte-"],
				"fallbackTag": "lte-proxy-1",
				"vupenSticky": {"initial": "lte-proxy-2"}
			},
			{
				"tag": "S",
				"selector": ["x"],
				"vupenSpill": {"balancerTag": "B", "uplink": ["cellular", "wifi"]}
			}
		]
	}`)
	if err != nil {
		t.Fatal(err)
	}
	want := &router.Config{
		BalancingRule: []*router.BalancingRule{
			{
				Tag:              "REG",
				OutboundSelector: []string{"proxy"},
				Strategy:         "leastping",
				FallbackTag:      "proxy-1",
				VupenSpill:       &router.VupenSpill{BalancerTag: "LTE", Uplink: []string{"cellular"}},
				VupenSticky:      &router.VupenSticky{Initial: "proxy-7"},
			},
			{
				Tag:              "LTE",
				OutboundSelector: []string{"lte-"},
				Strategy:         "random",
				FallbackTag:      "lte-proxy-1",
				VupenSticky:      &router.VupenSticky{Initial: "lte-proxy-2"},
			},
			{
				Tag:              "S",
				OutboundSelector: []string{"x"},
				Strategy:         "random",
				VupenSpill:       &router.VupenSpill{BalancerTag: "B", Uplink: []string{"cellular", "wifi"}},
			},
		},
	}
	if !proto.Equal(got, want) {
		t.Fatalf("got\n%v\nwant\n%v", got, want)
	}
}

// Without the new fields every strategy type builds as before: no vupen
// message is set (nil, not an empty message). Explicit null = absent.
func TestVupenAuto41AbsentFieldsStayUnset(t *testing.T) {
	for _, typ := range []string{"", "random", "leastPing", "leastLoad", "roundRobin"} {
		got, err := vupenAuto41ParseRouter(`{"balancers":[{"tag":"b","selector":["p"],"fallbackTag":"f","strategy":{"type":"` + typ + `"}}]}`)
		if err != nil {
			t.Fatalf("%q: %v", typ, err)
		}
		if br := got.BalancingRule[0]; br.VupenSpill != nil || br.VupenSticky != nil {
			t.Fatalf("%q: vupen fields set without JSON: %v", typ, br)
		}
	}
	got, err := vupenAuto41ParseRouter(`{"balancers":[{"tag":"b","selector":["p"],"vupenSpill":null,"vupenSticky":null}]}`)
	if err != nil {
		t.Fatal(err)
	}
	if br := got.BalancingRule[0]; br.VupenSpill != nil || br.VupenSticky != nil {
		t.Fatalf("null vupen fields must stay unset: %v", br)
	}
}

// vupenOnDemand: true is carried; absent or false is false (as before).
func TestVupenAuto41BurstOnDemandParsed(t *testing.T) {
	cases := []struct {
		json string
		want bool
	}{
		{`{"subjectSelector":["proxy"],` + vupenAuto41Ping + `}`, false},
		{`{"subjectSelector":["proxy"],"vupenOnDemand":false,` + vupenAuto41Ping + `}`, false},
		{`{"subjectSelector":["proxy"],"vupenOnDemand":true,` + vupenAuto41Ping + `}`, true},
	}
	for _, c := range cases {
		got, err := vupenAuto41ParseBurst(c.json)
		if err != nil {
			t.Fatalf("%s: %v", c.json, err)
		}
		if got.GetVupenOnDemand() != c.want {
			t.Fatalf("%s: vupenOnDemand=%v, want %v", c.json, got.GetVupenOnDemand(), c.want)
		}
		if got.GetPingConfig().GetInterval() != int64(100*time.Second) || got.GetPingConfig().GetSamplingCount() != 3 {
			t.Fatalf("%s: pingConfig changed: %v", c.json, got.GetPingConfig())
		}
	}
	// pingConfig is still required, with or without the new field.
	if _, err := vupenAuto41ParseBurst(`{"subjectSelector":["proxy"],"vupenOnDemand":true}`); err == nil {
		t.Fatal("burstObservatory without pingConfig must still be rejected")
	}
}

// Values of the wrong JSON type are rejected by the parser (no silent default).
func TestVupenAuto41WrongTypesRejected(t *testing.T) {
	for _, s := range []string{
		`{"balancers":[{"tag":"b","selector":["p"],"vupenSpill":"LTE"}]}`,
		`{"balancers":[{"tag":"b","selector":["p"],"vupenSpill":{"balancerTag":1}}]}`,
		`{"balancers":[{"tag":"b","selector":["p"],"vupenSpill":{"balancerTag":"LTE","uplink":"cellular"}}]}`,
		`{"balancers":[{"tag":"b","selector":["p"],"vupenSticky":"proxy-1"}]}`,
		`{"balancers":[{"tag":"b","selector":["p"],"vupenSticky":{"initial":7}}]}`,
	} {
		if _, err := vupenAuto41ParseRouter(s); err == nil {
			t.Fatalf("expected error for %s", s)
		}
	}
	for _, s := range []string{
		`{"subjectSelector":["proxy"],"vupenOnDemand":"true",` + vupenAuto41Ping + `}`,
		`{"subjectSelector":["proxy"],"vupenOnDemand":1,` + vupenAuto41Ping + `}`,
	} {
		if _, err := vupenAuto41ParseBurst(s); err == nil {
			t.Fatalf("expected error for %s", s)
		}
	}
}

// The existing balancer checks still apply when the new fields are present,
// and the mode is a field, not a new strategy type.
func TestVupenAuto41ExistingChecksKept(t *testing.T) {
	for _, s := range []string{
		`{"balancers":[{"selector":["p"],"vupenSticky":{"initial":"x"}}]}`,
		`{"balancers":[{"tag":"b","vupenSticky":{"initial":"x"}}]}`,
		`{"balancers":[{"tag":"b","selector":["p"],"strategy":{"type":"vupenSticky"},"vupenSticky":{"initial":"x"}}]}`,
	} {
		if _, err := vupenAuto41ParseRouter(s); err == nil {
			t.Fatalf("expected error for %s", s)
		}
	}
}

// Wire round-trip of the new fields, standalone and through the core config.
func TestVupenAuto41RoundTrip(t *testing.T) {
	br := &router.BalancingRule{
		Tag:              "REG",
		OutboundSelector: []string{"proxy"},
		Strategy:         "leastping",
		FallbackTag:      "proxy-1",
		VupenSpill:       &router.VupenSpill{BalancerTag: "LTE", Uplink: []string{"cellular"}},
		VupenSticky:      &router.VupenSticky{Initial: "proxy-7"},
	}
	b, err := proto.Marshal(br)
	if err != nil {
		t.Fatal(err)
	}
	back := new(router.BalancingRule)
	if err := proto.Unmarshal(b, back); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(br, back) {
		t.Fatalf("round-trip: got %v want %v", back, br)
	}

	bc := &burst.Config{SubjectSelector: []string{"proxy"}, VupenOnDemand: true}
	b, err = proto.Marshal(bc)
	if err != nil {
		t.Fatal(err)
	}
	backC := new(burst.Config)
	if err := proto.Unmarshal(b, backC); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(bc, backC) {
		t.Fatalf("round-trip: got %v want %v", backC, bc)
	}

	// Empty objects {} are "present": they stay non-nil through JSON and the
	// wire (a set empty sub-message is encoded as a zero-length field).
	empty, err := vupenAuto41ParseRouter(`{"balancers":[{"tag":"b","selector":["p"],"vupenSpill":{},"vupenSticky":{}}]}`)
	if err != nil {
		t.Fatal(err)
	}
	if eb := empty.BalancingRule[0]; eb.VupenSpill == nil || eb.VupenSticky == nil {
		t.Fatalf("{} must parse to non-nil messages: %v", eb)
	}
	b, err = proto.Marshal(empty.BalancingRule[0])
	if err != nil {
		t.Fatal(err)
	}
	backE := new(router.BalancingRule)
	if err := proto.Unmarshal(b, backE); err != nil {
		t.Fatal(err)
	}
	if backE.VupenSpill == nil || backE.VupenSticky == nil {
		t.Fatalf("{} must stay non-nil after a wire round-trip: %v", backE)
	}
	if !proto.Equal(empty.BalancingRule[0], backE) {
		t.Fatalf("round-trip of {}: got %v want %v", backE, empty.BalancingRule[0])
	}

	cfg := vupenAuto41Build(t, vupenAuto41NewJSON).(*core.Config)
	var sawRouter, sawBurst bool
	for _, app := range cfg.App {
		inst, err := app.GetInstance()
		if err != nil {
			t.Fatal(err)
		}
		switch m := inst.(type) {
		case *router.Config:
			sawRouter = true
			reg, lte := m.BalancingRule[0], m.BalancingRule[1]
			up := reg.GetVupenSpill().GetUplink()
			if reg.GetVupenSpill().GetBalancerTag() != "LTE" || len(up) != 1 || up[0] != "cellular" ||
				reg.GetVupenSticky().GetInitial() != "proxy-2" {
				t.Fatalf("REG lost vupen fields: %v", reg)
			}
			if lte.GetVupenSpill() != nil || lte.GetVupenSticky().GetInitial() != "lte-proxy-1" {
				t.Fatalf("LTE vupen fields wrong: %v", lte)
			}
		case *burst.Config:
			sawBurst = true
			if !m.GetVupenOnDemand() {
				t.Fatal("burst config lost vupenOnDemand")
			}
		}
	}
	if !sawRouter || !sawBurst {
		t.Fatalf("router=%v burst=%v not found in core config", sawRouter, sawBurst)
	}
}
