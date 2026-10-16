package burst_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/observatory/burst"
	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/features/extension"
	"github.com/xtls/xray-core/features/routing"
)

type routeResp struct {
	V       int    `json:"v"`
	Verdict string `json:"verdict"`
	From    string `json:"from"`
	To      string `json:"to"`
	Tried   int    `json:"tried"`
	Kind    string `json:"kind"`
	Detail  string `json:"detail"`
	Closed  int    `json:"closed"`
}

func checkRoute(t *testing.T, r *router.Router, req string) routeResp {
	t.Helper()
	var resp routeResp
	if err := json.Unmarshal([]byte(r.VupenCheckRoute(req)), &resp); err != nil {
		t.Fatal(err)
	}
	return resp
}

// Ядро 78, настоящее ядро в АВТО 4.1: узел работал — check ok; узел «заморозили»
// (24 КБ встают на 16 КБ) — check failed/stall, ничего не меняя; heal — узел
// исключён, переход на проверенный, VupenAutoState это показывает.
func TestVupenCheckRouteEndToEnd(t *testing.T) {
	vupenStickySettings(t, localListener(t))
	reportUplink()
	a := newSwitchRelay(t, muxBackend(t), 16<<10)
	inst := startCore(t, autoConfig(a.port, 0, muxBackend(t)))
	obs := inst.GetFeature(extension.ObservatoryType()).(*burst.Observer)
	rt := inst.GetFeature(routing.RouterType()).(*router.Router)
	if got := pickREG(t, inst); got != "proxy-a" {
		t.Fatalf("start: %q", got)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var st struct {
			Phase string `json:"phase"`
		}
		_ = json.Unmarshal([]byte(rt.VupenAutoState()), &st)
		if st.Phase == "holding" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if resp := checkRoute(t, rt, `{"v":1,"mode":"check","reason":"foreground"}`); resp.Verdict != "ok" || resp.From != "proxy-a" {
		t.Fatalf("working node: %+v", resp)
	}

	a.frozen.Store(true)
	resp := checkRoute(t, rt, `{"v":1,"mode":"check","reason":"foreground"}`)
	if resp.Verdict != "failed" || resp.Kind != "stall" || resp.From != "proxy-a" {
		t.Fatalf("frozen node: %+v", resp)
	}
	if pickREG(t, inst) != "proxy-a" || obs.VupenStickyExcluded("proxy-a") {
		t.Fatal("check must not switch or exclude")
	}
	resp = checkRoute(t, rt, `{"v":1,"mode":"heal","reason":"foreground"}`)
	if resp.Verdict != "switched" || resp.From != "proxy-a" || resp.To != "proxy-good" {
		t.Fatalf("heal: %+v", resp)
	}
	if pickREG(t, inst) != "proxy-good" || !obs.VupenStickyExcluded("proxy-a") {
		t.Fatal("after heal new connections go via the verified node, the frozen one is excluded")
	}
	var st struct {
		Active  bool `json:"active"`
		Current struct {
			Balancer, Tag string
		} `json:"current"`
		LastSwitch struct {
			From, To, Reason string
		} `json:"lastSwitch"`
		LastCheckRoute struct {
			Mode, Verdict string
		} `json:"lastCheckRoute"`
		Notice string `json:"notice"`
	}
	if err := json.Unmarshal([]byte(rt.VupenAutoState()), &st); err != nil {
		t.Fatal(err)
	}
	if !st.Active || st.Current.Tag != "proxy-good" || st.Current.Balancer != "REG" || st.LastSwitch.From != "proxy-a" ||
		st.LastCheckRoute.Mode != "heal" || st.LastCheckRoute.Verdict != "switched" || st.Notice != "" {
		t.Fatalf("state: %+v", st)
	}
}
