package router_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	routing_session "github.com/xtls/xray-core/features/routing/session"
	"github.com/xtls/xray-core/infra/conf"
)

// Vupen (T-079): куда попадает Apple на реальной маршрутизации панели, когда
// правило «Apple напрямую» пропущено (настройка включена, АВТО перелит в LTE).
// Профиль панели в репозиторий не кладём: путь к сохранённому ответу подписки —
// в VUPEN_PROFILE_JSON (поле body — JSON-список конфигов), иначе тест пропускается.
// Само решение «пропустить правило» проверяют тесты в tuning_vupen_apple_test.go;
// здесь — что ниже по реальным правилам Apple не уходит снова напрямую.

// appleDirectRuleJSON — правило, которое ставит приложение первым
// (xray_config_builder.dart _prependAppleDirectRules), с меткой T-079.
const appleDirectRuleJSON = `{"type":"field","ruleTag":"vupen-apple-direct","outboundTag":"direct","domain":[
"domain:apple.com","domain:icloud.com","domain:icloud-content.com","domain:apple-dns.net","domain:cdn-apple.com",
"domain:mzstatic.com","domain:me.com","domain:apple-cloudkit.com","domain:apple-mapkit.com"]}`

type profileRule struct {
	idx     int
	ruleTag string
	target  string
	cond    router.Condition
}

func loadProfileRules(t *testing.T, routing json.RawMessage) []profileRule {
	t.Helper()
	var rc conf.RouterConfig
	if err := json.Unmarshal(routing, &rc); err != nil {
		t.Fatal(err)
	}
	rc.RuleList = append([]json.RawMessage{json.RawMessage(appleDirectRuleJSON)}, rc.RuleList...)
	rc.Balancers = nil // балансировщики для порядка правил не нужны
	cfg, err := rc.Build()
	if err != nil {
		t.Fatal(err)
	}
	var out []profileRule
	for i, rr := range cfg.Rule {
		cond, err := rr.BuildCondition()
		if err != nil {
			t.Fatal(err)
		}
		target := rr.GetTag()
		if b := rr.GetBalancingTag(); b != "" {
			target = "balancer:" + b
		}
		out = append(out, profileRule{idx: i, ruleTag: rr.RuleTag, target: target, cond: cond})
	}
	return out
}

// land — первое подходящее правило; skipMarked — правило Apple пропущено.
func land(rules []profileRule, domain string, ip net.IP, skipMarked bool) string {
	ob := &session.Outbound{
		Target:      net.TCPDestination(net.IPAddress(ip), 443),
		RouteTarget: net.TCPDestination(net.DomainAddress(domain), 443), // sniff routeOnly
	}
	ctx := routing_session.AsRoutingContext(session.ContextWithOutbounds(context.Background(), []*session.Outbound{ob}))
	for _, r := range rules {
		if skipMarked && r.ruleTag == router.VupenAppleDirectRuleTag {
			continue
		}
		if r.cond.Apply(ctx) {
			return fmt.Sprintf("#%d %s", r.idx, r.target)
		}
	}
	return "no rule"
}

func TestVupenAppleOnRealPanelRouting(t *testing.T) {
	path := os.Getenv("VUPEN_PROFILE_JSON")
	if path == "" {
		t.Skip("VUPEN_PROFILE_JSON not set (saved subscription response)")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var resp struct {
		Body string `json:"body"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatal(err)
	}
	var configs []struct {
		Remarks string `json:"remarks"`
		Routing struct {
			Balancers []struct {
				Tag string `json:"tag"`
			} `json:"balancers"`
		} `json:"routing"`
	}
	var rawConfigs []json.RawMessage
	if err := json.Unmarshal([]byte(resp.Body), &configs); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(resp.Body), &rawConfigs); err != nil {
		t.Fatal(err)
	}
	picked := map[string]int{}
	for i, c := range configs {
		auto := false
		for _, b := range c.Routing.Balancers {
			auto = auto || b.Tag == "BEST"
		}
		if !auto {
			continue
		}
		kind := "regular"
		if strings.Contains(c.Remarks, "LTE") {
			kind = "lte"
		}
		if _, ok := picked[kind]; !ok {
			picked[kind] = i
		}
	}
	if len(picked) != 2 {
		t.Fatalf("AUTO configs found: %v", picked)
	}
	apple4 := net.ParseIP("17.253.144.10")    // 17.0.0.0/8 (Apple)
	apple6 := net.ParseIP("2620:149:a44::10") // 2620:149::/32 (Apple)
	for _, kind := range []string{"regular", "lte"} {
		var cfg struct {
			Routing json.RawMessage `json:"routing"`
		}
		if err := json.Unmarshal(rawConfigs[picked[kind]], &cfg); err != nil {
			t.Fatal(err)
		}
		rules := loadProfileRules(t, cfg.Routing)
		for _, domain := range []string{"gateway.icloud.com", "apple.com", "itunes.apple.com", "is1-ssl.mzstatic.com"} {
			for _, ip := range []net.IP{apple4, apple6} {
				before := land(rules, domain, ip, false)
				after := land(rules, domain, ip, true)
				t.Logf("%-7s %-22s %-18s setting off: %-22s on+LTE: %s", kind, domain, ip, before, after)
				if !strings.HasSuffix(before, " direct") {
					t.Errorf("%s %s %s: without the setting Apple must go direct, got %s", kind, domain, ip, before)
				}
				if strings.HasSuffix(after, " direct") {
					t.Errorf("%s %s %s: a later rule still sends Apple direct: %s", kind, domain, ip, after)
				}
			}
		}
	}
}
