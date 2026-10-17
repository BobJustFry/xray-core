package router

import (
	"context"
	"sync"
	"testing"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	routing_session "github.com/xtls/xray-core/features/routing/session"
)

// Vupen (T-079): «Apple через VPN при белых списках».

type vupenAlways struct{}

func (vupenAlways) Apply(routing.Context) bool { return true }

func appleCtx() routing.Context {
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
		Target: net.TCPDestination(net.DomainAddress("gateway.icloud.com"), 443),
	}})
	return routing_session.AsRoutingContext(ctx)
}

func setAppleViaVpn(t *testing.T, on bool) {
	t.Helper()
	prev := VupenAppleViaVpnOnLte()
	VupenSetAppleViaVpnOnLte(on)
	t.Cleanup(func() { VupenSetAppleViaVpnOnLte(prev) })
}

// appleRouter — правила как у приложения: «Apple напрямую» (с меткой или без) и
// дальше всё — в балансировщик REG.
func appleRouter(r *spillRig, ruleTag string) *Router {
	rt := routerWith(map[string]*Balancer{"REG": r.regB, "LTE": r.lteB})
	rules := []*Rule{
		{Tag: "direct", RuleTag: ruleTag, Condition: vupenAlways{}},
		{Balancer: r.regB, Condition: vupenAlways{}},
	}
	rt.rules.Store(&rules)
	return rt
}

func pickTag(t *testing.T, rt *Router) string {
	t.Helper()
	route, err := rt.PickRoute(appleCtx())
	if err != nil {
		t.Fatal(err)
	}
	return route.GetOutboundTag()
}

// spilledRig — REG мёртв, АВТО перелит в LTE (держит lte-2).
func spilledRig(t *testing.T) *spillRig {
	r := newSpillRig(t, []string{"cellular"}, []string{"p-1", "p-2", "p-3"}, []string{"lte-1", "lte-2"})
	regDeadLteAlive(r)
	r.pick()
	r.drain()
	r.pick()
	r.drain()
	if !r.reg.spilledNow() || r.pick() != "lte-2" {
		t.Fatalf("setup: spilled=%v pick=%s", r.reg.spilledNow(), r.pick())
	}
	return r
}

// Решение: настройка × мобильная группа × метка правила.
func TestVupenAppleViaVpnDecision(t *testing.T) {
	for _, c := range []struct {
		name      string
		on        bool
		spilled   bool
		uplink    string
		ruleTag   string
		wantProxy bool
	}{
		{"off, regular", false, false, "cellular", VupenAppleDirectRuleTag, false},
		{"off, LTE", false, true, "cellular", VupenAppleDirectRuleTag, false},
		{"on, regular", true, false, "cellular", VupenAppleDirectRuleTag, false},
		{"on, LTE", true, true, "cellular", VupenAppleDirectRuleTag, true},
		{"on, spilled but Wi-Fi now", true, true, "wifi", VupenAppleDirectRuleTag, false},
		{"on, LTE, rule without marker", true, true, "cellular", "", false},
		{"on, LTE, other ruleTag", true, true, "cellular", "apple", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			setAppleViaVpn(t, c.on)
			var r *spillRig
			if c.spilled {
				r = spilledRig(t)
			} else {
				r = newSpillRig(t, []string{"cellular"}, []string{"p-1"}, []string{"lte-1"})
				r.alive(map[string]int64{"p-1": 10})
				r.obs.mu.Lock()
				r.obs.verify["p-1"] = vupenStickyOK
				r.obs.mu.Unlock()
				r.pick()
				r.drain()
			}
			r.kind = c.uplink
			rt := appleRouter(r, c.ruleTag)
			got := pickTag(t, rt)
			if proxied := got != "direct"; proxied != c.wantProxy {
				t.Fatalf("route %q, want via VPN=%v", got, c.wantProxy)
			}
			st := autoState(t, rt)
			if st.AppleViaVpnOnLte != c.on || st.AppleViaVpnActive != (c.on && c.spilled && c.uplink == "cellular") {
				t.Fatalf("state: setting=%v active=%v", st.AppleViaVpnOnLte, st.AppleViaVpnActive)
			}
		})
	}
}

// Без АВТО 4.1 («Вручную», обычный балансировщик): мобильной группы нет — напрямую.
func TestVupenAppleViaVpnManualStaysDirect(t *testing.T) {
	setAppleViaVpn(t, true)
	plain := &Balancer{selectors: []string{"p"}, strategy: &LeastPingStrategy{}, ohm: &stickyFakeOhm{tags: []string{"p-1"}}}
	rt := routerWith(map[string]*Balancer{"proxy": plain})
	rules := []*Rule{
		{Tag: "direct", RuleTag: VupenAppleDirectRuleTag, Condition: vupenAlways{}},
		{Tag: "p-1", Condition: vupenAlways{}},
	}
	rt.rules.Store(&rules)
	if got := pickTag(t, rt); got != "direct" {
		t.Fatalf("manual: %q", got)
	}
}

// Переход без перезапуска: настройка включена; обычная группа — напрямую; ядро
// перелилось в LTE — новые соединения Apple через VPN; сеть сменилась (возврат) —
// снова напрямую. Правила и ядро те же.
func TestVupenAppleViaVpnFollowsTierFlip(t *testing.T) {
	setAppleViaVpn(t, true)
	r := newSpillRig(t, []string{"cellular"}, []string{"p-1", "p-2", "p-3"}, []string{"lte-1", "lte-2"})
	r.alive(map[string]int64{"p-1": 10, "lte-2": 50})
	r.obs.mu.Lock()
	r.obs.verify["p-1"] = vupenStickyOK
	r.obs.verify["lte-2"] = vupenStickyOK
	r.obs.mu.Unlock()
	r.pick()
	r.drain()
	rt := appleRouter(r, VupenAppleDirectRuleTag)
	if got := pickTag(t, rt); got != "direct" {
		t.Fatalf("regular tier: %q", got)
	}
	// Обычный узел перестал работать: проверка → поиск → перелив в LTE.
	r.alive(map[string]int64{"lte-2": 50})
	r.obs.mu.Lock()
	r.obs.check["p-1"] = vupenStickyFailed
	r.obs.mu.Unlock()
	r.reg.requestCheck("test")
	r.drain()
	r.pick()
	r.drain()
	if !r.reg.spilledNow() {
		t.Fatal("setup: not spilled")
	}
	if got := pickTag(t, rt); got != "lte-2" {
		t.Fatalf("LTE tier: Apple must go via the balancer, got %q", got)
	}
	// Сменилась сеть: вердикт «обычный мёртв» сброшен, снова обычная группа.
	r.netChanged("wifi")
	r.drain()
	if got := pickTag(t, rt); got != "direct" {
		t.Fatalf("back to regular: %q", got)
	}
	// Настройка выключена на ходу — на LTE Apple снова напрямую.
	r.kind = "cellular"
	VupenSetAppleViaVpnOnLte(false)
	if got := pickTag(t, rt); got != "direct" {
		t.Fatalf("setting off: %q", got)
	}
}

// Параллельный выбор маршрутов и переключение настройки — без гонок (-race).
func TestVupenAppleViaVpnConcurrent(t *testing.T) {
	setAppleViaVpn(t, false)
	r := spilledRig(t)
	rt := appleRouter(r, VupenAppleDirectRuleTag)
	var wg sync.WaitGroup
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				if _, err := rt.PickRoute(appleCtx()); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	for i := 0; i < 200; i++ {
		VupenSetAppleViaVpnOnLte(i%2 == 0)
	}
	wg.Wait()
}

// CR-103: решение для журнала — своё у каждого ядра: перелитое и неперелитое не
// перебивают друг друга.
func TestVupenAppleDecisionLogPerRouter(t *testing.T) {
	setAppleViaVpn(t, true)
	spilled := appleRouter(spilledRig(t), VupenAppleDirectRuleTag)
	r2 := newSpillRig(t, []string{"cellular"}, []string{"p-1"}, []string{"lte-1"})
	r2.alive(map[string]int64{"p-1": 10})
	r2.obs.mu.Lock()
	r2.obs.verify["p-1"] = vupenStickyOK
	r2.obs.mu.Unlock()
	r2.pick()
	r2.drain()
	regular := appleRouter(r2, VupenAppleDirectRuleTag)
	for i := 0; i < 3; i++ {
		if got := pickTag(t, spilled); got == "direct" {
			t.Fatalf("spilled router: %q", got)
		}
		if got := pickTag(t, regular); got != "direct" {
			t.Fatalf("regular router: %q", got)
		}
	}
	if s, g := spilled.vupenAppleLog.Load()%4, regular.vupenAppleLog.Load()%4; s != 2 || g != 1 {
		t.Fatalf("log state spilled=%d regular=%d, want 2 and 1", s, g)
	}
}
