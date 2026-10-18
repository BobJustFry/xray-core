package router

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	routing_session "github.com/xtls/xray-core/features/routing/session"
)

// Vupen (T-079, T-084): «Apple через VPN при белых списках», режимы 0/1/2.

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
	mode := VupenAppleModeOff
	if on {
		mode = VupenAppleModeOnLte
	}
	setAppleMode(t, mode)
}

func setAppleMode(t *testing.T, mode int) {
	t.Helper()
	prev := VupenAppleViaVpnMode()
	VupenSetAppleViaVpnMode(mode)
	t.Cleanup(func() { VupenSetAppleViaVpnMode(prev) })
}

// regularRig — АВТО 4.1 в обычной группе (держит p-1).
func regularRig(t *testing.T) *spillRig {
	r := newSpillRig(t, []string{"cellular"}, []string{"p-1"}, []string{"lte-1"})
	r.alive(map[string]int64{"p-1": 10})
	r.obs.mu.Lock()
	r.obs.verify["p-1"] = vupenStickyOK
	r.obs.mu.Unlock()
	r.pick()
	r.drain()
	return r
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

// Решение (T-084): режим × группа АВТО × сеть × метка правила.
func TestVupenAppleViaVpnDecision(t *testing.T) {
	for _, mode := range []int{VupenAppleModeOff, VupenAppleModeOnLte, VupenAppleModeAlways} {
		for _, spilled := range []bool{false, true} {
			for _, uplink := range []string{"cellular", "wifi"} {
				for _, ruleTag := range []string{VupenAppleDirectRuleTag, "", "apple"} {
					onLte := spilled && uplink == "cellular"
					active := mode == VupenAppleModeAlways || (mode == VupenAppleModeOnLte && onLte)
					wantProxy := active && ruleTag == VupenAppleDirectRuleTag
					name := fmt.Sprintf("mode=%d spilled=%v %s rule=%q", mode, spilled, uplink, ruleTag)
					t.Run(name, func(t *testing.T) {
						setAppleMode(t, mode)
						var r *spillRig
						if spilled {
							r = spilledRig(t)
						} else {
							r = regularRig(t)
						}
						r.kind = uplink
						rt := appleRouter(r, ruleTag)
						got := pickTag(t, rt)
						if proxied := got != "direct"; proxied != wantProxy {
							t.Fatalf("route %q, want via VPN=%v", got, wantProxy)
						}
						st := autoState(t, rt)
						if st.AppleViaVpnMode != mode || st.AppleViaVpnOnLte != (mode != VupenAppleModeOff) || st.AppleViaVpnActive != active {
							t.Fatalf("state: mode=%d onLte=%v active=%v", st.AppleViaVpnMode, st.AppleViaVpnOnLte, st.AppleViaVpnActive)
						}
					})
				}
			}
		}
	}
}

// T-084: прежний вызов — синоним режимов 1/0; неверный режим ничего не меняет.
func TestVupenAppleViaVpnModeAPI(t *testing.T) {
	setAppleMode(t, VupenAppleModeOff)
	if !VupenSetAppleViaVpnOnLte(true) || VupenAppleViaVpnMode() != VupenAppleModeOnLte || !VupenAppleViaVpnOnLte() {
		t.Fatal("alias true must set mode 1")
	}
	if VupenSetAppleViaVpnOnLte(true) {
		t.Fatal("same value must report no change")
	}
	if !VupenSetAppleViaVpnMode(VupenAppleModeAlways) || !VupenAppleViaVpnOnLte() {
		t.Fatal("mode 2")
	}
	gen := vupenAppleGen.Load()
	for _, bad := range []int{-1, 3, 100} {
		if VupenSetAppleViaVpnMode(bad) || VupenAppleViaVpnMode() != VupenAppleModeAlways {
			t.Fatalf("invalid mode %d changed the setting", bad)
		}
	}
	if vupenAppleGen.Load() != gen {
		t.Fatal("invalid mode bumped the generation")
	}
	if !VupenSetAppleViaVpnOnLte(false) || VupenAppleViaVpnMode() != VupenAppleModeOff || VupenAppleViaVpnOnLte() {
		t.Fatal("alias false must set mode 0")
	}
}

// Без АВТО 4.1 («Вручную», обычный балансировщик): мобильной группы нет — в
// режиме 1 напрямую; в режиме 2 (вручную выбран узел мобильной группы) — через VPN.
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
	VupenSetAppleViaVpnMode(VupenAppleModeAlways)
	if got := pickTag(t, rt); got != "p-1" {
		t.Fatalf("manual whitelist node, mode 2: %q", got)
	}
	if st := autoState(t, rt); !st.AppleViaVpnActive || st.AppleViaVpnMode != VupenAppleModeAlways {
		t.Fatalf("state: %+v", st)
	}
	VupenSetAppleViaVpnMode(VupenAppleModeOff)
	if got := pickTag(t, rt); got != "direct" {
		t.Fatalf("mode 0: %q", got)
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
	for i := 0; i < 300; i++ {
		VupenSetAppleViaVpnMode(i % 3)
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
	// Режим 2: обоим — через VPN; состояние журнала нового поколения настройки.
	VupenSetAppleViaVpnMode(VupenAppleModeAlways)
	gen := vupenAppleGen.Load()
	for _, rt := range []*Router{spilled, regular} {
		if got := pickTag(t, rt); got == "direct" {
			t.Fatalf("mode 2: %q", got)
		}
		if v := rt.vupenAppleLog.Load(); v != gen*4+2 {
			t.Fatalf("log state %d, want %d", v, gen*4+2)
		}
	}
}
