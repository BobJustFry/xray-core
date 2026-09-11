package router

import (
	"testing"

	"github.com/xtls/xray-core/app/observatory"
)

func st(tag string, alive bool, delay int64) *observatory.OutboundStatus {
	return &observatory.OutboundStatus{OutboundTag: tag, Alive: alive, Delay: delay}
}

func TestVupenLeastPingHysteresis(t *testing.T) {
	cands := outboundList{"a", "b", "c"}
	// первый выбор — просто минимум
	p := vupenLeastPingChoose("", cands, []*observatory.OutboundStatus{st("a", true, 200), st("b", true, 180), st("c", true, 300)}, 3)
	if p.tag != "b" {
		t.Fatalf("first pick %q", p.tag)
	}
	// новый лучше на 10 % — остаёмся
	p = vupenLeastPingChoose("b", cands, []*observatory.OutboundStatus{st("a", true, 165), st("b", true, 180), st("c", true, 300)}, 3)
	if p.tag != "b" || p.delay != 180 {
		t.Fatalf("10%% better must not switch: %+v", p)
	}
	// новый лучше на 25 % — переключаемся
	p = vupenLeastPingChoose("b", cands, []*observatory.OutboundStatus{st("a", true, 130), st("b", true, 180), st("c", true, 300)}, 3)
	if p.tag != "a" {
		t.Fatalf("25%% better must switch: %+v", p)
	}
	// текущий умер — переключаемся на лучшего
	p = vupenLeastPingChoose("b", cands, []*observatory.OutboundStatus{st("a", true, 300), st("b", false, 180), st("c", true, 310)}, 3)
	if p.tag != "a" {
		t.Fatalf("dead current must switch: %+v", p)
	}
}

func TestVupenLeastPingMinObserved(t *testing.T) {
	cands := outboundList{"a", "b", "c", "d", "e", "f", "g", "h"}
	// 1 из 8 (12 %) и один живой — рано.
	p := vupenLeastPingChoose("", cands, []*observatory.OutboundStatus{st("a", true, 200)}, 8)
	if p.tag != "" || p.total != 1 {
		t.Fatalf("1 of 8 observed must not pick: %+v", p)
	}
	// 2 из 8 (25 %) — порог покрытия достигнут, выбираем.
	p = vupenLeastPingChoose("", cands, []*observatory.OutboundStatus{st("a", true, 200), st("b", true, 180)}, 8)
	if p.tag != "b" {
		t.Fatalf("2 of 8 observed must pick by coverage: %+v", p)
	}
}

func TestVupenLeastPingMinAlive(t *testing.T) {
	// 27 кандидатов, как у балансировщика панели: три живых замера из 27 (11 %)
	// ниже доли покрытия, но три живых узла — уже выбор, а не fallback.
	cands := make(outboundList, 0, 27)
	for i := 0; i < 27; i++ {
		cands = append(cands, string(rune('a'+i)))
	}
	p := vupenLeastPingChoose("", cands, []*observatory.OutboundStatus{st("a", true, 300), st("b", true, 180), st("c", true, 250)}, 27)
	if p.tag != "b" || p.alive != 3 {
		t.Fatalf("3 alive of 27 must pick: %+v", p)
	}
	// Два живых и один мёртвый — живых меньше порога, покрытие 11 % — рано.
	p = vupenLeastPingChoose("", cands, []*observatory.OutboundStatus{st("a", true, 300), st("b", true, 180), st("c", false, 0)}, 27)
	if p.tag != "" {
		t.Fatalf("2 alive of 27 must wait: %+v", p)
	}
}
