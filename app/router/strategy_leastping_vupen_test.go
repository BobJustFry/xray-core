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
	cands := outboundList{"a", "b", "c", "d", "e", "f"}
	p := vupenLeastPingChoose("", cands, []*observatory.OutboundStatus{st("a", true, 200), st("b", true, 180)}, 6)
	if p.tag != "" || p.total != 2 {
		t.Fatalf("2 of 6 observed must not pick: %+v", p)
	}
	p = vupenLeastPingChoose("", cands, []*observatory.OutboundStatus{st("a", true, 200), st("b", true, 180), st("c", false, 0)}, 6)
	if p.tag != "b" {
		t.Fatalf("3 of 6 observed must pick: %+v", p)
	}
}
