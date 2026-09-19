package router

import (
	"testing"
	"time"
)

func vupenNode(tag string, avgMs int, fail, all int) *node {
	return &node{
		Tag:        tag,
		RTTAverage: time.Duration(avgMs) * time.Millisecond,
		CountFail:  fail,
		CountAll:   all,
	}
}

// Шум в замерах не должен менять узел: смена узла — это смена IP на выходе и
// разорванные сессии у приложений (бандл 2026-09-19, Telegram).
func TestVupenLeastLoadHysteresis(t *testing.T) {
	cur := vupenNode("proxy-10", 300, 0, 3)
	better := vupenNode("proxy-7", 260, 0, 3)
	qualified := []*node{better, cur}

	got := vupenLeastLoadChoose("proxy-10", qualified, []*node{better})
	if got == nil || got.Tag != "proxy-10" {
		t.Fatalf("ушли с текущего узла из-за 13%% разницы: %v", got)
	}

	// Заметно быстрее — меняем.
	much := vupenNode("proxy-7", 150, 0, 3)
	got = vupenLeastLoadChoose("proxy-10", []*node{much, cur}, []*node{much})
	if got == nil || got.Tag != "proxy-7" {
		t.Fatalf("не ушли на вдвое более быстрый узел: %v", got)
	}
}

// Текущий узел выпал из кандидатов (умер или протухли замеры) — держаться не за что.
func TestVupenLeastLoadDropsGoneCurrent(t *testing.T) {
	best := vupenNode("proxy-7", 400, 0, 3)
	got := vupenLeastLoadChoose("proxy-10", []*node{best}, []*node{best})
	if got == nil || got.Tag != "proxy-7" {
		t.Fatalf("не переключились с исчезнувшего узла: %v", got)
	}
}

// Провалы у текущего при чистом лучшем — тоже повод уйти, даже внутри гистерезиса.
func TestVupenLeastLoadLeavesFlakyCurrent(t *testing.T) {
	cur := vupenNode("proxy-10", 300, 1, 3)
	best := vupenNode("proxy-7", 290, 0, 3)
	got := vupenLeastLoadChoose("proxy-10", []*node{best, cur}, []*node{best})
	if got == nil || got.Tag != "proxy-7" {
		t.Fatalf("остались на узле с провалами: %v", got)
	}
}

// Кандидатов нет вовсе — выбирать нечего, решение принимает вызывающий (fallbackTag).
func TestVupenLeastLoadNoSelects(t *testing.T) {
	if got := vupenLeastLoadChoose("proxy-10", nil, nil); got != nil {
		t.Fatalf("на пустом наборе вернулся узел: %v", got)
	}
}

// Профиль просит распределение (expected > 1): пока текущий узел в наборе — держимся.
func TestVupenLeastLoadKeepsCurrentInsideSelects(t *testing.T) {
	a := vupenNode("proxy-1", 200, 0, 3)
	b := vupenNode("proxy-2", 210, 0, 3)
	got := vupenLeastLoadChoose("proxy-2", []*node{a, b}, []*node{a, b})
	if got == nil || got.Tag != "proxy-2" {
		t.Fatalf("ушли с узла, который сам же в наборе: %v", got)
	}
}
