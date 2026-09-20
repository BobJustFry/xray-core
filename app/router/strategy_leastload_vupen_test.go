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

// leastLoad сортирует по разбросу, а не по скорости: без отсева балансировщик
// садится на стабильный, но вдвое более медленный узел (бандл 2026-09-20).
func TestVupenLeastLoadDropsSlow(t *testing.T) {
	// Числа из того же раунда бандла: лучший 300, хвост до 956.
	nodes := []*node{
		vupenNode("proxy-4", 300, 0, 3),
		vupenNode("proxy", 325, 0, 3),
		vupenNode("proxy-19", 512, 0, 3),
		vupenNode("proxy-24", 727, 0, 3),
		vupenNode("proxy-21", 928, 0, 3),
		vupenNode("proxy-12", 956, 0, 3),
	}
	kept := vupenLeastLoadDropSlow(nodes)
	if len(kept) != 3 {
		t.Fatalf("порог 2× от 300 мс оставил %d узлов, ожидалось 3", len(kept))
	}
	for _, n := range kept {
		if n.RTTAverage > 600*time.Millisecond {
			t.Fatalf("в кандидатах остался %s на %v", n.Tag, n.RTTAverage)
		}
	}
}

// Сеть плохая у всех — отсев не должен выкашивать пул: порог относительный.
func TestVupenLeastLoadKeepsUniformlySlow(t *testing.T) {
	nodes := []*node{
		vupenNode("a", 900, 0, 3),
		vupenNode("b", 1100, 0, 3),
		vupenNode("c", 1300, 0, 3),
		vupenNode("d", 1500, 0, 3),
	}
	if got := len(vupenLeastLoadDropSlow(nodes)); got != 4 {
		t.Fatalf("на равномерно медленной сети отсеяли до %d узлов", got)
	}
}

// Ниже минимума не опускаемся: пустой пул хуже медленного узла.
func TestVupenLeastLoadKeepsMinimum(t *testing.T) {
	nodes := []*node{
		vupenNode("fast", 200, 0, 3),
		vupenNode("slow1", 900, 0, 3),
		vupenNode("slow2", 950, 0, 3),
		vupenNode("slow3", 980, 0, 3),
	}
	if got := len(vupenLeastLoadDropSlow(nodes)); got != 4 {
		t.Fatalf("отсев оставил %d узлов, минимум %d", got, VupenLeastLoadMinKeep)
	}
}

// Узел без замера судить нечем — оставляем.
func TestVupenLeastLoadKeepsUnmeasured(t *testing.T) {
	nodes := []*node{
		vupenNode("fast", 300, 0, 3),
		vupenNode("fresh", 0, 0, 0),
		vupenNode("ok", 400, 0, 3),
		vupenNode("slow", 1200, 0, 3),
	}
	kept := vupenLeastLoadDropSlow(nodes)
	var seen bool
	for _, n := range kept {
		if n.Tag == "fresh" {
			seen = true
		}
		if n.Tag == "slow" {
			t.Fatal("медленный узел остался в кандидатах")
		}
	}
	if !seen {
		t.Fatal("узел без замера выкинули")
	}
}
