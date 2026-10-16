package internet

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
)

// closeConn — соединение, у которого вызывается только Close; block — Close
// висит, пока канал не закрыт (как Close за синхронным WSARecv на Windows).
type closeConn struct {
	net.Conn
	closed atomic.Bool
	block  chan struct{}
}

func (c *closeConn) Close() error {
	if c.block != nil {
		<-c.block
	}
	c.closed.Store(true)
	return nil
}

// putEntry — запись реестра эпохи с готовым соединением (для сценариев без сокетов).
func putEntry(id vupenNetID, tag string, c net.Conn) {
	vupenNet.mu.Lock()
	key := vupenNetEntrySeq.Add(1)
	idx := &struct{ k uint64 }{key}
	vupenNet.entries[key] = &vupenNetEntry{id: id, get: func() net.Conn { return c }, idx: idx, tag: tag}
	vupenNet.index[idx] = key
	vupenNet.mu.Unlock()
}

// Ядро 78: чистка прежней сети закрывает соединения параллельно — один
// зависший Close не держит остальные и сам отсчёт эпохи.
func TestVupenNetSweepStuckCloseDoesNotHoldOthers(t *testing.T) {
	clock := netEpochTest(t)
	oldPar, oldWait := VupenNetCloseParallel, VupenNetCloseWait
	VupenNetCloseParallel, VupenNetCloseWait = 4, 200*time.Millisecond
	t.Cleanup(func() { VupenNetCloseParallel, VupenNetCloseWait = oldPar, oldWait })

	VupenSetUplink("wifi", "wifi-a")
	old := vupenNetID{kind: "wifi", sig: "wifi-a"}
	stuck := &closeConn{block: make(chan struct{})}
	t.Cleanup(func() { close(stuck.block) })
	putEntry(old, "proxy-1", stuck)
	var others []*closeConn
	for i := 0; i < 20; i++ {
		c := &closeConn{}
		others = append(others, c)
		putEntry(old, "proxy-2", c)
	}
	VupenSetUplink("cellular", "cell-a")
	done := make(chan struct{})
	go func() {
		clock.Advance(time.Duration(VupenNetChangeCloseStableSec) * time.Second)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("one blocked Close held the whole sweep")
	}
	for i, c := range others {
		if !c.closed.Load() {
			t.Fatalf("connection %d was not closed behind the stuck one", i)
		}
	}
	if lc := VupenNetState().LastClose; lc == nil || lc.Reason != "net-change" || lc.Conns != 21 {
		t.Fatalf("last close: %+v", lc)
	}
}

// Ядро 78 (VupenCheckRoute heal): закрыть сразу соединения одного узла — и
// только его.
func TestVupenCloseConnsNow(t *testing.T) {
	netEpochTest(t)
	VupenSetUplink("cellular", "cell-a")
	tcp := tcpServer(t)
	udp := udpServer(t)
	a1 := dial(t, auto41Ctx("proxy-4"), tcp)
	a2 := dial(t, auto41Ctx("proxy-4"), udp)
	b := dial(t, auto41Ctx("proxy-5"), tcp)
	if n := VupenCloseConnsNow(nil, "proxy-4"); n != 2 {
		t.Fatalf("closed %d, want 2", n)
	}
	if !isClosed(a1) || isClosed(b) {
		t.Fatalf("proxy-4 tcp closed=%v, proxy-5 closed=%v", isClosed(a1), isClosed(b))
	}
	_ = a2
	if netEntries() != 1 {
		t.Fatalf("closed connections must leave the registry: %d entries", netEntries())
	}
	if lc := VupenNetState().LastClose; lc == nil || lc.Reason != "check-route" || lc.Conns != 2 {
		t.Fatalf("last close: %+v", lc)
	}
	if VupenCloseConnsNow(nil, "") != 0 {
		t.Fatal("empty tag closes nothing")
	}
}

// CR-701: закрытие соединений узла (heal) — не смена сети: VupenNetClosing не
// рассылается (иначе окно проб обсерватории скроет провалы поиска heal).
func TestVupenCloseConnsNowDoesNotAnnounceClosing(t *testing.T) {
	netEpochTest(t)
	VupenSetUplink("cellular", "cell-a")
	c := &closeConn{}
	putEntry(vupenNetID{kind: "cellular", sig: "cell-a"}, "proxy-4", c)
	var events []VupenNetEvent
	unsub := VupenNetEpochSubscribe(func(ev VupenNetEvent) { events = append(events, ev) })
	t.Cleanup(unsub)
	if n := VupenCloseConnsNow(nil, "proxy-4"); n != 1 || !c.closed.Load() {
		t.Fatalf("closed %d", n)
	}
	if len(events) != 0 {
		t.Fatalf("closing one node's connections must not send epoch events: %v", events)
	}
}

// Соединения сторожа заморозки закрываются только своего ключа (экземпляра).
func TestVupenCloseConnsNowFreezeWatchKey(t *testing.T) {
	netEpochTest(t)
	mine, other := new(int), new(int)
	c1 := &vupenFreezeConn{Conn: &closeConn{}, key: mine, tag: "proxy-4"}
	c2 := &vupenFreezeConn{Conn: &closeConn{}, key: other, tag: "proxy-4"}
	c1.lastActive.Store(time.Now().UnixNano())
	c2.lastActive.Store(time.Now().UnixNano())
	w := vupenFreezeWatch
	w.mu.Lock()
	w.conns[c1], w.conns[c2] = struct{}{}, struct{}{}
	w.mu.Unlock()
	t.Cleanup(func() {
		w.mu.Lock()
		delete(w.conns, c1)
		delete(w.conns, c2)
		w.mu.Unlock()
	})
	if n := VupenCloseConnsNow(mine, "proxy-4"); n != 1 {
		t.Fatalf("closed %d, want 1", n)
	}
	if !c1.Conn.(*closeConn).closed.Load() || c2.Conn.(*closeConn).closed.Load() {
		t.Fatal("only the connections of this instance's observatory are closed")
	}
}

// VupenSetUplink сообщает, была ли смена: так burst взводит окно проб на
// каждой смене, включая мигания (CR-105).
func TestVupenSetUplinkReportsChange(t *testing.T) {
	netEpochTest(t)
	steps := []struct {
		kind, sig string
		want      bool
	}{
		{"wifi", "wifi-a", false}, // первое сообщение — не смена
		{"wifi", "wifi-a", false},
		{"wifi", "", true}, // пустая подпись = тип: другая подпись
		{"cellular", "cell-a", true},
		{"wifi", "wifi-a", true}, // мигание назад — тоже смена
		{"wifi", "wifi-a", false},
	}
	for i, s := range steps {
		if got := VupenSetUplink(s.kind, s.sig); got != s.want {
			t.Fatalf("step %d %s/%s: changed=%v, want %v", i, s.kind, s.sig, got, s.want)
		}
	}
}

// Снимок эпохи: тип, подпись, ждущее закрытие и сколько соединений оно закроет.
func TestVupenNetStateSnapshot(t *testing.T) {
	clock := netEpochTest(t)
	if VupenNetState().Active {
		t.Fatal("before VupenSetUplink the epoch is inactive")
	}
	dest := tcpServer(t)
	VupenSetUplink("wifi", "wifi-a")
	dial(t, auto41Ctx("proxy-1"), dest)
	dial(t, auto41Ctx("lte-1"), dest)
	clock.Advance(4 * time.Second)
	VupenSetUplink("cellular", "cell-a")
	clock.Advance(2 * time.Second)
	st := VupenNetState()
	if !st.Active || st.Kind != "cellular" || st.Sig != "cell-a" || st.StableFor != 2*time.Second {
		t.Fatalf("state: %+v", st)
	}
	if st.Pending == nil || st.Pending.Reason != "net-change" || st.Pending.Conns != 2 ||
		!st.Pending.At.Equal(clock.Now().Add(7*time.Second)) {
		t.Fatalf("pending: %+v", st.Pending)
	}
	clock.Advance(7 * time.Second)
	st = VupenNetState()
	if st.Pending != nil || st.LastClose == nil || st.LastClose.Conns != 2 {
		t.Fatalf("after the sweep: pending=%+v last=%+v", st.Pending, st.LastClose)
	}
}

// CR-105: подписчики узнают о закрытии ДО него (burst взводит окно проб, чтобы
// упавшие вместе с соединениями пробы не записались узлу).
func TestVupenNetClosingBeforeClose(t *testing.T) {
	clock := netEpochTest(t)
	VupenSetUplink("wifi", "wifi-a")
	c := &closeConn{}
	putEntry(vupenNetID{kind: "wifi", sig: "wifi-a"}, "proxy-1", c)
	var events []VupenNetEvent
	var openAtClosing bool
	unsub := VupenNetEpochSubscribe(func(ev VupenNetEvent) {
		events = append(events, ev)
		if ev == VupenNetClosing {
			openAtClosing = !c.closed.Load()
		}
	})
	t.Cleanup(unsub)
	VupenSetUplink("cellular", "cell-a")
	clock.Advance(time.Duration(VupenNetChangeCloseStableSec) * time.Second)
	if !openAtClosing || !c.closed.Load() {
		t.Fatalf("closing event must come before the close: open at event=%v closed=%v", openAtClosing, c.closed.Load())
	}
	if len(events) != 3 || events[0] != VupenNetChanged || events[1] != VupenNetClosing || events[2] != VupenNetStable {
		t.Fatalf("events: %v", events)
	}
}
