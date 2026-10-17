package tun

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
)

// Vupen (T-075): потолок байт во всех очередях UDP-сессий TUN.

// stalledUDPHandler — outbound висит, пока не закрыть release; потом читает до EOF.
func stalledUDPHandler(t *testing.T, capKB int) (*udpConnectionHandler, chan struct{}) {
	t.Helper()
	prevCap, prevConns := atomic.LoadInt32(&udpQueueMaxKB), atomic.LoadInt32(&maxUDPConns)
	SetUDPQueueMaxKB(capKB)
	SetMaxUDPConns(16)
	release := make(chan struct{})
	t.Cleanup(func() {
		atomic.StoreInt32(&udpQueueMaxKB, prevCap)
		atomic.StoreInt32(&maxUDPConns, prevConns)
	})
	u := newUdpConnectionHandler(func(conn net.Conn, dest net.Destination) {
		defer conn.Close()
		<-release
		c := conn.(*udpConn)
		for {
			if _, err := c.ReadMultiBuffer(); err != nil {
				return
			}
		}
	}, func(data []byte, src net.Destination, dst net.Destination) error { return nil })
	return u, release
}

// settledQueued — общий счётчик после того, как читатели прошлых тестов
// дочитали свои очереди (счётчик на пакет общий).
func settledQueued() int64 {
	last := tunStats.udpQueued.Load()
	for i := 0; i < 100; i++ {
		time.Sleep(20 * time.Millisecond)
		v := tunStats.udpQueued.Load()
		if v == last {
			return v
		}
		last = v
	}
	return last
}

func waitQueued(t *testing.T, want int64) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for tunStats.udpQueued.Load() != want && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := tunStats.udpQueued.Load(); got != want {
		t.Fatalf("queued %d bytes, want %d", got, want)
	}
}

// Зависший outbound: очередь растёт до потолка байт, дальше пакеты отбрасываются;
// outbound ожил и прочитал — байты вернулись в потолок.
func TestUDPQueueBytesCap(t *testing.T) {
	base := settledQueued()
	drops := tunStats.udpQueueDrops.Load()
	u, release := stalledUDPHandler(t, 2) // 2048 байт на все очереди
	pkt := make([]byte, 500)
	for i := 0; i < 6; i++ {
		u.HandlePacket(testSrc(1), testDst(443), pkt)
	}
	if got := tunStats.udpQueued.Load() - base; got != 2000 {
		t.Fatalf("queued %d, want 2000 (4 packets)", got)
	}
	if d := tunStats.udpQueueDrops.Load() - drops; d != 2 {
		t.Fatalf("drops %d, want 2", d)
	}
	// Потолок общий: вторая сессия тоже упирается в него.
	u.HandlePacket(testSrc(2), testDst(443), pkt)
	if d := tunStats.udpQueueDrops.Load() - drops; d != 3 {
		t.Fatalf("the cap is shared by sessions: drops %d, want 3", d)
	}
	close(release)
	waitQueued(t, base)
	// Место вернулось: снова принимаем.
	u.HandlePacket(testSrc(1), testDst(443), pkt)
	waitQueued(t, base) // прочитан сразу
	if d := tunStats.udpQueueDrops.Load() - drops; d != 3 {
		t.Fatalf("no new drops after release: %d", d)
	}
}

// Сессию убрали, а outbound её очередь не дочитал (закончил, вытеснена, DNS) —
// байты возвращаются в потолок сразу.
func TestUDPQueueBytesReleasedOnRemove(t *testing.T) {
	base := settledQueued()
	u, release := stalledUDPHandler(t, 1024)
	defer close(release)
	pkt := make([]byte, 300)
	for i := 0; i < 5; i++ {
		u.HandlePacket(testSrc(7), testDst(53), pkt)
	}
	c := u.testConn(testSrc(7))
	if got := tunStats.udpQueued.Load() - base; got != 1500 {
		t.Fatalf("queued %d, want 1500", got)
	}
	u.Lock()
	u.removeLocked(c)
	u.Unlock()
	if got := tunStats.udpQueued.Load() - base; got != 0 {
		t.Fatalf("after remove: queued %d, want 0", got)
	}
	if u.testLen() != 0 {
		t.Fatal("session not removed")
	}
}

// Пакеты, прочитанные через Read (не ReadMultiBuffer), тоже освобождают место.
func TestUDPQueueBytesReleasedOnRead(t *testing.T) {
	base := settledQueued()
	prev := atomic.LoadInt32(&udpQueueMaxKB)
	t.Cleanup(func() { atomic.StoreInt32(&udpQueueMaxKB, prev) })
	SetUDPQueueMaxKB(64)
	c := &udpConn{egress: make(chan *packet, 4)}
	if !c.enqueue(&packet{data: make([]byte, 100)}) {
		t.Fatal("enqueue")
	}
	b := make([]byte, 200)
	if n, err := c.Read(b); err != nil || n != 100 {
		t.Fatalf("read %d %v", n, err)
	}
	if got := tunStats.udpQueued.Load() - base; got != 0 {
		t.Fatalf("queued %d after read", got)
	}
}

// CR-002: стек TUN закрывается — все сессии убраны, байты их очередей вернулись.
func TestUDPQueueBytesReleasedOnCloseAll(t *testing.T) {
	base := settledQueued()
	u, release := stalledUDPHandler(t, 1024)
	defer close(release)
	pkt := make([]byte, 200)
	for p := uint16(1); p <= 5; p++ {
		for i := 0; i < 3; i++ {
			u.HandlePacket(testSrc(p), testDst(443), pkt)
		}
	}
	if got := tunStats.udpQueued.Load() - base; got != 3000 || u.testLen() != 5 {
		t.Fatalf("setup: queued %d, sessions %d", got, u.testLen())
	}
	u.closeAll()
	if got := tunStats.udpQueued.Load() - base; got != 0 || u.testLen() != 0 {
		t.Fatalf("after closeAll: queued %d, sessions %d", got, u.testLen())
	}
}

// CR-005: запись и чтение параллельно (горутины TUN и outbound-ов) — счётчик
// сходится к исходному, без гонок (-race).
func TestUDPQueueBytesParallel(t *testing.T) {
	base := settledQueued()
	prevCap, prevConns := atomic.LoadInt32(&udpQueueMaxKB), atomic.LoadInt32(&maxUDPConns)
	t.Cleanup(func() {
		atomic.StoreInt32(&udpQueueMaxKB, prevCap)
		atomic.StoreInt32(&maxUDPConns, prevConns)
	})
	SetUDPQueueMaxKB(64)
	SetMaxUDPConns(64)
	u := newUdpConnectionHandler(func(conn net.Conn, dest net.Destination) {
		defer conn.Close()
		c := conn.(*udpConn)
		for {
			if _, err := c.ReadMultiBuffer(); err != nil {
				return
			}
		}
	}, func(data []byte, src net.Destination, dst net.Destination) error { return nil })
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			pkt := make([]byte, 700)
			for i := 0; i < 2000; i++ {
				u.HandlePacket(testSrc(uint16(100+w%4)), testDst(443), pkt)
			}
		}(w)
	}
	wg.Wait()
	u.closeAll()
	waitQueued(t, base)
}
