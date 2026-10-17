package tun

import (
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
	if got := tunStats.udpQueued.Load() - base; got != 1500 || c.queued.Load() != 1500 {
		t.Fatalf("queued %d (session %d), want 1500", got, c.queued.Load())
	}
	u.Lock()
	u.removeLocked(c)
	u.Unlock()
	if got := tunStats.udpQueued.Load() - base; got != 0 || c.queued.Load() != 0 {
		t.Fatalf("after remove: queued %d (session %d), want 0", got, c.queued.Load())
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
	if got := tunStats.udpQueued.Load() - base; got != 0 || c.queued.Load() != 0 {
		t.Fatalf("queued %d after read", got)
	}
}
