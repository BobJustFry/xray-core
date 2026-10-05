package tun

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
)

// newTestUDPHandler — таблица с outbound-заглушкой: читает очередь сессии до EOF
// и закрывает её, как HandleConnection.
func newTestUDPHandler(t *testing.T, maxConns int) *udpConnectionHandler {
	t.Helper()
	prev := atomic.LoadInt32(&maxUDPConns)
	SetMaxUDPConns(maxConns)
	t.Cleanup(func() { atomic.StoreInt32(&maxUDPConns, prev) })
	return newUdpConnectionHandler(func(conn net.Conn, dest net.Destination) {
		defer conn.Close()
		c := conn.(*udpConn)
		for {
			if _, err := c.ReadMultiBuffer(); err != nil {
				return
			}
		}
	}, func(data []byte, src net.Destination, dst net.Destination) error { return nil })
}

func testSrc(port uint16) net.Destination {
	return net.UDPDestination(net.IPAddress([]byte{10, 0, 0, 2}), net.Port(port))
}

func testDst(port uint16) net.Destination {
	return net.UDPDestination(net.IPAddress([]byte{1, 1, 1, 1}), net.Port(port))
}

func (u *udpConnectionHandler) testConn(src net.Destination) *udpConn {
	u.RLock()
	defer u.RUnlock()
	return u.udpConns[src]
}

func (u *udpConnectionHandler) testLen() int {
	u.RLock()
	defer u.RUnlock()
	return len(u.udpConns)
}

func (u *udpConnectionHandler) testAge(src net.Destination, age time.Duration) {
	u.testConn(src).lastActive.Store(time.Now().Add(-age).UnixNano())
}

func TestUDPFullTableEvictsIdlest(t *testing.T) {
	u := newTestUDPHandler(t, 3)
	for p := uint16(1); p <= 3; p++ {
		u.HandlePacket(testSrc(p), testDst(443), []byte{1})
	}
	u.testAge(testSrc(1), 30*time.Second)
	u.testAge(testSrc(2), 60*time.Second) // самая давно молчащая
	u.testAge(testSrc(3), 20*time.Second)
	evicted := tunStats.udpEvicted.Load()

	u.HandlePacket(testSrc(4), testDst(443), []byte{1})

	if u.testConn(testSrc(4)) == nil {
		t.Fatal("new session was not admitted into the full table")
	}
	if u.testConn(testSrc(2)) != nil {
		t.Fatal("the idlest session was not evicted")
	}
	if u.testConn(testSrc(1)) == nil || u.testConn(testSrc(3)) == nil {
		t.Fatal("a session other than the idlest was evicted")
	}
	if got := tunStats.udpEvicted.Load() - evicted; got != 1 {
		t.Fatalf("udpEvicted grew by %d, want 1", got)
	}
}

func TestUDPFullTableOfLiveTrafficDrops(t *testing.T) {
	u := newTestUDPHandler(t, 2)
	u.HandlePacket(testSrc(1), testDst(443), []byte{1})
	u.HandlePacket(testSrc(2), testDst(443), []byte{1})
	drops := tunStats.udpCapDrops.Load()

	u.HandlePacket(testSrc(3), testDst(443), []byte{1})

	if u.testConn(testSrc(3)) != nil {
		t.Fatal("a session was admitted by evicting live traffic")
	}
	if u.testLen() != 2 {
		t.Fatalf("table has %d sessions, want 2", u.testLen())
	}
	if got := tunStats.udpCapDrops.Load() - drops; got != 1 {
		t.Fatalf("udpCapDrops grew by %d, want 1", got)
	}
}

func TestUDPEvictedSessionCloseKeepsItsSuccessor(t *testing.T) {
	u := newTestUDPHandler(t, 1)
	u.HandlePacket(testSrc(1), testDst(53), []byte{1})
	old := u.testConn(testSrc(1))

	u.Lock()
	u.removeLocked(old)
	u.Unlock()
	u.HandlePacket(testSrc(1), testDst(53), []byte{2})
	successor := u.testConn(testSrc(1))
	if successor == nil || successor == old {
		t.Fatal("no new session under the same source")
	}

	old.Close() // запоздалое закрытие вытесненной сессии

	if u.testConn(testSrc(1)) != successor {
		t.Fatal("closing the evicted session removed its successor")
	}
}

func TestUDPDNSReaper(t *testing.T) {
	u := newTestUDPHandler(t, 16)
	u.HandlePacket(testSrc(1), testDst(53), []byte{1})  // DNS, замолчит
	u.HandlePacket(testSrc(2), testDst(53), []byte{1})  // DNS, свежая
	u.HandlePacket(testSrc(3), testDst(443), []byte{1}) // не DNS, тоже молчит
	u.testAge(testSrc(1), udpDNSIdle+time.Second)
	u.testAge(testSrc(3), time.Minute)
	reaped := tunStats.udpDNSReaped.Load()

	if !u.reapDNSOnce(time.Now()) {
		t.Fatal("reaper stopped while a DNS session is still open")
	}
	if u.testConn(testSrc(1)) != nil {
		t.Fatal("idle DNS session was not reaped")
	}
	if u.testConn(testSrc(2)) == nil {
		t.Fatal("fresh DNS session was reaped")
	}
	if u.testConn(testSrc(3)) == nil {
		t.Fatal("non-DNS session was reaped by the DNS reaper")
	}
	if got := tunStats.udpDNSReaped.Load() - reaped; got != 1 {
		t.Fatalf("udpDNSReaped grew by %d, want 1", got)
	}

	u.testAge(testSrc(2), udpDNSIdle)
	if u.reapDNSOnce(time.Now()) {
		t.Fatal("reaper keeps running with no DNS sessions left")
	}
	u.RLock()
	running := u.dnsReaperRunning
	u.RUnlock()
	if running {
		t.Fatal("reaper flag left set after it stopped")
	}
}

func TestUDPPacketsKeepSessionAlive(t *testing.T) {
	u := newTestUDPHandler(t, 4)
	u.HandlePacket(testSrc(1), testDst(53), []byte{1})
	u.testAge(testSrc(1), udpDNSIdle+time.Second)

	u.HandlePacket(testSrc(1), testDst(53), []byte{2}) // новый запрос с того же порта

	u.reapDNSOnce(time.Now())
	if u.testConn(testSrc(1)) == nil {
		t.Fatal("a DNS session with a fresh packet was reaped")
	}
}
