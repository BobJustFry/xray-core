package tun

import (
	"net/netip"
	"runtime"
	"testing"

	"github.com/xtls/xray-core/common/net"
)

// Vupen (T-237): heap per idle established TCP connection of the built-in stack,
// without the outbound side (the dispatcher and the proxy are not here). Upstream
// #7130 claims about 14 KB per idle connection against 28 KB for gVisor; the
// patch map expects the stack itself to stay well below core 88. A device
// measurement (NE phys_footprint) is still what decides.
func TestVupenIdleConnMemory(t *testing.T) {
	if testing.Short() {
		t.Skip("memory measurement")
	}
	const n = 300
	conns := make(chan accepted, n)
	release := make(chan struct{})
	p, l := newPeer(t, "10.0.0.1:10000", "10.0.0.2:443")
	newTestStack(t, l, func(c net.Conn, d net.Destination) {
		conns <- accepted{c, d}
		<-release
	})
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	for i := 0; i < n; i++ {
		p.src = netip.AddrPortFrom(p.src.Addr(), uint16(10000+i))
		p.seq = 1000
		p.connect([]byte{2, 4, 0x05, 0xb4, 3, 3, 6, 4, 2, 0, 0}) // MSS 1460, wscale 6, SACK
		take(t, conns)
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	heap := (int64(after.HeapAlloc) - int64(before.HeapAlloc)) / n
	stack := (int64(after.StackInuse) - int64(before.StackInuse)) / n
	t.Logf("idle TCP over the built-in stack: heap %d B/conn, goroutine stacks %d B/conn (test handler parked), %d conns", heap, stack, n)
	close(release)
	if heap > 32<<10 {
		t.Fatalf("heap per idle connection %d B, more than 32 KiB", heap)
	}
}
