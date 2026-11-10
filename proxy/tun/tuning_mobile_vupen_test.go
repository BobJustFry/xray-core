package tun

import (
	"context"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

// Vupen (T-237): mobile limits on the built-in stack (#7130). Before it there
// was no test on the gVisor-era limits at all (patch map, group 17).

func withTCPLimits(t *testing.T, bufKB, inFlight int32) {
	t.Helper()
	prevBuf, prevFlight := atomic.LoadInt32(&tcpBufMaxKB), atomic.LoadInt32(&tcpMaxInFlight)
	atomic.StoreInt32(&tcpBufMaxKB, bufKB)
	atomic.StoreInt32(&tcpMaxInFlight, inFlight)
	t.Cleanup(func() {
		atomic.StoreInt32(&tcpBufMaxKB, prevBuf)
		atomic.StoreInt32(&tcpMaxInFlight, prevFlight)
	})
}

// tcpBufMaxKB only lowers the upstream window, and never below tcpWindowMinKB.
func TestVupenTCPWindow(t *testing.T) {
	cases := []struct {
		kb       int32
		upstream int32
		want     int32
	}{
		{1024, tcpWindow, tcpWindow},           // default: upstream 256 KiB
		{512, tcpWindow, tcpWindow},            // iPhone .mobile preset: still 256 KiB
		{128, tcpWindow, 128 << 10},            // lowered
		{16, tcpWindow, tcpWindowMinKB << 10},  // floor
		{1024, tcpLargeWindow, tcpLargeWindow}, // large segments (Linux)
		{512, tcpLargeWindow, 512 << 10},
		{0, tcpWindow, tcpWindow}, // unset falls back to 1024 KiB
	}
	for _, c := range cases {
		withTCPLimits(t, c.kb, 256)
		if got := vupenTCPWindow(c.upstream); got != c.want {
			t.Errorf("tcpBufMaxKB %d, upstream %d: window %d, want %d", c.kb, c.upstream, got, c.want)
		}
	}
}

// NewStack takes both limits; the window reaches every connection.
func TestVupenNewStackTakesLimits(t *testing.T) {
	withTCPLimits(t, 128, 7)
	l := newLink()
	defer l.Close()
	st, err := NewStack(context.Background(), StackOptions{Tun: l, MTU: testMTU}, &Handler{})
	if err != nil {
		t.Fatal(err)
	}
	s := st.(*stack)
	if s.window != 128<<10 {
		t.Fatalf("window %d, want %d", s.window, 128<<10)
	}
	if s.openingLimit() != 7 {
		t.Fatalf("opening limit %d, want 7", s.openingLimit())
	}
	// a stack built without NewStack (upstream tests) keeps upstream's limit
	if (&stack{}).openingLimit() != tcpOpening {
		t.Fatal("zero maxOpening must mean tcpOpening")
	}
}

// Over the in-flight limit the SYN gets no answer and is counted as synDrop;
// once a handshake completes the next SYN is answered again.
func TestVupenSynDropAtLimit(t *testing.T) {
	conns := make(chan accepted, 2)
	p, l := newPeer(t, "10.0.0.1:1000", "10.0.0.2:80")
	s := newTestStack(t, l, accept(conns))
	s.maxOpening = 1
	drops := tunStats.synDrop.Load()

	// first SYN: answered, the handshake stays open
	p.send(p.seq, tcpSyn, nil, nil)
	first := p.receive()
	if first.flags != tcpSyn|tcpAck {
		t.Fatal("no SYN-ACK to the first SYN: flags ", first.flags)
	}
	// second SYN from another port: dropped
	p.src = netip.AddrPortFrom(p.src.Addr(), 1001)
	p.send(5000, tcpSyn, nil, nil)
	p.silent(200 * time.Millisecond)
	if d := tunStats.synDrop.Load() - drops; d != 1 {
		t.Fatalf("synDrop +%d, want +1", d)
	}
	if n := s.opening.Load(); n != 1 {
		t.Fatalf("opening %d, want 1", n)
	}

	// the first handshake completes: room for the next one
	p.src = netip.AddrPortFrom(p.src.Addr(), 1000)
	p.ack = first.seq + 1
	p.send(p.seq+1, tcpAck, nil, nil)
	a := take(t, conns)
	defer a.conn.Close()
	p.src = netip.AddrPortFrom(p.src.Addr(), 1001)
	p.send(5000, tcpSyn, nil, nil)
	if s := p.receive(); s.flags != tcpSyn|tcpAck {
		t.Fatal("no SYN-ACK after the limit was freed: flags ", s.flags)
	}
}
