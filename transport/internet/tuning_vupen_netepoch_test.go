package internet

import (
	"context"
	"errors"
	"fmt"
	stdnet "net"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
)

// ── test clock ──────────────────────────────────────────────────────────────

type netFakeTimer struct {
	at      time.Time
	f       func()
	stopped bool
	fired   bool
	d       time.Duration
}

type netFakeClock struct {
	mu     sync.Mutex
	now    time.Time
	timers []*netFakeTimer
}

func (c *netFakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *netFakeClock) After(d time.Duration, f func()) func() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := &netFakeTimer{at: c.now.Add(d), f: f, d: d}
	c.timers = append(c.timers, t)
	return func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		if t.fired || t.stopped {
			return false
		}
		t.stopped = true
		return true
	}
}

// Advance moves the clock and fires every due timer (outside the clock lock).
func (c *netFakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	var due []*netFakeTimer
	for _, t := range c.timers {
		if !t.fired && !t.stopped && !t.at.After(c.now) {
			t.fired = true
			due = append(due, t)
		}
	}
	c.mu.Unlock()
	for _, t := range due {
		t.f()
	}
}

func (c *netFakeClock) pending() []*netFakeTimer {
	c.mu.Lock()
	defer c.mu.Unlock()
	var p []*netFakeTimer
	for _, t := range c.timers {
		if !t.fired && !t.stopped {
			p = append(p, t)
		}
	}
	return p
}

type netAuto41Key struct{}

// netEpochTest — fresh epoch state, fake clock, Auto41 = ctx carries netAuto41Key.
func netEpochTest(t *testing.T) *netFakeClock {
	t.Helper()
	clock := &netFakeClock{now: time.Unix(1_800_000_000, 0)}
	oldNow, oldAfter, oldHooks := vupenNetNow, vupenNetAfter, vupenNetEpochHooks.Load()
	vupenNet.resetForTest()
	vupenNetNow, vupenNetAfter = clock.Now, clock.After
	VupenSetNetEpochHooks(&VupenNetEpochHooks{Auto41: func(ctx context.Context) bool {
		return ctx.Value(netAuto41Key{}) != nil
	}})
	t.Cleanup(func() {
		vupenNet.resetForTest()
		vupenNetNow, vupenNetAfter = oldNow, oldAfter
		vupenNetEpochHooks.Store(oldHooks)
	})
	return clock
}

func auto41Ctx(tag string) context.Context {
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Tag: tag}})
	return context.WithValue(ctx, netAuto41Key{}, true)
}

func plainCtx(tag string) context.Context {
	return session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Tag: tag}})
}

func netEntries() int {
	vupenNet.mu.Lock()
	defer vupenNet.mu.Unlock()
	return len(vupenNet.entries)
}

// tcpServer accepts and keeps connections open until the test ends.
func tcpServer(t *testing.T) net.Destination {
	t.Helper()
	l, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var conns []stdnet.Conn
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		l.Close()
		mu.Lock()
		for _, c := range conns {
			c.Close()
		}
		mu.Unlock()
	})
	a := l.Addr().(*stdnet.TCPAddr)
	return net.TCPDestination(net.IPAddress(a.IP), net.Port(a.Port))
}

func udpServer(t *testing.T) net.Destination {
	t.Helper()
	pc, err := stdnet.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	a := pc.LocalAddr().(*stdnet.UDPAddr)
	return net.UDPDestination(net.IPAddress(a.IP), net.Port(a.Port))
}

func dial(t *testing.T, ctx context.Context, dest net.Destination) net.Conn {
	t.Helper()
	c, err := DialSystem(ctx, dest, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// isClosed — the conn was closed locally (not merely idle).
func isClosed(c net.Conn) bool {
	_ = c.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	_, err := c.Read(make([]byte, 1))
	return errors.Is(err, stdnet.ErrClosed)
}

// ── tests ───────────────────────────────────────────────────────────────────

// Without VupenSetUplink nothing is tracked and DialSystem returns the very
// same connection types as before (no wrapper).
func TestVupenNetEpochInertWithoutAPI(t *testing.T) {
	netEpochTest(t)
	tcp := dial(t, auto41Ctx("proxy-1"), tcpServer(t))
	udp := dial(t, auto41Ctx("direct"), udpServer(t))
	if _, ok := tcp.(*net.TCPConn); !ok {
		t.Fatalf("tcp conn type changed: %T", tcp)
	}
	if _, ok := udp.(*PacketConnWrapper); !ok {
		t.Fatalf("udp conn type changed: %T", udp)
	}
	if vupenNetEpochBeforeDial(auto41Ctx("proxy-1")) != nil || netEntries() != 0 {
		t.Fatal("tracked without VupenSetUplink")
	}
}

// After VupenSetUplink, a core instance without AUTO 4.1 is not tracked.
func TestVupenNetEpochOtherInstancesUntouched(t *testing.T) {
	clock := netEpochTest(t)
	VupenSetUplink("wifi", "")
	tcp := dial(t, plainCtx("proxy-1"), tcpServer(t))
	udp := dial(t, plainCtx("direct"), udpServer(t))
	if netEntries() != 0 {
		t.Fatalf("non-AUTO-4.1 connections tracked: %d", netEntries())
	}
	VupenSetUplink("cellular", "")
	clock.Advance(time.Duration(VupenNetChangeCloseStableSec) * time.Second)
	if isClosed(tcp) || isClosed(udp) {
		t.Fatal("a non-AUTO-4.1 connection was closed on network change")
	}
	// No hooks at all (router package not linked) = not tracked either.
	vupenNetEpochHooks.Store(nil)
	if vupenNetEpochBeforeDial(auto41Ctx("proxy-1")) != nil {
		t.Fatal("tracked without hooks")
	}
}

func TestVupenNetEpochBookkeeping(t *testing.T) {
	clock := netEpochTest(t)
	VupenSetUplink("wifi", "")
	s := vupenNet
	if !s.active.Load() || s.epoch != 1 || s.current != (vupenNetID{"wifi", "wifi"}) || s.base != s.current {
		t.Fatalf("first report: %+v", s)
	}
	if len(clock.pending()) != 0 {
		t.Fatal("first report must not schedule a close")
	}
	VupenSetUplink("wifi", "")
	if s.epoch != 1 || len(clock.pending()) != 0 {
		t.Fatal("a repeated report is not a network change")
	}
	VupenSetUplink("cellular", "cellular:pdp_ip0")
	if s.epoch != 2 || s.current != (vupenNetID{"cellular", "cellular:pdp_ip0"}) || s.base.kind != "wifi" {
		t.Fatalf("change: %+v", s)
	}
	p := clock.pending()
	if len(p) != 1 || p[0].d != 9*time.Second {
		t.Fatalf("want one 9 s countdown, got %+v", p)
	}
	if snap := s.snap.Load(); snap.id != s.current {
		t.Fatalf("dial snapshot not published: %+v", snap)
	}
	// Same kind, other signature = change too.
	VupenSetUplink("cellular", "cellular:pdp_ip1")
	if s.epoch != 3 || len(clock.pending()) != 1 {
		t.Fatalf("sig change: epoch=%d pending=%d", s.epoch, len(clock.pending()))
	}
}

// Real change: after 9 s on the new network, connections of the old network
// (to nodes and direct, TCP and UDP) are closed; 8.9 s is not enough.
func TestVupenNetEpochClosesOldNetworkAfter9s(t *testing.T) {
	clock := netEpochTest(t)
	tcpDest, udpDest := tcpServer(t), udpServer(t)
	VupenSetUplink("wifi", "wifi:en0")
	proxyOld := dial(t, auto41Ctx("proxy-1"), tcpDest)
	directOld := dial(t, auto41Ctx("direct"), tcpDest)
	directUDPOld := dial(t, auto41Ctx("direct"), udpDest)
	if netEntries() != 3 {
		t.Fatalf("want 3 tracked, got %d", netEntries())
	}
	VupenSetUplink("cellular", "cellular:pdp_ip0")
	proxyNew := dial(t, auto41Ctx("proxy-2"), tcpDest)

	clock.Advance(8900 * time.Millisecond)
	for _, c := range []net.Conn{proxyOld, directOld, directUDPOld, proxyNew} {
		if isClosed(c) {
			t.Fatal("closed before 9 s")
		}
	}
	clock.Advance(100 * time.Millisecond)
	for name, c := range map[string]net.Conn{"proxy tcp": proxyOld, "direct tcp": directOld, "direct udp": directUDPOld} {
		if !isClosed(c) {
			t.Fatalf("%s of the old network not closed after 9 s", name)
		}
	}
	if isClosed(proxyNew) {
		t.Fatal("a connection of the new network was closed")
	}
	if netEntries() != 1 {
		t.Fatalf("registry keeps closed entries: %d", netEntries())
	}
}

// Return to the previous network within 9 s closes nothing.
func TestVupenNetEpochFlapClosesNothing(t *testing.T) {
	clock := netEpochTest(t)
	VupenSetUplink("wifi", "wifi:en0")
	c := dial(t, auto41Ctx("proxy-1"), tcpServer(t))
	VupenSetUplink("cellular", "cellular:pdp_ip0")
	clock.Advance(5 * time.Second)
	VupenSetUplink("wifi", "wifi:en0")
	if len(clock.pending()) != 0 {
		t.Fatal("return to the previous network must cancel the countdown")
	}
	clock.Advance(time.Minute)
	if isClosed(c) {
		t.Fatal("a flap closed a connection")
	}
}

// A new change before 9 s restarts the countdown from the last change.
func TestVupenNetEpochFlappingRestartsCountdown(t *testing.T) {
	clock := netEpochTest(t)
	VupenSetUplink("wifi", "wifi:en0")
	c := dial(t, auto41Ctx("proxy-1"), tcpServer(t))
	VupenSetUplink("cellular", "cellular:pdp_ip0")
	clock.Advance(5 * time.Second)
	VupenSetUplink("wired", "wired:en5")
	clock.Advance(5 * time.Second) // 10 s since the first change, 5 since the last
	if isClosed(c) {
		t.Fatal("countdown was not restarted by the second change")
	}
	clock.Advance(3900 * time.Millisecond)
	if isClosed(c) {
		t.Fatal("closed before 9 s on the last network")
	}
	clock.Advance(100 * time.Millisecond)
	if !isClosed(c) {
		t.Fatal("not closed 9 s after the last change")
	}
}

// After a completed close, a later return to the old network starts a new
// countdown and closes what was opened on the network in between.
func TestVupenNetEpochSecondChange(t *testing.T) {
	clock := netEpochTest(t)
	dest := tcpServer(t)
	VupenSetUplink("wifi", "wifi:en0")
	VupenSetUplink("cellular", "cellular:pdp_ip0")
	clock.Advance(9 * time.Second)
	onCell := dial(t, auto41Ctx("proxy-1"), dest)
	VupenSetUplink("wifi", "wifi:en0")
	if len(clock.pending()) != 1 {
		t.Fatal("wifi after a completed switch to cellular is a real change")
	}
	clock.Advance(9 * time.Second)
	if !isClosed(onCell) {
		t.Fatal("cellular connection not closed after 9 s back on wifi")
	}
}

// A dial that started on the old network and finished after its close sweep
// is closed and reported as a dial error.
func TestVupenNetEpochLateRegistration(t *testing.T) {
	clock := netEpochTest(t)
	VupenSetUplink("wifi", "wifi:en0")
	snap := vupenNetEpochBeforeDial(auto41Ctx("proxy-1"))
	raw, err := stdnet.Dial("tcp", tcpServer(t).NetAddr())
	if err != nil {
		t.Fatal(err)
	}
	VupenSetUplink("cellular", "cellular:pdp_ip0")
	clock.Advance(9 * time.Second)
	if err := vupenNetEpochTrack(raw, snap); err == nil {
		t.Fatal("late connection of the old network must fail")
	}
	if !isClosed(raw) {
		t.Fatal("late connection of the old network not closed")
	}
	// Same network as the sweep: fine.
	snap2 := vupenNetEpochBeforeDial(auto41Ctx("proxy-1"))
	raw2, err := stdnet.Dial("tcp", tcpServer(t).NetAddr())
	if err != nil {
		t.Fatal(err)
	}
	defer raw2.Close()
	if err := vupenNetEpochTrack(raw2, snap2); err != nil || netEntries() != 1 {
		t.Fatalf("connection of the current network rejected: %v entries=%d", err, netEntries())
	}
}

// Closed and dropped connections leave the registry (no growth).
func TestVupenNetEpochRegistryDoesNotGrow(t *testing.T) {
	netEpochTest(t)
	VupenSetUplink("wifi", "")
	dest := tcpServer(t)
	for i := 0; i < 200; i++ {
		c, err := DialSystem(auto41Ctx("direct"), dest, nil)
		if err != nil {
			t.Fatal(err)
		}
		c.Close()
	}
	deadline := time.Now().Add(5 * time.Second)
	for netEntries() > 0 && time.Now().Before(deadline) {
		runtime.GC()
		time.Sleep(10 * time.Millisecond)
	}
	if n := netEntries(); n != 0 {
		t.Fatalf("registry kept %d entries of closed connections", n)
	}
}

// Real timers: superseded countdowns are stopped, nothing keeps goroutines.
func TestVupenNetEpochNoGoroutineLeak(t *testing.T) {
	netEpochTest(t)
	vupenNetNow = time.Now
	vupenNetAfter = func(d time.Duration, f func()) func() bool { return time.AfterFunc(d, f).Stop }
	before := runtime.NumGoroutine()
	VupenSetUplink("wifi", "")
	for i := 0; i < 500; i++ {
		if i%2 == 0 {
			VupenSetUplink("cellular", "")
		} else {
			VupenSetUplink("wifi", "")
		}
	}
	VupenSetUplink("cellular", "") // leave one countdown pending
	vupenNet.mu.Lock()
	stop := vupenNet.stopPending
	vupenNet.mu.Unlock()
	if stop == nil || !stop() {
		t.Fatal("expected exactly one live countdown")
	}
	runtime.GC()
	if after := runtime.NumGoroutine(); after > before+2 {
		t.Fatalf("goroutines: before %d, after %d", before, after)
	}
}

// Dials, closes and network changes in parallel (run with -race).
func TestVupenNetEpochConcurrent(t *testing.T) {
	clock := netEpochTest(t)
	dest := tcpServer(t)
	VupenSetUplink("wifi", "")
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 25; i++ {
				c, err := DialSystem(auto41Ctx("direct"), dest, nil)
				if err == nil {
					c.Close()
				}
			}
		}()
	}
	for i := 0; i < 50; i++ {
		if i%2 == 0 {
			VupenSetUplink("cellular", "")
		} else {
			VupenSetUplink("wifi", "")
		}
		clock.Advance(time.Duration(4+i%7) * time.Second) // some changes settle (>= 9 s), some flap
	}
	wg.Wait()
}

// CR-101: transports that keep only PacketConnWrapper.PacketConn (hysteria,
// XHTTP/H3, mKCP, udpmask, wireguard) — the wrapper is collected, the socket
// must still be tracked and closed on the sweep.
func TestVupenNetEpochTracksInnerUDPSocket(t *testing.T) {
	clock := netEpochTest(t)
	VupenSetUplink("wifi", "wifi:en0")
	raw, err := DialSystem(auto41Ctx("proxy-hy2"), udpServer(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	inner := raw.(*PacketConnWrapper).PacketConn.(*net.UDPConn)
	t.Cleanup(func() { inner.Close() })
	raw = nil // keep only the inner socket, like the QUIC transports do
	for i := 0; i < 3; i++ {
		runtime.GC()
	}
	time.Sleep(20 * time.Millisecond) // let cleanups run
	if netEntries() != 1 {
		t.Fatalf("inner socket entry dropped after GC: entries=%d", netEntries())
	}
	VupenSetUplink("cellular", "cellular:pdp_ip0")
	clock.Advance(9 * time.Second)
	if !isClosed(inner) {
		t.Fatal("inner UDP socket of the old network not closed")
	}
	runtime.KeepAlive(inner)
}

// CR-101: freeze-wrapped TCP — the wrapper is closed while alive (it leaves the
// watchdog list), the inner socket otherwise.
func TestVupenNetEpochFreezeWrappedTCP(t *testing.T) {
	freezeTestHooks(t, true)
	t.Run("wrapper alive", func(t *testing.T) {
		clock := netEpochTest(t)
		VupenSetUplink("wifi", "wifi:en0")
		c := dial(t, auto41Ctx("proxy-1"), tcpServer(t))
		fc, ok := c.(*vupenFreezeConn)
		if !ok {
			t.Fatalf("expected a freeze-wrapped conn, got %T", c)
		}
		VupenSetUplink("cellular", "cellular:pdp_ip0")
		clock.Advance(9 * time.Second)
		if !isClosed(fc.Conn) {
			t.Fatal("inner socket not closed")
		}
		vupenFreezeWatch.mu.Lock()
		_, watched := vupenFreezeWatch.conns[fc]
		vupenFreezeWatch.mu.Unlock()
		if watched {
			t.Fatal("closed wrapper still in the watchdog list (wrapper was not closed)")
		}
	})
	t.Run("wrapper collected", func(t *testing.T) {
		clock := netEpochTest(t)
		VupenSetUplink("wifi", "wifi:en0")
		c, err := DialSystem(auto41Ctx("proxy-1"), tcpServer(t), nil)
		if err != nil {
			t.Fatal(err)
		}
		fc := c.(*vupenFreezeConn)
		inner := fc.Conn.(*net.TCPConn)
		t.Cleanup(func() { inner.Close() })
		vupenFreezeWatch.remove(fc) // as after the 30-min forget
		c, fc = nil, nil
		for i := 0; i < 3; i++ {
			runtime.GC()
		}
		time.Sleep(20 * time.Millisecond)
		if netEntries() != 1 {
			t.Fatalf("inner socket entry dropped after GC: entries=%d", netEntries())
		}
		VupenSetUplink("cellular", "cellular:pdp_ip0")
		clock.Advance(9 * time.Second)
		if !isClosed(inner) {
			t.Fatal("inner TCP socket not closed after its wrapper was collected")
		}
		runtime.KeepAlive(inner)
	})
}

// CR-102: gRPC dials in its own context — the AUTO 4.1 decision is carried.
func TestVupenNetEpochCarry(t *testing.T) {
	netEpochTest(t)
	gctx := context.Background()
	if VupenNetEpochCarry(gctx, auto41Ctx("p")) != gctx {
		t.Fatal("carry must be a no-op before VupenSetUplink")
	}
	VupenSetUplink("wifi", "")
	if got := VupenNetEpochCarry(gctx, plainCtx("p")); got != gctx || vupenNetEpochBeforeDial(got) != nil {
		t.Fatal("carry must be a no-op for a non-AUTO-4.1 instance")
	}
	carried := VupenNetEpochCarry(gctx, auto41Ctx("p"))
	if vupenNetEpochBeforeDial(carried) == nil {
		t.Fatal("carried context is not tracked")
	}
	// Tracked through DialSystem too.
	c := dial(t, carried, tcpServer(t))
	if netEntries() != 1 {
		t.Fatalf("carried dial not tracked: entries=%d", netEntries())
	}
	_ = c
}

// CR-102: udphop opens replacement sockets with context.Background(); they are
// tracked iff the original socket is.
func TestVupenNetEpochContextFor(t *testing.T) {
	netEpochTest(t)
	dest := udpServer(t)
	stray, err := stdnet.ListenUDP("udp", &stdnet.UDPAddr{IP: stdnet.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer stray.Close()
	if vupenNetEpochBeforeDial(VupenNetEpochContextFor(stray)) != nil {
		t.Fatal("tracked before VupenSetUplink")
	}
	VupenSetUplink("wifi", "")
	if vupenNetEpochBeforeDial(VupenNetEpochContextFor(stray)) != nil {
		t.Fatal("an untracked socket must give an untracked context")
	}
	plain := dial(t, plainCtx("proxy-hy2"), dest).(*PacketConnWrapper).PacketConn
	if vupenNetEpochBeforeDial(VupenNetEpochContextFor(plain)) != nil {
		t.Fatal("a non-AUTO-4.1 socket must give an untracked context")
	}
	auto := dial(t, auto41Ctx("proxy-hy2"), dest).(*PacketConnWrapper).PacketConn
	if vupenNetEpochBeforeDial(VupenNetEpochContextFor(auto)) == nil {
		t.Fatal("replacement of a tracked socket must be tracked")
	}
}

// 2.3: subscribers get "changed" on every change (flaps included) and
// "stable" once the new network has held for VupenNetChangeCloseStableSec.
func TestVupenNetEpochSubscribe(t *testing.T) {
	clock := netEpochTest(t)
	var mu sync.Mutex
	var got []VupenNetEvent
	unsub := VupenNetEpochSubscribe(func(ev VupenNetEvent) {
		mu.Lock()
		got = append(got, ev)
		mu.Unlock()
	})
	events := func() []VupenNetEvent {
		mu.Lock()
		defer mu.Unlock()
		return append([]VupenNetEvent(nil), got...)
	}
	VupenSetUplink("wifi", "")     // first report: no event
	VupenSetUplink("cellular", "") // changed
	clock.Advance(5 * time.Second)
	VupenSetUplink("wifi", "") // flap back: changed, no stable
	clock.Advance(time.Minute)
	VupenSetUplink("cellular", "") // changed
	clock.Advance(time.Duration(VupenNetChangeCloseStableSec) * time.Second)
	want := []VupenNetEvent{VupenNetChanged, VupenNetChanged, VupenNetChanged, VupenNetStable}
	if g := events(); fmt.Sprint(g) != fmt.Sprint(want) {
		t.Fatalf("events %v, want %v", g, want)
	}
	unsub()
	VupenSetUplink("wifi", "")
	if g := events(); len(g) != len(want) {
		t.Fatalf("event after unsubscribe: %v", g)
	}
}
