package tun

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"os"
	"regexp"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
)

// Vupen (T-237): tunStats/Stats() on the built-in stack. Before T-237 there was
// no test on them (patch map, group 18), while the NE heartbeat reads Stats()
// through libXray (TunStats in ios/Vendor/libXray/tuning_vupen.go).

func eventually(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for deadline := time.Now().Add(3 * time.Second); !ok(); time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("timed out: ", what)
		}
	}
}

// The heartbeat line keeps its keys and their order (core 88 format).
func TestVupenStatsLine(t *testing.T) {
	keys := []string{"reader", "rx", "rxErr", "rxMulti", "rxDesync", "tx", "txDrop", "tcpLive", "tcpAcc", "hsFail", "synDrop", "udp", "udpDrop", "udpEvict", "dnsReap", "udpQ", "udpQDrop", "hsRefused"}
	fields := strings.Fields(Stats())
	if len(fields) != len(keys) {
		t.Fatalf("%d fields, want %d: %q", len(fields), len(keys), Stats())
	}
	for i, f := range fields {
		k, v, ok := strings.Cut(f, "=")
		if !ok || k != keys[i] || !regexp.MustCompile(`^-?\d+(KB)?$`).MatchString(v) {
			t.Fatalf("field %d %q, want key %q", i, f, keys[i])
		}
	}
}

// An established connection is counted as accepted and live until its handler returns.
func TestVupenStatsTCPLive(t *testing.T) {
	conns := make(chan accepted, 1)
	done := make(chan struct{})
	p, l := newPeer(t, "10.0.0.1:2000", "10.0.0.2:80")
	newTestStack(t, l, func(c net.Conn, d net.Destination) {
		accept(conns)(c, d)
		<-done
	})
	acc, live := tunStats.tcpAccepted.Load(), tunStats.tcpLive.Load()
	p.connect(nil)
	a := take(t, conns)
	if d := tunStats.tcpAccepted.Load() - acc; d != 1 {
		t.Fatalf("tcpAccepted +%d, want +1", d)
	}
	if d := tunStats.tcpLive.Load() - live; d != 1 {
		t.Fatalf("tcpLive +%d, want +1", d)
	}
	a.conn.Close()
	close(done)
	eventually(t, "tcpLive back", func() bool { return tunStats.tcpLive.Load() == live })
}

// A reset before the end of the handshake is a failed handshake refused by the app.
func TestVupenStatsHandshakeRefused(t *testing.T) {
	p, l := newPeer(t, "10.0.0.1:2001", "10.0.0.2:80")
	s := newTestStack(t, l, func(net.Conn, net.Destination) { t.Error("not established") })
	fail, refused := tunStats.tcpHandshakeFail.Load(), tunStats.tcpRefused.Load()
	p.send(p.seq, tcpSyn, nil, nil)
	if sa := p.receive(); sa.flags != tcpSyn|tcpAck {
		t.Fatal("no SYN-ACK")
	}
	p.send(p.seq+1, tcpRst, nil, nil)
	forgotten(t, s)
	if d := tunStats.tcpHandshakeFail.Load() - fail; d != 1 {
		t.Fatalf("tcpHandshakeFail +%d, want +1", d)
	}
	if d := tunStats.tcpRefused.Load() - refused; d != 1 {
		t.Fatalf("tcpRefused +%d, want +1", d)
	}
}

// flakyLink fails its first read with a temporary error, then reads as link does.
type flakyLink struct {
	*link
	failed atomic.Bool
}

func (l *flakyLink) ReadPacket(b []byte) ([]byte, error) {
	if !l.failed.Swap(true) {
		return nil, errors.New("temporary")
	}
	return l.link.ReadPacket(b)
}

type writeFailLink struct{ *link }

func (writeFailLink) WritePacket([]byte, []byte) error { return io.ErrShortWrite }

// The read loop of a stack made by NewStack: alive while it reads, a temporary
// error is counted and retried, a packet in and its answer out are counted, a
// closed tun stops it.
func TestVupenStatsReadLoop(t *testing.T) {
	l := &flakyLink{link: newLink()}
	answers := make(chan []byte, 4)
	l.out = func(b []byte) { answers <- b }
	alive, rx, rxErr, tx := tunStats.readerAlive.Load(), tunStats.readPackets.Load(), tunStats.readErrors.Load(), tunStats.writePackets.Load()
	st, err := NewStack(context.Background(), StackOptions{Tun: l, MTU: testMTU}, &Handler{})
	if err != nil {
		t.Fatal(err)
	}
	st.Start()
	eventually(t, "reader alive", func() bool { return tunStats.readerAlive.Load() == alive+1 })
	eventually(t, "read error counted", func() bool { return tunStats.readErrors.Load() == rxErr+1 })

	// an echo request: read, answered, written
	l.in <- icmpEcho("10.0.0.1", "10.0.0.2")
	select {
	case <-answers:
	case <-time.After(3 * time.Second):
		t.Fatal("no echo reply: the loop did not survive the temporary error")
	}
	if d := tunStats.readPackets.Load() - rx; d != 1 {
		t.Fatalf("readPackets +%d, want +1", d)
	}
	if d := tunStats.writePackets.Load() - tx; d != 1 {
		t.Fatalf("writePackets +%d, want +1", d)
	}

	l.Close() // io.EOF: fatal, the loop stops although the stack is not closed
	eventually(t, "reader stopped", func() bool { return tunStats.readerAlive.Load() == alive })
	st.Close()
}

// A failed write to the tun is a writeDrop.
func TestVupenStatsWriteDrop(t *testing.T) {
	l := writeFailLink{newLink()}
	defer l.Close()
	st, err := NewStack(context.Background(), StackOptions{Tun: l, MTU: testMTU}, &Handler{})
	if err != nil {
		t.Fatal(err)
	}
	drops := tunStats.writeDrops.Load()
	s := st.(*stack)
	pkt := icmpEcho("10.0.0.1", "10.0.0.2")
	p, ok := parsePacket(pkt)
	if !ok {
		t.Fatal("bad test packet")
	}
	s.handleICMP(p)
	if d := tunStats.writeDrops.Load() - drops; d != 1 {
		t.Fatalf("writeDrops +%d, want +1", d)
	}
}

func TestVupenReadFatal(t *testing.T) {
	fatal := []error{
		io.EOF, os.ErrClosed,
		syscall.EBADF, syscall.ECONNRESET, syscall.ENOTCONN, syscall.EPIPE,
		&os.PathError{Op: "read", Path: "utun", Err: syscall.ECONNRESET}, // as os.File.Read wraps it
	}
	for _, err := range fatal {
		if !isTunReadFatal(err) {
			t.Errorf("%v: not fatal", err)
		}
	}
	for _, err := range []error{errors.New("temporary"), syscall.EAGAIN, syscall.EINTR, syscall.ENOBUFS} {
		if isTunReadFatal(err) {
			t.Errorf("%v: fatal", err)
		}
	}
}

// icmpEcho is an IPv4 echo request from src to dst.
func icmpEcho(src, dst string) []byte {
	var b [ipv6HeaderSize + 8]byte
	n := putIPHeader(b[:], protoICMPv4, netip.MustParseAddr(src), netip.MustParseAddr(dst))
	m := b[n : n+8]
	m[0] = 8
	binary.BigEndian.PutUint16(m[2:], checksum(sum(m, 0)))
	setIPLength(b[:n], n+8)
	return append([]byte(nil), b[:n+8]...)
}
