package tun

import (
	"encoding/binary"
	"testing"
)

func ipv4Frame(payload int) []byte {
	total := 20 + payload
	f := make([]byte, streamHeaderSize+total)
	f[3] = streamAFInet
	f[4] = 0x45
	binary.BigEndian.PutUint16(f[streamHeaderSize+2:], uint16(total))
	for i := streamHeaderSize + 20; i < len(f); i++ {
		f[i] = byte(i)
	}
	return f
}

func ipv6Frame(payload int) []byte {
	f := make([]byte, streamHeaderSize+40+payload)
	f[3] = streamAFInet6
	f[4] = 0x60
	binary.BigEndian.PutUint16(f[streamHeaderSize+4:], uint16(payload))
	return f
}

func feed(t *testing.T, f *streamFramer, b []byte) {
	t.Helper()
	n := copy(f.free(), b)
	if n != len(b) {
		t.Fatalf("accumulator full: %d of %d", n, len(b))
	}
	f.commit(n)
}

func popAll(t *testing.T, f *streamFramer) [][]byte {
	t.Helper()
	var out [][]byte
	for {
		fl, err := f.frameLen()
		if err != nil {
			t.Fatalf("unexpected desync: %v", err)
		}
		if fl == 0 {
			return out
		}
		dst := make([]byte, fl-streamHeaderSize)
		if n := f.pop(fl, dst); n != len(dst) {
			t.Fatalf("pop copied %d of %d", n, len(dst))
		}
		out = append(out, dst)
	}
}

// Два кадра одним чтением — ровно тот случай, что терял вторую Initial-датаграмму QUIC.
func TestStreamFramerCoalescedRead(t *testing.T) {
	f := newStreamFramer()
	a, b := ipv4Frame(1208), ipv4Frame(1046)
	feed(t, f, append(append([]byte{}, a...), b...))
	got := popAll(t, f)
	if len(got) != 2 || len(got[0]) != 1228 || len(got[1]) != 1066 {
		t.Fatalf("got %d frames: %v", len(got), lens(got))
	}
	if f.n != 0 {
		t.Fatalf("leftover %d", f.n)
	}
}

// Кадр, разрезанный между двумя чтениями, ждёт остатка и не теряется.
func TestStreamFramerSplitRead(t *testing.T) {
	f := newStreamFramer()
	a := ipv4Frame(1208)
	feed(t, f, a[:700])
	if got := popAll(t, f); len(got) != 0 {
		t.Fatalf("partial frame delivered: %v", lens(got))
	}
	feed(t, f, a[700:])
	got := popAll(t, f)
	if len(got) != 1 || len(got[0]) != 1228 || got[0][0] != 0x45 {
		t.Fatalf("got %v", lens(got))
	}
}

// Заголовок разрезан внутри 4 байт AF — тоже ждём.
func TestStreamFramerHeaderSplit(t *testing.T) {
	f := newStreamFramer()
	a := ipv6Frame(100)
	feed(t, f, a[:3])
	if got := popAll(t, f); len(got) != 0 {
		t.Fatal("delivered on 3 bytes")
	}
	feed(t, f, a[3:])
	got := popAll(t, f)
	if len(got) != 1 || len(got[0]) != 140 {
		t.Fatalf("got %v", lens(got))
	}
}

// Мусор перед кадром: resync находит следующий правдоподобный заголовок.
func TestStreamFramerResync(t *testing.T) {
	f := newStreamFramer()
	junk := []byte{0xde, 0xad, 0xbe, 0xef, 0x11, 0x22}
	a := ipv4Frame(40)
	feed(t, f, append(append([]byte{}, junk...), a...))
	if _, err := f.frameLen(); err == nil {
		t.Fatal("expected desync")
	}
	if dropped := f.resync(); dropped != len(junk) {
		t.Fatalf("dropped %d, want %d", dropped, len(junk))
	}
	got := popAll(t, f)
	if len(got) != 1 || len(got[0]) != 60 || f.desync != 1 {
		t.Fatalf("got %v desync=%d", lens(got), f.desync)
	}
}

// T-253: pop only moves off; the tail of a partial frame is moved to the start
// by free() before the next Read, so a frame that does not fit behind off still
// fits after it, and nothing is lost or reordered.
func TestStreamFramerCompactsOnFree(t *testing.T) {
	f := newStreamFramer()
	var stream []byte
	for i := range 60 {
		stream = append(stream, ipv4Frame(1000+i)...)
	}
	big := ipv6Frame(20000)
	stream = append(stream, big...)
	want := 61
	var got [][]byte
	for len(stream) > 0 {
		room := f.free()
		if f.off != 0 {
			t.Fatalf("free left off=%d", f.off)
		}
		n := copy(room, stream[:min(len(stream), 9000)])
		f.commit(n)
		stream = stream[n:]
		got = append(got, popAll(t, f)...)
	}
	if len(got) != want || f.n != 0 || f.off != 0 {
		t.Fatalf("got %d frames, want %d; n=%d off=%d", len(got), want, f.n, f.off)
	}
	for i := range 60 {
		if len(got[i]) != 20+1000+i || got[i][0] != 0x45 {
			t.Fatalf("frame %d: len %d", i, len(got[i]))
		}
	}
	if len(got[60]) != 40+20000 || got[60][0] != 0x60 {
		t.Fatalf("last frame: len %d", len(got[60]))
	}
}

// resync after frames that were popped: it searches from off, not from 0.
func TestStreamFramerResyncAfterPop(t *testing.T) {
	f := newStreamFramer()
	a, b := ipv4Frame(100), ipv4Frame(50)
	feed(t, f, append(append(append([]byte{}, a...), 0xff, 0xff, 0xff), b...))
	if fl, err := f.frameLen(); err != nil || fl != len(a) {
		t.Fatalf("first frame %d %v", fl, err)
	}
	f.pop(len(a), make([]byte, len(a)-streamHeaderSize))
	if _, err := f.frameLen(); err == nil {
		t.Fatal("expected desync")
	}
	if dropped := f.resync(); dropped != 3 {
		t.Fatalf("dropped %d, want 3", dropped)
	}
	if got := popAll(t, f); len(got) != 1 || len(got[0]) != 70 {
		t.Fatalf("got %v", lens(got))
	}
}

func lens(b [][]byte) []int {
	out := make([]int, len(b))
	for i := range b {
		out[i] = len(b[i])
	}
	return out
}
