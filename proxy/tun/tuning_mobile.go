package tun

import "sync/atomic"

// Mobile TUN limits (Vupen). Set before RunXray via libXray; defaults match SwiftyXrayKit .mobile.
var (
	tcpBufMaxKB    int32 = 1024
	tcpMaxInFlight int32 = 256
	maxUDPConns    int32 = 128
	// Per-session egress queue depth (packets). Was a literal 1024: even an empty
	// channel is 1024 pointers (~8 KB) per session, and a stalled outbound could
	// queue 1024 MTU-sized packets per session before dropping (TUN-1).
	udpEgressDepth int32 = 128
	// Vupen (T-075, аудит T-071): потолок байт во всех очередях UDP-сессий TUN
	// вместе. Без него худший случай — сессии × глубина × MTU (192 × 128 × 1,5 КБ
	// ≈ 37 МБ при зависшем outbound'е) при стене памяти NE около 50 МБ.
	udpQueueMaxKB int32 = 4096
)

// SetTCPBufMaxKB sets max TCP RX/TX buffer per connection in kilobytes.
// Since the built-in stack (upstream #7130) it caps the window of every
// connection: what is taken from the system before the outbound reads it and
// what is sent to the system before it is acknowledged. It can only lower the
// upstream window (256 KiB, 1 MiB for a tun that takes large segments), never
// raise it, and is not below tcpWindowMinKB. Read when the stack is created.
func SetTCPBufMaxKB(kb int) {
	if kb > 0 {
		atomic.StoreInt32(&tcpBufMaxKB, int32(kb))
	}
}

// SetTCPMaxInFlight sets the number of TCP handshakes in progress at once
// (SYN-ACK sent, final ACK not yet received), NOT of live connections. With
// gVisor it was the forwarder's maxInFlight; with the built-in stack (#7130) it
// replaces the tcpOpening constant (65535): a SYN over the limit is dropped
// silently, as upstream does, and counted in Stats() as synDrop. Read when the
// stack is created. Until core 47 it capped live connections (Complete() was
// called after the whole connection had ended); it does not now.
func SetTCPMaxInFlight(n int) {
	if n > 0 {
		atomic.StoreInt32(&tcpMaxInFlight, int32(n))
	}
}

// SetMaxUDPConns sets max concurrent UDP sessions in the TUN handler.
func SetMaxUDPConns(n int) {
	if n > 0 {
		atomic.StoreInt32(&maxUDPConns, int32(n))
	}
}

func mobileTCPBufMaxBytes() int {
	kb := atomic.LoadInt32(&tcpBufMaxKB)
	if kb <= 0 {
		kb = 1024
	}
	return int(kb) * 1024
}

func mobileTCPMaxInFlight() int {
	n := int(atomic.LoadInt32(&tcpMaxInFlight))
	if n <= 0 {
		return 256
	}
	if n > 65535 {
		return 65535
	}
	return n
}

func mobileMaxUDPConns() int {
	n := int(atomic.LoadInt32(&maxUDPConns))
	if n <= 0 {
		return 128
	}
	return n
}

// SetUDPEgressDepth sets the per-session UDP egress queue depth (packets).
func SetUDPEgressDepth(n int) {
	if n > 0 {
		atomic.StoreInt32(&udpEgressDepth, int32(n))
	}
}

// SetUDPQueueMaxKB sets the cap of bytes queued in all TUN UDP sessions together.
func SetUDPQueueMaxKB(kb int) {
	if kb > 0 {
		atomic.StoreInt32(&udpQueueMaxKB, int32(kb))
	}
}

func mobileUDPQueueMaxBytes() int64 {
	kb := atomic.LoadInt32(&udpQueueMaxKB)
	if kb <= 0 {
		kb = 4096
	}
	return int64(kb) * 1024
}

func mobileUDPEgressDepth() int {
	n := int(atomic.LoadInt32(&udpEgressDepth))
	if n <= 0 {
		return 128
	}
	return n
}

// tcpWindowMinKB is the least window SetTCPBufMaxKB can set: 128 KiB, the
// value of the iPhone .mobile preset, the smallest one the apps ship. Below it
// the stack's ACK on arrival (once tcpWindow/4 = 64 KiB, a constant, is
// unacknowledged) fires only on a full window, so the system waits for the
// outbound to read or for tcpTick, and one stream gets ~5 Mbit/s at 100 ms RTT.
const tcpWindowMinKB = 128

// vupenTCPWindow caps the window of the built-in stack by tcpBufMaxKB.
func vupenTCPWindow(upstream int32) int32 {
	w := int32(min(mobileTCPBufMaxBytes(), int(upstream)))
	return max(w, min(tcpWindowMinKB<<10, upstream))
}

// openingLimit is how many connections may wait for the answer to their SYN-ACK.
func (s *stack) openingLimit() int32 {
	if s.maxOpening <= 0 {
		return tcpOpening
	}
	return s.maxOpening
}
