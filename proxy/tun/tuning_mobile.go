package tun

import "sync/atomic"

// Mobile TUN limits (Vupen). Set before RunXray via libXray; defaults match SwiftyXrayKit .mobile.
var (
	tcpBufMaxKB    int32 = 1024
	tcpMaxInFlight int32 = 256
	maxUDPConns    int32 = 128
)

// SetTCPBufMaxKB sets max TCP RX/TX buffer per connection in kilobytes.
func SetTCPBufMaxKB(kb int) {
	if kb > 0 {
		atomic.StoreInt32(&tcpBufMaxKB, int32(kb))
	}
}

// SetTCPMaxInFlight sets max concurrent TCP connections in gVisor forwarder.
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
