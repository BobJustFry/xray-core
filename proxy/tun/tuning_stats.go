package tun

import (
	"fmt"
	"sync"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// Vupen: счётчики тракта TUN для heartbeat расширения.
//
// До них тракт умирал молча: цикл чтения выходил без строки в лог, gVisor ронял
// SYN сверх maxInFlight без строки в лог, переполнение UDP писалось на debug.
// Расширение при этом сообщало «xray.running=yes», проба через socks проходила,
// а в TUN 28 минут не входило ни одного пакета (iOS, 2026-09-08 16:15–16:43).
// Цифры ниже печатаются в heartbeat — по ним видно, какое звено умерло.
var tunStats struct {
	readerAlive      atomic.Int32 // 1 — цикл чтения из TUN работает
	readPackets      atomic.Uint64
	readErrors       atomic.Uint64
	writePackets     atomic.Uint64
	writeDrops       atomic.Uint64 // запись в TUN не удалась (EAGAIN и прочее)
	tcpLive          atomic.Int32  // соединений в HandleConnection прямо сейчас
	tcpAccepted      atomic.Uint64 // рукопожатий завершено
	tcpHandshakeFail atomic.Uint64 // CreateEndpoint вернул ошибку (таймаут ACK и т.п.)
	udpSessions      atomic.Int32
	udpCapDrops      atomic.Uint64 // пакетов отброшено по лимиту UDP-сессий
}

var (
	tunStackMu sync.Mutex
	tunStack   *stack.Stack
)

func setTunStack(s *stack.Stack) {
	tunStackMu.Lock()
	tunStack = s
	tunStackMu.Unlock()
}

// Stats — одна строка для heartbeat NE. `synDrop` — счётчик самого gVisor
// (ForwardMaxInFlightDrop): SYN, отброшенные из-за maxInFlight; до ядра 47 это
// был единственный след того, что лимит соединений сработал, и он не читался.
func Stats() string {
	var synDrop uint64
	tunStackMu.Lock()
	if tunStack != nil {
		synDrop = tunStack.Stats().TCP.ForwardMaxInFlightDrop.Value()
	}
	tunStackMu.Unlock()
	return fmt.Sprintf(
		"reader=%d rx=%d rxErr=%d tx=%d txDrop=%d tcpLive=%d tcpAcc=%d hsFail=%d synDrop=%d udp=%d udpDrop=%d",
		tunStats.readerAlive.Load(),
		tunStats.readPackets.Load(),
		tunStats.readErrors.Load(),
		tunStats.writePackets.Load(),
		tunStats.writeDrops.Load(),
		tunStats.tcpLive.Load(),
		tunStats.tcpAccepted.Load(),
		tunStats.tcpHandshakeFail.Load(),
		synDrop,
		tunStats.udpSessions.Load(),
		tunStats.udpCapDrops.Load(),
	)
}

// logEvery — первая ошибка и каждая сотая, чтобы повторяющийся отказ не заливал лог.
func logEvery(n uint64) bool {
	return n == 1 || n%100 == 0
}
