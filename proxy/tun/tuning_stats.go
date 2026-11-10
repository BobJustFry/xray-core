package tun

import (
	"fmt"
	"sync/atomic"
)

// Vupen: счётчики тракта TUN для heartbeat расширения.
//
// До них тракт умирал молча: цикл чтения выходил без строки в лог, gVisor ронял
// SYN сверх maxInFlight без строки в лог, переполнение UDP писалось на debug.
// Расширение при этом сообщало «xray.running=yes», проба через socks проходила,
// а в TUN 28 минут не входило ни одного пакета (iOS, 2026-09-08 16:15–16:43).
// Цифры ниже печатаются в heartbeat — по ним видно, какое звено умерло.
var tunStats struct {
	readerAlive      atomic.Int32 // число живых циклов чтения: 1 норма, 0 мёртв, 2 утечка
	readPackets      atomic.Uint64
	readErrors       atomic.Uint64
	rxCoalesced      atomic.Uint64 // кадров, вырезанных из одного Read сверх первого (ядро 51)
	rxDesync         atomic.Uint64 // битых заголовков потока (resync)
	writePackets     atomic.Uint64
	writeDrops       atomic.Uint64 // запись в TUN не удалась (EAGAIN и прочее)
	tcpLive          atomic.Int32  // соединений в HandleConnection прямо сейчас
	tcpAccepted      atomic.Uint64 // рукопожатий завершено
	tcpHandshakeFail atomic.Uint64 // CreateEndpoint вернул ошибку (таймаут ACK и т.п.)
	tcpRefused       atomic.Uint64 // из них сброс самим приложением (T-083), в журнал — Debug
	synDrop          atomic.Uint64 // SYN отброшен: рукопожатий в полёте уже tcpMaxInFlight
	udpSessions      atomic.Int32
	udpCapDrops      atomic.Uint64 // пакетов отброшено по лимиту UDP-сессий
	udpEvicted       atomic.Uint64 // сессий вытеснено при полной таблице (ядро 72)
	udpDNSReaped     atomic.Uint64 // DNS-сессий закрыто через udpDNSIdle (ядро 72)
	udpQueued        atomic.Int64  // байт в очередях всех UDP-сессий (T-075)
	udpQueueDrops    atomic.Uint64 // пакетов отброшено по потолку байт в очередях (T-075)
}

// Stats — одна строка для heartbeat NE. `synDrop` — SYN, отброшенные из-за
// лимита рукопожатий в полёте (при gVisor это был его ForwardMaxInFlightDrop);
// до ядра 47 это был единственный след того, что лимит сработал.
func Stats() string {
	return fmt.Sprintf(
		"reader=%d rx=%d rxErr=%d rxMulti=%d rxDesync=%d tx=%d txDrop=%d tcpLive=%d tcpAcc=%d hsFail=%d synDrop=%d udp=%d udpDrop=%d udpEvict=%d dnsReap=%d udpQ=%dKB udpQDrop=%d hsRefused=%d",
		tunStats.readerAlive.Load(),
		tunStats.readPackets.Load(),
		tunStats.readErrors.Load(),
		tunStats.rxCoalesced.Load(),
		tunStats.rxDesync.Load(),
		tunStats.writePackets.Load(),
		tunStats.writeDrops.Load(),
		tunStats.tcpLive.Load(),
		tunStats.tcpAccepted.Load(),
		tunStats.tcpHandshakeFail.Load(),
		tunStats.synDrop.Load(),
		tunStats.udpSessions.Load(),
		tunStats.udpCapDrops.Load(),
		tunStats.udpEvicted.Load(),
		tunStats.udpDNSReaped.Load(),
		tunStats.udpQueued.Load()>>10,
		tunStats.udpQueueDrops.Load(),
		tunStats.tcpRefused.Load(),
	)
}

// logEvery — первая ошибка и каждая сотая, чтобы повторяющийся отказ не заливал лог.
func logEvery(n uint64) bool {
	return n == 1 || n%100 == 0
}
