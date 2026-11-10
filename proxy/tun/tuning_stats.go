package tun

import (
	"context"
	goerrors "errors"
	"fmt"
	"io"
	gonet "net"
	"os"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/xtls/xray-core/common/errors"
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
	tcpHandshakeFail atomic.Uint64 // рукопожатие не завершилось (нет ACK на SYN-ACK или RST)
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

// handleTCPConn hands an established connection over, counted in tcpAccepted and tcpLive.
func (s *stack) handleTCPConn(c *tcpConn) {
	tunStats.tcpAccepted.Add(1)
	tunStats.tcpLive.Add(1)
	defer tunStats.tcpLive.Add(-1)
	s.handle(c, c.dst)
}

// vupenTCPAborted counts a handshake that did not complete: no ACK to the SYN-ACK
// (tcpHandshakeFail, as gVisor's CreateEndpoint error was) or a reset from the
// app before the end of the handshake (also tcpRefused, T-083: an extra parallel
// attempt, harmless, so only Debug). A stack that closes is not counted. c.mu is held.
func vupenTCPAborted(c *tcpConn, err error) {
	if c.established || err != errTCPTimeout && err != errTCPReset {
		return
	}
	n := tunStats.tcpHandshakeFail.Add(1)
	if err == errTCPReset {
		tunStats.tcpRefused.Add(1)
		errors.LogDebug(c.stack.ctx, "[tun] handshake reset by the app: ", c.src, " > ", c.dst)
		return
	}
	if logEvery(n) {
		errors.LogInfo(c.stack.ctx, "[tun] handshake failed (", n, "): ", err.Error(), " ", c.src, " > ", c.dst)
	}
}

// isTunReadFatal — дескриптор закрыт или EOF: повторять нечего.
func isTunReadFatal(err error) bool {
	if goerrors.Is(err, io.EOF) || goerrors.Is(err, os.ErrClosed) || goerrors.Is(err, gonet.ErrClosed) {
		return true
	}
	var errno syscall.Errno
	if goerrors.As(err, &errno) {
		return errno == syscall.EBADF
	}
	return false
}

// vupenReadRetry counts a read error and logs the first and every 100th, and
// a fatal one. It returns whether to read again, after a pause that doubles up
// to 250 ms (the gVisor-era dispatchLoop did the same, core 47).
func vupenReadRetry(ctx context.Context, err error, backoff *time.Duration) bool {
	n := tunStats.readErrors.Add(1)
	fatal := isTunReadFatal(err)
	if fatal || logEvery(n) {
		suffix := " — retry"
		if fatal {
			suffix = " — reader stops"
		}
		errors.LogError(ctx, "[tun] read failed (", n, "): ", err.Error(), suffix)
	}
	if fatal {
		return false
	}
	*backoff = min(*backoff*2+5*time.Millisecond, 250*time.Millisecond)
	time.Sleep(*backoff)
	return true
}

// vupenCountingTun counts the writes to the tun: writePackets, writeDrops.
type vupenCountingTun struct{ Tun }

func (t vupenCountingTun) WritePacket(header, payload []byte) error {
	return countWrite(t.Tun.WritePacket(header, payload))
}

// vupenCountingSegmenter is the same for a tun that takes large segments.
type vupenCountingSegmenter struct{ segmenter }

func (t vupenCountingSegmenter) WriteSegment(header []byte, payload [][]byte, mss int) error {
	return countWrite(t.segmenter.WriteSegment(header, payload, mss))
}

func countWrite(err error) error {
	if err != nil {
		tunStats.writeDrops.Add(1)
	} else {
		tunStats.writePackets.Add(1)
	}
	return err
}
