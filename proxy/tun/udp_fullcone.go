package tun

import (
	"context"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
)

type packet struct {
	data []byte
	dest *net.Destination
}

// sub-handler specifically for udp connections under main handler
type udpConnectionHandler struct {
	sync.RWMutex

	udpConns map[net.Destination]*udpConn

	// Vupen: сборщик коротких DNS-сессий работает, только пока они есть.
	dnsReaperRunning bool

	handleConnection func(conn net.Conn, dest net.Destination)
	writePacket      func(data []byte, src net.Destination, dst net.Destination) error
}

func newUdpConnectionHandler(handleConnection func(conn net.Conn, dest net.Destination), writePacket func(data []byte, src net.Destination, dst net.Destination) error) *udpConnectionHandler {
	handler := &udpConnectionHandler{
		udpConns:         make(map[net.Destination]*udpConn),
		handleConnection: handleConnection,
		writePacket:      writePacket,
	}

	return handler
}

// HandlePacket handles UDP packets coming from tun, to forward to the dispatcher
// this custom handler support FullCone NAT of returning packets, binding connection only by the source addr:port
func (u *udpConnectionHandler) HandlePacket(src net.Destination, dst net.Destination, data []byte) {
	u.RLock()
	conn, found := u.udpConns[src]
	if found {
		conn.touch()
		if !conn.enqueue(&packet{data: data, dest: &dst}) {
			errors.LogDebug(context.Background(), "drop udp with size ", len(data), " to ", dst.NetAddr(), " original ", conn.dst.NetAddr(), " > queue full")
		}
		u.RUnlock()
		return
	}
	u.RUnlock()

	u.Lock()
	defer u.Unlock()

	conn, found = u.udpConns[src]
	if !found {
		if len(u.udpConns) >= mobileMaxUDPConns() && !u.evictIdlestLocked() {
			// Vupen: было LogDebug — на рабочем уровне лога переполнение не видно.
			n := tunStats.udpCapDrops.Add(1)
			if logEvery(n) {
				errors.LogWarning(context.Background(), "[tun] drop udp: max sessions ", mobileMaxUDPConns(), " (drops ", n, ")")
			}
			return
		}
		egress := make(chan *packet, mobileUDPEgressDepth())
		conn = &udpConn{handler: u, egress: egress, src: src, dst: dst, dns: dst.Port == 53}
		conn.touch()
		u.udpConns[src] = conn
		tunStats.udpSessions.Store(int32(len(u.udpConns)))
		if conn.dns && !u.dnsReaperRunning {
			u.dnsReaperRunning = true
			go u.reapDNSSessions()
		}

		go u.handleConnection(conn, dst)
	}

	// send packet data to the egress channel, if it has buffer, or discard
	if !conn.enqueue(&packet{data: data, dest: &dst}) {
		errors.LogDebug(context.Background(), "drop udp with size ", len(data), " to ", dst.NetAddr(), " original ", conn.dst.NetAddr(), " > queue full 2")
	}
}

func (u *udpConnectionHandler) connectionFinished(c *udpConn) {
	u.Lock()
	// Vupen: сессию могли уже вытеснить, и под тем же адресом источника теперь
	// живёт новая — её не трогаем.
	if conn, found := u.udpConns[c.src]; found && conn == c {
		u.removeLocked(conn)
	}
	u.Unlock()
}

// closeAll — стек TUN закрывается: убрать все сессии (outbound'ы получают конец,
// байты их очередей возвращаются в общий потолок).
func (u *udpConnectionHandler) closeAll() {
	u.Lock()
	defer u.Unlock()
	for _, c := range u.udpConns {
		u.removeLocked(c)
	}
}

// removeLocked убирает сессию из таблицы и закрывает её очередь: чтение отдаёт
// io.EOF, outbound доделывает своё и выходит. Вызывать под u.Lock().
func (u *udpConnectionHandler) removeLocked(conn *udpConn) {
	delete(u.udpConns, conn.src)
	close(conn.egress)
	// Vupen (T-075): то, что осталось в очереди, outbound уже не прочтёт (он
	// закончил) или это сессия, молчавшая 5–10 с (вытеснение, DNS), — байты
	// возвращаются в общий потолок сразу. Чтение после close отдаёт остаток и
	// конец, так что выбирать вместе с читателем безопасно.
	for e := range conn.egress {
		conn.release(e)
	}
	tunStats.udpSessions.Store(int32(len(u.udpConns)))
}

// Vupen: сроки жизни UDP-сессий в таблице TUN (ядро 72).
//
// Сессия держит место, пока outbound не закроет её по connIdle (300 с). iOS шлёт
// каждый DNS-запрос с нового порта, поэтому каждый запрос — отдельная сессия на
// 5 минут: таблица на 192 места выдерживала ~38 новых UDP-потоков в минуту,
// дальше новые потоки (и DNS) молча отбрасывались, и интернет пропадал до
// переподключения (vSupport iPhone 646, 2026-10-05: udp=192 из 192 с 11:09,
// 3500 отбросов за 20 минут, 77% сессий — порт 53).
const (
	// udpDNSIdle — сколько живёт сессия на порт 53 после последнего пакета.
	// С запасом на медленный ответ: Яндекс через балансировщик — до ~0,7 с,
	// таймаут одного сервера в ядре — 4 с.
	udpDNSIdle = 10 * time.Second
	// udpDNSReapEvery — как часто сборщик смотрит DNS-сессии. Пока их нет,
	// сборщика нет и лишних пробуждений во сне тоже.
	udpDNSReapEvery = 2 * time.Second
	// udpEvictMinIdle — при полной таблице новую сессию пускаем, вытеснив самую
	// давно молчащую, если она молчит хотя бы столько. Если все места заняты
	// живым трафиком, новый поток, как раньше, отбрасывается.
	udpEvictMinIdle = 5 * time.Second
)

// evictIdlestLocked освобождает место под новую сессию. Вызывать под u.Lock().
func (u *udpConnectionHandler) evictIdlestLocked() bool {
	var victim *udpConn
	var oldest int64
	for _, c := range u.udpConns {
		if t := c.lastActive.Load(); victim == nil || t < oldest {
			victim, oldest = c, t
		}
	}
	if victim == nil {
		return false
	}
	idle := time.Since(time.Unix(0, oldest))
	if idle < udpEvictMinIdle {
		return false
	}
	u.removeLocked(victim)
	n := tunStats.udpEvicted.Add(1)
	if logEvery(n) {
		errors.LogWarning(context.Background(), "[tun] udp table full (", mobileMaxUDPConns(), "): evicted session to ", victim.dst.NetAddr(), " idle ", idle.Round(time.Second), " (evictions ", n, ")")
	}
	return true
}

// reapDNSSessions закрывает DNS-сессии, молчащие дольше udpDNSIdle, и выходит,
// когда DNS-сессий не осталось.
func (u *udpConnectionHandler) reapDNSSessions() {
	ticker := time.NewTicker(udpDNSReapEvery)
	defer ticker.Stop()
	for range ticker.C {
		if !u.reapDNSOnce(time.Now()) {
			return
		}
	}
}

// reapDNSOnce — один проход сборщика. Возвращает false, если DNS-сессий больше
// нет и сборщик остановлен.
func (u *udpConnectionHandler) reapDNSOnce(now time.Time) bool {
	u.Lock()
	defer u.Unlock()
	left := 0
	for _, c := range u.udpConns {
		if !c.dns {
			continue
		}
		if now.Sub(time.Unix(0, c.lastActive.Load())) >= udpDNSIdle {
			u.removeLocked(c)
			tunStats.udpDNSReaped.Add(1)
			continue
		}
		left++
	}
	if left == 0 {
		u.dnsReaperRunning = false
		return false
	}
	return true
}

// udp connection abstraction
type udpConn struct {
	handler *udpConnectionHandler

	egress chan *packet
	src    net.Destination
	dst    net.Destination

	// Vupen: dns — сессия на порт 53, у неё короткий срок жизни; lastActive —
	// время последнего пакета в любую сторону, UnixNano.
	dns        bool
	lastActive atomic.Int64
}

// enqueue — в очередь сессии, если есть место и в ней, и в общем потолке байт
// (mobileUDPQueueMaxBytes). Звать под u.RLock или u.Lock (очередь не закрыта).
func (c *udpConn) enqueue(p *packet) bool {
	n := int64(len(p.data))
	if tunStats.udpQueued.Add(n) > mobileUDPQueueMaxBytes() {
		tunStats.udpQueued.Add(-n)
		if d := tunStats.udpQueueDrops.Add(1); logEvery(d) {
			errors.LogWarning(context.Background(), "[tun] drop udp: queued bytes cap ", mobileUDPQueueMaxBytes()>>10, " KB (drops ", d, ")")
		}
		return false
	}
	select {
	case c.egress <- p:
		return true
	default:
		tunStats.udpQueued.Add(-n)
		return false
	}
}

// release — пакет ушёл из очереди (прочитан outbound'ом или выброшен при закрытии).
func (c *udpConn) release(p *packet) {
	tunStats.udpQueued.Add(-int64(len(p.data)))
}

func (c *udpConn) touch() {
	c.lastActive.Store(time.Now().UnixNano())
}

func (c *udpConn) ReadMultiBuffer() (buf.MultiBuffer, error) {
	for {
		e, ok := <-c.egress
		if !ok {
			return nil, io.EOF
		}
		c.release(e)

		b := buf.New()
		if _, err := b.Write(e.data); err != nil {
			errors.LogErrorInner(context.Background(), err, "drop packet to ", e.dest, " with size ", len(e.data))
			b.Release()
			continue
		}
		b.UDP = e.dest

		return buf.MultiBuffer{b}, nil
	}
}

// Read packets from the connection
func (c *udpConn) Read(p []byte) (int, error) {
	e, ok := <-c.egress
	if !ok {
		return 0, io.EOF
	}
	c.release(e)
	n := copy(p, e.data)
	if n != len(e.data) {
		return 0, io.ErrShortBuffer
	}
	return n, nil
}

func (c *udpConn) WriteMultiBuffer(mb buf.MultiBuffer) error {
	for i, b := range mb {
		dst := c.dst
		if b.UDP != nil {
			if b.UDP.Address.Family().IsDomain() {
				errors.LogError(context.Background(), "impossible domain packet ", b.UDP, " reply via original target ", dst)
			} else {
				dst = *b.UDP
			}
		}
		c.touch()
		err := c.handler.writePacket(b.Bytes(), dst, c.src)
		if err != nil {
			buf.ReleaseMulti(mb[i:])
			return err
		}
		b.Release()
	}
	return nil
}

// Write returning packets back
func (c *udpConn) Write(p []byte) (int, error) {
	// sending packets back mean sending payload with source/destination reversed
	c.touch()
	err := c.handler.writePacket(p, c.dst, c.src)
	if err != nil {
		return 0, nil
	}

	return len(p), nil
}

func (c *udpConn) Close() error {
	c.handler.connectionFinished(c)

	return nil
}

func (c *udpConn) LocalAddr() net.Addr {
	return c.dst.RawNetAddr()
}

func (c *udpConn) RemoteAddr() net.Addr {
	return c.src.RawNetAddr()
}

func (c *udpConn) SetDeadline(t time.Time) error {
	return nil
}

func (c *udpConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *udpConn) SetWriteDeadline(t time.Time) error {
	return nil
}
