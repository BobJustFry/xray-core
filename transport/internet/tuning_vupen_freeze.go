package internet

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
)

// Vupen (ядро 71): сторож заморозки ТСПУ на соединениях к узлам.
//
// ТСПУ не рвёт соединение с зарубежным адресом хостинга, а после ~15–20 КБ в
// одном TCP-соединении перестаёт пропускать данные: RST нет, соединение просто
// молчит (net4people/bbs#490). Короткие пробы балансировщика в этот порог
// укладываются, поэтому замороженный узел выглядел для него живым и быстрым —
// бандл iPhone 2026-09-27 23:30:49: leastLoad перешёл на такой узел, и через
// 45 секунд интернета не стало.
//
// Сторож считает байты на самом TCP-соединении к узлу (под TLS/REALITY/XHTTP —
// ровно то, что видит ТСПУ) и замечает рисунок заморозки: мы отправили данные,
// а в ответ за VupenFreezeSilence не пришло ничего, и по соединению к этому
// моменту прошло от VupenFreezeMinBytes до VupenFreezeMaxBytes. Сам он ничего не
// банит — только сообщает обсерватории (Suspect), а та проверяет узел загрузкой
// через него и уже по её итогу решает. Ложная тревога стоит одной проверки.
var (
	VupenFreezeMinBytes = int64(12 << 10)
	VupenFreezeMaxBytes = int64(64 << 10)
	VupenFreezeSilence  = 7 * time.Second
	// Соединение, по которому давно ничего не шло, из наблюдения убираем, даже
	// если его забыли закрыть, — чтобы список не рос.
	vupenFreezeForgetAfter = 30 * time.Minute
	vupenFreezeScanEvery   = time.Second
)

// VupenFreezeHooks — связь со слоем обсерватории, который сюда импортировать
// нельзя (он сам зависит от transport/internet).
type VupenFreezeHooks struct {
	// Watch — наблюдать ли соединение outbound'а tag в этом ядре (ctx несёт
	// экземпляр ядра). Возвращает ключ для Suspect или nil.
	Watch func(ctx context.Context, tag string) any
	// Suspect — соединение этого outbound'а замолчало по рисунку заморозки.
	Suspect func(key any, tag string, sent, recv int64)
}

var vupenFreezeHooks atomic.Pointer[VupenFreezeHooks]

// VupenSetFreezeHooks — ставит обсерватория (burst) при загрузке пакета.
func VupenSetFreezeHooks(h *VupenFreezeHooks) { vupenFreezeHooks.Store(h) }

type vupenFreezeConn struct {
	net.Conn
	key  any
	tag  string
	sent atomic.Int64
	recv atomic.Int64
	// pendingSince — первая запись после последнего чтения (unix nano); 0 — ждать
	// нечего: всё отправленное уже получило хоть какой-то ответ.
	pendingSince atomic.Int64
	lastActive   atomic.Int64
	fired        atomic.Bool
}

func (c *vupenFreezeConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.recv.Add(int64(n))
		c.pendingSince.Store(0)
		c.lastActive.Store(time.Now().UnixNano())
	}
	return n, err
}

func (c *vupenFreezeConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if n > 0 {
		now := time.Now().UnixNano()
		c.sent.Add(int64(n))
		c.pendingSince.CompareAndSwap(0, now)
		c.lastActive.Store(now)
	}
	return n, err
}

func (c *vupenFreezeConn) Close() error {
	vupenFreezeWatch.remove(c)
	return c.Conn.Close()
}

// vupenFreezeSuspicious — рисунок заморозки на момент now. Чистая функция, под тест.
func vupenFreezeSuspicious(sent, recv, pendingSince, now int64) bool {
	if pendingSince == 0 || now-pendingSince < int64(VupenFreezeSilence) {
		return false
	}
	total := sent + recv
	return total >= VupenFreezeMinBytes && total <= VupenFreezeMaxBytes
}

type vupenFreezeSet struct {
	mu      sync.Mutex
	conns   map[*vupenFreezeConn]struct{}
	running bool
}

var vupenFreezeWatch = &vupenFreezeSet{conns: map[*vupenFreezeConn]struct{}{}}

func (s *vupenFreezeSet) add(c *vupenFreezeConn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.conns[c] = struct{}{}
	if !s.running {
		s.running = true
		go s.loop()
	}
}

func (s *vupenFreezeSet) remove(c *vupenFreezeConn) {
	s.mu.Lock()
	delete(s.conns, c)
	s.mu.Unlock()
}

// loop — один проход в секунду по всем наблюдаемым соединениям; выходит, когда
// наблюдать нечего (следующее соединение запустит его снова).
func (s *vupenFreezeSet) loop() {
	t := time.NewTicker(vupenFreezeScanEvery)
	defer t.Stop()
	for range t.C {
		s.mu.Lock()
		if len(s.conns) == 0 {
			s.running = false
			s.mu.Unlock()
			return
		}
		now := time.Now().UnixNano()
		var fire []*vupenFreezeConn
		for c := range s.conns {
			if now-c.lastActive.Load() > int64(vupenFreezeForgetAfter) {
				delete(s.conns, c)
				continue
			}
			if c.fired.Load() {
				continue
			}
			if vupenFreezeSuspicious(c.sent.Load(), c.recv.Load(), c.pendingSince.Load(), now) {
				c.fired.Store(true)
				fire = append(fire, c)
			}
		}
		s.mu.Unlock()
		hooks := vupenFreezeHooks.Load()
		for _, c := range fire {
			if hooks != nil && hooks.Suspect != nil {
				hooks.Suspect(c.key, c.tag, c.sent.Load(), c.recv.Load())
			}
		}
	}
}

// vupenFreezeWrap — обернуть TCP-соединение к узлу, если его outbound
// наблюдает обсерватория этого ядра; иначе вернуть как есть.
func vupenFreezeWrap(ctx context.Context, conn net.Conn, dest net.Destination) net.Conn {
	hooks := vupenFreezeHooks.Load()
	if hooks == nil || hooks.Watch == nil || conn == nil || dest.Network != net.Network_TCP {
		return conn
	}
	outbounds := session.OutboundsFromContext(ctx)
	if len(outbounds) == 0 {
		return conn
	}
	tag := outbounds[len(outbounds)-1].Tag
	if tag == "" {
		return conn
	}
	key := hooks.Watch(ctx, tag)
	if key == nil {
		return conn
	}
	c := &vupenFreezeConn{Conn: conn, key: key, tag: tag}
	c.lastActive.Store(time.Now().UnixNano())
	vupenFreezeWatch.add(c)
	return c
}
