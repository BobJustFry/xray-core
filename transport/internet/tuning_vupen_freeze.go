package internet

import (
	"context"
	stderrors "errors"
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

	// Ядро 76 (D-19, для всех балансировщиков; ADR-0001 §4.4 (2) П2): узел
	// подозреваем, только когда замолчали VupenFreezeConns разных соединений к
	// нему за VupenFreezeConnsWindow. Одно замолчавшее соединение — ещё не
	// заморозка (бандлы OPUSPLAN §3: 242 ложных срабатывания на здоровом узле).
	VupenFreezeConns       = 2
	VupenFreezeConnsWindow = 30 * time.Second
	// VupenFreezeHandshakeSilence — соединение к узлу отправило данные, а за это
	// время не получило ни байта (рукопожатие TLS/REALITY висит): неудачная
	// попытка для П1 (ядро 76). По умолчанию — как VupenFreezeSilence.
	VupenFreezeHandshakeSilence = 7 * time.Second
	// VupenFreezeLoneSilence — исключение из правила двух соединений (CR-301,
	// решение владельца): узел, весь трафик которого идёт одним соединением
	// (gRPC, mux.cool, XHTTP с maxConcurrency при слабом трафике), подозреваем и
	// по одному замолчавшему соединению — если это единственное наблюдаемое
	// соединение к узлу с данными во время его тишины (любое другое, получившее
	// за это время хоть байт, тревогу снимает). Тишина дольше обычной — осторожнее.
	VupenFreezeLoneSilence = 15 * time.Second
)

// vupenServiceKey — метка контекста служебных соединений ядра (пробы
// обсерватории, проверки 24 и 64 КБ): сторож их не наблюдает и признаком
// отказа их ошибки не считаются (ADR-0001 §4.4 (2) П2 (а)).
type vupenServiceKey struct{}

// VupenServiceContext — соединения, открытые в этом контексте, служебные.
func VupenServiceContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, vupenServiceKey{}, true)
}

func vupenIsService(ctx context.Context) bool {
	v, _ := ctx.Value(vupenServiceKey{}).(bool)
	return v
}

// VupenIsServiceContext — соединения этого контекста служебные (для тестов и журнала).
func VupenIsServiceContext(ctx context.Context) bool { return vupenIsService(ctx) }

// VupenFreezeHooks — связь со слоем обсерватории, который сюда импортировать
// нельзя (он сам зависит от transport/internet).
type VupenFreezeHooks struct {
	// Watch — наблюдать ли соединение outbound'а tag в этом ядре (ctx несёт
	// экземпляр ядра). Возвращает ключ для Suspect или nil.
	Watch func(ctx context.Context, tag string) any
	// Suspect — соединения этого outbound'а замолчали по рисунку заморозки
	// (не меньше VupenFreezeConns разных за VupenFreezeConnsWindow).
	Suspect func(key any, tag string, sent, recv int64)
	// Attempt — итог установления соединения к узлу (ядро 76, признак П1):
	// ok — узел ответил хоть байтом; !ok — соединение не установилось.
	// Может быть nil.
	Attempt func(key any, tag string, ok bool, detail string)
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
	// lastRecv — когда пришёл последний байт ответа (ядро 76, CR-301).
	lastRecv atomic.Int64
	fired    atomic.Bool
	// loneFired — тревога по одному соединению уже была (CR-301).
	loneFired atomic.Bool
	// answered — узел ответил хоть байтом (ядро 76: успешная попытка для П1).
	answered atomic.Bool
	// noReply — уже сообщили «отправили, а ответа нет» (П1, ядро 76).
	noReply atomic.Bool
	// attempt — попытка outbound-обработчика, к которой относится соединение
	// (VupenTransportAttempt): одна попытка считается один раз (CR-302).
	attempt *vupenAttempt
}

func (c *vupenFreezeConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		now := time.Now().UnixNano()
		c.recv.Add(int64(n))
		c.pendingSince.Store(0)
		c.lastActive.Store(now)
		c.lastRecv.Store(now)
		if !c.answered.Load() && c.answered.CompareAndSwap(false, true) {
			vupenFreezeAttempt(c.key, c.tag, true, "")
		}
	}
	if err != nil && !vupenIsTimeoutErr(err) {
		// Ядро 76: соединение кончилось (EOF, сброс) — замёрзнуть оно уже не может.
		// Убираем из наблюдения сразу: рукопожатие TLS/REALITY с ошибкой не
		// закрывает сырое соединение, и оно висело бы в списке до 30 минут.
		// Таймаут чтения (дедлайн) — не конец соединения: наблюдаем дальше.
		vupenFreezeWatch.remove(c)
	}
	return n, err
}

func vupenIsTimeoutErr(err error) bool {
	var ne interface{ Timeout() bool }
	return stderrors.As(err, &ne) && ne.Timeout()
}

func (c *vupenFreezeConn) Write(b []byte) (int, error) {
	// Ядро 76 (D-25): отметка «ждём ответа» — до записи. Ответ может прийти,
	// пока Write ещё не вернулся (его прочтёт другая горутина); тогда Read её
	// снимет. Отметка после записи переживала такой ответ, и соединение, где всё
	// отвечено, выглядело молчащим (ложная тревога; T-019).
	var mark int64
	if len(b) > 0 {
		mark = time.Now().UnixNano()
		if !c.pendingSince.CompareAndSwap(0, mark) {
			mark = 0 // отметка уже стоит с прошлой записи
		}
	}
	n, err := c.Conn.Write(b)
	if n > 0 {
		c.sent.Add(int64(n))
		c.lastActive.Store(time.Now().UnixNano())
	} else if mark != 0 {
		c.pendingSince.CompareAndSwap(mark, 0) // ничего не ушло — и ждать нечего
	}
	return n, err
}

func (c *vupenFreezeConn) Close() error {
	vupenFreezeWatch.remove(c)
	return c.Conn.Close()
}

// vupenFreezeSuspicious — рисунок заморозки на момент now. Чистая функция, под тест.
//
// Ядро 76 (D-19, П2 (б)): только соединения с данными в обе стороны до тишины —
// поток, который только отправляет, ответа и не ждёт.
func vupenFreezeSuspicious(sent, recv, pendingSince, now int64) bool {
	if pendingSince == 0 || now-pendingSince < int64(VupenFreezeSilence) {
		return false
	}
	if sent <= 0 || recv <= 0 {
		return false
	}
	total := sent + recv
	return total >= VupenFreezeMinBytes && total <= VupenFreezeMaxBytes
}

// vupenFreezeAttempt — сообщить итог попытки соединения (П1), если есть кому.
func vupenFreezeAttempt(key any, tag string, ok bool, detail string) {
	if h := vupenFreezeHooks.Load(); h != nil && h.Attempt != nil {
		h.Attempt(key, tag, ok, detail)
	}
}

// vupenAttempt — одна попытка установить транспорт к узлу (Handler.Dial).
type vupenAttempt struct{ failed atomic.Bool }

type vupenAttemptKey struct{}

func vupenNoAttempt(error) {}

// VupenTransportAttempt — попытка outbound-обработчика tag установить транспорт
// (ядро 76, признаки П1/П5). Вызывается перед internet.Dial; возвращённую
// функцию зовут с его итогом: TCP-соединение, рукопожатие TLS/REALITY,
// QUIC-рукопожатие Hysteria/H3 (ошибок назначения здесь нет). Только для АВТО 4.1
// и не для служебных соединений; иначе ctx как есть и пустая функция. Отмена
// вызывающим — не отказ. «Ни байта ответа» (сторож) и поздняя ошибка той же
// попытки считаются одной неудачей (CR-302).
func VupenTransportAttempt(ctx context.Context, tag string) (context.Context, func(error)) {
	if !vupenNet.active.Load() || tag == "" || vupenIsService(ctx) {
		return ctx, vupenNoAttempt
	}
	hooks := vupenFreezeHooks.Load()
	if hooks == nil || hooks.Watch == nil || hooks.Attempt == nil || !vupenNetAuto41(ctx) {
		return ctx, vupenNoAttempt
	}
	a := &vupenAttempt{}
	ctx = context.WithValue(ctx, vupenAttemptKey{}, a)
	return ctx, func(err error) {
		if err != nil && (stderrors.Is(err, context.Canceled) || ctx.Err() == context.Canceled) {
			return
		}
		if err != nil && !a.failed.CompareAndSwap(false, true) {
			return // эту попытку уже посчитал сторож («ни байта ответа»)
		}
		key := hooks.Watch(ctx, tag)
		if key == nil {
			return
		}
		if err != nil {
			hooks.Attempt(key, tag, false, "transport: "+err.Error())
		} else {
			hooks.Attempt(key, tag, true, "")
		}
	}
}

// vupenFreezeNode — узел в наблюдении: обсерватория и тег.
type vupenFreezeNode struct {
	key any
	tag string
}

type vupenFreezeSet struct {
	mu      sync.Mutex
	conns   map[*vupenFreezeConn]struct{}
	running bool
	// recent — когда замолчали соединения узла (ядро 76): узел подозреваем,
	// когда их набралось VupenFreezeConns за VupenFreezeConnsWindow.
	recent map[vupenFreezeNode][]int64
}

var vupenFreezeWatch = &vupenFreezeSet{conns: map[*vupenFreezeConn]struct{}{}, recent: map[vupenFreezeNode][]int64{}}

// noteSilentLocked — соединение c замолчало; true — пора сообщить об узле.
func (s *vupenFreezeSet) noteSilentLocked(c *vupenFreezeConn, now int64) bool {
	node := vupenFreezeNode{c.key, c.tag}
	kept := s.recent[node][:0]
	for _, at := range s.recent[node] {
		if now-at <= int64(VupenFreezeConnsWindow) {
			kept = append(kept, at)
		}
	}
	kept = append(kept, now)
	if len(kept) >= VupenFreezeConns {
		delete(s.recent, node)
		return true
	}
	s.recent[node] = kept
	return false
}

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
			s.recent = map[vupenFreezeNode][]int64{}
			s.mu.Unlock()
			return
		}
		now := time.Now().UnixNano()
		var fire, noReply []*vupenFreezeConn
		// CR-301: последний ответ по каждому узлу — снимает тревогу «одного соединения».
		lastRecv := map[vupenFreezeNode]int64{}
		for c := range s.conns {
			node := vupenFreezeNode{c.key, c.tag}
			if r := c.lastRecv.Load(); r > lastRecv[node] {
				lastRecv[node] = r
			}
		}
		for c := range s.conns {
			if now-c.lastActive.Load() > int64(vupenFreezeForgetAfter) {
				delete(s.conns, c)
				continue
			}
			// Ядро 76 (П1): отправили, а за VupenFreezeHandshakeSilence ни байта ответа.
			if c.recv.Load() == 0 && !c.noReply.Load() {
				if ps := c.pendingSince.Load(); ps != 0 && now-ps >= int64(VupenFreezeHandshakeSilence) {
					c.noReply.Store(true)
					if c.attempt == nil || c.attempt.failed.CompareAndSwap(false, true) {
						noReply = append(noReply, c)
					}
				}
			}
			if c.fired.Load() {
				// CR-301: уже замолчало, но второго нет. Единственное соединение узла
				// с данными во время тишины и тишина дольше VupenFreezeLoneSilence —
				// тоже тревога (один раз на соединение).
				if ps := c.pendingSince.Load(); !c.loneFired.Load() && ps != 0 &&
					now-ps >= int64(VupenFreezeLoneSilence) &&
					lastRecv[vupenFreezeNode{c.key, c.tag}] <= ps &&
					vupenFreezeSuspicious(c.sent.Load(), c.recv.Load(), ps, now) {
					c.loneFired.Store(true)
					delete(s.recent, vupenFreezeNode{c.key, c.tag})
					fire = append(fire, c)
				}
				continue
			}
			if vupenFreezeSuspicious(c.sent.Load(), c.recv.Load(), c.pendingSince.Load(), now) {
				c.fired.Store(true)
				if s.noteSilentLocked(c, now) {
					fire = append(fire, c)
				}
			}
		}
		s.mu.Unlock()
		for _, c := range noReply {
			vupenFreezeAttempt(c.key, c.tag, false, "no reply after send")
		}
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
	if hooks == nil || hooks.Watch == nil || conn == nil || dest.Network != net.Network_TCP || vupenIsService(ctx) {
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
	c.attempt, _ = ctx.Value(vupenAttemptKey{}).(*vupenAttempt)
	c.lastActive.Store(time.Now().UnixNano())
	vupenFreezeWatch.add(c)
	return c
}
