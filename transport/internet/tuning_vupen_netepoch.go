package internet

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
	"weak"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
)

// Vupen (ядро 74, АВТО 4.1; ADR-0001 §9.1, §13; D-18, D-19): эпохи сети.
//
// Под VPN приложения говорят с TUN, а он при смене Wi-Fi ↔ сотовая не
// меняется. Исходящие соединения ядра остаются привязаны к прежнему
// физическому интерфейсу и после смены сети часто умирают молча — приложение
// висит до своего тайм-аута. Платформа сообщает ядру тип и подпись пути
// (VupenSetUplink); каждое исходящее соединение запоминает сеть, под которой
// открыто. Когда новая сеть продержалась VupenNetChangeCloseStableSec без
// смены, ядро закрывает все соединения, открытые под другой сетью, — и к
// узлам, и прямые (`direct`). Приложение получает сброс и сразу
// переподключается через новую сеть.
//
// Мигание: вернулись к прежней сети раньше 9 с — ничего не закрываем. Новая
// смена до истечения — отсчёт заново.
//
// Работает, только если (1) платформа хоть раз вызвала VupenSetUplink и
// (2) соединение открыто экземпляром ядра с АВТО 4.1 (хук Auto41 ставит
// app/router). Иначе DialSystem — тот же путь, плюс одна атомарная проверка.
// Соединения не оборачиваются: тип, который получает вызывающий, не меняется.

// VupenNetChangeCloseStableSec — сколько секунд новая сеть должна продержаться
// без смены, прежде чем закрыть соединения прежней сети (D-18). По тому же
// таймеру АВТО 4.1 повторяет поиск, если ничего не работает (ADR-0001 §4.4 (6) В3).
// Переменная, а не константа: значение ещё может поменять владелец.
var VupenNetChangeCloseStableSec = 9

// VupenNetEvent — событие эпохи сети для подписчиков (app/router, АВТО 4.1).
type VupenNetEvent int

const (
	// VupenNetChanged — тип или подпись сети сменились (сразу, в том числе на мигании).
	VupenNetChanged VupenNetEvent = iota + 1
	// VupenNetStable — новая сеть продержалась VupenNetChangeCloseStableSec
	// (тот же момент, когда закрываются соединения прежней сети).
	VupenNetStable
)

var vupenNetSubs = struct {
	mu   sync.Mutex
	next uint64
	m    map[uint64]func(VupenNetEvent)
}{m: map[uint64]func(VupenNetEvent){}}

// VupenNetEpochSubscribe — получать события эпохи сети. f вызывается вне
// блокировок, из горутины таймера или VupenSetUplink, и не должна блокировать.
// Возвращает отписку.
func VupenNetEpochSubscribe(f func(VupenNetEvent)) (unsubscribe func()) {
	vupenNetSubs.mu.Lock()
	vupenNetSubs.next++
	id := vupenNetSubs.next
	vupenNetSubs.m[id] = f
	vupenNetSubs.mu.Unlock()
	return func() {
		vupenNetSubs.mu.Lock()
		delete(vupenNetSubs.m, id)
		vupenNetSubs.mu.Unlock()
	}
}

func vupenNetNotify(ev VupenNetEvent) {
	vupenNetSubs.mu.Lock()
	fs := make([]func(VupenNetEvent), 0, len(vupenNetSubs.m))
	for _, f := range vupenNetSubs.m {
		fs = append(fs, f)
	}
	vupenNetSubs.mu.Unlock()
	for _, f := range fs {
		f(ev)
	}
}

// VupenNetEpochHooks — связь со слоем, который знает конфиг экземпляра ядра
// (сюда core импортировать нельзя: он сам зависит от transport/internet).
type VupenNetEpochHooks struct {
	// Auto41 — включён ли АВТО 4.1 в экземпляре ядра, к которому относится ctx.
	Auto41 func(ctx context.Context) bool
}

var vupenNetEpochHooks atomic.Pointer[VupenNetEpochHooks]

// VupenSetNetEpochHooks — ставит app/router при загрузке пакета.
func VupenSetNetEpochHooks(h *VupenNetEpochHooks) { vupenNetEpochHooks.Store(h) }

// Точки подмены для тестов.
var (
	vupenNetNow   = time.Now
	vupenNetAfter = func(d time.Duration, f func()) (stop func() bool) {
		return time.AfterFunc(d, f).Stop
	}
)

// vupenNetID — сеть: тип и подпись пути.
type vupenNetID struct{ kind, sig string }

func (id vupenNetID) String() string { return id.kind + " sig=" + id.sig }

// vupenNetSnap — то, что читает путь установления соединения (без блокировки).
type vupenNetSnap struct {
	id     vupenNetID
	sweeps uint64
}

type vupenNetEntry struct {
	id  vupenNetID
	get func() net.Conn // nil — сокет уже собран сборщиком мусора
	idx any             // ключ в index (слабый указатель на сокет)
}

type vupenNetState struct {
	active atomic.Bool
	snap   atomic.Pointer[vupenNetSnap]

	mu      sync.Mutex
	current vupenNetID
	// base — сеть, на которой последний раз отработало закрытие (или первая
	// сообщённая): с ней сравнивается возврат.
	base         vupenNetID
	epoch        uint64
	leftBaseAt   time.Time
	stopPending  func() bool
	sweeps       uint64
	entries      map[uint64]*vupenNetEntry
	index        map[any]uint64 // слабый указатель на сокет → ключ записи
	untrackedLog bool
}

func newVupenNetState() *vupenNetState {
	return &vupenNetState{entries: map[uint64]*vupenNetEntry{}, index: map[any]uint64{}}
}

var (
	vupenNet = newVupenNetState()
	// Ключи записей реестра — сквозные на процесс (очистка записи может прийти позже).
	vupenNetEntrySeq atomic.Uint64
)

// VupenSetUplink — платформа сообщает тип сети (cellular | wifi | wired |
// other | none) и подпись пути; пустая подпись = тип. Смена типа или подписи —
// новая эпоха сети.
func VupenSetUplink(kind, sig string) {
	vupenNet.setUplink(kind, sig)
}

func (s *vupenNetState) publishLocked() {
	s.snap.Store(&vupenNetSnap{id: s.current, sweeps: s.sweeps})
}

func (s *vupenNetState) setUplink(kind, sig string) {
	if sig == "" {
		sig = kind
	}
	id := vupenNetID{kind: kind, sig: sig}

	s.mu.Lock()
	now := vupenNetNow()
	if !s.active.Load() {
		s.current, s.base, s.epoch = id, id, 1
		s.publishLocked()
		s.active.Store(true)
		s.mu.Unlock()
		errors.LogWarning(context.Background(), "[netchange] uplink unknown→", id, " epoch=1")
		return
	}
	if id == s.current {
		s.mu.Unlock()
		return
	}
	old := s.current
	s.current = id
	s.epoch++
	epoch := s.epoch
	hadPending := s.stopPending != nil
	if hadPending {
		s.stopPending()
		s.stopPending = nil
	}
	if id == s.base {
		// Мигание: вернулись к сети, на которой соединения открыты, — закрывать нечего.
		away := now.Sub(s.leftBaseAt)
		s.publishLocked()
		s.mu.Unlock()
		errors.LogWarning(context.Background(), "[netchange] uplink ", old.kind, "→", id, " epoch=", epoch)
		if hadPending {
			errors.LogWarning(context.Background(), "[netchange] close cancelled: back to ", id.sig,
				" after ", away.Milliseconds(), " ms")
		}
		vupenNetNotify(VupenNetChanged)
		return
	}
	if !hadPending {
		s.leftBaseAt = now
	}
	s.stopPending = vupenNetAfter(time.Duration(VupenNetChangeCloseStableSec)*time.Second, func() { s.stable(epoch) })
	s.publishLocked()
	s.mu.Unlock()
	errors.LogWarning(context.Background(), "[netchange] uplink ", old.kind, "→", id, " epoch=", epoch)
	vupenNetNotify(VupenNetChanged)
}

// stable — сеть эпохи epoch продержалась 9 с: закрыть соединения других сетей.
func (s *vupenNetState) stable(epoch uint64) {
	s.mu.Lock()
	if epoch != s.epoch || s.stopPending == nil {
		// Уже была новая смена (её таймер Stop не успел остановить этот).
		s.mu.Unlock()
		return
	}
	s.stopPending = nil
	s.base = s.current
	s.sweeps++
	var closing []net.Conn
	for key, e := range s.entries {
		if e.id == s.current {
			continue
		}
		delete(s.entries, key)
		delete(s.index, e.idx)
		if c := e.get(); c != nil {
			closing = append(closing, c)
		}
	}
	cur := s.current
	s.publishLocked()
	s.mu.Unlock()

	for _, c := range closing {
		c.Close()
	}
	errors.LogWarning(context.Background(), fmt.Sprintf(
		"[netchange] stable %ds on %s: closed %d connections (reason=net-change)",
		VupenNetChangeCloseStableSec, cur.sig, len(closing)))
	vupenNetNotify(VupenNetStable)
}

// vupenNetAuto41Ctx — метка контекста: соединение открывает экземпляр с АВТО 4.1
// (для дайлеров, у которых в контексте нет экземпляра ядра: gRPC, udphop).
type vupenNetAuto41Ctx struct{}

func vupenNetAuto41(ctx context.Context) bool {
	if v, _ := ctx.Value(vupenNetAuto41Ctx{}).(bool); v {
		return true
	}
	h := vupenNetEpochHooks.Load()
	return h != nil && h.Auto41 != nil && h.Auto41(ctx)
}

// VupenNetEpochCarry — перенести в dialCtx решение «АВТО 4.1» из ctx запроса.
// Для дайлеров, которые открывают сокет в своём контексте (gRPC). Без вызова
// VupenSetUplink и для экземпляров без АВТО 4.1 возвращает dialCtx как есть.
func VupenNetEpochCarry(dialCtx, ctx context.Context) context.Context {
	if !vupenNet.active.Load() || !vupenNetAuto41(ctx) {
		return dialCtx
	}
	return context.WithValue(dialCtx, vupenNetAuto41Ctx{}, true)
}

// VupenNetEpochContextFor — контекст для сокета, который открывается взамен pc
// (udphop: смена порта). Если pc отслеживается — новый сокет тоже; иначе
// context.Background(), как было.
func VupenNetEpochContextFor(pc any) context.Context {
	ctx := context.Background()
	if !vupenNet.active.Load() {
		return ctx
	}
	var idx any
	switch c := pc.(type) {
	case *net.UDPConn:
		idx = weak.Make(c)
	case *net.TCPConn:
		idx = weak.Make(c)
	default:
		return ctx
	}
	vupenNet.mu.Lock()
	_, ok := vupenNet.index[idx]
	vupenNet.mu.Unlock()
	if !ok {
		return ctx
	}
	return context.WithValue(ctx, vupenNetAuto41Ctx{}, true)
}

// vupenNetEpochBeforeDial — снимок сети перед установлением соединения или nil,
// если соединение не отслеживается (API не вызывался или ядро не АВТО 4.1).
func vupenNetEpochBeforeDial(ctx context.Context) *vupenNetSnap {
	if !vupenNet.active.Load() || !vupenNetAuto41(ctx) {
		return nil
	}
	return vupenNet.snap.Load()
}

// vupenNetEpochTrack — запомнить соединение под сетью снимка. Ошибка —
// соединение открыто под прежней сетью, а её закрытие уже прошло: оно закрыто,
// вызывающий получает ошибку установления.
//
// Снимок берётся до dialSystem, то есть и до разрешения имени (DNS) и до
// connect: сокет привязан к пути, который был, когда установление началось.
// Если сеть сменилась посреди установления, соединение считается открытым под
// прежней сетью и закрывается вместе с ней — в худшем случае закроем одно
// соединение, которое успело уйти уже по новой сети (приложение
// переподключится), но не оставим висеть соединение мёртвой сети.
func vupenNetEpochTrack(conn net.Conn, snap *vupenNetSnap) error {
	if conn == nil || snap == nil {
		return nil
	}
	s := vupenNet
	s.mu.Lock()
	if s.sweeps != snap.sweeps && snap.id != s.base {
		// Пока соединение устанавливалось, закрытие прежней сети уже прошло.
		base := s.base
		s.mu.Unlock()
		conn.Close()
		return errors.New("[netchange] connection opened on ", snap.id.sig,
			", closed after the switch to ", base.sig).AtWarning()
	}
	key := vupenNetEntrySeq.Add(1)
	get, idx := vupenNetWeakConn(conn, key)
	if get == nil {
		logIt := !s.untrackedLog
		s.untrackedLog = true
		s.mu.Unlock()
		if logIt {
			errors.LogInfo(context.Background(), fmt.Sprintf("[netchange] connection type %T is not tracked", conn))
		}
		return nil
	}
	s.entries[key] = &vupenNetEntry{id: snap.id, get: get, idx: idx}
	s.index[idx] = key
	s.mu.Unlock()
	return nil
}

// vupenNetForget — сокет собран сборщиком мусора: убрать запись.
func vupenNetForget(key uint64) {
	s := vupenNet
	s.mu.Lock()
	if e, ok := s.entries[key]; ok {
		delete(s.entries, key)
		delete(s.index, e.idx)
	}
	s.mu.Unlock()
}

// vupenNetWeakConn — слабые ссылки на соединение: реестр не держит его в
// памяти, а запись удаляется, когда собран сам сокет. Отслеживается сокет, а не
// обёртка: многие транспорты (hysteria, QUIC в XHTTP, mKCP, udpmask, wireguard)
// берут из *PacketConnWrapper только PacketConn, и обёртка собирается раньше,
// чем перестаёт работать сокет. Только известные типы системного дайлера;
// иначе nil (не отслеживаем).
func vupenNetWeakConn(conn net.Conn, key uint64) (func() net.Conn, any) {
	switch c := conn.(type) {
	case *net.TCPConn:
		return vupenNetWeak(c, key)
	case *net.UDPConn:
		return vupenNetWeak(c, key)
	case *PacketConnWrapper:
		if u, ok := c.PacketConn.(*net.UDPConn); ok {
			return vupenNetWeak(u, key)
		}
	case *vupenFreezeConn:
		if inner, ok := c.Conn.(*net.TCPConn); ok {
			// Закрываем обёртку, пока она жива (так она уходит и из списка
			// сторожа), иначе — сам сокет.
			getInner, idx := vupenNetWeak(inner, key)
			w := weak.Make(c)
			return func() net.Conn {
				if v := w.Value(); v != nil {
					return v
				}
				return getInner()
			}, idx
		}
	}
	return nil, nil
}

func vupenNetWeak[T any, P interface {
	*T
	net.Conn
}](p P, key uint64) (func() net.Conn, any) {
	w := weak.Make((*T)(p))
	runtime.AddCleanup((*T)(p), vupenNetForget, key)
	return func() net.Conn {
		if v := w.Value(); v != nil {
			return P(v)
		}
		return nil
	}, w
}
