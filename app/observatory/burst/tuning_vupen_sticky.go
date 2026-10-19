package burst

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// Ядро 75 (АВТО 4.1, D-16, D-18; ADR-0001 §4.4): обсерватория по требованию и
// то, что нужно балансировщику «держать текущий» (app/router,
// strategy_vupen_sticky.go).
//
// С vupenOnDemand планировщик не запускается: проб нет, пока текущий узел
// работает. Пробы, проверка 64 КБ и проверка 24 КБ идут только по запросу
// балансировщика. Остальные обсерватории (без поля) работают как раньше.
var (
	// VupenStickyCheckURL — файл проверки 24 КБ вместо списка по умолчанию
	// (VupenCheckDefaultURLs, ядро 85); "" — список. Платформа задаёт свой список через
	// VupenSetCheckURL (tuning_vupen_api.go), он главнее.
	VupenStickyCheckURL       = ""
	VupenStickyCheckBytes     = int64(24576)
	VupenStickyCheckTimeout   = 6 * time.Second
	VupenStickyCheckStall     = 1500 * time.Millisecond
	VupenStickyCheckFirstByte = 5 * time.Second
	// VupenNetCheckAddr — «есть ли сеть у устройства»: TCP через outbound direct,
	// без данных (ADR-0001 §4.4 (6) В2). Значение ещё может поменять владелец.
	VupenNetCheckAddr    = "77.88.8.8:443"
	VupenNetCheckTimeout = 3 * time.Second
)

// Итоги проверок для балансировщика (строки, чтобы не тянуть типы между пакетами).
const (
	VupenStickyOK      = "ok"
	VupenStickyFailed  = "failed"
	VupenStickyUnknown = "unknown"
	VupenNetUp         = "up"
	VupenNetDown       = "down"
	VupenNetUnknown    = "unknown"
)

func (o *Observer) vupenStartOnDemand() {
	o.hp.vupenOnDemand = true
	o.hp.vupenSubject = o.vupenIsSubject
	vupenObsRegister(o.hp)
	errors.LogWarning(o.ctx, "[observatory] on demand: no scheduled rounds (selector ", o.config.SubjectSelector, ")")
}

func (o *Observer) vupenStopOnDemand() {
	vupenObsUnregister(o.hp)
	o.hp.cancelCtx()
}

// vupenIsSubject — outbound tag входит в наблюдаемые (по селектору обсерватории).
func (o *Observer) vupenIsSubject(tag string) bool {
	for _, s := range o.config.GetSubjectSelector() {
		if strings.HasPrefix(tag, s) {
			return true
		}
	}
	return false
}

// VupenStickyProbe — один раунд HEAD-проб по tags (через полосы TCP/UDP), синхронно.
func (o *Observer) VupenStickyProbe(tags []string) {
	if o.hp == nil || len(tags) == 0 {
		return
	}
	o.hp.doCheck(o.hp.ctx, tags, 0, 1)
}

// VupenStickyVerify — проверка загрузкой 64 КБ (ядро 71) синхронно; итог тот же,
// что у проверки ядра 71: прошёл — «проверен», заморозка подтвердилась — узел
// исключён на VupenTspuFrozenFor. Ядро 83 (T-108, CR-005): с защитой от смены сети —
// проверка, прошедшая через неё, заморозку не ставит (так что брошенная вызывающим
// проверка, дожившая в фоне, не замораживает узел уже после того, как её бросили).
func (o *Observer) VupenStickyVerify(tag string) string {
	if o.hp == nil {
		return VupenStickyUnknown
	}
	return o.hp.vupenTspuVerifyNowCtx(o.hp.ctx, tag, "search", nil, true)
}

// VupenStickyCheck — загрузка 24 КБ через узел tag мимо правил маршрутизации
// (список VupenSetCheckURL, правила перебора — tuning_vupen_checklist.go).
func (o *Observer) VupenStickyCheck(tag string) string {
	if o.hp == nil {
		return VupenStickyUnknown
	}
	return o.VupenStickyCheckCtx(o.hp.ctx, tag)
}

// VupenStickyCheckCtx — то же, но прерывается вместе с ctx (ядро 83, T-108, CR-002):
// прерванная проверка — unknown, провалом не считается.
func (o *Observer) VupenStickyCheckCtx(ctx context.Context, tag string) string {
	if o.hp == nil {
		return VupenStickyUnknown
	}
	r := o.VupenStickyCheckWithCtx(ctx, tag, VupenCheckOptions{})
	errors.LogWarning(o.hp.ctx, fmt.Sprintf("[sticky] check %s: %s (%s)", tag, r.Verdict, r.Detail))
	return r.Verdict
}

// VupenStickyExcluded — узел исключён (заморожен) и не может быть выбором.
func (o *Observer) VupenStickyExcluded(tag string) bool {
	return o.hp != nil && o.hp.vupenTspuFrozen(tag)
}

// VupenStickyExclude — исключить узел на VupenTspuFrozenFor (тот же механизм, что у ядра 71).
func (o *Observer) VupenStickyExclude(tag, reason string) {
	o.VupenStickyExcludeFor(tag, reason, VupenTspuFrozenFor)
}

// VupenStickyAsleep — устройство спит или нет сети по сигналу платформы: поиск запрещён.
func (o *Observer) VupenStickyAsleep() bool {
	return !VupenObservatoryActive()
}

// vupenSignalListeners — подписчики на признаки отказа узлов (ядро 76).
type vupenSignalListeners struct {
	mu   sync.Mutex
	next int
	m    map[int]func(tag, kind string, ok bool, detail string)
}

// VupenStickyListen — получать признаки отказа узлов этой обсерватории:
// kind "dial" (ok — узел ответил, !ok — соединение не установилось) и "freeze"
// (замолчали соединения). f вызывается из горутин соединений и не должна
// блокировать. Возвращает отписку.
func (o *Observer) VupenStickyListen(f func(tag, kind string, ok bool, detail string)) func() {
	if o.hp == nil {
		return func() {}
	}
	l := &o.hp.vupenListeners
	l.mu.Lock()
	if l.m == nil {
		l.m = map[int]func(tag, kind string, ok bool, detail string){}
	}
	l.next++
	id := l.next
	l.m[id] = f
	l.mu.Unlock()
	return func() {
		l.mu.Lock()
		delete(l.m, id)
		l.mu.Unlock()
	}
}

func (h *HealthPing) vupenSignal(tag, kind string, ok bool, detail string) {
	l := &h.vupenListeners
	l.mu.Lock()
	fs := make([]func(tag, kind string, ok bool, detail string), 0, len(l.m))
	for _, f := range l.m {
		fs = append(fs, f)
	}
	l.mu.Unlock()
	for _, f := range fs {
		f(tag, kind, ok, detail)
	}
}

// vupenDialer — outbound, через который можно установить соединение (proxyman).
type vupenDialer interface {
	Dial(ctx context.Context, dest net.Destination) (stat.Connection, error)
}

var vupenNetWarnOnce sync.Once

// VupenStickyNetwork — есть ли сеть у самого устройства: TCP к VupenNetCheckAddr
// через outbound `direct` (если он freedom), иначе через любой freedom. Нет ни
// того, ни другого — «неизвестно» (одно предупреждение за процесс).
func (o *Observer) VupenStickyNetwork() string {
	d, tag := vupenDirectDialer(o.ohm)
	if d == nil {
		vupenNetWarnOnce.Do(func() {
			errors.LogWarning(o.ctx, "[vupen] config warning: no direct/freedom outbound → network check unknown")
		})
		return VupenNetUnknown
	}
	dest, err := net.ParseDestination("tcp:" + VupenNetCheckAddr)
	if err != nil {
		return VupenNetUnknown
	}
	ctx, cancel := context.WithTimeout(o.ctx, VupenNetCheckTimeout)
	defer cancel()
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{Tag: tag, Target: dest}})
	conn, err := d.Dial(ctx, dest)
	if err != nil {
		errors.LogWarning(o.ctx, "[sticky] network check via ", tag, " to ", VupenNetCheckAddr, ": down (", err, ")")
		return VupenNetDown
	}
	conn.Close()
	return VupenNetUp
}

func vupenDirectDialer(ohm outbound.Manager) (vupenDialer, string) {
	if ohm == nil {
		return nil, ""
	}
	isFreedom := func(h outbound.Handler) bool {
		ps := h.ProxySettings()
		return ps != nil && strings.HasSuffix(ps.Type, "freedom.Config")
	}
	if h := ohm.GetHandler("direct"); h != nil && isFreedom(h) {
		if d, ok := h.(vupenDialer); ok {
			return d, h.Tag()
		}
	}
	for _, h := range ohm.ListHandlers(context.Background()) {
		if isFreedom(h) {
			if d, ok := h.(vupenDialer); ok {
				return d, h.Tag()
			}
		}
	}
	return nil, ""
}

// vupenTspuVerifyNowCtx — проверка 64 КБ синхронно; итог — этой проверки, а не
// прежней отметки «проверен». Если узел уже проверяется (ядро 71 заказало
// проверку), ждём её и берём её итог, второй раз не качаем. С контекстом вызывающего и защитой от смены сети
// (guard, ядро 83: см. vupenTspuVerifyCtx).
func (h *HealthPing) vupenTspuVerifyNowCtx(ctx context.Context, tag, reason string, hold func() bool, guard bool) string {
	waited := false
	for {
		h.tspu.mu.Lock()
		e := h.tspu.entryLocked(tag)
		if !e.checking {
			if waited {
				v := e.lastVerdict
				h.tspu.mu.Unlock()
				return vupenStickyVerdict(v)
			}
			e.checking = true
			e.lastCheck = time.Now()
			h.tspu.mu.Unlock()
			break
		}
		h.tspu.mu.Unlock()
		waited = true
		if !vupenSleep(ctx, 50*time.Millisecond) || h.ctx.Err() != nil {
			return VupenStickyUnknown
		}
	}
	return vupenStickyVerdict(h.vupenTspuVerifyCtx(ctx, tag, reason, hold, guard))
}

func vupenStickyVerdict(v vupenTspuVerdict) string {
	switch v {
	case vupenTspuOK:
		return VupenStickyOK
	case vupenTspuSuspect:
		return VupenStickyFailed
	}
	return VupenStickyUnknown
}
