package router

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"

	xerrors "github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/transport/internet"
)

// Ядро 82 (T-091): класс сотовой сети по прямой проверке досягаемости DNS-адресов.
//
// Белые списки (БС) оператора пропускают только «разрешённые» адреса. Проверка —
// шесть параллельных прямых TCP-соединений (не через туннель, не ICMP): три
// иностранных DNS и три Яндекс DNS. Классы:
//
//	normal    — отвечает хотя бы один иностранный;
//	whitelist — не отвечает ни один из трёх иностранных И отвечает хотя бы один Яндекс;
//	noNetwork — не отвечает ничего;
//	unknown   — ошибка проверки (локальная ошибка сокета) или соединение ушло в туннель.
//
// Когда проверяем: только пока тип сети — cellular (никогда на Wi-Fi/проводной/
// прочей), и только по событиям: старт ядра, смена сети (Changed — через короткую
// паузу, Stable — если итог был неокончательным), отказ АВТО при поиске (не чаще
// раза в VupenNetClassMinGap), таймер лёгкой проверки при переливе. Периодических
// «молотилок» нет.
//
// Что делаем: whitelist → перелив в LTE сразу (без ожидания полного неудачного
// поиска по REG), поиски по REG на время БС не идут; пока перелито — вместо дорогой
// проверки REG через туннель раз в VupenLteRegularRecheck дешёвая проверка: иностранные
// всё ещё мертвы → остаёмся, REG не трогаем; иностранные ответили → БС кончились,
// возврат в REG и поиск. noNetwork → поисков и смен узла нет, ждём событие сети.
// normal/unknown → как раньше.
//
// Прямое соединение: обычный net.Dialer процесса. Android: наш пакет исключён из
// VPN (addDisallowedApplication / не в списке разрешённых), iOS: сокеты процесса
// расширения не заходят в собственный туннель — тот же путь, каким ядро ходит к
// узлам. Страховка: если адрес сокета принадлежит интерфейсу вида tun/utun/ppp/wg,
// результат — unknown (измерили бы туннель).
const (
	vupenNetClassNormal    = "normal"
	vupenNetClassWhitelist = "whitelist"
	vupenNetClassNoNetwork = "noNetwork"
	vupenNetClassUnknown   = "unknown"
)

var (
	// VupenNetClassForeign / VupenNetClassYandex — адреса проверки (официальные
	// публичные DNS; Яндекс — docs/knowledge/yandex-dns-whitelist-probe.md).
	VupenNetClassForeign = []string{"1.1.1.1", "8.8.8.8", "9.9.9.9"}
	VupenNetClassYandex  = []string{"77.88.8.8", "77.88.8.1", "77.88.8.88"}
	// VupenNetClassPort — TCP 443 (DoH): у Яндекса задокументирован; порт 53 в БС
	// оператор может перехватывать для любого адреса.
	VupenNetClassPort = "443"
	// VupenNetClassTimeout — общий срок проверки, все соединения параллельно.
	VupenNetClassTimeout = 2 * time.Second
	// VupenNetClassSettle — пауза после смены сети до проверки (новая смена
	// переносит её).
	VupenNetClassSettle = 1500 * time.Millisecond
	// VupenNetClassMinGap — не чаще: повторная проверка по отказу АВТО в той же сети.
	VupenNetClassMinGap = 30 * time.Second

	// Точки подмены для тестов.
	vupenNetClassConnect = vupenDirectConnect
	vupenNetEpochNow     = func() uint64 { return internet.VupenNetState().Epoch }
)

// vupenNetHostResult — итог одного адреса.
type vupenNetHostResult struct {
	host    string
	foreign bool
	state   string // ok | fail | tunnel | local | skip
}

type vupenNetClassResult struct {
	class string
	at    time.Time
	hosts []vupenNetHostResult
}

// short — «1.1.1.1=ok 8.8.8.8=fail …» для журнала и VupenAutoState.
func (r vupenNetClassResult) short() string {
	parts := make([]string, 0, len(r.hosts))
	for _, h := range r.hosts {
		parts = append(parts, h.host+"="+h.state)
	}
	return strings.Join(parts, " ")
}

// vupenNetClassState — под mu; пишут горутина обработчика и вызов Changed.
type vupenNetClassState struct {
	mu         sync.Mutex
	class      string // класс текущей сети ("" — не проверялась в этой сети)
	epoch      uint64 // эпоха сети, в которой получен класс
	last       vupenNetClassResult
	probes     int
	stopSettle func() bool
}

// vupenDirectConnect — прямое TCP-соединение (процесс не в туннеле); viaTunnel —
// локальный адрес сокета принадлежит интерфейсу туннеля.
func vupenDirectConnect(ctx context.Context, hostport string) (viaTunnel bool, err error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", hostport)
	if err != nil {
		return false, err
	}
	defer c.Close()
	return vupenLocalIsTunnel(c.LocalAddr()), nil
}

// vupenLocalIsTunnel — адрес принадлежит tun/utun/ppp/wg-интерфейсу. Если список
// интерфейсов не читается (Android 11+ закрывает netlink) — false: ответить
// нечем, остаётся гарантия платформы.
func vupenLocalIsTunnel(a net.Addr) bool {
	ta, ok := a.(*net.TCPAddr)
	if !ok || ta == nil {
		return false
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	for _, ifc := range ifaces {
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, ad := range addrs {
			if ipn, ok := ad.(*net.IPNet); ok && ipn.IP.Equal(ta.IP) {
				name := strings.ToLower(ifc.Name)
				for _, p := range []string{"tun", "utun", "ppp", "wg", "tap", "ipsec"} {
					if strings.HasPrefix(name, p) {
						return true
					}
				}
				return false
			}
		}
	}
	return false
}

// vupenLocalSockErr — ошибка не сети, а самого сокета (нет дескрипторов, нет прав):
// это «проверка не удалась», а не «ничего не отвечает».
func vupenLocalSockErr(err error) bool {
	for _, e := range []error{syscall.EMFILE, syscall.ENFILE, syscall.EPERM, syscall.EACCES, syscall.ENOBUFS, syscall.ENOMEM} {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
}

// vupenNetClassRun — шесть параллельных соединений, не дольше VupenNetClassTimeout.
// Иностранный ответил — класс normal сразу (остальные отменяются).
func vupenNetClassRun() vupenNetClassResult {
	type probe struct {
		host    string
		foreign bool
	}
	var all []probe
	for _, h := range VupenNetClassForeign {
		all = append(all, probe{h, true})
	}
	for _, h := range VupenNetClassYandex {
		all = append(all, probe{h, false})
	}
	res := vupenNetClassResult{hosts: make([]vupenNetHostResult, len(all))}
	for i, p := range all {
		res.hosts[i] = vupenNetHostResult{host: p.host, foreign: p.foreign, state: "skip"}
	}
	ctx, cancel := context.WithTimeout(context.Background(), VupenNetClassTimeout)
	defer cancel()
	type out struct {
		i      int
		tunnel bool
		err    error
	}
	ch := make(chan out, len(all))                           // буфер: горутины не зависают после раннего выхода
	connect, port := vupenNetClassConnect, VupenNetClassPort // горутины дописываются и после раннего выхода
	for i, p := range all {
		go func() {
			tun, err := connect(ctx, net.JoinHostPort(p.host, port))
			ch <- out{i, tun, err}
		}()
	}
	var foreignOK, yandexOK, tunnel, local, failed int
	done := false
	for n := 0; n < len(all) && !done; n++ {
		o := <-ch
		h := &res.hosts[o.i]
		switch {
		case o.err != nil && vupenLocalSockErr(o.err):
			h.state = "local"
			local++
		case o.err != nil:
			h.state = "fail"
			failed++
		case o.tunnel:
			h.state = "tunnel"
			tunnel++
		default:
			h.state = "ok"
			if h.foreign {
				foreignOK++
				done = true // normal — остальные не ждём
			} else {
				yandexOK++
			}
		}
	}
	switch {
	case tunnel > 0:
		res.class = vupenNetClassUnknown
	case foreignOK > 0:
		res.class = vupenNetClassNormal
	case local > 0 && yandexOK == 0 && failed == 0:
		res.class = vupenNetClassUnknown // везде локальная ошибка сокета
	case yandexOK > 0:
		res.class = vupenNetClassWhitelist
	default:
		res.class = vupenNetClassNoNetwork
	}
	return res
}

// ── в обработчике балансировщика ────────────────────────────────────────────

// netClassActive — проверка вообще возможна: есть перелив в LTE, и сеть сотовая.
// Wi-Fi/проводная/прочая/неизвестная — никогда.
func (s *vupenSticky) netClassActive() bool {
	sp := s.spill
	return sp != nil && sp.invalid == "" && sp.cellular && sp.target.Load() != nil &&
		vupenUplinkKind() == vupenSpillOnlyOnUplinkKind
}

// netClassNow — класс текущей сети (пусто — не проверялась в этой сети).
func (s *vupenSticky) netClassNow() (class string, at time.Time) {
	c := &s.netcls
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.class == "" || c.epoch != vupenNetEpochNow() {
		return "", c.last.at
	}
	return c.class, c.last.at
}

// netClassProbe — проверить сейчас (только сотовая); возвращает класс текущей сети.
// Если сеть сменилась за время проверки, итог выбрасывается.
func (s *vupenSticky) netClassProbe(reason string) string {
	if !s.netClassActive() {
		return ""
	}
	epoch := vupenNetEpochNow()
	res := vupenNetClassRun()
	res.at = vupenStickyNow()
	if !s.netClassActive() || vupenNetEpochNow() != epoch {
		xerrors.LogWarning(s.logCtx(), "[netclass] ", s.balancer, ": result dropped, the network changed during the probe (", reason, ")")
		return ""
	}
	c := &s.netcls
	c.mu.Lock()
	prev := c.class
	c.class, c.epoch, c.last = res.class, epoch, res
	c.probes++
	c.mu.Unlock()
	xerrors.LogWarning(s.logCtx(), "[netclass] ", s.balancer, ": ", res.class, " (", reason, "; was ", orDash(prev), ") ", res.short())
	return res.class
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// netClassFresh — класс сети; проверяет, если в этой сети ещё не проверяли или
// последняя проверка старше VupenNetClassMinGap.
func (s *vupenSticky) netClassFresh(reason string) string {
	if !s.netClassActive() {
		return ""
	}
	class, at := s.netClassNow()
	if class == "" || vupenStickyNow().Sub(at) >= VupenNetClassMinGap {
		return s.netClassProbe(reason)
	}
	return class
}

// netClassGate — перед автоматическим поиском по REG: true — поиск не нужен
// (БС: перелито; нет сети: узел не виноват). Остальное — false, всё как раньше.
func (s *vupenSticky) netClassGate(reason string) bool {
	switch s.netClassFresh(reason) {
	case vupenNetClassWhitelist:
		if s.spillWhitelist(reason) {
			xerrors.LogWarning(s.logCtx(), "[netclass] ", s.balancer, ": whitelist — REG search skipped (", reason, ")")
			return true
		}
	case vupenNetClassNoNetwork:
		xerrors.LogWarning(s.logCtx(), "[netclass] ", s.balancer, ": no network — search and node change skipped (", reason, ")")
		if s.getPhase() != vupenPhaseHolding {
			// Узла нет и искать нечем: «ничего не работает» — повтор по графику и по
			// событию сети (net-stable); новая проверка — не чаще VupenNetClassMinGap.
			s.setPhase(vupenPhaseNoWorking)
			s.scheduleRetry(false)
		}
		return true
	}
	return false
}

// spillWhitelist — БС: перелить в LTE сразу (без паузы между переливами).
func (s *vupenSticky) spillWhitelist(reason string) bool {
	sp := s.spill
	if sp == nil {
		return false
	}
	if sp.spilled.Load() {
		sp.byWhitelist.Store(true)
		return true
	}
	if !s.trySpillOpt("whitelist: "+reason, true) {
		return false
	}
	sp.byWhitelist.Store(true)
	return true
}

// whitelistHolds — БС держится и мы уже в LTE: проверки и поиски по REG не нужны.
func (s *vupenSticky) whitelistHolds() bool {
	sp := s.spill
	if sp == nil || !sp.spilled.Load() || !sp.byWhitelist.Load() || !s.netClassActive() {
		return false
	}
	class, _ := s.netClassNow()
	return class == vupenNetClassWhitelist
}

// runNetClass — событие netclass: проверка по событию сети/старту и действие по итогу.
func (s *vupenSticky) runNetClass(reason string) {
	if !s.netClassActive() {
		return
	}
	if reason == "net-stable" {
		// Changed уже дал окончательный итог — вторая проверка не нужна.
		if class, _ := s.netClassNow(); class == vupenNetClassNormal || class == vupenNetClassWhitelist {
			return
		}
	}
	switch s.netClassProbe(reason) {
	case vupenNetClassWhitelist:
		s.spillWhitelist(reason)
	case vupenNetClassNormal:
		s.whitelistEnded(reason)
	}
}

// whitelistEnded — иностранные снова отвечают. Если перелив был из-за БС: вернуть
// выбор в REG и искать. Возвращает true, если вернули.
func (s *vupenSticky) whitelistEnded(reason string) bool {
	sp := s.spill
	if sp == nil || !sp.byWhitelist.Load() || !sp.spilled.Load() {
		return false
	}
	if !s.unspill("whitelist ended: foreign DNS answers (" + reason + ")") {
		return false
	}
	if sp.stopRecheck != nil {
		sp.stopRecheck()
		sp.stopRecheck = nil
	}
	s.closeLTEConns()
	s.retryIdx = 0
	s.search("whitelist ended")
	return true
}

// netClassRecheck — пока перелито: дешёвая проверка вместо REG-поиска через туннель.
// handled — проверка сделала всё (старый REG-recheck не нужен).
func (s *vupenSticky) netClassRecheck() (handled bool) {
	if !s.netClassActive() {
		return false
	}
	switch class := s.netClassProbe("lte-recheck"); class {
	case vupenNetClassWhitelist:
		s.spill.byWhitelist.Store(true)
		xerrors.LogWarning(s.logCtx(), "[spill] ", s.balancer, ": whitelist holds — staying on ", s.spill.targetTag, ", REG untouched")
		return true
	case vupenNetClassNoNetwork:
		xerrors.LogWarning(s.logCtx(), "[spill] ", s.balancer, ": no network — staying on ", s.spill.targetTag, ", waiting for a network event")
		return true
	case vupenNetClassNormal:
		if s.whitelistEnded("lte-recheck") {
			return true
		}
	}
	return false // normal без БС или unknown — как раньше
}

// netClassOnChanged — сеть сменилась (из подписки на эпоху сети; быстро, без проверок).
func (s *vupenSticky) netClassOnChanged() {
	if s.spill == nil {
		return
	}
	c := &s.netcls
	c.mu.Lock()
	c.class = ""
	if c.stopSettle != nil {
		c.stopSettle()
		c.stopSettle = nil
	}
	if s.netClassActive() {
		c.stopSettle = vupenStickyAfter(VupenNetClassSettle, func() {
			s.send(vupenStickyEvent{kind: "netclass", reason: "network changed"})
		})
	}
	c.mu.Unlock()
}

// netClassJSON — для VupenAutoState.
func (s *vupenSticky) netClassJSON() (class string, atMs int64, hosts string) {
	if s.spill == nil {
		return "", 0, ""
	}
	c := &s.netcls
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.last.at.IsZero() {
		return "", 0, ""
	}
	cls := c.class
	if cls == "" || c.epoch != vupenNetEpochNow() {
		cls = ""
	}
	return cls, c.last.at.UnixMilli(), c.last.short()
}
