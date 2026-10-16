package router

import (
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"time"

	"github.com/xtls/xray-core/app/observatory/burst"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/transport/internet"
)

// Ядро 78 (АВТО 4.1, шаг 2.6; ADR-0001 §5.1, §5.4, §13; D-12, D-14 п. 4, D-25,
// D-27): то, что отдают экспорты libXray VupenAutoState и VupenCheckRoute.
// Формат — JSON, поле v = 1; новые поля только добавляются. Время —
// миллисекунды Unix UTC (0 — не было). Ошибки — verdict "unknown" + detail,
// исключений через границу нет.
//
// VupenCheckRoute — подсказка ядру, а не команда туннелю: туннель и ядро не
// перезапускаются, узел меняет «держать текущий» после собственной проверки.
//
//   - "check" (≤ VupenCheckRouteCheckBudget = 8 с, ничего не меняет): 24 КБ через узел, который сейчас
//     выбирает АВТО (REG или при переливе LTE), мимо правил маршрутизации;
//     провал → проверка сети устройства через direct. Вердикт: ok | failed |
//     network_down | no_working | unknown.
//   - "heal" (≤ 15 с, после failed): повторная проверка того же узла (не нужна,
//     если в check не дольше VupenCheckRouteSkipRecheckFor назад он встал посреди
//     файла или не начал его — рисунок заморозки);
//     ожил — ok. Иначе узел исключается на excludeMin, его соединения
//     закрываются, поиск проверяет до maxSwitches узлов пула; ничего — на
//     сотовой перелив в LTE, иначе «нет рабочих». Вердикт: ok | switched |
//     network_down | no_working | spilled_lte | unknown.
//   - "switch" (ядро 79, D-42; ≤ 15 с, кнопка «Сменить сервер»): текущий узел не
//     проверяется и не исключается — он только пропускается в этом поиске.
//     Кандидаты — неисключённые узлы той же группы (REG, при переливе — LTE),
//     кроме текущего и тех, с кого пользователь уже уходил (visited); каждый
//     проверяется 64 КБ, как в поиске. Все прочие рабочие уже были — круг заново,
//     с того, с кого ушли раньше всех (A→B→C→A, без A→B→A). Нашёлся — switched,
//     соединения прежнего закрываются (closeConnections). Никто не прошёл —
//     остаёмся на текущем, no_alternative, список не меняется. Перелива в LTE
//     из-за switch нет никогда; «нет рабочих» из-за switch тоже. Вердикт:
//     switched | no_alternative | no_working (рабочих не было и до запроса) | unknown.

var (
	// VupenCheckRouteHealWait — сколько VupenCheckRoute(heal) ждёт итог; дальше
	// ядро доводит лечение само, итог — в VupenAutoState (lastCheckRoute, current).
	VupenCheckRouteHealWait = 15 * time.Second
	// VupenCheckRouteSkipRecheckFor — сколько действует отметка check «встал /
	// не начался»: heal в это время не качает узел второй раз (CR-703); позже —
	// повторная проверка, как после любого провала.
	VupenCheckRouteSkipRecheckFor = 60 * time.Second
	// VupenCheckRouteCheckBudget — предел режима check целиком: загрузка (с
	// запасным файлом) и проверка сети устройства (CR-704). На загрузки остаётся
	// бюджет минус burst.VupenNetCheckTimeout.
	VupenCheckRouteCheckBudget = 8 * time.Second
	// Пределы параметров запроса (защита от ошибок вызова, не настройки).
	vupenRouteMaxBytes    = int64(1 << 20)
	vupenRouteMaxMs       = int64(60_000)
	vupenRouteMaxSwitches = 10
	vupenRouteMaxExclude  = 24 * 60
)

// Вердикты VupenCheckRoute.
const (
	vupenRouteOK          = "ok"
	vupenRouteFailed      = "failed"
	vupenRouteSwitched    = "switched"
	vupenRouteNetDown     = "network_down"
	vupenRouteNoWorking   = "no_working"
	vupenRouteSpilledLTE  = "spilled_lte"
	vupenRouteUnknown     = "unknown"
	vupenRouteCheckMode   = "check"
	vupenRouteHealMode    = "heal"
	vupenRouteFreezeStall = "stall"
	vupenRouteNoStart     = "nostart"

	// Ядро 79 (D-42).
	vupenRouteSwitchMode    = "switch"
	vupenRouteNoAlternative = "no_alternative"
)

// vupenStickyRouteObs — что ещё нужно от обсерватории для VupenCheckRoute (burst, ядро 78).
type vupenStickyRouteObs interface {
	VupenStickyCheckWith(tag string, opt burst.VupenCheckOptions) burst.VupenCheckResult
	VupenStickyExcludeFor(tag, reason string, d time.Duration)
	VupenStickyCloseConns(tag string) int
}

// vupenRouteReq — запрос VupenCheckRoute.
type vupenRouteReq struct {
	V                int    `json:"v"`
	Mode             string `json:"mode"`     // check | heal | switch (ядро 79)
	Balancer         string `json:"balancer"` // тег балансировщика АВТО; "" — тот, у кого vupenSpill
	URL              string `json:"url"`      // "" — файлы VupenSetCheckURL
	FallbackURL      string `json:"fallbackUrl"`
	Bytes            int64  `json:"bytes"`          // 0 — 24576
	MinStallMs       int64  `json:"minStallMs"`     // 0 — 1500
	MaxFirstByteMs   int64  `json:"maxFirstByteMs"` // 0 — 5000
	TimeoutMs        int64  `json:"timeoutMs"`      // 0 — 6000
	MaxSwitches      int    `json:"maxSwitches"`    // 0 — 3 (switch: сколько кандидатов проверить)
	ExcludeMin       int    `json:"excludeMin"`     // 0 — 15 (switch не исключает — поле не действует)
	CloseConnections *bool  `json:"closeConnections"`
	Reason           string `json:"reason"` // foreground | after-connect | manual (для журнала)
}

// vupenRouteResp — ответ VupenCheckRoute.
type vupenRouteResp struct {
	V        int    `json:"v"`
	Verdict  string `json:"verdict"`
	From     string `json:"from"`  // узел, который проверяли
	To       string `json:"to"`    // узел после лечения (switched / spilled_lte; no_alternative — тот же, что from)
	Tried    int    `json:"tried"` // сколько узлов проверено загрузкой
	Ms       int64  `json:"ms"`
	Kind     string `json:"kind"` // stall | nostart | error | http — вид провала проверки
	Detail   string `json:"detail"`
	Balancer string `json:"balancer"` // кто выбирал узел: REG или LTE (при переливе)
	Closed   int    `json:"closed"`   // сколько соединений исключённого узла закрыто
}

// vupenRouteMark — итог последнего check (для heal того же узла).
type vupenRouteMark struct {
	tag, kind, detail string
	at                time.Time
}

// vupenHealReq — heal в горутине обработчика (там живёт состояние балансировщика).
type vupenHealReq struct {
	q     vupenRouteReq
	reply chan vupenRouteResp
}

func parseVupenRouteReq(raw string) (vupenRouteReq, string) {
	var q vupenRouteReq
	if err := json.Unmarshal([]byte(raw), &q); err != nil {
		return q, "bad request: " + err.Error()
	}
	if q.Mode != vupenRouteCheckMode && q.Mode != vupenRouteHealMode && q.Mode != vupenRouteSwitchMode {
		return q, fmt.Sprintf("bad request: mode %q (want check, heal or switch)", q.Mode)
	}
	for _, u := range []struct{ name, v string }{{"url", q.URL}, {"fallbackUrl", q.FallbackURL}} {
		if u.v != "" {
			if e := burst.VupenCheckURLError(u.v); e != "" {
				return q, "bad request: " + u.name + ": " + e
			}
		}
	}
	if q.URL == "" && q.FallbackURL != "" {
		return q, "bad request: fallbackUrl without url"
	}
	for _, n := range []struct {
		name   string
		v, max int64
	}{
		{"bytes", q.Bytes, vupenRouteMaxBytes}, {"minStallMs", q.MinStallMs, vupenRouteMaxMs},
		{"maxFirstByteMs", q.MaxFirstByteMs, vupenRouteMaxMs}, {"timeoutMs", q.TimeoutMs, vupenRouteMaxMs},
		{"maxSwitches", int64(q.MaxSwitches), int64(vupenRouteMaxSwitches)},
		{"excludeMin", int64(q.ExcludeMin), int64(vupenRouteMaxExclude)},
	} {
		if n.v < 0 || n.v > n.max {
			return q, fmt.Sprintf("bad request: %s %d (0…%d)", n.name, n.v, n.max)
		}
	}
	return q, ""
}

func (q vupenRouteReq) options() burst.VupenCheckOptions {
	return burst.VupenCheckOptions{
		URL: q.URL, FallbackURL: q.FallbackURL, Bytes: q.Bytes,
		Stall:     time.Duration(q.MinStallMs) * time.Millisecond,
		FirstByte: time.Duration(q.MaxFirstByteMs) * time.Millisecond,
		Timeout:   time.Duration(q.TimeoutMs) * time.Millisecond,
	}
}

func (q vupenRouteReq) maxSwitches() int {
	if q.MaxSwitches > 0 {
		return q.MaxSwitches
	}
	return VupenStickySearchMaxChecks
}

func (q vupenRouteReq) closeConns() bool { return q.CloseConnections == nil || *q.CloseConnections }

// vupenRoot — балансировщик АВТО: по тегу или тот, у кого vupenSpill (иначе
// первый «держать текущий», который не цель перелива); при нескольких — первый по тегу.
func (r *Router) vupenRoot(tag string) (*vupenSticky, string) {
	if r == nil {
		return nil, "the core is not running"
	}
	const noAuto = "no AUTO 4.1 balancer (vupenSticky) in the config"
	p := r.balancers.Load()
	if p == nil {
		return nil, noAuto
	}
	balancers := *p
	if tag != "" {
		b := balancers[tag]
		if b == nil || b.vupen == nil {
			return nil, fmt.Sprintf("balancer %q has no vupenSticky", tag)
		}
		return b.vupen, ""
	}
	var spill, plain []string
	for t, b := range balancers {
		switch {
		case b == nil || b.vupen == nil:
		case b.vupen.spill != nil:
			spill = append(spill, t)
		case !b.vupen.spillTargetOf.Load():
			plain = append(plain, t)
		}
	}
	sort.Strings(spill)
	sort.Strings(plain)
	if all := append(spill, plain...); len(all) > 0 {
		return balancers[all[0]].vupen, ""
	}
	return nil, noAuto
}

// serving — кто сейчас выбирает узел: цель перелива, если перелито (и сеть сотовая).
func (s *vupenSticky) serving() *vupenSticky {
	if t := s.spillTarget(); t != nil && t.vupen != nil {
		return t.vupen
	}
	return s
}

func (s *vupenSticky) viewTag() string {
	if p := s.view.Load(); p != nil {
		return *p
	}
	return ""
}

// VupenCheckRoute — экспорт libXray (ADR-0001 §13). Безопасен на nil (ядро не запущено).
func (r *Router) VupenCheckRoute(req string) string {
	b, _ := json.Marshal(r.vupenCheckRoute(req))
	return string(b)
}

func (r *Router) vupenCheckRoute(raw string) vupenRouteResp {
	start := time.Now()
	q, bad := parseVupenRouteReq(raw)
	if bad != "" {
		return vupenRouteResp{V: 1, Verdict: vupenRouteUnknown, Detail: bad}
	}
	root, why := r.vupenRoot(q.Balancer)
	if root == nil {
		return vupenRouteResp{V: 1, Verdict: vupenRouteUnknown, Detail: why}
	}
	x := root.serving()
	var resp vupenRouteResp
	if q.Mode == vupenRouteCheckMode {
		resp = x.checkRoute(q)
	} else {
		resp = x.requestHeal(q)
	}
	resp.V, resp.Balancer = 1, x.balancer
	resp.Ms = time.Since(start).Milliseconds()
	x.setReport(func(rep *vupenStickyReport) {
		rep.lastRoute = vupenStickyMark{at: vupenStickyNow(), kind: q.Mode, detail: resp.Verdict, from: resp.From, to: resp.To, reason: q.Reason}
	})
	errors.LogWarning(x.logCtx(), fmt.Sprintf("[sticky] %s: checkRoute %s (%s): %s from=%q to=%q tried=%d %dms %s %s",
		x.balancer, q.Mode, q.Reason, resp.Verdict, resp.From, resp.To, resp.Tried, resp.Ms, resp.Kind, resp.Detail))
	return resp
}

func (s *vupenSticky) routeObs() (vupenStickyObservatory, vupenStickyRouteObs, string) {
	obs := s.observatory()
	if obs == nil {
		return nil, nil, "no observatory with node checks"
	}
	ro, ok := obs.(vupenStickyRouteObs)
	if !ok {
		return nil, nil, "the observatory cannot check routes"
	}
	if obs.VupenStickyAsleep() {
		return nil, nil, "asleep or no network (observatory paused)"
	}
	return obs, ro, ""
}

// checkRoute — режим check: ничего не меняет (кроме отметки для heal).
func (s *vupenSticky) checkRoute(q vupenRouteReq) vupenRouteResp {
	resp := vupenRouteResp{Verdict: vupenRouteUnknown, From: s.viewTag()}
	obs, ro, why := s.routeObs()
	if why != "" {
		resp.Detail = why
		return resp
	}
	switch p := s.getPhase(); p {
	case vupenPhaseHolding:
	case vupenPhaseNoWorking:
		devNet := obs.VupenStickyNetwork()
		s.setReport(func(r *vupenStickyReport) { r.network = devNet })
		if devNet == vupenNetDown {
			resp.Verdict = vupenRouteNetDown
		} else {
			resp.Verdict = vupenRouteNoWorking
		}
		return resp
	default:
		resp.Detail = "the core is " + p.String() + " — no node to check yet"
		return resp
	}
	tag := resp.From
	opt := q.options()
	// CR-704: check целиком (загрузки + проверка сети) — не дольше бюджета.
	opt.Budget = VupenCheckRouteCheckBudget - burst.VupenNetCheckTimeout
	if opt.Budget <= 0 {
		opt.Budget = time.Second
	}
	res := ro.VupenStickyCheckWith(tag, opt)
	resp.Tried, resp.Kind, resp.Detail = 1, res.Kind, res.Detail
	switch res.Verdict {
	case vupenStickyOK:
		resp.Verdict = vupenRouteOK
		s.setReport(func(r *vupenStickyReport) { r.network, r.routeCheck = vupenNetUp, vupenRouteMark{} })
	case vupenStickyFailed:
		devNet := obs.VupenStickyNetwork()
		now := vupenStickyNow()
		s.setReport(func(r *vupenStickyReport) {
			r.network = devNet
			r.lastSignal = vupenStickyMark{at: now, kind: "manual", detail: tag + ": checkRoute (" + q.Reason + ")"}
			r.lastFailure = vupenStickyMark{at: now, kind: "check-route", detail: tag + ": " + res.Detail}
			if devNet == vupenNetUp {
				r.routeCheck = vupenRouteMark{tag: tag, kind: res.Kind, detail: res.Detail, at: now}
			}
		})
		switch devNet {
		case vupenNetUp:
			resp.Verdict = vupenRouteFailed
		case vupenNetDown:
			resp.Verdict = vupenRouteNetDown
		default:
			resp.Detail += "; device network state unknown (no direct/freedom outbound) → node kept"
		}
	}
	return resp
}

// requestHeal — heal или switch (ядро 79) в горутине обработчика; ждём итог не
// дольше VupenCheckRouteHealWait.
func (s *vupenSticky) requestHeal(q vupenRouteReq) vupenRouteResp {
	if s.getPhase() == vupenPhaseNew {
		return vupenRouteResp{Verdict: vupenRouteUnknown, Detail: "the balancer has not started yet (no traffic)"}
	}
	h := &vupenHealReq{q: q, reply: make(chan vupenRouteResp, 1)}
	if !s.send(vupenStickyEvent{kind: "heal", heal: h}) {
		return vupenRouteResp{Verdict: vupenRouteUnknown, From: s.viewTag(), Detail: "busy: event queue full"}
	}
	t := time.NewTimer(VupenCheckRouteHealWait)
	defer t.Stop()
	select {
	case resp := <-h.reply:
		return resp
	case <-t.C:
		doing := "healing"
		if q.Mode == vupenRouteSwitchMode {
			doing = "switching"
		}
		return vupenRouteResp{Verdict: vupenRouteUnknown, From: s.viewTag(),
			Detail: "still " + doing + " after " + VupenCheckRouteHealWait.String() + " — see VupenAutoState"}
	case <-s.stopCh:
		return vupenRouteResp{Verdict: vupenRouteUnknown, Detail: "the balancer was stopped"}
	}
}

// healRoute — режим heal (горутина обработчика).
func (s *vupenSticky) healRoute(h *vupenHealReq) vupenRouteResp {
	q := h.q
	resp := vupenRouteResp{Verdict: vupenRouteUnknown, From: s.viewTag()}
	obs, ro, why := s.routeObs()
	if why != "" {
		resp.Detail = why
		return resp
	}
	s.stateMu.Lock()
	last := s.report.routeCheck
	s.report.routeCheck = vupenRouteMark{}
	s.stateMu.Unlock()

	switch p := s.getPhase(); p {
	case vupenPhaseHolding:
	case vupenPhaseNoWorking:
		// Рабочих не было: поискать сразу (как повтор по графику).
		s.retryIdx = 0
		resp.Tried = s.searchN("checkRoute heal", q.maxSwitches())
		return s.healOutcome(resp)
	default:
		resp.Detail = "the core is " + p.String()
		return resp
	}
	tag := s.current
	resp.From = tag
	if last.tag != "" && last.tag != tag {
		// Пока приложение показывало сообщение, ядро уже сменило узел само.
		resp.Verdict, resp.From, resp.To = vupenRouteSwitched, last.tag, tag
		resp.Detail = "the core already switched"
		return resp
	}
	fresh := !last.at.IsZero() && vupenStickyNow().Sub(last.at) <= VupenCheckRouteSkipRecheckFor
	if last.tag == tag && fresh && (last.kind == vupenRouteFreezeStall || last.kind == vupenRouteNoStart) {
		// Рисунок заморозки ТСПУ в check — вердикт сразу, без повтора.
		resp.Kind, resp.Detail = last.kind, "check: "+last.detail
	} else {
		res := ro.VupenStickyCheckWith(tag, q.options())
		resp.Tried, resp.Kind, resp.Detail = 1, res.Kind, res.Detail
		switch res.Verdict {
		case vupenStickyOK:
			s.setReport(func(r *vupenStickyReport) { r.network = vupenNetUp })
			resp.Verdict = vupenRouteOK
			return resp
		case vupenStickyFailed:
			devNet := obs.VupenStickyNetwork()
			s.setReport(func(r *vupenStickyReport) { r.network = devNet })
			switch devNet {
			case vupenNetUp:
			case vupenNetDown:
				resp.Verdict = vupenRouteNetDown
				return resp
			default:
				resp.Detail += "; device network state unknown → node kept"
				return resp
			}
		default:
			return resp
		}
	}
	exclude := time.Duration(q.ExcludeMin) * time.Minute
	ro.VupenStickyExcludeFor(tag, "checkRoute ("+q.Reason+")", exclude)
	if q.closeConns() {
		resp.Closed = ro.VupenStickyCloseConns(tag)
	}
	s.setReport(func(r *vupenStickyReport) {
		r.failedChecks++
		r.lastFailure = vupenStickyMark{at: vupenStickyNow(), kind: "check-route", detail: tag + ": " + resp.Detail}
	})
	errors.LogWarning(s.logCtx(), fmt.Sprintf("[sticky] %s: checkRoute heal: %s failed (net ok) → excluded, %d connections closed, search %s",
		s.balancer, tag, resp.Closed, s.balancer))
	resp.Tried += s.searchN("checkRoute: "+tag+" failed", q.maxSwitches())
	return s.healOutcome(resp)
}

func (s *vupenSticky) healOutcome(resp vupenRouteResp) vupenRouteResp {
	switch {
	case s.spilledNow():
		resp.Verdict = vupenRouteSpilledLTE
		if t := s.spill.target.Load(); t != nil && t.vupen != nil {
			resp.To = t.vupen.viewTag()
		}
	case s.getPhase() == vupenPhaseHolding:
		resp.To = s.current
		if s.current != resp.From {
			resp.Verdict = vupenRouteSwitched
		} else {
			resp.Verdict = vupenRouteOK
		}
	case s.getPhase() == vupenPhaseNoWorking:
		resp.Verdict = vupenRouteNoWorking
	}
	return resp
}

// switchRoute — режим switch (ядро 79, D-42; горутина обработчика): сменить
// работающий узел по просьбе пользователя, без проверки и без исключения текущего.
func (s *vupenSticky) switchRoute(h *vupenHealReq) vupenRouteResp {
	q := h.q
	resp := vupenRouteResp{Verdict: vupenRouteUnknown, From: s.viewTag()}
	obs, ro, why := s.routeObs()
	if why != "" {
		resp.Detail = why
		return resp
	}
	if s.visitedReset.Swap(false) {
		s.visited = nil // сеть сменилась — перебор заново
	}
	reason := "checkRoute switch (" + q.Reason + ")"
	switch p := s.getPhase(); p {
	case vupenPhaseHolding:
	case vupenPhaseNoWorking:
		// Рабочих не было и до запроса: поискать сразу (как heal), но без перелива
		// в LTE — switch не переливает никогда; дальше повтор по графику.
		s.retryIdx = 0
		resp.Tried = s.searchOpt(reason, q.maxSwitches(), false)
		if s.getPhase() == vupenPhaseHolding {
			resp.Verdict, resp.To = vupenRouteSwitched, s.current
		} else {
			resp.Verdict = vupenRouteNoWorking
		}
		return resp
	default:
		resp.Detail = "the core is " + p.String()
		return resp
	}
	prev := s.current
	resp.From = prev
	cands, _ := s.b.SelectOutbounds()
	// Исключённые по провалам (heal, сторож, проверки) — не кандидаты; текущий
	// пропускается только в этом поиске.
	var others, fresh, seen []string
	for _, t := range cands {
		if t == prev || obs.VupenStickyExcluded(t) {
			continue
		}
		others = append(others, t)
		if slices.Contains(s.visited, t) {
			seen = append(seen, t)
		} else {
			fresh = append(fresh, t)
		}
	}
	budget := q.maxSwitches()
	errors.LogWarning(s.logCtx(), fmt.Sprintf("[sticky] %s: checkRoute switch (%s): leave %s without a check: %d other, %d already visited",
		s.balancer, q.Reason, prev, len(others), len(seen)))
	// Выдача остаётся prev (он работает), пока новый не проверен.
	s.setPhase(vupenPhaseSearching)
	tried, found := 0, false
	if len(fresh) > 0 {
		tried, found = s.verifyPool(obs, fresh, reason, "switch", false, func(alive []string) []string {
			return vupenStickyDiverse(alive, s.nodeKey, budget)
		})
	}
	if !found && len(seen) > 0 && tried < budget {
		// Все прочие рабочие уже были: круг заново — с того, с кого ушли раньше всех.
		left := budget - tried
		var n int
		n, found = s.verifyPool(obs, seen, reason+" next round", "switch", false, func(alive []string) []string {
			order := slices.Clone(alive)
			sort.SliceStable(order, func(i, j int) bool {
				return slices.Index(s.visited, order[i]) < slices.Index(s.visited, order[j])
			})
			if len(order) > left {
				order = order[:left]
			}
			return order
		})
		tried += n
		if found {
			s.visited = nil
		}
	}
	resp.Tried = tried
	if found {
		to := s.current
		s.visited = append(slices.DeleteFunc(s.visited, func(t string) bool { return t == prev || t == to }), prev)
		resp.Verdict, resp.To = vupenRouteSwitched, to
		if q.closeConns() {
			resp.Closed = ro.VupenStickyCloseConns(prev)
		}
		errors.LogWarning(s.logCtx(), fmt.Sprintf("[sticky] %s: checkRoute switch: %s → %s, %d connections of %s closed, visited %v",
			s.balancer, prev, to, resp.Closed, prev, s.visited))
		return resp
	}
	// Никто другой не прошёл: остаёмся на prev (не «нет рабочих»), список не меняется.
	s.holdBecause(prev, "switch")
	resp.Verdict, resp.To = vupenRouteNoAlternative, prev
	resp.Detail = fmt.Sprintf("no other working node in %s (%d other, %d checked) → kept %s", s.balancer, len(others), tried, prev)
	errors.LogWarning(s.logCtx(), "[sticky] ", s.balancer, ": checkRoute switch: ", resp.Detail)
	return resp
}

// ── VupenAutoState ──────────────────────────────────────────────────────────

type vupenAutoEventJSON struct {
	AtMs   int64  `json:"atMs"`
	Kind   string `json:"kind"`
	Detail string `json:"detail"`
}

type vupenAutoSwitchJSON struct {
	AtMs   int64  `json:"atMs"`
	From   string `json:"from"`
	To     string `json:"to"`
	Reason string `json:"reason"` // check | search | spill | return | switch (ядро 79)
}

type vupenAutoCloseJSON struct {
	AtMs   int64  `json:"atMs"`
	Reason string `json:"reason"` // net-change | lte-return | check-route (через запятую)
	Conns  int    `json:"conns"`
}

type vupenAutoRouteJSON struct {
	AtMs    int64  `json:"atMs"`
	Mode    string `json:"mode"`
	Verdict string `json:"verdict"`
	From    string `json:"from"`
	To      string `json:"to"`
	Reason  string `json:"reason"`
}

type vupenAutoStickyJSON struct {
	Since          int64              `json:"since"`        // когда взят текущий узел
	StartVerdict   string             `json:"startVerdict"` // ok | failed | unknown | none
	Searching      bool               `json:"searching"`
	NextSearchAtMs int64              `json:"nextSearchAtMs"`
	LastFailSignal vupenAutoEventJSON `json:"lastFailSignal"` // dial | freeze | manual
}

type vupenAutoCurrentJSON struct {
	Balancer string `json:"balancer"` // кто выбирает: REG или LTE при переливе
	Tag      string `json:"tag"`
	Host     string `json:"host"`
	Port     uint32 `json:"port"`
}

// vupenAutoJSON — VupenAutoState (ADR-0001 §13 плюс поля шага 2.6).
//
// notice — какое сообщение показать (тексты — copywriter):
//
//	"no_network" — «Нет интернета в этой сети» (D-14 п. 4, D-25 п. 3): сети нет
//	               по платформе (uplink none) или по проверке direct;
//	"no_working" — «Нет рабочих серверов» (D-12, D-27: после трёх проверок);
//	"searching"  — «Сервер не отвечает, ищу другой» (D-27: идёт поиск после
//	               первой неудачной проверки);
//	"lte"        — перешли на мобильные серверы (смысл bannerAutoTierLte);
//	""           — ничего.
//
// «Кажется, с интернетом проблема, меняю сервер» (D-12) — по ответу
// VupenCheckRoute (failed → heal), а не по состоянию.
type vupenAutoJSON struct {
	V              int                  `json:"v"`
	Active         bool                 `json:"active"` // ядро запущено и в конфиге есть АВТО 4.1
	Detail         string               `json:"detail"` // почему не active
	Balancer       string               `json:"balancer"`
	Uplink         string               `json:"uplink"` // cellular | wifi | wired | other | none | unknown
	Sig            string               `json:"sig"`
	Epoch          uint64               `json:"epoch"`
	StableForMs    int64                `json:"stableForMs"`
	Tier           string               `json:"tier"`  // regular | lte
	Phase          string               `json:"phase"` // new | checking | holding | searching | no-working
	RegularAlive   int                  `json:"regularAlive"`
	LteAlive       int                  `json:"lteAlive"`
	Sticky         vupenAutoStickyJSON  `json:"sticky"`
	Current        vupenAutoCurrentJSON `json:"current"`
	Spilled        bool                 `json:"spilled"`
	NoWorking      bool                 `json:"noWorking"`
	FailedChecks   int                  `json:"failedChecks"`
	Network        string               `json:"network"` // up | down | unknown | "" (не проверялась в этой сети)
	Notice         string               `json:"notice"`
	LastFailure    vupenAutoEventJSON   `json:"lastFailure"` // check | verify | check-route
	PendingClose   vupenAutoCloseJSON   `json:"pendingClose"`
	LastClose      vupenAutoCloseJSON   `json:"lastClose"`
	LastSwitch     vupenAutoSwitchJSON  `json:"lastSwitch"`
	LastCheckRoute vupenAutoRouteJSON   `json:"lastCheckRoute"`
	Spills         int                  `json:"spills"`
	Returns        int                  `json:"returns"`
	SpillBlocked   string               `json:"spillBlocked"`
}

func vupenMs(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixMilli()
}

func vupenCloseJSON(c *internet.VupenNetClose) vupenAutoCloseJSON {
	if c == nil {
		return vupenAutoCloseJSON{}
	}
	return vupenAutoCloseJSON{AtMs: vupenMs(c.At), Reason: c.Reason, Conns: c.Conns}
}

// VupenAutoState — экспорт libXray (ADR-0001 §13). Безопасен на nil (ядро не запущено).
func (r *Router) VupenAutoState() string {
	b, _ := json.Marshal(r.vupenAutoState())
	return string(b)
}

func (r *Router) vupenAutoState() vupenAutoJSON {
	out := vupenAutoJSON{V: 1, Uplink: "unknown", RegularAlive: -1, LteAlive: -1}
	ni := internet.VupenNetState()
	if ni.Active {
		out.Uplink, out.Sig, out.Epoch, out.StableForMs = ni.Kind, ni.Sig, ni.Epoch, ni.StableFor.Milliseconds()
	}
	out.PendingClose, out.LastClose = vupenCloseJSON(ni.Pending), vupenCloseJSON(ni.LastClose)
	root, why := r.vupenRoot("")
	if root == nil {
		out.Detail = why
		return out
	}
	st := root.state()
	out.Active, out.Balancer = true, root.balancer
	out.Tier, out.Phase, out.RegularAlive, out.LteAlive = st.Tier, st.Phase, st.RegularAlive, st.LteAlive
	out.Sticky = vupenAutoStickyJSON{
		Since: vupenMs(st.Since), StartVerdict: st.StartVerdict, Searching: st.Searching,
		NextSearchAtMs: vupenMs(st.NextSearchAt),
		LastFailSignal: vupenAutoEventJSON{AtMs: vupenMs(st.LastSignal.at), Kind: st.LastSignal.kind, Detail: st.LastSignal.detail},
	}
	if out.Sticky.StartVerdict == "" {
		out.Sticky.StartVerdict = "none"
	}
	out.Current = vupenAutoCurrentJSON{Balancer: st.Serving, Tag: st.Current, Host: st.Host, Port: st.Port}
	out.Spilled, out.NoWorking, out.FailedChecks, out.Network = st.Spilled, st.NoWorking, st.FailedChecks, st.Network
	out.LastFailure = vupenAutoEventJSON{AtMs: vupenMs(st.LastFailure.at), Kind: st.LastFailure.kind, Detail: st.LastFailure.detail}
	out.LastSwitch = vupenAutoSwitchJSON{AtMs: vupenMs(st.LastSwitch.at), From: st.LastSwitch.from, To: st.LastSwitch.to, Reason: st.LastSwitch.reason}
	out.LastCheckRoute = vupenAutoRouteJSON{AtMs: vupenMs(st.LastRoute.at), Mode: st.LastRoute.kind, Verdict: st.LastRoute.detail,
		From: st.LastRoute.from, To: st.LastRoute.to, Reason: st.LastRoute.reason}
	out.Spills, out.Returns, out.SpillBlocked = st.Spills, st.Returns, st.SpillBlocked
	out.Notice = vupenAutoNotice(out)
	return out
}

func vupenAutoNotice(s vupenAutoJSON) string {
	switch {
	case !s.Active:
		return ""
	case s.Uplink == "none" || s.Network == vupenNetDown:
		return "no_network"
	case s.NoWorking:
		return "no_working"
	case s.Sticky.Searching && s.FailedChecks >= 1:
		return "searching"
	case s.Tier == "lte":
		return "lte"
	}
	return ""
}
