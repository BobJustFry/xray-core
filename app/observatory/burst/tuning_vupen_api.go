package burst

import (
	"context"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/transport/internet"
)

// Ядро 78 (АВТО 4.1, шаг 2.6; ADR-0001 §5.1, §5.2, §13): то, что нужно экспортам
// libXray — тип сети от платформы, адрес файла проверки 24 КБ, проверка с
// параметрами и видом провала, исключение на заданный срок и немедленное
// закрытие соединений узла.

// VupenUplinkKinds — типы сети, которые платформа передаёт в VupenSetUplink.
var VupenUplinkKinds = []string{"cellular", "wifi", "wired", "other", "none"}

// VupenSetUplink — тип и подпись пути от платформы (экспорт libXray): эпоха сети
// (transport/internet) и окно проб обсерватории на КАЖДОЙ смене типа или
// подписи, включая мигания (CR-105). Неизвестный тип — ошибка, ничего не
// меняется. "" — принято.
func VupenSetUplink(kind, sig string) string {
	if !slices.Contains(VupenUplinkKinds, kind) {
		return fmt.Sprintf("uplink kind %q is not one of %v", kind, VupenUplinkKinds)
	}
	if internet.VupenSetUplink(kind, sig) {
		VupenObservatoryNetworkChanged("uplink " + kind)
	}
	return ""
}

func init() {
	// CR-105: чистка соединений прежней сети (через 9 с после последней смены)
	// роняет пробы, которые шли по закрываемым соединениям. Окно после смены к
	// этому моменту могло истечь (мигания: смена, ещё смена через 5 с — чистка
	// на 14-й), поэтому окно взводится и перед самим закрытием.
	internet.VupenNetEpochSubscribe(vupenOnNetEvent)
}

func vupenOnNetEvent(ev internet.VupenNetEvent) {
	if ev == internet.VupenNetClosing {
		VupenObservatoryNetworkChanged("connections closing")
	}
}

// VupenStickyCheckFallbackURL — запасной файл проверки 24 КБ вместе с VupenStickyCheckURL
// (прежний путь: тесты и вызывающие без VupenSetCheckURL). В нём можно перечислить
// несколько адресов через пробел. "" — без запасного.
var VupenStickyCheckFallbackURL = ""

// VupenSetCheckURL — файлы проверки 24 КБ (экспорт libXray, ADR-0001 §4.4 (6) В2).
// Сигнатура прежняя (primary, fallback), чтобы мосты Kotlin/Swift/Windows не менялись; с ядра 85
// fallback может нести СПИСОК адресов через пробел или перевод строки — порядок списка
// [primary, fallback...] и есть порядок проверки (tuning_vupen_checklist.go). Только https
// с именем узла; запасных можно не задавать (""). Ошибка — текст, адреса не меняются;
// "" — принято.
func VupenSetCheckURL(primary, fallback string) string {
	if err := VupenCheckURLError(primary); err != "" {
		return "primary: " + err
	}
	urls := vupenURLsOf(primary, fallback)
	if err := vupenValidURLs(urls); err != "" {
		return err
	}
	vupenCheckURLs.store(urls)
	errors.LogWarning(context.Background(), "[sticky] check files ", strings.Join(urls, " "))
	return ""
}

// VupenCheckURLError — почему адрес не годится для проверки ("" — годится).
func VupenCheckURLError(raw string) string {
	if raw == "" {
		return "empty"
	}
	u, err := url.Parse(raw)
	if err != nil {
		return err.Error()
	}
	switch {
	case u.Scheme != "https":
		return fmt.Sprintf("%q is not https", raw)
	case u.Hostname() == "":
		return fmt.Sprintf("%q has no host", raw)
	case u.User != nil:
		return fmt.Sprintf("%q carries user info", raw)
	}
	return ""
}

// vupenCheckFiles — первый и второй адрес списка 24 КБ сейчас (для тестов и журнала).
func vupenCheckFiles() (primary, fallback string) {
	l := vupenCheckList()
	if len(l) > 0 {
		primary = l[0]
	}
	if len(l) > 1 {
		fallback = l[1]
	}
	return
}

// VupenCheckOptions — параметры одной проверки 24 КБ (VupenCheckRoute). Нули —
// значения ядра (VupenStickyCheck*, VupenSetCheckURL).
type VupenCheckOptions struct {
	URL, FallbackURL string // URL "" — список VupenSetCheckURL; FallbackURL — один адрес или несколько через пробел
	Bytes            int64
	Stall            time.Duration
	FirstByte        time.Duration
	Timeout          time.Duration
	// Budget — предел на все загрузки проверки вместе (до двух адресов; CR-704):
	// каждая не дольше остатка, следующая не начинается, если остатка нет. 0 — без предела.
	Budget time.Duration
}

// VupenCheckResult — итог проверки: Verdict ok | failed | unknown; Kind у
// провала или «не поняли»: stall (встал посреди файла), nostart (не начался
// вовремя), error (ошибка соединения), http (HTTP ≠ 200).
type VupenCheckResult struct {
	Verdict string
	Kind    string
	Detail  string
	Elapsed time.Duration
}

// VupenStickyCheckWith — загрузка через узел tag мимо правил маршрутизации, с
// параметрами opt; основной «не понял» — проверка запасным файлом.
func (o *Observer) VupenStickyCheckWith(tag string, opt VupenCheckOptions) VupenCheckResult {
	if o.hp == nil {
		return VupenCheckResult{Verdict: VupenStickyUnknown, Detail: "no observatory"}
	}
	return o.VupenStickyCheckWithCtx(o.hp.ctx, tag, opt)
}

// VupenStickyCheckWithCtx — то же, но проверку можно прервать (ядро 83, T-108, CR-002:
// смена сети не ждёт загрузки 24 КБ). Прерванная проверка — «не поняли» (unknown), а не
// провал: оборванная загрузка выглядит как обрыв узла.
func (o *Observer) VupenStickyCheckWithCtx(ctx context.Context, tag string, opt VupenCheckOptions) VupenCheckResult {
	if o.hp == nil {
		return VupenCheckResult{Verdict: VupenStickyUnknown, Detail: "no observatory"}
	}
	ctx, cancel := vupenMergeCtx(o.hp.ctx, ctx) // значения контекста ядра - от hp.ctx
	defer cancel()
	// Без URL — список платформы с памятью выигравшего; с URL — адреса вызывающего, без памяти.
	var list *vupenURLList
	var urls []string
	if opt.URL == "" {
		list, urls = &vupenCheckURLs, vupenCheckList()
	} else {
		urls = vupenURLsOf(opt.URL, opt.FallbackURL)
	}
	if opt.Bytes <= 0 {
		opt.Bytes = VupenStickyCheckBytes
	}
	if opt.Stall <= 0 {
		opt.Stall = VupenStickyCheckStall
	}
	if opt.FirstByte <= 0 {
		opt.FirstByte = VupenStickyCheckFirstByte
	}
	if opt.Timeout <= 0 {
		opt.Timeout = VupenStickyCheckTimeout
	}
	start := time.Now()
	limit := func() bool { // false — бюджет кончился
		if opt.Budget <= 0 {
			return true
		}
		left := opt.Budget - time.Since(start)
		if left <= 0 {
			return false
		}
		if opt.Timeout > left {
			opt.Timeout = left
		}
		return true
	}
	limit()
	run := vupenRunList(ctx, list, urls, limit, func() bool { return o.hp.vupenNodeAlive(tag) },
		func(r vupenDownloadResult) bool { return vupenTspuClassify(r, opt.Bytes) == vupenTspuOK },
		func(u string) vupenDownloadResult { return o.hp.vupenDownloadCheck(ctx, tag, u, opt) })
	var res VupenCheckResult
	if len(run.tries) == 0 {
		res = VupenCheckResult{Verdict: VupenStickyUnknown, Detail: "no check url"}
	} else {
		res = vupenCheckResultOf(run.last().r, opt.Bytes)
		res.Elapsed = run.elapsed()
		for i := len(run.tries) - 2; i >= 0; i-- {
			res.Detail = "fallback after " + run.tries[i].r.String() + ": " + res.Detail
		}
		if run.hostDead && !run.ok {
			// Ни один адрес не открылся одним и тем же образом: виноват хост проверки, а не узел.
			res.Verdict = VupenStickyUnknown
			res.Detail += " (check hosts unreachable: not the node)"
		}
	}
	if ctx.Err() != nil && o.hp.ctx.Err() == nil {
		return VupenCheckResult{Verdict: VupenStickyUnknown, Detail: "aborted by the caller (" + res.Detail + ")", Elapsed: res.Elapsed}
	}
	return res
}

// vupenDownloadCheck — одна загрузка файла проверки 24 КБ через узел tag.
func (h *HealthPing) vupenDownloadCheck(ctx context.Context, tag, file string, opt VupenCheckOptions) vupenDownloadResult {
	client := newHTTPClient(ctx, h.dispatcher, tag, 0)
	return vupenDownloadFB(ctx, client, file, opt.Timeout, opt.Stall, opt.FirstByte)
}

// vupenCheckResultOf — итог одной загрузки файла проверки 24 КБ.
func vupenCheckResultOf(r vupenDownloadResult, want int64) VupenCheckResult {
	v := vupenTspuClassify(r, want)
	res := VupenCheckResult{Verdict: VupenStickyUnknown, Detail: r.String(), Elapsed: r.elapsed}
	switch {
	case v == vupenTspuOK:
		res.Verdict = VupenStickyOK
	case v == vupenTspuSuspect:
		res.Verdict = VupenStickyFailed
	case r.status == 0 && r.err != nil:
		// Ответа узла нет вовсе (соединение отвергнуто, сброшено, рукопожатие не
		// прошло): для проверки текущего это провал — исключать или нет, решит
		// проверка сети. «Не поняли» — только HTTP ≠ 200 (ответ был). Ядро 85: если так
		// провалились и этот, и запасной адрес одним образом, итог станет unknown выше
		// (vupenRunList.hostDead). У проверки 64 КБ (ядро 71) классификация прежняя.
		res.Verdict = VupenStickyFailed
	case r.status == 200 && r.bytes < vupenStickyExpectedN(r, want) && r.err != nil:
		// Заголовки пришли, а тело оборвалось ошибкой (сброс посреди файла) — тоже провал.
		res.Verdict = VupenStickyFailed
	}
	if res.Verdict != VupenStickyOK {
		switch {
		case r.stalled:
			res.Kind = "stall"
		case !r.started && r.timedOut:
			res.Kind = "nostart"
		case r.status != 0 && r.status != 200:
			res.Kind = "http"
		default:
			res.Kind = "error"
		}
	}
	return res
}

func vupenStickyExpectedN(r vupenDownloadResult, want int64) int64 {
	if r.expected > want {
		return r.expected
	}
	return want
}

// VupenStickyExcludeFor — исключить узел на d (VupenCheckRoute: excludeMin).
func (o *Observer) VupenStickyExcludeFor(tag, reason string, d time.Duration) {
	if o.hp == nil {
		return
	}
	if d <= 0 {
		d = VupenTspuFrozenFor
	}
	h := o.hp
	h.tspu.mu.Lock()
	e := h.tspu.entryLocked(tag)
	e.frozenUntil = time.Now().Add(d)
	// Ядро 83 (T-108, CR-004): явное исключение (провал 24 КБ, heal, сторож) — по
	// настоящей причине; frozenAt нужен только заморозкам проверки 64 КБ, которые
	// снимаются с концом БС (VupenStickyUnfreezeTags).
	e.frozenAt = time.Time{}
	e.verifiedUntil = time.Time{}
	h.tspu.mu.Unlock()
	errors.LogWarning(h.ctx, "[sticky] ", tag, " excluded for ", d, " (", reason, ")")
}

// VupenStickyCloseConns — закрыть сразу соединения узла tag этого экземпляра
// ядра (сторож заморозки и эпоха сети). Возвращает сколько закрыто.
func (o *Observer) VupenStickyCloseConns(tag string) int {
	var key any
	if o.hp != nil {
		key = o.hp
	}
	return internet.VupenCloseConnsNow(key, tag)
}
