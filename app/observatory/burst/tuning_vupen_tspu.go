package burst

import (
	"context"
	stderrors "errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/transport/internet"
)

// Vupen (ядро 71): балансировщик видит заморозку ТСПУ.
//
// Пробы обсерватории — один HEAD на gstatic, сотни байт. ТСПУ пропускает первые
// ~15–20 КБ соединения с зарубежным адресом хостинга и дальше молчит, поэтому
// замороженный узел проходил пробы, выглядел быстрым, и leastLoad на него
// переходил (бандл iPhone 2026-09-27 23:30:49: через 45 с интернета не стало).
//
// Что сделано:
//   - после каждого раунда VupenTspuTopK лучших кандидатов, ещё не проверенных,
//     проверяются загрузкой VupenTspuBytes через сам узел (тем же путём, что трафик);
//   - файл дошёл — узел «проверен» на VupenTspuVerifiedFor; встал или не начался,
//     и это повторилось во второй попытке, — «заморожен» на VupenTspuFrozenFor и
//     для всех стратегий считается мёртвым (createResult: Alive=false);
//   - сторож соединений (transport/internet/tuning_vupen_freeze.go) замечает
//     рисунок заморозки на рабочем трафике и просит проверить узел вне очереди;
//   - балансировщики уходят с рабочего узла только на проверенный
//     (app/router, vupenVerifiedSwitch).
//
// Трафик: 64 КБ на кандидата раз в 30 минут и по тревоге сторожа, а не на
// каждый узел каждый раунд.
var (
	VupenTspuEnabled      = true
	VupenTspuURL          = "https://speed.cloudflare.com/__down?bytes=65536"
	VupenTspuBytes        = int64(64 << 10)
	VupenTspuTimeout      = 15 * time.Second
	VupenTspuStall        = 5 * time.Second
	VupenTspuTopK         = 3
	VupenTspuVerifiedFor  = 30 * time.Minute
	VupenTspuFrozenFor    = 15 * time.Minute
	VupenTspuSuspectEvery = time.Minute
	// Проверка кончилась «не поняли» (Cloudflare ответил 429, ошибка сразу…):
	// узел не проверен, и балансировщик просит проверку на каждом новом
	// соединении. Чаще этого — не гоняем.
	VupenTspuRecheckAfter = 3 * time.Minute
	VupenTspuRetryPause   = 2 * time.Second
)

type vupenTspuVerdict int

const (
	// Проверка не состоялась (ошибка сразу, Cloudflare ответил не 200…).
	vupenTspuUnknown vupenTspuVerdict = iota
	// Файл дошёл целиком.
	vupenTspuOK
	// Узел жив по пробам, а файл встал или не начался.
	vupenTspuSuspect
)

type vupenTspuEntry struct {
	verifiedUntil time.Time
	frozenUntil   time.Time
	checking      bool
	lastCheck     time.Time
}

type vupenTspuState struct {
	mu sync.Mutex
	m  map[string]*vupenTspuEntry
}

func (s *vupenTspuState) entryLocked(tag string) *vupenTspuEntry {
	if s.m == nil {
		s.m = make(map[string]*vupenTspuEntry)
	}
	e := s.m[tag]
	if e == nil {
		e = &vupenTspuEntry{}
		s.m[tag] = e
	}
	return e
}

func (h *HealthPing) vupenTspuVerified(tag string) bool {
	h.tspu.mu.Lock()
	defer h.tspu.mu.Unlock()
	e := h.tspu.m[tag]
	return e != nil && time.Now().Before(e.verifiedUntil)
}

// vupenTspuFrozenLockedAccess — то же, для вызова под h.access (порядок
// блокировок всегда access → tspu.mu).
func (h *HealthPing) vupenTspuFrozenLockedAccess(tag string) bool { return h.vupenTspuFrozen(tag) }

// VupenTspuVerified — узел проверен загрузкой через него (для балансировщиков).
func (o *Observer) VupenTspuVerified(tag string) bool {
	return o.hp != nil && o.hp.vupenTspuVerified(tag)
}

// VupenTspuRequestVerify — балансировщик хочет перейти на узел: проверить его.
func (o *Observer) VupenTspuRequestVerify(tag string) {
	if o.hp != nil {
		o.hp.vupenTspuRequest(tag, false, "switch")
	}
}

func (h *HealthPing) vupenTspuFrozen(tag string) bool {
	h.tspu.mu.Lock()
	defer h.tspu.mu.Unlock()
	e := h.tspu.m[tag]
	return e != nil && time.Now().Before(e.frozenUntil)
}

// vupenTspuRequest — поставить узел на проверку. force — по тревоге сторожа:
// проверяем и уже проверенный узел, но не чаще VupenTspuSuspectEvery.
func (h *HealthPing) vupenTspuRequest(tag string, force bool, reason string) {
	if !VupenTspuEnabled || tag == "" {
		return
	}
	now := time.Now()
	h.tspu.mu.Lock()
	e := h.tspu.entryLocked(tag)
	skip := e.checking || now.Before(e.frozenUntil) ||
		(!force && now.Before(e.verifiedUntil)) ||
		(!force && !e.lastCheck.IsZero() && now.Sub(e.lastCheck) < VupenTspuRecheckAfter) ||
		(force && now.Sub(e.lastCheck) < VupenTspuSuspectEvery)
	if !skip {
		e.checking = true
		e.lastCheck = now
	}
	h.tspu.mu.Unlock()
	if !skip {
		go h.vupenTspuVerify(tag, reason)
	}
}

// vupenTspuAfterRound — после раунда: VupenTspuTopK лучших живых кандидатов без
// свежей проверки идут на проверку (по очереди, по одному — tspuSem).
func (h *HealthPing) vupenTspuAfterRound(tags []string) {
	if !VupenTspuEnabled || VupenTspuTopK <= 0 {
		return
	}
	type cand struct {
		tag string
		avg time.Duration
	}
	var cands []cand
	h.access.Lock()
	for _, tag := range tags {
		r, ok := h.Results[tag]
		if !ok {
			continue
		}
		s := r.getStatistics()
		if s.All == 0 || s.All == s.Fail {
			continue
		}
		cands = append(cands, cand{tag, s.Average})
	}
	h.access.Unlock()
	sort.Slice(cands, func(i, j int) bool { return cands[i].avg < cands[j].avg })
	n := 0
	for _, c := range cands {
		if n >= VupenTspuTopK {
			break
		}
		if h.vupenTspuFrozen(c.tag) {
			continue
		}
		n++
		h.vupenTspuRequest(c.tag, false, "candidate")
	}
}

func (h *HealthPing) vupenTspuVerify(tag, reason string) {
	verdict := vupenTspuUnknown
	detail := ""
	defer func() {
		now := time.Now()
		h.tspu.mu.Lock()
		e := h.tspu.entryLocked(tag)
		e.checking = false
		switch verdict {
		case vupenTspuOK:
			e.verifiedUntil = now.Add(VupenTspuVerifiedFor)
			e.frozenUntil = time.Time{}
		case vupenTspuSuspect:
			e.frozenUntil = now.Add(VupenTspuFrozenFor)
			e.verifiedUntil = time.Time{}
		}
		h.tspu.mu.Unlock()
		switch verdict {
		case vupenTspuOK:
			errors.LogWarning(h.ctx, fmt.Sprintf("[tspu] %s verified (%s): %s", tag, reason, detail))
		case vupenTspuSuspect:
			errors.LogWarning(h.ctx, fmt.Sprintf("[tspu] %s frozen (%s): %s → out of the balancer for %s",
				tag, reason, detail, VupenTspuFrozenFor))
		default:
			if detail != "" {
				errors.LogWarning(h.ctx, fmt.Sprintf("[tspu] %s not verified (%s): %s", tag, reason, detail))
			}
		}
	}()

	select {
	case h.tspuSem <- struct{}{}:
	case <-h.ctx.Done():
		return
	}
	defer func() { <-h.tspuSem }()
	if !VupenObservatoryActive() {
		return
	}
	lane := vupenLaneTCP
	if h.laneOf != nil {
		lane = h.laneOf(tag)
	}
	sem := h.lanes.sem(lane)
	if !vupenAcquire(h.ctx, sem) {
		return
	}
	defer vupenRelease(sem)

	stall := VupenTspuStall
	h.access.Lock()
	if r, ok := h.Results[tag]; ok {
		if byPing := 3 * r.getStatistics().Average; byPing > stall {
			stall = byPing
		}
	}
	h.access.Unlock()

	probe := h.tspuProbe
	if probe == nil {
		probe = h.vupenTspuProbeOnce
	}
	v1, d1 := probe(h.ctx, tag, stall)
	if v1 != vupenTspuSuspect {
		verdict, detail = v1, d1
		return
	}
	// ТСПУ срабатывает непостоянно, а сбой бывает и случайным: подтверждаем.
	if !vupenSleep(h.ctx, VupenTspuRetryPause) {
		return
	}
	v2, d2 := probe(h.ctx, tag, stall)
	detail = "1) " + d1 + "; 2) " + d2
	if v2 == vupenTspuSuspect {
		verdict = vupenTspuSuspect
	}
	// Прошёл со второго раза — ТСПУ непостоянен, «проверенным» не считаем.
}

// vupenTspuProbeOnce — одна загрузка через узел tag.
func (h *HealthPing) vupenTspuProbeOnce(ctx context.Context, tag string, stall time.Duration) (vupenTspuVerdict, string) {
	client := newHTTPClient(h.ctx, h.dispatcher, tag, 0)
	r := vupenDownload(ctx, client, VupenTspuURL, VupenTspuTimeout, stall)
	return vupenTspuClassify(r, VupenTspuBytes), r.String()
}

type vupenDownloadResult struct {
	status    int
	bytes     int64
	expected  int64
	started   bool
	stalled   bool
	elapsed   time.Duration
	err       error
	timedOut  bool
	stallWait time.Duration
}

func (r vupenDownloadResult) String() string {
	switch {
	case r.status == 200 && r.bytes >= r.expected && r.expected > 0:
		return fmt.Sprintf("%d KB in %d ms", r.bytes>>10, r.elapsed.Milliseconds())
	case r.stalled:
		return fmt.Sprintf("stalled at %d KB of %d (%s silence)", r.bytes>>10, r.expected>>10, r.stallWait)
	case !r.started && r.timedOut:
		return fmt.Sprintf("the file never started in %s", r.elapsed.Round(time.Second))
	case r.status != 0 && r.status != 200:
		return fmt.Sprintf("HTTP %d", r.status)
	case r.err != nil:
		return fmt.Sprintf("error after %d KB: %v", r.bytes>>10, r.err)
	}
	return fmt.Sprintf("%d KB of %d", r.bytes>>10, r.expected>>10)
}

// vupenTspuClassify — итог одной загрузки. Чистая функция, под тест.
func vupenTspuClassify(r vupenDownloadResult, want int64) vupenTspuVerdict {
	expected := r.expected
	if expected <= 0 {
		expected = want
	}
	if r.status == 200 && r.bytes >= expected {
		return vupenTspuOK
	}
	if r.status != 0 && r.status != 200 {
		return vupenTspuUnknown
	}
	// Узел живой по пробам: файл встал посреди или не начался до таймаута —
	// рисунок заморозки. Мгновенная ошибка — нет.
	if r.stalled || (!r.started && r.timedOut) {
		return vupenTspuSuspect
	}
	return vupenTspuUnknown
}

// vupenDownload — GET url клиентом client с подсчётом байт тела; сторож тишины
// включается с первого байта тела и обрывает загрузку после stall без данных.
func vupenDownload(ctx context.Context, client *http.Client, url string, timeout, stall time.Duration) vupenDownloadResult {
	r := vupenDownloadResult{stallWait: stall}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		r.err = err
		return r
	}
	req.Header.Set("Cache-Control", "no-cache")
	// Без сжатия: по проводу должны пройти все байты файла.
	req.Header.Set("Accept-Encoding", "identity")

	start := time.Now()
	var lastProgress atomic.Int64
	var stalled atomic.Bool
	done := make(chan struct{})
	defer close(done)
	go func() {
		t := time.NewTicker(200 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				last := lastProgress.Load()
				if last != 0 && time.Since(time.Unix(0, last)) > stall {
					stalled.Store(true)
					cancel()
					return
				}
			}
		}
	}()

	resp, err := client.Do(req)
	if err != nil {
		r.elapsed = time.Since(start)
		r.err = err
		r.timedOut = vupenIsTimeout(err)
		return r
	}
	defer resp.Body.Close()
	r.status = resp.StatusCode
	if resp.ContentLength > 0 {
		r.expected = resp.ContentLength
	}
	buf := make([]byte, 8<<10)
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			r.bytes += int64(n)
			r.started = true
			lastProgress.Store(time.Now().UnixNano())
		}
		if rerr != nil {
			if rerr != io.EOF {
				r.err = rerr
				r.timedOut = vupenIsTimeout(rerr)
			}
			break
		}
	}
	r.elapsed = time.Since(start)
	r.stalled = stalled.Load() && (r.expected <= 0 || r.bytes < r.expected)
	return r
}

func vupenIsTimeout(err error) bool {
	if stderrors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var ne net.Error
	return stderrors.As(err, &ne) && ne.Timeout()
}

// ── Сторож соединений → проверка ────────────────────────────────────────────

func init() {
	internet.VupenSetFreezeHooks(&internet.VupenFreezeHooks{
		Watch:   vupenTspuWatch,
		Suspect: vupenTspuSuspectHook,
	})
}

// vupenTspuWatch — обсерватория того же ядра, что и соединение, если она
// наблюдает outbound tag; иначе nil (соединение не отслеживается).
func vupenTspuWatch(ctx context.Context, tag string) any {
	if !VupenTspuEnabled {
		return nil
	}
	inst := core.FromContext(ctx)
	if inst == nil {
		return nil
	}
	vupenObs.mu.Lock()
	pings := make([]*HealthPing, 0, len(vupenObs.pings))
	for h := range vupenObs.pings {
		if h.inst == inst {
			pings = append(pings, h)
		}
	}
	vupenObs.mu.Unlock()
	for _, h := range pings {
		h.access.Lock()
		_, ok := h.Results[tag]
		h.access.Unlock()
		if ok {
			return h
		}
	}
	return nil
}

func vupenTspuSuspectHook(key any, tag string, sent, recv int64) {
	h, ok := key.(*HealthPing)
	if !ok || h == nil {
		return
	}
	errors.LogWarning(h.ctx, fmt.Sprintf(
		"[tspu] %s: a connection went silent after %d KB (up %d, down %d) — checking the node",
		tag, (sent+recv)>>10, sent>>10, recv>>10))
	h.vupenTspuRequest(tag, true, "silent connection")
}
