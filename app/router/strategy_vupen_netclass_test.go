package router

import (
	"context"
	"net"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// ncFake — фальшивые прямые соединения: какой адрес отвечает, кто «в туннеле».
type ncFake struct {
	mu       sync.Mutex
	ok       map[string]bool
	tunnel   map[string]bool
	localErr bool
	block    bool // не отвечать до конца срока
	hosts    []string
	epoch    uint64
}

func (f *ncFake) connect(ctx context.Context, hostport string) (bool, error) {
	host, port, _ := net.SplitHostPort(hostport)
	f.mu.Lock()
	f.hosts = append(f.hosts, host+":"+port)
	ok, tun, local, block := f.ok[host], f.tunnel[host], f.localErr, f.block
	f.mu.Unlock()
	if block {
		<-ctx.Done()
		return false, ctx.Err()
	}
	if local {
		return false, syscall.EMFILE
	}
	if !ok {
		return false, syscall.ECONNREFUSED
	}
	return tun, nil
}

func (f *ncFake) set(foreign, yandex bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ok = map[string]bool{}
	for _, h := range VupenNetClassForeign {
		f.ok[h] = foreign
	}
	for _, h := range VupenNetClassYandex {
		f.ok[h] = yandex
	}
}

func (f *ncFake) normal()    { f.set(true, true) }
func (f *ncFake) whitelist() { f.set(false, true) }
func (f *ncFake) down()      { f.set(false, false) }

// probes — сколько полных проверок (по шесть адресов) было.
func (f *ncFake) probes() int {
	// Каждый запуск стартует ровно шесть горутин; после раннего выхода (иностранный
	// ответил) последние ещё дописываются — ждём кратности шести.
	for i := 0; i < 200; i++ {
		f.mu.Lock()
		n := len(f.hosts)
		f.mu.Unlock()
		if n%6 == 0 {
			return n / 6
		}
		time.Sleep(5 * time.Millisecond)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.hosts) / 6
}

func (f *ncFake) newEpoch() {
	f.mu.Lock()
	f.epoch++
	f.mu.Unlock()
}

func installNetClassFake(t *testing.T) *ncFake {
	t.Helper()
	f := &ncFake{}
	f.normal()
	oc, oe := vupenNetClassConnect, vupenNetEpochNow
	vupenNetClassConnect = f.connect
	vupenNetEpochNow = func() uint64 { f.mu.Lock(); defer f.mu.Unlock(); return f.epoch }
	t.Cleanup(func() { vupenNetClassConnect, vupenNetEpochNow = oc, oe })
	return f
}

// Остальные тесты пакета не должны ходить в настоящую сеть: по умолчанию «всё отвечает».
func init() {
	vupenNetClassConnect = func(context.Context, string) (bool, error) { return false, nil }
	vupenNetEpochNow = func() uint64 { return 0 }
}

// ncChange — как события эпохи ядра 74: тип сети сменился (новая эпоха, возврат из
// перелива, класс сети забыт, проверка назначена через паузу).
func (r *spillRig) ncChange(f *ncFake, kind string) {
	f.newEpoch()
	r.netChanged(kind)
	r.reg.netClassOnChanged()
	r.drain()
}

func (r *spillRig) ncSettle() {
	r.clock.Advance(VupenNetClassSettle)
	r.drain()
}

// ncRegProbed — ядро проверяло или искало среди узлов REG (p-*).
func ncRegProbed(r *spillRig) bool {
	r.obs.mu.Lock()
	defer r.obs.mu.Unlock()
	for _, p := range r.obs.probes {
		for _, tag := range p {
			if strings.HasPrefix(tag, "p-") {
				return true
			}
		}
	}
	for _, tag := range append(append([]string(nil), r.obs.checks...), r.obs.verifies...) {
		if strings.HasPrefix(tag, "p-") {
			return true
		}
	}
	return false
}

func ncRegExcluded(r *spillRig) bool {
	r.obs.mu.Lock()
	defer r.obs.mu.Unlock()
	for tag, ex := range r.obs.excluded {
		if ex && strings.HasPrefix(tag, "p-") {
			return true
		}
	}
	return false
}

// ncRegSearched — поиск по REG: пробы или проверки 64 КБ узлов REG (без 24 КБ initial при старте).
func ncRegSearched(r *spillRig) bool {
	r.obs.mu.Lock()
	defer r.obs.mu.Unlock()
	for _, p := range r.obs.probes {
		for _, tag := range p {
			if strings.HasPrefix(tag, "p-") {
				return true
			}
		}
	}
	for _, tag := range r.obs.verifies {
		if strings.HasPrefix(tag, "p-") {
			return true
		}
	}
	return false
}

// ── классы ──────────────────────────────────────────────────────────────────

func TestVupenNetClassClasses(t *testing.T) {
	for _, c := range []struct {
		name  string
		setup func(f *ncFake)
		want  string
	}{
		{"all answer", func(f *ncFake) {}, vupenNetClassNormal},
		{"only one foreign answers (the other two and Yandex dead)", func(f *ncFake) {
			f.down()
			f.ok["8.8.8.8"] = true
		}, vupenNetClassNormal},
		{"foreign dead, one Yandex answers", func(f *ncFake) {
			f.down()
			f.ok["77.88.8.88"] = true
		}, vupenNetClassWhitelist},
		{"foreign dead, all Yandex answer", func(f *ncFake) { f.whitelist() }, vupenNetClassWhitelist},
		{"nothing answers", func(f *ncFake) { f.down() }, vupenNetClassNoNetwork},
		{"every answer came through the tunnel (one route for all hosts)", func(f *ncFake) {
			f.tunnel = map[string]bool{}
			for _, h := range append(append([]string{}, VupenNetClassForeign...), VupenNetClassYandex...) {
				f.tunnel[h] = true
			}
		}, vupenNetClassUnknown},
		{"socket error everywhere", func(f *ncFake) { f.localErr = true }, vupenNetClassUnknown},
	} {
		f := installNetClassFake(t)
		c.setup(f)
		res := vupenNetClassRun()
		if res.class != c.want {
			t.Errorf("%s: class %q, want %q (%s)", c.name, res.class, c.want, res.short())
		}
	}
}

// Шесть адресов (три иностранных, три Яндекса), TCP 443, все параллельно.
func TestVupenNetClassTargetsAndPort(t *testing.T) {
	f := installNetClassFake(t)
	f.down() // без раннего выхода
	vupenNetClassRun()
	want := map[string]bool{"1.1.1.1:443": true, "8.8.8.8:443": true, "9.9.9.9:443": true,
		"77.88.8.8:443": true, "77.88.8.1:443": true, "77.88.8.88:443": true}
	if len(f.hosts) != 6 {
		t.Fatalf("hosts %v", f.hosts)
	}
	for _, h := range f.hosts {
		if !want[h] {
			t.Fatalf("unexpected target %s in %v", h, f.hosts)
		}
		delete(want, h)
	}
}

// Общий срок — VupenNetClassTimeout, соединения параллельно, не по очереди.
func TestVupenNetClassTimeoutIsTotalAndParallel(t *testing.T) {
	f := installNetClassFake(t)
	f.block = true
	old := VupenNetClassTimeout
	VupenNetClassTimeout = 150 * time.Millisecond
	t.Cleanup(func() { VupenNetClassTimeout = old })
	start := time.Now()
	res := vupenNetClassRun()
	if d := time.Since(start); d > 600*time.Millisecond {
		t.Fatalf("6 blocked connects took %s, want about the %s total", d, VupenNetClassTimeout)
	}
	if res.class != vupenNetClassNoNetwork {
		t.Fatalf("class %q", res.class)
	}
}

// Настоящий TCP: слушатель на loopback отвечает, закрытый порт — нет; сокет в туннель не попал.
func TestVupenDirectConnectRealSocket(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("no loopback:", err)
	}
	defer ln.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	via, err := vupenDirectConnect(ctx, ln.Addr().String())
	if err != nil || via {
		t.Fatalf("loopback connect: viaTunnel=%v err=%v", via, err)
	}
	ln.Close()
	if _, err := vupenDirectConnect(ctx, ln.Addr().String()); err == nil {
		t.Fatal("a closed port must fail")
	}
	if vupenLocalIsTunnel(&net.TCPAddr{IP: net.ParseIP("203.0.113.9"), Port: 1}) {
		t.Fatal("an address that no interface owns is not the tunnel")
	}
}

// ── Wi-Fi никогда ───────────────────────────────────────────────────────────

func TestVupenNetClassNeverProbesOffCellular(t *testing.T) {
	for _, kind := range []string{"wifi", "wired", "other", "none", "unknown"} {
		f := installNetClassFake(t)
		f.whitelist() // если бы проверили — перелили бы
		r := newSpillRig(t, []string{"cellular", "wifi"}, []string{"p-1", "p-2"}, []string{"lte-1"})
		r.kind = kind
		regDeadLteAlive(r)
		r.pick()
		r.drain()
		r.reg.netClassOnChanged()
		r.clock.Advance(time.Hour)
		r.drain()
		r.reg.send(vupenStickyEvent{kind: "netclass", reason: "manual"})
		r.reg.send(vupenStickyEvent{kind: "netclass", reason: "net-stable"})
		r.reg.send(vupenStickyEvent{kind: "net-stable"})
		r.reg.send(vupenStickyEvent{kind: "lte-recheck"})
		r.drain()
		if f.probes() != 0 {
			t.Fatalf("%s: %d probes, the probe must never run off cellular", kind, f.probes())
		}
		if cls, _, _ := r.reg.netClassJSON(); cls != "" {
			t.Fatalf("%s: class %q", kind, cls)
		}
	}
}

// ── БС: перелив сразу, без поиска по REG ────────────────────────────────────

func TestVupenNetClassWhitelistAtStartSpillsWithoutRegSearch(t *testing.T) {
	f := installNetClassFake(t)
	f.whitelist()
	r := newSpillRig(t, []string{"cellular"}, []string{"p-1", "p-2", "p-3"}, []string{"lte-1", "lte-2"})
	regDeadLteAlive(r)
	r.reg.initial = "p-1"
	r.pick()
	r.drain()
	if !r.reg.spilledNow() {
		t.Fatal("whitelist → spill at once")
	}
	if ncRegProbed(r) {
		t.Fatalf("no REG probe/check/verify during the whitelist: probes=%v checks=%v", r.obs.probes, r.obs.checks)
	}
	if r.obs.excluded["p-1"] {
		t.Fatal("a REG node must not be excluded because of the whitelist")
	}
	if f.probes() != 1 {
		t.Fatalf("one probe expected, %d", f.probes())
	}
	r.pick()
	r.drain()
	if got := r.pick(); got != "lte-2" {
		t.Fatalf("traffic via the verified LTE node, got %q", got)
	}
	cls, at, hosts := r.reg.netClassJSON()
	if cls != vupenNetClassWhitelist || at == 0 || !strings.Contains(hosts, "77.88.8.8=ok") || !strings.Contains(hosts, "1.1.1.1=fail") {
		t.Fatalf("state: %q %d %q", cls, at, hosts)
	}
	if st := r.reg.state(); st.LastSwitch.reason != "spill" || st.Spills != 1 {
		t.Fatalf("state %+v", st)
	}
}

// Контроль: тот же сценарий в обычной сети — полный поиск по REG, как раньше.
func TestVupenNetClassNormalBehavesAsBefore(t *testing.T) {
	installNetClassFake(t)
	r := newSpillRig(t, []string{"cellular"}, []string{"p-1", "p-2", "p-3"}, []string{"lte-1", "lte-2"})
	regDeadLteAlive(r)
	r.pick()
	r.drain()
	if !ncRegProbed(r) {
		t.Fatal("normal network: the REG search must run")
	}
	if !r.reg.spilledNow() {
		t.Fatal("normal network, REG dead: spill after the failed search, as before")
	}
	if r.reg.spill.byWhitelist.Load() {
		t.Fatal("not a whitelist spill")
	}
}

// Пока БС держится: ни REG-проверок, ни поисков, ни повторов, ни исключений.
func TestVupenNetClassWhitelistSuppressesRegWork(t *testing.T) {
	f := installNetClassFake(t)
	f.whitelist()
	r := newSpillRig(t, []string{"cellular"}, []string{"p-1", "p-2"}, []string{"lte-1"})
	regDeadLteAlive(r)
	r.pick()
	r.drain()
	r.pick()
	r.drain()
	for _, k := range []string{"check", "search", "retry", "net-stable", "current-excluded"} {
		r.reg.send(vupenStickyEvent{kind: k, reason: "t"})
	}
	r.drain()
	r.reg.requestCheck("signal dial: 3 failed")
	r.drain()
	if ncRegProbed(r) || ncRegExcluded(r) {
		t.Fatalf("REG touched during the whitelist: probes=%v checks=%v excl=%v", r.obs.probes, r.obs.checks, r.obs.excluded)
	}
	if !r.reg.spilledNow() {
		t.Fatal("still spilled")
	}
}

// Пока перелито из-за БС: лёгкая проверка по таймеру вместо REG-поиска; иностранные
// мертвы — остаёмся; ответили — возврат и поиск по REG.
func TestVupenNetClassRecheckCheapThenReturn(t *testing.T) {
	f := installNetClassFake(t)
	f.whitelist()
	r := newSpillRig(t, []string{"cellular"}, []string{"p-1", "p-2", "p-3"}, []string{"lte-1", "lte-2"})
	regDeadLteAlive(r)
	r.pick()
	r.drain()
	r.pick()
	r.drain()
	base := f.probes()
	for i := 0; i < 3; i++ {
		r.clock.Advance(VupenLteRegularRecheck)
		r.drain()
		if !r.reg.spilledNow() || ncRegProbed(r) {
			t.Fatalf("recheck %d: must stay on LTE and leave REG alone (probes=%v)", i, r.obs.probes)
		}
	}
	if got := f.probes() - base; got != 3 {
		t.Fatalf("one cheap probe per recheck, got %d for 3", got)
	}
	// Иностранные снова отвечают; REG ожил.
	f.normal()
	r.alive(map[string]int64{"p-1": 10, "p-2": 20, "p-3": 30, "lte-1": 40, "lte-2": 50})
	r.obs.mu.Lock()
	r.obs.verify["p-1"] = vupenStickyOK
	r.obs.mu.Unlock()
	r.clock.Advance(VupenLteRegularRecheck)
	r.drain()
	if r.reg.spilledNow() {
		t.Fatal("foreign DNS answers → the whitelist is over → return")
	}
	if !ncRegProbed(r) {
		t.Fatal("after the return the REG search must run")
	}
	if got := r.pick(); got != "p-1" {
		t.Fatalf("back on REG, got %q", got)
	}
	if st := r.reg.state(); st.Returns != 1 || r.reg.spill.byWhitelist.Load() {
		t.Fatalf("state %+v", st)
	}
}

// Перелито не из-за БС (иностранные отвечают): старая проверка REG, как раньше.
func TestVupenNetClassNonWhitelistSpillKeepsOldRecheck(t *testing.T) {
	installNetClassFake(t)
	r := newSpillRig(t, []string{"cellular"}, []string{"p-1", "p-2", "p-3", "p-4", "p-5"}, []string{"lte-1", "lte-2"})
	regDeadLteAlive(r)
	r.reg.current = "p-4"
	r.pick()
	r.drain()
	r.pick()
	r.drain()
	if !r.reg.spilledNow() {
		t.Fatal("setup: spilled")
	}
	r.obs.mu.Lock()
	r.obs.check["p-4"] = vupenStickyOK
	r.obs.delay["p-4"] = 5
	r.obs.mu.Unlock()
	r.clock.Advance(VupenLteRegularRecheck)
	r.drain()
	if r.reg.spilledNow() {
		t.Fatal("a regular node passed the old light check → return")
	}
}

// Нет сети: ни поисков, ни смены узлов; узел не исключается.
func TestVupenNetClassNoNetworkNoSearchNoChurn(t *testing.T) {
	f := installNetClassFake(t)
	f.down()
	r := newSpillRig(t, []string{"cellular"}, []string{"p-1", "p-2"}, []string{"lte-1"})
	regDeadLteAlive(r)
	r.alive(map[string]int64{"p-1": 10, "p-2": 20}) // REG жив по замерам: будь сеть — поиск бы шёл
	r.pick()
	r.drain()
	if ncRegSearched(r) || ncRegExcluded(r) || r.reg.spilledNow() {
		t.Fatalf("no network: no search/excludes/spill; probes=%v verifies=%v", r.obs.probes, r.obs.verifies)
	}
	r.reg.send(vupenStickyEvent{kind: "retry"})
	r.reg.send(vupenStickyEvent{kind: "net-stable"})
	r.drain()
	if ncRegSearched(r) || ncRegExcluded(r) {
		t.Fatal("still no search while nothing answers")
	}
	// Сеть вернулась: событие сети → проверка → поиск идёт.
	f.normal()
	r.alive(map[string]int64{"p-1": 10, "p-2": 20})
	r.obs.mu.Lock()
	r.obs.verify["p-1"] = vupenStickyOK
	r.obs.mu.Unlock()
	r.ncChange(f, "cellular")
	r.ncSettle()
	r.reg.send(vupenStickyEvent{kind: "net-stable"})
	r.drain()
	if got := r.pick(); got != "p-1" {
		t.Fatalf("after the network came back the search ran, pick %q", got)
	}
}

// Нет сети во время перелива: остаёмся на LTE, REG не трогаем.
func TestVupenNetClassNoNetworkWhileSpilledStays(t *testing.T) {
	f := installNetClassFake(t)
	f.whitelist()
	r := newSpillRig(t, []string{"cellular"}, []string{"p-1", "p-2"}, []string{"lte-1"})
	regDeadLteAlive(r)
	r.pick()
	r.drain()
	r.pick()
	r.drain()
	f.down()
	r.clock.Advance(VupenLteRegularRecheck)
	r.drain()
	if !r.reg.spilledNow() || ncRegProbed(r) {
		t.Fatal("no network while on LTE: stay, no REG work")
	}
}

// ── события, антидребезг, без «молотилки» ───────────────────────────────────

func TestVupenNetClassChangedIsDebouncedAndOneProbe(t *testing.T) {
	f := installNetClassFake(t)
	f.whitelist()
	r := newSpillRig(t, []string{"cellular"}, []string{"p-1"}, []string{"lte-1"})
	regDeadLteAlive(r)
	r.pick()
	r.drain()
	base := f.probes()
	for i := 0; i < 5; i++ { // мигание сети: пять смен подряд
		f.newEpoch()
		r.netChanged("cellular")
		r.reg.netClassOnChanged()
		r.clock.Advance(200 * time.Millisecond)
		r.drain()
	}
	if f.probes() != base {
		t.Fatalf("no probe during the flapping (%d new)", f.probes()-base)
	}
	r.ncSettle()
	if f.probes() != base+1 {
		t.Fatalf("exactly one probe after the network settled, got %d", f.probes()-base)
	}
	if !r.reg.spilledNow() {
		t.Fatal("whitelist on the new network → spill again at once")
	}
	// net-stable после окончательного итога — без второй проверки.
	r.reg.send(vupenStickyEvent{kind: "netclass", reason: "net-stable"})
	r.drain()
	if f.probes() != base+1 {
		t.Fatalf("stable after a conclusive result: no second probe (%d)", f.probes()-base)
	}
}

// Неокончательный итог (нет сети) — net-stable проверяет ещё раз.
func TestVupenNetClassStableReprobesInconclusive(t *testing.T) {
	f := installNetClassFake(t)
	f.down()
	r := newSpillRig(t, []string{"cellular"}, []string{"p-1"}, []string{"lte-1"})
	r.ncChange(f, "cellular")
	r.ncSettle()
	base := f.probes()
	f.normal()
	r.reg.send(vupenStickyEvent{kind: "netclass", reason: "net-stable"})
	r.drain()
	if f.probes() != base+1 {
		t.Fatalf("stable after noNetwork: one more probe, got %d", f.probes()-base)
	}
	if cls, _ := r.reg.netClassNow(); cls != vupenNetClassNormal {
		t.Fatalf("class %q", cls)
	}
}

// Отказ АВТО в той же сети: повторная проверка один раз, не чаще MinGap; в БС —
// перелив без исключения узла и без поиска.
func TestVupenNetClassReprobeOnHealthFailureDebounced(t *testing.T) {
	f := installNetClassFake(t)
	r := newSpillRig(t, []string{"cellular"}, []string{"p-1", "p-2"}, []string{"lte-1"})
	r.alive(map[string]int64{"p-1": 10, "p-2": 20, "lte-1": 40})
	r.obs.mu.Lock()
	r.obs.verify["p-1"] = vupenStickyOK
	r.obs.mu.Unlock()
	r.reg.initial = "p-1"
	r.pick()
	r.drain() // старт: проверка сети + 24 КБ initial прошли
	if f.probes() != 1 || r.reg.getPhase() != vupenPhaseHolding {
		t.Fatalf("start: probes=%d phase=%v", f.probes(), r.reg.getPhase())
	}
	// Отказ через 5 с: свежий итог, повторной проверки нет.
	r.obs.mu.Lock()
	r.obs.check["p-1"] = vupenStickyFailed
	r.obs.network = vupenNetUp
	r.obs.mu.Unlock()
	r.clock.Advance(5 * time.Second)
	r.reg.requestCheck("signal dial: 3 failed")
	r.drain()
	if f.probes() != 1 {
		t.Fatalf("a failure 5 s after the probe: cached class, got %d probes", f.probes())
	}
	// Через минуту сеть стала БС; отказ → повторная проверка → перелив без исключения.
	r.obs.mu.Lock()
	r.obs.excluded = map[string]bool{}
	r.obs.mu.Unlock()
	r.reg.current = "p-1"
	r.reg.setPhase(vupenPhaseHolding)
	f.whitelist()
	r.clock.Advance(time.Minute)
	r.obs.mu.Lock()
	nProbes := len(r.obs.probes)
	r.obs.mu.Unlock()
	r.reg.requestCheck("signal dial: 3 failed")
	r.drain()
	if f.probes() != 2 {
		t.Fatalf("one re-probe after the failure, got %d", f.probes())
	}
	r.obs.mu.Lock()
	defer r.obs.mu.Unlock()
	if !r.reg.spilledNow() || r.obs.excluded["p-1"] || len(r.obs.probes) != nProbes {
		t.Fatalf("whitelist: spill, node not excluded, no REG search (spilled=%v excl=%v)", r.reg.spilledNow(), r.obs.excluded)
	}
}

// БС повторилась в новой сети быстрее, чем через минуту после прошлого перелива:
// для БС пауза между переливами не действует.
func TestVupenNetClassWhitelistIgnoresSpillMinGap(t *testing.T) {
	f := installNetClassFake(t)
	f.whitelist()
	r := newSpillRig(t, []string{"cellular"}, []string{"p-1"}, []string{"lte-1"})
	regDeadLteAlive(r)
	r.pick()
	r.drain()
	if !r.reg.spilledNow() {
		t.Fatal("first spill")
	}
	r.clock.Advance(5 * time.Second)
	r.ncChange(f, "wifi") // ушли на Wi-Fi: возврат
	r.ncChange(f, "cellular")
	r.ncSettle()
	if !r.reg.spilledNow() || r.reg.state().Spills != 2 {
		t.Fatalf("second spill within the 60 s gap: %+v", r.reg.state())
	}
}

// Долго в БС: проверок ровно по таймеру, никакой молотилки.
func TestVupenNetClassNoProbingLoop(t *testing.T) {
	f := installNetClassFake(t)
	f.whitelist()
	r := newSpillRig(t, []string{"cellular"}, []string{"p-1"}, []string{"lte-1"})
	regDeadLteAlive(r)
	r.pick()
	r.drain()
	r.pick()
	r.drain()
	for i := 0; i < 3*60; i++ { // три часа по минуте
		r.clock.Advance(time.Minute)
		r.drain()
	}
	want := 1 + 3*60/int(VupenLteRegularRecheck/time.Minute) // старт + по таймеру
	if got := f.probes(); got != want {
		t.Fatalf("3 h of whitelist: %d probes, want %d (start + one per %s)", got, want, VupenLteRegularRecheck)
	}
}

// Нет перелива в конфиге — проверка не запускается.
func TestVupenNetClassOffWithoutSpill(t *testing.T) {
	f := installNetClassFake(t)
	f.whitelist()
	r := newStickyRig(t, "p-1", "p-1", "p-1", "p-2")
	old := vupenUplinkKind
	vupenUplinkKind = func() string { return "cellular" }
	t.Cleanup(func() { vupenUplinkKind = old })
	r.alive(map[string]int64{"p-1": 10})
	r.pick()
	r.drain()
	if f.probes() != 0 {
		t.Fatal("no vupenSpill → no probe")
	}
}

// Класс сети живёт в пределах эпохи: сеть сменилась (новая эпоха) — старый класс не годится.
func TestVupenNetClassIsPerNetworkEpoch(t *testing.T) {
	f := installNetClassFake(t)
	f.whitelist()
	r := newSpillRig(t, []string{"cellular"}, []string{"p-1"}, []string{"lte-1"})
	if got := r.reg.netClassProbe("t"); got != vupenNetClassWhitelist {
		t.Fatalf("probe: %q", got)
	}
	if cls, _ := r.reg.netClassNow(); cls != vupenNetClassWhitelist {
		t.Fatalf("same epoch: %q", cls)
	}
	f.newEpoch()
	if cls, _ := r.reg.netClassNow(); cls != "" {
		t.Fatalf("new epoch: the old class %q must not be used", cls)
	}
	if cls, _, _ := r.reg.netClassJSON(); cls != "" {
		t.Fatalf("state must not show the old network's class: %q", cls)
	}
	// Сеть сменилась прямо во время проверки — итог выбрасывается.
	f2 := installNetClassFake(t)
	f2.whitelist()
	vupenNetClassConnect = func(ctx context.Context, hp string) (bool, error) {
		f2.newEpoch()
		return f2.connect(ctx, hp)
	}
	if got := r.reg.netClassProbe("t"); got != "" {
		t.Fatalf("a result of a probe overlapped by a network change must be dropped, got %q", got)
	}
}

// CR-006: проверка текущего провалилась, устройство подтвердило сеть (devNet up), а
// прямые адреса молчат — «нет сети» от пробы не перекрывает проверку устройства:
// узел исключается и поиск идёт как раньше.
func TestVupenNetClassNoNetworkDoesNotOverrideDeviceNetworkUp(t *testing.T) {
	f := installNetClassFake(t)
	r := newSpillRig(t, []string{"cellular"}, []string{"p-1", "p-2"}, []string{"lte-1"})
	r.alive(map[string]int64{"p-1": 10, "p-2": 20})
	r.obs.mu.Lock()
	r.obs.verify["p-2"] = vupenStickyOK
	r.obs.mu.Unlock()
	r.reg.initial = "p-1"
	r.pick()
	r.drain()
	r.expectHolding(t, "p-1")
	f.down()
	r.clock.Advance(time.Minute)
	r.obs.mu.Lock()
	r.obs.check["p-1"] = vupenStickyFailed
	r.obs.network = vupenNetUp
	r.obs.mu.Unlock()
	r.reg.requestCheck("signal freeze")
	r.drain()
	if !r.obs.excluded["p-1"] || !ncRegSearched(r) {
		t.Fatalf("device network is up: the failed node is excluded and REG searched (excl=%v probes=%v)", r.obs.excluded, r.obs.probes)
	}
	r.expectHolding(t, "p-2")
}

// Контроль: устройство говорит «сети нет» — узел не трогаем, как раньше.
func TestVupenNetClassDeviceNetworkDownKeepsNode(t *testing.T) {
	f := installNetClassFake(t)
	r := newSpillRig(t, []string{"cellular"}, []string{"p-1", "p-2"}, []string{"lte-1"})
	r.alive(map[string]int64{"p-1": 10, "p-2": 20})
	r.reg.initial = "p-1"
	r.pick()
	r.drain()
	f.down()
	r.clock.Advance(time.Minute)
	r.obs.mu.Lock()
	r.obs.check["p-1"] = vupenStickyFailed
	r.obs.network = vupenNetDown
	r.obs.mu.Unlock()
	r.reg.requestCheck("signal freeze")
	r.drain()
	if ncRegExcluded(r) || ncRegSearched(r) {
		t.Fatalf("no device network: node untouched (excl=%v)", r.obs.excluded)
	}
	r.expectHolding(t, "p-1")
}

func (r *spillRig) expectHolding(t *testing.T, tag string) {
	t.Helper()
	if got := r.reg.getPhase(); got != vupenPhaseHolding {
		t.Fatalf("phase %v, want holding", got)
	}
	if got := r.pick(); got != tag {
		t.Fatalf("pick %q, want %q", got, tag)
	}
}
