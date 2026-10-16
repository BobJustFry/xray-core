package internet

import (
	"context"
	stderrors "errors"
	"fmt"
	"io"
	stdnet "net"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
)

func TestVupenFreezeSuspicious(t *testing.T) {
	now := time.Now().UnixNano()
	silent := now - int64(VupenFreezeSilence) - 1
	fresh := now - int64(time.Second)
	cases := []struct {
		name              string
		sent, recv, since int64
		want              bool
	}{
		{"silent after 16 KB", 12 << 10, 4 << 10, silent, true},
		{"upload only (no answer yet)", 16 << 10, 0, silent, false},
		{"nothing pending", 12 << 10, 4 << 10, 0, false},
		{"not silent long enough", 12 << 10, 4 << 10, fresh, false},
		{"too early: handshake only", 2 << 10, 5 << 10, silent, false},
		{"too late: a busy connection that paused", 300 << 10, 5 << 20, silent, false},
	}
	for _, c := range cases {
		if got := vupenFreezeSuspicious(c.sent, c.recv, c.since, now); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

type freezeHit struct {
	key        any
	tag        string
	sent, recv int64
}

// freezeTestHooks — сторож в тесте: короткая тишина, частый проход, свои хуки.
func freezeTestHooks(t *testing.T, watch bool) chan freezeHit {
	t.Helper()
	oldSilence, oldScan := VupenFreezeSilence, vupenFreezeScanEvery
	VupenFreezeSilence = 150 * time.Millisecond
	vupenFreezeScanEvery = 20 * time.Millisecond
	hits := make(chan freezeHit, 8)
	// Ядро 76: тишины соседнего теста не складываются с нашими.
	vupenFreezeWatch.mu.Lock()
	vupenFreezeWatch.recent = map[vupenFreezeNode][]int64{}
	vupenFreezeWatch.mu.Unlock()
	old := vupenFreezeHooks.Load()
	VupenSetFreezeHooks(&VupenFreezeHooks{
		Watch: func(ctx context.Context, tag string) any {
			if !watch {
				return nil
			}
			return "hp"
		},
		Suspect: func(key any, tag string, sent, recv int64) {
			hits <- freezeHit{key, tag, sent, recv}
		},
	})
	t.Cleanup(func() {
		// CR-402: цикл сторожа читает vupenFreezeScanEvery при старте; ждём, пока
		// он выйдет (соединения теста уже закрыты — их очистки отработали раньше).
		deadline := time.Now().Add(5 * time.Second)
		for {
			vupenFreezeWatch.mu.Lock()
			running := vupenFreezeWatch.running
			vupenFreezeWatch.mu.Unlock()
			if !running {
				break
			}
			if time.Now().After(deadline) {
				t.Error("the watchdog loop is still running after the test closed its connections")
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		VupenFreezeSilence, vupenFreezeScanEvery = oldSilence, oldScan
		vupenFreezeHooks.Store(old)
	})
	return hits
}

func freezeCtx(tag string) context.Context {
	return session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Tag: tag}})
}

var tcpDest = net.TCPDestination(net.DomainAddress("node.example"), 443)

// VupenNoteTransportDial — попытка целиком: до internet.Dial и с его итогом.
func VupenNoteTransportDial(ctx context.Context, tag string, err error) {
	_, done := VupenTransportAttempt(ctx, tag)
	done(err)
}

// silentConn — соединение к узлу под заморозкой (ядро 76: с данными в обе
// стороны до тишины): узел отвечает на первые 2 КБ, дальше всё читает
// (TCP-ACK), но молчит. Мы шлём ещё 16 КБ.
func silentConn(t *testing.T, ctx context.Context) net.Conn {
	t.Helper()
	client, server := stdnet.Pipe()
	t.Cleanup(func() { server.Close() })
	go func() {
		buf := make([]byte, 2048)
		if _, err := io.ReadFull(server, buf); err != nil {
			return
		}
		if _, err := server.Write(buf); err != nil {
			return
		}
		_, _ = io.Copy(io.Discard, server)
	}()
	c := vupenFreezeWrap(ctx, client, tcpDest)
	t.Cleanup(func() { c.Close() })
	if _, ok := c.(*vupenFreezeConn); !ok {
		t.Fatal("a watched outbound must be wrapped")
	}
	if _, err := c.Write(make([]byte, 2048)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(c, make([]byte, 2048)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(make([]byte, 16<<10)); err != nil {
		t.Fatal(err)
	}
	return c
}

func expectNoHit(t *testing.T, hits chan freezeHit, wait time.Duration, why string) {
	t.Helper()
	select {
	case h := <-hits:
		t.Fatalf("%s: unexpected hit %+v", why, h)
	case <-time.After(wait):
	}
}

// Ядро 76 (D-19): одно замолчавшее соединение — ещё не заморозка (до
// VupenFreezeLoneSilence; исключение CR-301 — ниже).
func TestVupenFreezeSingleSilentConnectionIsNotReported(t *testing.T) {
	hits := freezeTestHooks(t, true)
	setLoneSilence(t, time.Hour)
	silentConn(t, freezeCtx("proxy-7"))
	expectNoHit(t, hits, 4*VupenFreezeSilence, "one silent connection")
}

func setLoneSilence(t *testing.T, d time.Duration) {
	t.Helper()
	old := VupenFreezeLoneSilence
	VupenFreezeLoneSilence = d
	t.Cleanup(func() { VupenFreezeLoneSilence = old })
}

// CR-301: весь трафик узла — одно соединение (gRPC, mux.cool): оно замолчало и
// это единственное соединение к узлу — одна тревога, но только после
// VupenFreezeLoneSilence, а не после обычной тишины.
func TestVupenFreezeLoneConnectionReportedOnce(t *testing.T) {
	hits := freezeTestHooks(t, true)
	setLoneSilence(t, 700*time.Millisecond)
	start := time.Now()
	silentConn(t, freezeCtx("proxy-7"))
	select {
	case h := <-hits:
		if h.tag != "proxy-7" || time.Since(start) < VupenFreezeLoneSilence {
			t.Fatalf("lone connection: %+v after %v (lone silence %v)", h, time.Since(start), VupenFreezeLoneSilence)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the only connection to a node froze: must be reported")
	}
	expectNoHit(t, hits, 3*VupenFreezeLoneSilence, "once per connection")
}

// CR-301: рядом есть рабочее соединение к тому же узлу (получает данные во время
// тишины) — узел жив, тревоги нет.
func TestVupenFreezeLoneSuppressedByWorkingConnection(t *testing.T) {
	hits := freezeTestHooks(t, true)
	setLoneSilence(t, 700*time.Millisecond)
	silentConn(t, freezeCtx("proxy-7"))
	client, server := stdnet.Pipe()
	t.Cleanup(func() { server.Close() })
	working := vupenFreezeWrap(freezeCtx("proxy-7"), client, tcpDest)
	t.Cleanup(func() { working.Close() })
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	go func() { // узел отвечает по рабочему соединению
		for {
			select {
			case <-stop:
				return
			case <-time.After(100 * time.Millisecond):
				if _, err := server.Write([]byte("tick")); err != nil {
					return
				}
			}
		}
	}()
	go func() { _, _ = io.Copy(io.Discard, working) }()
	expectNoHit(t, hits, 4*VupenFreezeLoneSilence, "a working connection to the same node")
}

// Два разных соединения к узлу замолчали в пределах окна — одна тревога.
func TestVupenFreezeTwoSilentConnectionsFireOnce(t *testing.T) {
	hits := freezeTestHooks(t, true)
	silentConn(t, freezeCtx("proxy-7"))
	silentConn(t, freezeCtx("proxy-7"))
	select {
	case h := <-hits:
		if h.tag != "proxy-7" || h.key != "hp" || h.recv != 2048 {
			t.Fatalf("unexpected hit: %+v", h)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("two silent connections to one node must be reported")
	}
	expectNoHit(t, hits, 300*time.Millisecond, "must fire once for the pair")
}

// Соединения к разным узлам и вне окна не складываются.
func TestVupenFreezeConnectionsOfDifferentNodesOrOutsideWindow(t *testing.T) {
	hits := freezeTestHooks(t, true)
	oldWin := VupenFreezeConnsWindow
	VupenFreezeConnsWindow = 400 * time.Millisecond
	t.Cleanup(func() { VupenFreezeConnsWindow = oldWin })
	silentConn(t, freezeCtx("proxy-7"))
	silentConn(t, freezeCtx("proxy-8"))
	expectNoHit(t, hits, 4*VupenFreezeSilence, "different nodes")
	time.Sleep(VupenFreezeConnsWindow)
	silentConn(t, freezeCtx("proxy-7")) // the first proxy-7 silence is out of the window
	expectNoHit(t, hits, 4*VupenFreezeSilence, "outside the window")
}

// Поток, который только отправляет (ответа ещё не было), не считается (П2 (б)).
func TestVupenFreezeUploadOnlyIsNotCounted(t *testing.T) {
	hits := freezeTestHooks(t, true)
	for i := 0; i < 2; i++ {
		client, server := stdnet.Pipe()
		t.Cleanup(func() { server.Close() })
		go func() { _, _ = io.Copy(io.Discard, server) }()
		c := vupenFreezeWrap(freezeCtx("proxy-7"), client, tcpDest)
		t.Cleanup(func() { c.Close() })
		if _, err := c.Write(make([]byte, 16<<10)); err != nil {
			t.Fatal(err)
		}
	}
	expectNoHit(t, hits, 4*VupenFreezeSilence, "upload-only connections")
}

// Служебные соединения (пробы, проверки 24/64 КБ) сторож не наблюдает (П2 (а)).
func TestVupenFreezeSkipsServiceConnections(t *testing.T) {
	freezeTestHooks(t, true)
	client, server := stdnet.Pipe()
	defer server.Close()
	defer client.Close()
	if c := vupenFreezeWrap(VupenServiceContext(freezeCtx("proxy-7")), client, tcpDest); c != client {
		t.Fatal("a service connection must stay unwrapped")
	}
	if !VupenIsServiceContext(VupenServiceContext(context.Background())) || VupenIsServiceContext(context.Background()) {
		t.Fatal("service context marker")
	}
}

type attemptHit struct {
	tag string
	ok  bool
}

// П1/П5 (ядро 76): итог internet.Dial в обработчике outbound'а сообщается
// только для АВТО 4.1, не для служебных соединений и не при отмене вызывающим;
// первый байт ответа на наблюдаемом соединении — успешная попытка.
func TestVupenFreezeAttempts(t *testing.T) {
	freezeTestHooks(t, true)
	netEpochTest(t) // Auto41 = ctx carries netAuto41Key
	attempts := make(chan attemptHit, 8)
	h := *vupenFreezeHooks.Load()
	h.Attempt = func(key any, tag string, ok bool, detail string) { attempts <- attemptHit{tag, ok} }
	VupenSetFreezeHooks(&h)

	VupenSetUplink("wifi", fmt.Sprintf("freeze-attempts-%d", time.Now().UnixNano()))
	VupenNoteTransportDial(auto41Ctx("proxy-7"), "proxy-7", stderrors.New("tls: handshake failure"))
	if a := <-attempts; a != (attemptHit{"proxy-7", false}) {
		t.Fatalf("transport failure: %+v", a)
	}
	VupenNoteTransportDial(auto41Ctx("proxy-7"), "proxy-7", nil)
	if a := <-attempts; a != (attemptHit{"proxy-7", true}) {
		t.Fatalf("transport established: %+v", a)
	}
	canceled, cancel := context.WithCancel(auto41Ctx("proxy-7"))
	cancel()
	VupenNoteTransportDial(canceled, "proxy-7", context.Canceled)
	VupenNoteTransportDial(VupenServiceContext(auto41Ctx("proxy-7")), "proxy-7", stderrors.New("refused"))
	VupenNoteTransportDial(plainCtx("proxy-7"), "proxy-7", stderrors.New("refused")) // not AUTO 4.1
	select {
	case a := <-attempts:
		t.Fatalf("cancel / service / non-AUTO must not count: %+v", a)
	default:
	}

	client, server := stdnet.Pipe()
	defer server.Close()
	c := vupenFreezeWrap(freezeCtx("proxy-7"), client, tcpDest)
	defer c.Close()
	go func() { _, _ = server.Write([]byte("hello")); _, _ = server.Write([]byte("again")) }()
	buf := make([]byte, 5)
	_, _ = io.ReadFull(c, buf)
	_, _ = io.ReadFull(c, buf)
	if a := <-attempts; a != (attemptHit{"proxy-7", true}) {
		t.Fatalf("first answer byte: %+v", a)
	}
	select {
	case a := <-attempts:
		t.Fatalf("only the first answer counts: %+v", a)
	case <-time.After(50 * time.Millisecond):
	}
}

// П1 (ядро 76): рукопожатие висит — отправили, а ни байта ответа за
// VupenFreezeHandshakeSilence: одна неудачная попытка; ответ пришёл — нет.
func TestVupenFreezeHandshakeNoReply(t *testing.T) {
	freezeTestHooks(t, true)
	old := VupenFreezeHandshakeSilence
	VupenFreezeHandshakeSilence = 200 * time.Millisecond
	t.Cleanup(func() { VupenFreezeHandshakeSilence = old })
	attempts := make(chan attemptHit, 8)
	h := *vupenFreezeHooks.Load()
	h.Attempt = func(key any, tag string, ok bool, detail string) { attempts <- attemptHit{tag, ok} }
	VupenSetFreezeHooks(&h)

	hung, server := stdnet.Pipe()
	t.Cleanup(func() { server.Close() })
	go func() { _, _ = io.Copy(io.Discard, server) }()
	c := vupenFreezeWrap(freezeCtx("proxy-7"), hung, tcpDest)
	t.Cleanup(func() { c.Close() })
	start := time.Now()
	if _, err := c.Write(make([]byte, 517)); err != nil { // ClientHello
		t.Fatal(err)
	}
	select {
	case a := <-attempts:
		if a != (attemptHit{"proxy-7", false}) || time.Since(start) < VupenFreezeHandshakeSilence {
			t.Fatalf("hung handshake: %+v after %v", a, time.Since(start))
		}
	case <-time.After(3 * time.Second):
		t.Fatal("a hung handshake must count as a failed attempt")
	}
	select {
	case a := <-attempts:
		t.Fatalf("one report per connection: %+v", a)
	case <-time.After(3 * vupenFreezeScanEvery):
	}

	answered, server2 := stdnet.Pipe()
	t.Cleanup(func() { server2.Close() })
	go func() {
		b := make([]byte, 517)
		_, _ = io.ReadFull(server2, b)
		_, _ = server2.Write([]byte("server hello"))
		_, _ = io.Copy(io.Discard, server2)
	}()
	c2 := vupenFreezeWrap(freezeCtx("proxy-8"), answered, tcpDest)
	t.Cleanup(func() { c2.Close() })
	_, _ = c2.Write(make([]byte, 517))
	_, _ = c2.Read(make([]byte, 64))
	if a := <-attempts; a != (attemptHit{"proxy-8", true}) {
		t.Fatalf("answered handshake: %+v", a)
	}
	select {
	case a := <-attempts:
		t.Fatalf("an answered handshake must not count as a failure: %+v", a)
	case <-time.After(4 * VupenFreezeHandshakeSilence):
	}
}

// Живой узел отвечает на каждую запись — тревоги нет. Регрессия D-25: одного
// соединения достаточно для тревоги (VupenFreezeLoneSilence = обычная тишина),
// так что отметка «ждём ответа», пережившая ответ, дала бы ложную тревогу.
func TestVupenFreezeQuietWhenTheNodeAnswers(t *testing.T) {
	hits := freezeTestHooks(t, true)
	setLoneSilence(t, VupenFreezeSilence)
	client, server := stdnet.Pipe()
	defer server.Close()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 4096)
		for {
			n, err := server.Read(buf)
			if err != nil {
				return
			}
			if _, err := server.Write(buf[:n]); err != nil {
				return
			}
		}
	}()
	c := vupenFreezeWrap(freezeCtx("proxy-10"), client, tcpDest)
	go func() { _, _ = io.Copy(io.Discard, c) }()
	for i := 0; i < 4; i++ {
		if _, err := c.Write(make([]byte, 4096)); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case h := <-hits:
		t.Fatalf("an answering node must not be reported: %+v", h)
	case <-time.After(500 * time.Millisecond):
	}
	c.Close()
	wg.Wait()
}

func TestVupenFreezeSkipsUnwatchedAndNonTCP(t *testing.T) {
	freezeTestHooks(t, false)
	client, server := stdnet.Pipe()
	defer server.Close()
	defer client.Close()
	if c := vupenFreezeWrap(freezeCtx("direct"), client, tcpDest); c != client {
		t.Fatal("an outbound the observatory does not watch must stay unwrapped")
	}
	freezeTestHooks(t, true)
	udp := net.UDPDestination(net.DomainAddress("node.example"), 443)
	if c := vupenFreezeWrap(freezeCtx("proxy-2"), client, udp); c != client {
		t.Fatal("UDP must stay unwrapped: the freeze is a TCP thing")
	}
	if c := vupenFreezeWrap(context.Background(), client, tcpDest); c != client {
		t.Fatal("no outbound in ctx — nothing to report against")
	}
}

// Ядро 76: соединение с ошибкой чтения (EOF, сброс) уходит из наблюдения сразу,
// даже если его не закрыли (рукопожатие TLS с ошибкой сырое соединение не закрывает).
func TestVupenFreezeReadErrorStopsWatching(t *testing.T) {
	freezeTestHooks(t, true)
	client, server := stdnet.Pipe()
	c := vupenFreezeWrap(freezeCtx("proxy-7"), client, tcpDest).(*vupenFreezeConn)
	server.Close()
	if _, err := c.Read(make([]byte, 8)); err == nil {
		t.Fatal("expected a read error")
	}
	vupenFreezeWatch.mu.Lock()
	_, watched := vupenFreezeWatch.conns[c]
	vupenFreezeWatch.mu.Unlock()
	if watched {
		t.Fatal("a connection that failed must leave the watch list")
	}
}

// CR-302: «ни байта ответа» сторожа и поздняя ошибка той же попытки — одна неудача.
func TestVupenFreezeHungHandshakeCountedOnce(t *testing.T) {
	freezeTestHooks(t, true)
	netEpochTest(t)
	VupenSetUplink("wifi", fmt.Sprintf("hung-once-%d", time.Now().UnixNano()))
	old := VupenFreezeHandshakeSilence
	VupenFreezeHandshakeSilence = 200 * time.Millisecond
	t.Cleanup(func() { VupenFreezeHandshakeSilence = old })
	attempts := make(chan attemptHit, 8)
	h := *vupenFreezeHooks.Load()
	h.Attempt = func(key any, tag string, ok bool, detail string) { attempts <- attemptHit{tag, ok} }
	VupenSetFreezeHooks(&h)

	ctx, done := VupenTransportAttempt(auto41Ctx("proxy-7"), "proxy-7")
	hung, server := stdnet.Pipe()
	t.Cleanup(func() { server.Close() })
	go func() { _, _ = io.Copy(io.Discard, server) }()
	c := vupenFreezeWrap(ctx, hung, tcpDest)
	t.Cleanup(func() { c.Close() })
	_, _ = c.Write(make([]byte, 517))
	select {
	case a := <-attempts:
		if a != (attemptHit{"proxy-7", false}) {
			t.Fatalf("hung handshake: %+v", a)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the hung handshake must be reported")
	}
	done(stderrors.New("tls: handshake timeout")) // the same attempt fails later
	select {
	case a := <-attempts:
		t.Fatalf("the same attempt must not count twice: %+v", a)
	case <-time.After(100 * time.Millisecond):
	}
	// Другая попытка с ошибкой — считается.
	_, done2 := VupenTransportAttempt(auto41Ctx("proxy-7"), "proxy-7")
	done2(stderrors.New("refused"))
	if a := <-attempts; a != (attemptHit{"proxy-7", false}) {
		t.Fatalf("another attempt: %+v", a)
	}
}

// CR-303: таймаут чтения (дедлайн) — не конец соединения, наблюдение остаётся.
func TestVupenFreezeReadTimeoutKeepsWatching(t *testing.T) {
	freezeTestHooks(t, true)
	client, server := stdnet.Pipe()
	defer server.Close()
	c := vupenFreezeWrap(freezeCtx("proxy-7"), client, tcpDest).(*vupenFreezeConn)
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	if _, err := c.Read(make([]byte, 8)); err == nil || !vupenIsTimeoutErr(err) {
		t.Fatalf("expected a timeout, got %v", err)
	}
	vupenFreezeWatch.mu.Lock()
	_, watched := vupenFreezeWatch.conns[c]
	vupenFreezeWatch.mu.Unlock()
	if !watched {
		t.Fatal("a read timeout must keep the connection watched")
	}
}

// CR-305: до первого VupenSetUplink попытка — ничего (дешёвая проверка до хука Auto41).
func TestVupenTransportAttemptInactiveIsNoop(t *testing.T) {
	freezeTestHooks(t, true)
	netEpochTest(t) // state reset: VupenSetUplink not called
	called := false
	VupenSetNetEpochHooks(&VupenNetEpochHooks{Auto41: func(context.Context) bool { called = true; return true }})
	ctx := auto41Ctx("proxy-7")
	got, done := VupenTransportAttempt(ctx, "proxy-7")
	done(stderrors.New("refused"))
	if got != ctx || called {
		t.Fatalf("inactive: ctx changed=%v, Auto41 hook called=%v", got != ctx, called)
	}
}

// D-25 (детерминированно): ответ пришёл, пока Write ещё не вернулся, — после
// записи соединение не должно «ждать ответа».
type replyDuringWrite struct {
	net.Conn
	onWrite func()
}

func (c *replyDuringWrite) Write(b []byte) (int, error) { c.onWrite(); return len(b), nil }
func (c *replyDuringWrite) Read(b []byte) (int, error)  { return len(b), nil }

func TestVupenFreezeReplyDuringWriteClearsPending(t *testing.T) {
	inner := &replyDuringWrite{}
	fc := &vupenFreezeConn{Conn: inner}
	inner.onWrite = func() { _, _ = fc.Read(make([]byte, 100)) }
	if _, err := fc.Write(make([]byte, 100)); err != nil {
		t.Fatal(err)
	}
	if fc.sent.Load() != 100 || fc.recv.Load() != 100 || fc.pendingSince.Load() != 0 {
		t.Fatalf("answered during write: sent=%d recv=%d pendingSince=%d (must be 0)",
			fc.sent.Load(), fc.recv.Load(), fc.pendingSince.Load())
	}
	// Без ответа отметка стоит, а неудачная запись без байт её не оставляет.
	quiet := &vupenFreezeConn{Conn: &replyDuringWrite{onWrite: func() {}}}
	_, _ = quiet.Write(make([]byte, 10))
	if quiet.pendingSince.Load() == 0 {
		t.Fatal("a write without an answer must mark the connection as waiting")
	}
	failed := &vupenFreezeConn{Conn: failingConn{}}
	_, _ = failed.Write(make([]byte, 10))
	if failed.pendingSince.Load() != 0 {
		t.Fatal("a write that sent nothing must not leave a waiting mark")
	}
}

type failingConn struct{ net.Conn }

func (failingConn) Write([]byte) (int, error) { return 0, stderrors.New("broken pipe") }
