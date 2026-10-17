package hysteria

import (
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
)

// Vupen (T-075, CR-003): закрытый outbound удаляет только свои клиенты Hysteria.
func TestVupenReleaseHysteriaOnlyOwnEntries(t *testing.T) {
	initmanager.Do(func() {
		manager = &clientManager{m: make(map[dialerConf]*client)}
		go manager.clean()
		internet.VupenRegisterStreamRelease(vupenReleaseHysteria)
	})
	a, b := &internet.MemoryStreamConfig{}, &internet.MemoryStreamConfig{}
	d1 := net.UDPDestination(net.LocalHostIP, 1001)
	d2 := net.UDPDestination(net.LocalHostIP, 1002)
	manager.Lock()
	saved := manager.m
	manager.m = map[dialerConf]*client{
		{d1, a}: {dest: d1}, {d2, a}: {dest: d2}, {d1, b}: {dest: d1},
	}
	manager.Unlock()
	t.Cleanup(func() {
		manager.Lock()
		manager.m = saved
		manager.Unlock()
	})
	internet.VupenReleaseStreamSettings(a)
	manager.RLock()
	defer manager.RUnlock()
	if len(manager.m) != 1 || manager.m[dialerConf{d1, b}] == nil {
		t.Fatalf("left %d entries, want only b", len(manager.m))
	}
}

// CR-101: клиент закрываемого outbound'а посреди рукопожатия (держит свой замок)
// не держит manager: Dial других и Close не ждут; сам клиент закроется, когда
// замок освободится.
func TestVupenReleaseHysteriaDoesNotWaitForBusyClient(t *testing.T) {
	initmanager.Do(func() {
		manager = &clientManager{m: make(map[dialerConf]*client)}
		go manager.clean()
		internet.VupenRegisterStreamRelease(vupenReleaseHysteria)
	})
	closed := make(chan *client, 1)
	orig := vupenHysteriaClose
	vupenHysteriaClose = func(c *client) {
		orig(c)
		closed <- c
	}
	t.Cleanup(func() { vupenHysteriaClose = orig })
	ss := &internet.MemoryStreamConfig{}
	d := net.UDPDestination(net.LocalHostIP, 1003)
	busy := &client{dest: d}
	manager.Lock()
	saved := manager.m
	manager.m = map[dialerConf]*client{{d, ss}: busy}
	manager.Unlock()
	t.Cleanup(func() {
		manager.Lock()
		manager.m = saved
		manager.Unlock()
	})
	busy.Lock() // «рукопожатие» идёт

	done := make(chan struct{})
	go func() {
		internet.VupenReleaseStreamSettings(ss)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		busy.Unlock()
		t.Fatal("release waits for the busy client")
	}
	got := make(chan struct{})
	go func() {
		manager.RLock()
		manager.RUnlock()
		close(got)
	}()
	select {
	case <-got:
	case <-time.After(100 * time.Millisecond):
		busy.Unlock()
		t.Fatal("manager is blocked by a busy client")
	}
	select {
	case <-closed:
		busy.Unlock()
		t.Fatal("closed while its handshake still holds the lock")
	case <-time.After(50 * time.Millisecond):
	}
	busy.Unlock()
	select {
	case c := <-closed:
		if c != busy {
			t.Fatal("another client closed")
		}
	case <-time.After(time.Second):
		t.Fatal("the client was not closed after its lock was released")
	}
}

// CR-101: очистка простоя не ждёт клиента посреди рукопожатия (иначе под
// manager.RLock она останавливала все Dial Hysteria в процессе).
func TestVupenHysteriaCleanSkipsBusyClient(t *testing.T) {
	busy := &client{}
	busy.Lock()
	done := make(chan struct{})
	go func() {
		busy.clean()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		busy.Unlock()
		t.Fatal("clean waits for a busy client")
	}
	busy.Unlock()
}
