package hysteria

import (
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/transport/internet"
)

// closeHook is an Instance feature whose Close, like Handler.Close of an outbound,
// calls VupenReleaseStreamSettings (-> manager.Lock) while Instance.Close holds
// statusLock; the sleep stands for a slow inbound Close (Windows TUN).
type closeHook struct {
	ss    *internet.MemoryStreamConfig
	delay time.Duration
}

func (h *closeHook) Type() interface{} { return (*closeHook)(nil) }
func (h *closeHook) Start() error      { return nil }
func (h *closeHook) Close() error {
	time.Sleep(h.delay)
	internet.VupenReleaseStreamSettings(h.ss)
	return nil
}

// T-322 (upstream #7122): the 1 s cleaner must not call Instance.IsRunning (statusLock)
// while holding manager.RLock: Instance.Close holds statusLock and waits for
// manager.Lock in the release hook -> deadlock (xray-core afae5abe, Windows stop).
// The delay (> 1 s tick) guarantees a cleaner tick lands inside Close.
func TestVupenCleanDoesNotDeadlockWithInstanceClose(t *testing.T) {
	initmanager.Do(func() {
		manager = &clientManager{m: make(map[dialerConf]*client)}
		go manager.clean()
		internet.VupenRegisterStreamRelease(vupenReleaseHysteria)
	})
	inst := new(core.Instance)
	hookSS := &internet.MemoryStreamConfig{}
	if err := inst.AddFeature(&closeHook{ss: hookSS, delay: 1500 * time.Millisecond}); err != nil {
		t.Fatal(err)
	}
	d := net.UDPDestination(net.LocalHostIP, 1004)
	entrySS := &internet.MemoryStreamConfig{} // not the hook's: the entry stays for the cleaner
	cl := &client{dest: d, instance: inst}
	key := dialerConf{d, entrySS}
	manager.Lock()
	saved := manager.m
	manager.m = map[dialerConf]*client{key: cl}
	manager.Unlock()
	t.Cleanup(func() {
		restored := make(chan struct{})
		go func() { // a deadlocked manager must not hang the cleanup too
			manager.Lock()
			manager.m = saved
			manager.Unlock()
			close(restored)
		}()
		select {
		case <-restored:
		case <-time.After(200 * time.Millisecond):
		}
	})

	done := make(chan struct{})
	go func() {
		inst.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(6 * time.Second):
		t.Fatal("deadlock: Instance.Close (statusLock) vs hysteria cleaner (manager.RLock -> IsRunning)")
	}

	// The instance is stopped, so the cleaner must drop the entry on a following tick.
	deadline := time.Now().Add(3 * time.Second)
	for {
		manager.RLock()
		n := len(manager.m)
		manager.RUnlock()
		if n == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("entry of a closed instance not removed by the cleaner (%d left)", n)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
