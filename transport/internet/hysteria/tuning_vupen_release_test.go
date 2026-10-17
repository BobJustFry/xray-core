package hysteria

import (
	"testing"

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
