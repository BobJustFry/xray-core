package burst

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet/tagged"
)

// Стартовый раунд: все пробы падают → через VupenObservatoryRetryDelay должен
// прийти повтор ровно для провалившихся узлов (ядро 52).
func TestVupenSchedulerRetriesFailedSubjects(t *testing.T) {
	oldDialer := tagged.Dialer
	tagged.Dialer = func(ctx context.Context, d routing.Dispatcher, dest net.Destination, tag string) (net.Conn, error) {
		return nil, errors.New("down")
	}
	defer func() { tagged.Dialer = oldDialer }()

	oldInit, oldRetry := VupenObservatoryInitialDelay, VupenObservatoryRetryDelay
	VupenObservatoryInitialDelay, VupenObservatoryRetryDelay = 10*time.Millisecond, 50*time.Millisecond
	defer func() { VupenObservatoryInitialDelay, VupenObservatoryRetryDelay = oldInit, oldRetry }()

	var mu sync.Mutex
	var retried []string
	oldHook := vupenRetryHook
	vupenRetryHook = func(tags []string) {
		mu.Lock()
		retried = append(retried, tags...)
		mu.Unlock()
	}
	defer func() { vupenRetryHook = oldHook }()

	h := NewHealthPing(context.Background(), nil, &HealthPingConfig{
		Interval:      int64(10 * time.Second),
		SamplingCount: 1,
		Timeout:       int64(200 * time.Millisecond),
		Destination:   "http://127.0.0.1:9/generate_204",
	})
	h.StartScheduler(func() ([]string, error) { return []string{"a", "b"}, nil })
	defer h.StopScheduler()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(retried)
		mu.Unlock()
		if n == 2 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(retried) != 2 {
		t.Fatalf("retry hook saw %v, want [a b]", retried)
	}
}
