package burst

import (
	"testing"
	"time"
)

func TestVupenSkipDeadBackoff(t *testing.T) {
	h := &HealthPing{Settings: &HealthPingSettings{Interval: time.Second, SamplingCount: 3}}
	h.PutResult("x", rttFailed)
	h.PutResult("x", rttFailed)
	if h.vupenSkipDead("x") {
		t.Fatal("2 failures: not yet dead")
	}
	h.PutResult("x", rttFailed)
	skips := 0
	for i := 0; i < VupenObservatoryDeadBackoff; i++ {
		if h.vupenSkipDead("x") {
			skips++
		}
	}
	if skips != VupenObservatoryDeadBackoff-1 {
		t.Fatalf("expected %d skips of %d, got %d", VupenObservatoryDeadBackoff-1, VupenObservatoryDeadBackoff, skips)
	}
	h.PutResult("x", 120*time.Millisecond)
	if h.vupenSkipDead("x") {
		t.Fatal("success must reset")
	}
}
