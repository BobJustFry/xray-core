package burst

import (
	"context"
	"testing"
	"time"
)

func TestVupenLaneFor(t *testing.T) {
	cases := []struct {
		stream, proxy, want string
	}{
		{"hysteria", "xray.proxy.hysteria.Config", vupenLaneUDP},
		{"", "xray.proxy.hysteria.Config", vupenLaneUDP},
		{"mkcp", "xray.proxy.vless.outbound.Config", vupenLaneUDP},
		{"", "xray.proxy.wireguard.DeviceConfig", vupenLaneUDP},
		{"tcp", "xray.proxy.vless.outbound.Config", vupenLaneTCP},
		{"splithttp", "xray.proxy.vless.outbound.Config", vupenLaneTCP},
		{"", "", vupenLaneTCP},
	}
	for _, c := range cases {
		if got := vupenLaneFor(c.stream, c.proxy); got != c.want {
			t.Errorf("vupenLaneFor(%q,%q)=%s want %s", c.stream, c.proxy, got, c.want)
		}
	}
}

// Полоса на один слот пропускает по одному и отпускает при отмене.
func TestVupenLaneSerializesAndCancels(t *testing.T) {
	lanes := newVupenLanes()
	sem := lanes.sem(vupenLaneUDP)
	if !vupenAcquire(context.Background(), sem) {
		t.Fatal("first acquire")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if vupenAcquire(ctx, sem) {
		t.Fatal("second acquire must wait until cancel")
	}
	vupenRelease(sem)
	if !vupenAcquire(context.Background(), sem) {
		t.Fatal("acquire after release")
	}
	vupenRelease(sem)
}

func TestVupenRoundSummaryAndFailedTags(t *testing.T) {
	h := &HealthPing{Settings: &HealthPingSettings{Interval: time.Second, SamplingCount: 3}}
	h.PutResult("a", 120*time.Millisecond)
	h.PutResult("b", rttFailed)
	h.PutResult("c", 400*time.Millisecond)
	h.PutResult("c", rttFailed)
	failed := h.vupenFailedTags([]string{"a", "b", "c", "zzz"})
	if len(failed) != 1 || failed[0] != "b" {
		t.Fatalf("failed=%v", failed)
	}
	s := h.vupenRoundSummary("initial", []string{"c", "b", "a", "zzz"})
	for _, want := range []string{"round=initial", "n=4", "alive=2", " a=120/0/1", " b=dead(1)", " c=400/1/2", " zzz=none"} {
		if !contains(s, want) {
			t.Errorf("summary %q lacks %q", s, want)
		}
	}
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// Тихое окно: TCP-проба уступает UDP-хендшейку не дольше VupenObservatoryUDPQuiet.
func TestVupenTCPYieldsToUDPHandshake(t *testing.T) {
	old := VupenObservatoryUDPQuiet
	VupenObservatoryUDPQuiet = 60 * time.Millisecond
	defer func() { VupenObservatoryUDPQuiet = old }()
	l := newVupenLanes()
	start := time.Now()
	l.vupenTCPYield(context.Background())
	if time.Since(start) > 20*time.Millisecond {
		t.Fatal("no udp in flight: must not wait")
	}
	l.vupenUDPBegin()
	start = time.Now()
	l.vupenTCPYield(context.Background())
	if d := time.Since(start); d < 40*time.Millisecond || d > 200*time.Millisecond {
		t.Fatalf("waited %v, want ~60ms", d)
	}
	l.vupenUDPEnd()
	start = time.Now()
	l.vupenTCPYield(context.Background())
	if time.Since(start) > 20*time.Millisecond {
		t.Fatal("after udp end: must not wait")
	}
}
