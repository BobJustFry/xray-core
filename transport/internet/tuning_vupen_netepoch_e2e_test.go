package internet_test

import (
	"fmt"
	"io"
	stdnet "net"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/core"
	coreserial "github.com/xtls/xray-core/infra/conf/serial"
	_ "github.com/xtls/xray-core/main/distro/all"
	"github.com/xtls/xray-core/transport/internet"
)

// End to end, real time (~9 s per case): an AUTO 4.1 core and a plain core
// (like PROXY-ping) in one process, each relaying a client connection. After a
// network change has been stable for 9 s, only the AUTO 4.1 relay is reset.
// Cases: `direct` (freedom) and VLESS over gRPC (the gRPC dialer opens its
// socket in its own context — CR-102).
func TestVupenNetEpochE2EClosesOnlyAuto41(t *testing.T) {
	if testing.Short() {
		t.Skip("real 9 s countdown")
	}
	internet.VupenNetEpochResetForTest()
	t.Cleanup(internet.VupenNetEpochResetForTest)

	echo := echoServer(t)
	grpcServer := vlessGRPCServer(t)

	for _, tc := range []struct {
		name     string
		outbound string
	}{
		{"direct", `{"tag": "out-1", "protocol": "freedom"}`},
		{"vless-grpc", fmt.Sprintf(`{"tag": "out-1", "protocol": "vless",
		  "settings": {"vnext": [{"address": "127.0.0.1", "port": %d,
		    "users": [{"id": "%s", "encryption": "none"}]}]},
		  "streamSettings": {"network": "grpc", "grpcSettings": {"serviceName": "vupen"}}}`, grpcServer, testUUID)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			internet.VupenNetEpochResetForTest()
			auto41Port := startRelay(t, echo, tc.outbound, true)
			plainPort := startRelay(t, echo, tc.outbound, false)

			internet.VupenSetUplink("wifi", "wifi:en0")
			auto41 := dialRelay(t, auto41Port)
			plain := dialRelay(t, plainPort)

			internet.VupenSetUplink("cellular", "cellular:pdp_ip0")
			time.Sleep(8 * time.Second)
			if !alive(auto41) || !alive(plain) {
				t.Fatal("a relay was reset before 9 s")
			}
			time.Sleep(1500 * time.Millisecond)
			if alive(auto41) {
				t.Fatal("AUTO 4.1 connection of the old network still alive after 9 s")
			}
			if !alive(plain) {
				t.Fatal("a plain (non-AUTO-4.1) instance lost its connection")
			}
		})
	}
}

const testUUID = "b831381d-6324-4d53-ad4f-8cda48b30811"

func echoServer(t *testing.T) string {
	t.Helper()
	l, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	return l.Addr().String()
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*stdnet.TCPAddr).Port
}

func startCore(t *testing.T, cfg string) {
	t.Helper()
	config, err := coreserial.LoadJSONConfig(strings.NewReader(cfg))
	if err != nil {
		t.Fatal(err)
	}
	inst, err := core.New(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := inst.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { inst.Close() })
}

// vlessGRPCServer — a plain core (no vupen fields): VLESS over gRPC → freedom.
func vlessGRPCServer(t *testing.T) int {
	t.Helper()
	port := freePort(t)
	startCore(t, fmt.Sprintf(`{
	  "log": {"loglevel": "none"},
	  "inbounds": [{"listen": "127.0.0.1", "port": %d, "protocol": "vless",
	    "settings": {"clients": [{"id": "%s"}], "decryption": "none"},
	    "streamSettings": {"network": "grpc", "grpcSettings": {"serviceName": "vupen"}}}],
	  "outbounds": [{"protocol": "freedom", "settings": {"finalRules": [{"action": "allow", "ip": ["127.0.0.1"]}]}}]
	}`, port, testUUID))
	return port
}

// startRelay — dokodemo → balancer B (vupenSticky when auto41) → outbound.
func startRelay(t *testing.T, target, outbound string, auto41 bool) int {
	t.Helper()
	port := freePort(t)
	host, tport, _ := stdnet.SplitHostPort(target)
	sticky := ""
	if auto41 {
		sticky = `, "vupenSticky": {"initial": "out-1"}`
	}
	startCore(t, fmt.Sprintf(`{
	  "log": {"loglevel": "none"},
	  "inbounds": [{"listen": "127.0.0.1", "port": %d, "protocol": "dokodemo-door",
	    "settings": {"address": "%s", "port": %s, "network": "tcp"}}],
	  "outbounds": [%s],
	  "routing": {
	    "rules": [{"port": "0-65535", "balancerTag": "B"}],
	    "balancers": [{"tag": "B", "selector": ["out-"], "strategy": {"type": "random"}%s}]
	  }
	}`, port, host, tport, outbound, sticky))
	return port
}

func dialRelay(t *testing.T, port int) stdnet.Conn {
	t.Helper()
	c, err := stdnet.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	if !alive(c) {
		t.Fatal("relay does not echo")
	}
	return c
}

// alive — one byte round-trips through the relay.
func alive(c stdnet.Conn) bool {
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Write([]byte{'x'}); err != nil {
		return false
	}
	b := make([]byte, 1)
	n, err := c.Read(b)
	return err == nil && n == 1
}
