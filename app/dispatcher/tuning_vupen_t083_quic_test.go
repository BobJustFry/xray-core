package dispatcher

import (
	"crypto"
	"crypto/aes"
	"encoding/binary"
	"errors"
	"testing"

	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/protocol/quic"
	"github.com/xtls/xray-core/transport/pipe"
	"golang.org/x/crypto/hkdf"
)

// Vupen (T-083, S2) на уровне диспетчера: ClientHello QUIC целиком без SNI — снифер
// сразу говорит «содержимое не распознано» (ранний выход, без 200 мс), половина —
// «нужно ещё данных».

func t083ExpandLabel(secret []byte, label string, n int) []byte {
	b := binary.BigEndian.AppendUint16(nil, uint16(n))
	b = append(b, byte(6+len(label)))
	b = append(b, "tls13 "...)
	b = append(b, label...)
	b = append(b, 0)
	out := make([]byte, n)
	if _, err := hkdf.Expand(crypto.SHA256.New, secret, b).Read(out); err != nil {
		panic(err)
	}
	return out
}

func t083Initial(t *testing.T, offset int, data []byte, pn byte) []byte {
	t.Helper()
	dcid := []byte{9, 8, 7, 6, 5, 4, 3, 2}
	frames := []byte{0x06}
	frames = binary.BigEndian.AppendUint16(frames, uint16(offset)|0x4000)
	frames = binary.BigEndian.AppendUint16(frames, uint16(len(data))|0x4000)
	frames = append(frames, data...)
	hdr := append([]byte{0xc0, 0, 0, 0, 1, byte(len(dcid))}, dcid...)
	hdr = append(hdr, 0, 0)
	if want := 1200 - len(hdr) - 2 - 1 - 16; len(frames) < want {
		frames = append(frames, make([]byte, want-len(frames))...)
	}
	l := 1 + len(frames) + 16
	hdr = append(hdr, byte(0x40|l>>8), byte(l))
	pnOff := len(hdr)
	hdr = append(hdr, pn)
	salt := []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}
	secret := t083ExpandLabel(hkdf.Extract(crypto.SHA256.New, dcid, salt), "client in", 32)
	aead := quic.AEADAESGCMTLS13(t083ExpandLabel(secret, "quic key", 16), t083ExpandLabel(secret, "quic iv", 12))
	nonce := make([]byte, aead.NonceSize())
	nonce[len(nonce)-1] = pn
	pkt := aead.Seal(append([]byte(nil), hdr...), nonce, frames, hdr)
	block, _ := aes.NewCipher(t083ExpandLabel(secret, "quic hp", 16))
	mask := make([]byte, 16)
	block.Encrypt(mask, pkt[pnOff+4:pnOff+20])
	pkt[0] ^= mask[0] & 0x0f
	pkt[pnOff] ^= mask[1]
	return pkt
}

func t083ClientHelloNoSNI() []byte {
	body := append([]byte{0x03, 0x03}, make([]byte, 32)...)
	body = append(body, 0x00, 0x00, 0x02, 0x13, 0x01, 0x01, 0x00)
	ext := []byte{0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04}
	pad := make([]byte, 1400)
	ext = append(ext, 0xfe, 0x0d, byte(len(pad)>>8), byte(len(pad)))
	ext = append(ext, pad...)
	body = append(body, byte(len(ext)>>8), byte(len(ext)))
	body = append(body, ext...)
	return append([]byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
}

func TestVupenSnifferQUICNoSNIExitsAtOnce(t *testing.T) {
	ch := t083ClientHelloNoSNI()
	half := len(ch) / 2
	p1, p2 := t083Initial(t, 0, ch[:half], 0), t083Initial(t, half, ch[half:], 1)
	ctx := t083Ctx(3)

	s := NewSniffer(ctx, []string{"quic"}, 443)
	if _, err := s.Sniff(ctx, append([]byte(nil), p1...), net.Network_UDP); !errors.Is(err, protocol.ErrProtoNeedMoreData) {
		t.Fatalf("half: %v", err)
	}
	s = NewSniffer(ctx, []string{"quic"}, 443)
	_, err := s.Sniff(ctx, append(append([]byte(nil), p1...), p2...), net.Network_UDP)
	if err != errUnknownContent {
		t.Fatalf("complete ClientHello without SNI: %v, want unknown content (early exit)", err)
	}
	vupenCountQUICFlow(ctx)
	if got := vupenQUICStatsString(); got == "" {
		t.Fatal("stats")
	}
}

// Время до решения на тракте снифа: полный ClientHello без SNI — сразу, а не
// по истечении 200 мс бюджета; половина — по-прежнему ждёт бюджет.
func TestVupenSniffNoSNITiming(t *testing.T) {
	ch := t083ClientHelloNoSNI()
	half := len(ch) / 2
	run := func(pkts ...[]byte) (time.Duration, error) {
		r, w := pipe.New(pipe.WithoutSizeLimit())
		var mb buf.MultiBuffer
		for _, p := range pkts {
			mb = append(mb, buf.FromBytes(append([]byte(nil), p...)))
		}
		if err := w.WriteMultiBuffer(mb); err != nil {
			t.Fatal(err)
		}
		cr := &cachedReader{reader: r}
		payload := buf.NewWithSize(32767)
		defer payload.Release()
		ctx := t083Ctx(4)
		start := time.Now()
		_, err := vupenSniffContentTwoPhase(ctx, cr, net.Network_UDP, 443, NewSniffer(ctx, []string{"quic"}, 443), payload)
		return time.Since(start), err
	}
	full, err := run(t083Initial(t, 0, ch[:half], 0), t083Initial(t, half, ch[half:], 1))
	if err == nil || full > 100*time.Millisecond {
		t.Fatalf("no-SNI ClientHello: %v after %s, want an early exit", err, full)
	}
	part, err := run(t083Initial(t, 0, ch[:half], 0))
	if err == nil || part < VupenSniffPhase1Deadline-20*time.Millisecond {
		t.Fatalf("half ClientHello: %v after %s, want the full budget", err, part)
	}
	t.Logf("decision: complete no-SNI %s, incomplete %s (budget %s)", full.Round(time.Millisecond), part.Round(time.Millisecond), VupenSniffPhase1Deadline)
}
