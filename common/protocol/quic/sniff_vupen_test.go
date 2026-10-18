package quic

import (
	"crypto"
	"crypto/aes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/xtls/xray-core/common/protocol"
	"golang.org/x/crypto/hkdf"
)

// Vupen (T-083): S1 (хвост из нулей, апстрим #6882) и S2 (быстрые вердикты) на
// собственных фикстурах: Initial QUIC v1 собирается и шифруется здесь же по
// RFC 9001 §5 (те же ключи и защита заголовка, что расшифровывает SniffQUIC).

// vupenClientHello — TLS ClientHello (тип 1, с длиной); sni == "" — без имени.
func vupenClientHello(sni string) []byte {
	var body []byte
	body = append(body, 0x03, 0x03)             // legacy_version
	body = append(body, make([]byte, 32)...)    // random
	body = append(body, 0x00)                   // session id
	body = append(body, 0x00, 0x02, 0x13, 0x01) // cipher_suites: TLS_AES_128_GCM_SHA256
	body = append(body, 0x01, 0x00)             // compression
	var ext []byte
	ext = append(ext, 0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04) // supported_versions: TLS 1.3
	if sni != "" {
		name := []byte(sni)
		list := append([]byte{0x00}, byte(len(name)>>8), byte(len(name)))
		list = append(list, name...)
		sn := append([]byte{byte(len(list) >> 8), byte(len(list))}, list...)
		ext = append(ext, 0x00, 0x00, byte(len(sn)>>8), byte(len(sn)))
		ext = append(ext, sn...)
	}
	// Ключ ML-KEM в iOS 26 раздувает ClientHello до ~1,5 КБ — здесь «шум» того же размера.
	pad := make([]byte, 1400)
	ext = append(ext, 0xfe, 0x0d, byte(len(pad)>>8), byte(len(pad)))
	ext = append(ext, pad...)
	body = append(body, byte(len(ext)>>8), byte(len(ext)))
	body = append(body, ext...)
	return append([]byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
}

var vupenTestDCID = []byte{1, 2, 3, 4, 5, 6, 7, 8}

// vupenInitial — один Initial (v1) с кадром CRYPTO [offset, offset+len(data)),
// дополненный PADDING до 1200 байт датаграммы; pn — номер пакета.
func vupenInitial(t *testing.T, offset int, data []byte, pn byte) []byte {
	t.Helper()
	var frames []byte
	frames = append(frames, 0x06)
	frames = appendVarint(frames, uint64(offset))
	frames = appendVarint(frames, uint64(len(data)))
	frames = append(frames, data...)
	const pnLen = 1
	hdrFixed := []byte{0xc0 | (pnLen - 1), 0, 0, 0, 1, byte(len(vupenTestDCID))}
	hdrFixed = append(hdrFixed, vupenTestDCID...)
	hdrFixed = append(hdrFixed, 0x00, 0x00) // scid len 0, token len 0
	// длина: номер пакета + шифртекст (кадры + тег 16) — до 1200 байт датаграммы
	if want := 1200 - len(hdrFixed) - 2 - pnLen - 16; len(frames) < want {
		frames = append(frames, make([]byte, want-len(frames))...)
	}
	length := pnLen + len(frames) + 16
	hdr := append(hdrFixed, byte(0x40|length>>8), byte(length))
	pnOffset := len(hdr)
	hdr = append(hdr, pn)

	initial := hkdf.Extract(crypto.SHA256.New, vupenTestDCID, quicV1.initialSalt)
	secret := hkdfExpandLabel(initial, "client in", crypto.SHA256.Size())
	key := hkdfExpandLabel(secret, "quic key", 16)
	iv := hkdfExpandLabel(secret, "quic iv", 12)
	hp := hkdfExpandLabel(secret, "quic hp", 16)
	aead := AEADAESGCMTLS13(key, iv)
	nonce := make([]byte, aead.NonceSize())
	nonce[len(nonce)-1] = pn
	pkt := aead.Seal(append([]byte(nil), hdr...), nonce, frames, hdr)
	block, err := aes.NewCipher(hp)
	if err != nil {
		t.Fatal(err)
	}
	mask := make([]byte, 16)
	block.Encrypt(mask, pkt[pnOffset+4:pnOffset+4+16])
	pkt[0] ^= mask[0] & 0x0f
	pkt[pnOffset] ^= mask[1]
	return pkt
}

func appendVarint(b []byte, v uint64) []byte {
	switch {
	case v < 64:
		return append(b, byte(v))
	case v < 16384:
		return binary.BigEndian.AppendUint16(b, uint16(v)|0x4000)
	default:
		return binary.BigEndian.AppendUint32(b, uint32(v)|0x80000000)
	}
}

func TestVupenSniffQUICFixtureWithSNI(t *testing.T) {
	ch := vupenClientHello("vupen.example")
	half := len(ch) / 2
	two := append(vupenInitial(t, 0, ch[:half], 0), vupenInitial(t, half, ch[half:], 1)...)
	h, err := SniffQUIC(two)
	if err != nil || h.Domain() != "vupen.example" {
		t.Fatalf("two Initials: %v %v", h, err)
	}
	if _, err := SniffQUIC(vupenInitial(t, 0, ch[:half], 0)); !errors.Is(err, protocol.ErrProtoNeedMoreData) {
		t.Fatalf("half of ClientHello: %v, want need more data", err)
	}
}

// S2: ClientHello целиком и без SNI — сразу «имени нет», не «нужно ещё данных».
func TestVupenSniffQUICCompleteClientHelloWithoutSNI(t *testing.T) {
	ch := vupenClientHello("")
	half := len(ch) / 2
	p1, p2 := vupenInitial(t, 0, ch[:half], 0), vupenInitial(t, half, ch[half:], 1)
	if _, err := SniffQUIC(append(append([]byte(nil), p1...), p2...)); !errors.Is(err, ErrQUICNoSNI) {
		t.Fatalf("complete ClientHello without SNI: %v", err)
	}
	// Только первая половина — ждать дальше.
	if _, err := SniffQUIC(append([]byte(nil), p1...)); !errors.Is(err, protocol.ErrProtoNeedMoreData) {
		t.Fatalf("first half: %v", err)
	}
	// Вторая половина без первой (дыра в CRYPTO с нуля) — сообщение не собрано, ждать.
	if _, err := SniffQUIC(vupenInitial(t, half, ch[half:], 1)); !errors.Is(err, protocol.ErrProtoNeedMoreData) {
		t.Fatalf("second half only: %v", err)
	}
	// Половины не по порядку — всё равно собрано.
	if _, err := SniffQUIC(append(vupenInitial(t, half, ch[half:], 1), vupenInitial(t, 0, ch[:half], 0)...)); !errors.Is(err, ErrQUICNoSNI) {
		t.Fatalf("out of order halves: %v", err)
	}
}

// S2: поток начинается не с Initial (0-RTT — продолжение соединения) — сразу «имени не будет».
func TestVupenSniffQUICFirstPacketNotInitial(t *testing.T) {
	pkt, _ := hex.DecodeString("d00000000108010203040506070800" + "4014" + "000102030405060708090a0b0c0d0e0f10111213")
	// d0: long header, fixed bit, type 0b01 (0-RTT для v1)
	if _, err := SniffQUIC(pkt); !errors.Is(err, ErrQUICNotFirstInitial) {
		t.Fatalf("0-RTT first: %v", err)
	}
	// Initial, за ним 0-RTT — нормальный порядок: 0-RTT пропускается, имя находится.
	ch := vupenClientHello("vupen.example")
	h, err := SniffQUIC(append(vupenInitial(t, 0, ch, 0), pkt...))
	if err != nil || h.Domain() != "vupen.example" {
		t.Fatalf("Initial then 0-RTT: %v %v", h, err)
	}
}

// S1 (апстрим #6882): нули после пакета (склеенные датаграммы с дополнением) не
// ломают разбор — ни для неполного Initial, ни между двумя.
func TestVupenSniffQUICTrailingZeros(t *testing.T) {
	ch := vupenClientHello("vupen.example")
	half := len(ch) / 2
	p1, p2 := vupenInitial(t, 0, ch[:half], 0), vupenInitial(t, half, ch[half:], 1)
	zeros := make([]byte, 37)
	if _, err := SniffQUIC(append(append([]byte(nil), p1...), zeros...)); !errors.Is(err, protocol.ErrProtoNeedMoreData) {
		t.Fatalf("incomplete Initial + zeros: %v, want need more data", err)
	}
	spliced := append(append(append([]byte(nil), p1...), zeros...), p2...)
	h, err := SniffQUIC(spliced)
	if err != nil || h.Domain() != "vupen.example" {
		t.Fatalf("Initial + zeros + Initial: %v %v", h, err)
	}
}
