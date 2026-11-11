package tun

import (
	"encoding/binary"
	"errors"
)

// Vupen: разбор кадров `[4 байта AF][IP-пакет]` из потокового сокета.
//
// Расширение iOS не отдаёт ядру utun: Swift читает packetFlow и пишет каждый
// пакет в socketpair(SOCK_STREAM) через writev. У потокового сокета нет границ
// сообщений: два кадра 1232 + 1070 байт лежат подряд, один Read в буфер MTU+4
// возвращал первый кадр плюс хвост второго — gVisor обрезал первый по
// TotalLength, а следующий Read начинался с середины второго кадра и тот
// молча пропадал (мусорный version-нибл). Полноразмерные TCP-сегменты
// (кадр ровно MTU+4) выравнивались с буфером случайно, поэтому TCP этого почти
// не чувствовал; QUIC терял вторую Initial-датаграмму ClientHello в 22 из 26
// потоков (vSupport iOS 590, 2026-09-09 18:14: `reads=1 bytes=1200
// last=NeedMoreData`), а хвост доезжал только ретрансмитом через 1–8 с.
//
// streamFramer накапливает байты и отдаёт по одному целому кадру; длина кадра
// берётся из IP-заголовка (IPv4 TotalLength, IPv6 PayloadLength + 40), как это
// делает нисходящий поток на стороне Swift. Битый заголовок — resync по
// следующему правдоподобному `AF + version`, со счётчиком и строкой в лог.
// Накопитель acc[off:n]: off — начало первого неразобранного кадра. pop только
// двигает off, сдвиг остатка в начало делает free() перед следующим Read — один
// memmove хвоста (неполного кадра) на Read, а не всего остатка на каждый кадр.
type streamFramer struct {
	acc    []byte
	off    int
	n      int
	desync int
}

const (
	streamHeaderSize    = 4 // AF-заголовок кадра, как у utun
	streamFramerAccSize = 64 * 1024
	streamAFInet        = 2  // AF_INET  (Darwin)
	streamAFInet6       = 30 // AF_INET6 (Darwin)
	streamMaxFrame      = streamHeaderSize + 65535
)

var errStreamDesync = errors.New("tun stream: frame header does not match AF/IP header")

func newStreamFramer() *streamFramer {
	return &streamFramer{acc: make([]byte, streamFramerAccSize)}
}

// free — куда дочитать следующий Read; неполный хвост сначала сдвигается в начало.
func (f *streamFramer) free() []byte {
	if f.off > 0 {
		f.n = copy(f.acc, f.acc[f.off:f.n])
		f.off = 0
	}
	return f.acc[f.n:]
}

// reset — выбросить всё накопленное.
func (f *streamFramer) reset() { f.off, f.n = 0, 0 }

// commit — Read положил n байт в free().
func (f *streamFramer) commit(n int) { f.n += n }

// frameLen — длина первого целого кадра (включая 4 байта AF); 0 — кадр ещё
// неполный; errStreamDesync — заголовок не похож на кадр.
func (f *streamFramer) frameLen() (int, error) {
	p := f.acc[f.off:f.n]
	if len(p) < streamHeaderSize+1 {
		return 0, nil
	}
	af, ver := p[3], p[4]>>4
	if p[0] != 0 || p[1] != 0 || p[2] != 0 {
		return 0, errStreamDesync
	}
	switch {
	case af == streamAFInet && ver == 4:
		if len(p) < streamHeaderSize+20 {
			return 0, nil
		}
		total := int(binary.BigEndian.Uint16(p[streamHeaderSize+2 : streamHeaderSize+4]))
		if total < 20 {
			return 0, errStreamDesync
		}
		return f.complete(len(p), streamHeaderSize+total)
	case af == streamAFInet6 && ver == 6:
		if len(p) < streamHeaderSize+40 {
			return 0, nil
		}
		payload := int(binary.BigEndian.Uint16(p[streamHeaderSize+4 : streamHeaderSize+6]))
		return f.complete(len(p), streamHeaderSize+40+payload)
	default:
		return 0, errStreamDesync
	}
}

// complete — кадр длиной frame целиком среди have накопленных байт? Кадр
// длиннее накопителя не дочитать никогда — это desync.
func (f *streamFramer) complete(have, frame int) (int, error) {
	if frame > streamMaxFrame || frame > len(f.acc) {
		return 0, errStreamDesync
	}
	if have < frame {
		return 0, nil
	}
	return frame, nil
}

// pop — вырезает первый кадр длиной frame: IP-пакет без AF-заголовка копируется
// в dst (длины frame-4), off сдвигается за кадр; остаток не двигается (free).
func (f *streamFramer) pop(frame int, dst []byte) int {
	n := copy(dst, f.acc[f.off+streamHeaderSize:f.off+frame])
	if f.off += frame; f.off == f.n {
		f.reset()
	}
	return n
}

// resync — после битого заголовка ищет следующий правдоподобный кадр:
// `00 00 00 AF` + совпадающий version-нибл. Всё до него выбрасывается; если не
// найдено — накопитель очищается целиком. Возвращает число выброшенных байт.
func (f *streamFramer) resync() int {
	f.desync++
	p := f.acc[f.off:f.n]
	for i := 1; i+streamHeaderSize < len(p); i++ {
		if p[i] != 0 || p[i+1] != 0 || p[i+2] != 0 {
			continue
		}
		af, ver := p[i+3], p[i+4]>>4
		if (af == streamAFInet && ver == 4) || (af == streamAFInet6 && ver == 6) {
			f.off += i
			return i
		}
	}
	dropped := len(p)
	f.reset()
	return dropped
}
