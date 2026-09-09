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
type streamFramer struct {
	acc    []byte
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

// free — сколько байт ещё можно дочитать в накопитель.
func (f *streamFramer) free() []byte { return f.acc[f.n:] }

// commit — Read положил n байт в free().
func (f *streamFramer) commit(n int) { f.n += n }

// frameLen — длина первого целого кадра (включая 4 байта AF); 0 — кадр ещё
// неполный; errStreamDesync — заголовок не похож на кадр.
func (f *streamFramer) frameLen() (int, error) {
	if f.n < streamHeaderSize+1 {
		return 0, nil
	}
	af, ver := f.acc[3], f.acc[4]>>4
	if f.acc[0] != 0 || f.acc[1] != 0 || f.acc[2] != 0 {
		return 0, errStreamDesync
	}
	switch {
	case af == streamAFInet && ver == 4:
		if f.n < streamHeaderSize+20 {
			return 0, nil
		}
		total := int(binary.BigEndian.Uint16(f.acc[streamHeaderSize+2 : streamHeaderSize+4]))
		if total < 20 {
			return 0, errStreamDesync
		}
		return f.complete(streamHeaderSize + total)
	case af == streamAFInet6 && ver == 6:
		if f.n < streamHeaderSize+40 {
			return 0, nil
		}
		payload := int(binary.BigEndian.Uint16(f.acc[streamHeaderSize+4 : streamHeaderSize+6]))
		return f.complete(streamHeaderSize + 40 + payload)
	default:
		return 0, errStreamDesync
	}
}

func (f *streamFramer) complete(frame int) (int, error) {
	if frame > streamMaxFrame || frame > len(f.acc) {
		return 0, errStreamDesync
	}
	if f.n < frame {
		return 0, nil
	}
	return frame, nil
}

// pop — вырезает первый кадр длиной frame: IP-пакет без AF-заголовка копируется
// в dst (длины frame-4, из пула buf), остаток накопителя сдвигается в начало.
func (f *streamFramer) pop(frame int, dst []byte) int {
	n := copy(dst, f.acc[streamHeaderSize:frame])
	copy(f.acc, f.acc[frame:f.n])
	f.n -= frame
	return n
}

// resync — после битого заголовка ищет следующий правдоподобный кадр:
// `00 00 00 AF` + совпадающий version-нибл. Всё до него выбрасывается; если не
// найдено — накопитель очищается целиком. Возвращает число выброшенных байт.
func (f *streamFramer) resync() int {
	f.desync++
	for i := 1; i+streamHeaderSize < f.n; i++ {
		if f.acc[i] != 0 || f.acc[i+1] != 0 || f.acc[i+2] != 0 {
			continue
		}
		af, ver := f.acc[i+3], f.acc[i+4]>>4
		if (af == streamAFInet && ver == 4) || (af == streamAFInet6 && ver == 6) {
			copy(f.acc, f.acc[i:f.n])
			f.n -= i
			return i
		}
	}
	dropped := f.n
	f.n = 0
	return dropped
}
