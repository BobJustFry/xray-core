package internet

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
)

// Ядро 78 (АВТО 4.1, шаг 2.6; ADR-0001 §5.1, §13): закрытие соединений без
// ожидания друг друга, немедленное закрытие соединений узла (VupenCheckRoute,
// режим heal) и состояние эпохи сети для VupenAutoState.

var (
	// VupenNetCloseParallel — сколько соединений закрывается одновременно. На
	// Windows net.Conn.Close может ждать синхронный WSARecv
	// (common/buf/readv_windows.go): один зависший Close не должен держать
	// остальные.
	VupenNetCloseParallel = 8
	// VupenNetCloseWait — сколько вызывающий ждёт закрытий; зависшие
	// закрываются дальше сами (их число — в журнале).
	VupenNetCloseWait = 2 * time.Second
)

// vupenCloseConns — закрыть conns параллельно (не больше VupenNetCloseParallel
// сразу) и подождать не дольше VupenNetCloseWait.
func vupenCloseConns(conns []net.Conn) {
	if len(conns) == 0 {
		return
	}
	workers := VupenNetCloseParallel
	if workers < 1 {
		workers = 1
	}
	if workers > len(conns) {
		workers = len(conns)
	}
	queue := make(chan net.Conn, len(conns))
	for _, c := range conns {
		queue <- c
	}
	close(queue)
	var left atomic.Int64
	left.Store(int64(len(conns)))
	done := make(chan struct{})
	for i := 0; i < workers; i++ {
		go func() {
			for c := range queue {
				c.Close()
				if left.Add(-1) == 0 {
					close(done)
				}
			}
		}()
	}
	t := time.NewTimer(VupenNetCloseWait)
	defer t.Stop()
	select {
	case <-done:
	case <-t.C:
		errors.LogWarning(context.Background(), fmt.Sprintf(
			"[netchange] %d of %d connections still closing after %s (Close blocked) — continuing",
			left.Load(), len(conns), VupenNetCloseWait))
	}
}

// VupenNetClose — закрытие соединений (для VupenAutoState).
type VupenNetClose struct {
	At     time.Time
	Reason string // net-change | lte-return | check-route (через запятую, если вместе)
	Conns  int
}

var vupenNetLastClose atomic.Pointer[VupenNetClose]

func vupenNetRecordClose(reason string, conns int) {
	if conns <= 0 {
		return
	}
	vupenNetLastClose.Store(&VupenNetClose{At: vupenNetNow(), Reason: reason, Conns: conns})
}

// VupenNetInfo — эпоха сети сейчас (VupenAutoState).
type VupenNetInfo struct {
	Active    bool // платформа хоть раз вызвала VupenSetUplink
	Kind, Sig string
	Epoch     uint64
	StableFor time.Duration // сколько сеть не менялась
	// Pending — закрытие, которое ждёт 9 с стабильной сети (nil — не ждёт).
	Pending *VupenNetClose
	// LastClose — последнее закрытие соединений (nil — не было).
	LastClose *VupenNetClose
}

// VupenNetState — снимок эпохи сети.
func VupenNetState() VupenNetInfo {
	s := vupenNet
	info := VupenNetInfo{LastClose: vupenNetLastClose.Load()}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.active.Load() {
		return info
	}
	now := vupenNetNow()
	info.Active, info.Kind, info.Sig, info.Epoch = true, s.current.kind, s.current.sig, s.epoch
	info.StableFor = now.Sub(s.changedAt)
	at := s.changedAt.Add(time.Duration(VupenNetChangeCloseStableSec) * time.Second)
	var reasons []string
	conns := 0
	if s.stopPending != nil {
		reasons = append(reasons, "net-change")
		for _, e := range s.entries {
			if e.id != s.current {
				conns++
			}
		}
	}
	var live []*vupenTagClose
	for _, r := range s.tagCloses {
		if !r.cancelled.Load() {
			live = append(live, r)
		}
	}
	if len(live) > 0 {
		for _, r := range live {
			reasons = append(reasons, r.reason)
		}
		for _, e := range s.entries {
			if s.stopPending != nil && e.id != s.current {
				continue // уже посчитано
			}
			for _, r := range live {
				if r.match(e.tag) {
					conns++
					break
				}
			}
		}
	}
	if len(reasons) > 0 {
		reason := reasons[0]
		for _, r := range reasons[1:] {
			if r != reason {
				reason += "," + r
			}
		}
		info.Pending = &VupenNetClose{At: at, Reason: reason, Conns: conns}
	}
	return info
}

// VupenCloseConnsNow — закрыть сразу соединения outbound'а tag (VupenCheckRoute,
// heal: узел признан замороженным, это не смена сети): отслеживаемые эпохой
// сети (TCP и UDP, ядро АВТО 4.1) и соединения сторожа заморозки с ключом key
// (обсерватория экземпляра ядра; nil — только эпоха). Возвращает сколько закрыто.
//
// CR-701: VupenNetClosing здесь не рассылается — сеть не менялась, а окно проб
// обсерватории перед поиском heal скрыло бы провалы проб (ложное «нет рабочих»
// и перелив в LTE). Событие — только для чистки эпохи и возврата с LTE.
func VupenCloseConnsNow(key any, tag string) int {
	if tag == "" {
		return 0
	}
	seen := map[net.Conn]struct{}{}
	var closing []net.Conn
	add := func(c net.Conn) {
		if c == nil {
			return
		}
		if _, ok := seen[c]; ok {
			return
		}
		seen[c] = struct{}{}
		closing = append(closing, c)
	}
	s := vupenNet
	s.mu.Lock()
	for k, e := range s.entries {
		if e.tag != tag {
			continue
		}
		delete(s.entries, k)
		delete(s.index, e.idx)
		add(e.get())
	}
	s.mu.Unlock()
	if key != nil {
		w := vupenFreezeWatch
		w.mu.Lock()
		for c := range w.conns {
			if c.key == key && c.tag == tag {
				add(c)
			}
		}
		w.mu.Unlock()
	}
	vupenCloseConns(closing)
	vupenNetRecordClose("check-route", len(closing))
	return len(closing)
}
