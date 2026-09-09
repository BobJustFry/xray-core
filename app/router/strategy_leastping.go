package router

import (
	"context"
	"sync"

	"github.com/xtls/xray-core/app/observatory"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/extension"
)

type LeastPingStrategy struct {
	ctx         context.Context
	observatory extension.Observatory

	// Vupen (ядро 52): последний выбранный узел — чтобы логировать только смену.
	pickMu   sync.Mutex
	lastPick string
}

// vupenLogPickChange пишет строку только при смене выбора: по ней в vSupport
// видно, какой узел балансировщик считает лучшим и с каким RTT.
func (l *LeastPingStrategy) vupenLogPickChange(tag string, delayMs int64, alive int, total int) {
	l.pickMu.Lock()
	changed := l.lastPick != tag
	l.lastPick = tag
	l.pickMu.Unlock()
	if !changed {
		return
	}
	ctx := l.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	errors.LogWarning(ctx, "[balancer] leastPing → ", tag, " delay=", delayMs, "ms alive=", alive, "/", total)
}

func (l *LeastPingStrategy) GetPrincipleTarget(strings []string) []string {
	return []string{l.PickOutbound(strings)}
}

func (l *LeastPingStrategy) InjectContext(ctx context.Context) {
	l.ctx = ctx
	common.Must(core.RequireFeatures(l.ctx, func(observatory extension.Observatory) error {
		l.observatory = observatory
		return nil
	}))
}

func (l *LeastPingStrategy) PickOutbound(strings []string) string {
	if l.observatory == nil {
		errors.LogError(l.ctx, "observer is nil")
		return ""
	}
	observeReport, err := l.observatory.GetObservation(l.ctx)
	if err != nil {
		errors.LogInfoInner(l.ctx, err, "cannot get observer report")
		return ""
	}
	outboundsList := outboundList(strings)
	if result, ok := observeReport.(*observatory.ObservationResult); ok {
		status := result.Status
		leastPing := int64(99999999)
		selectedOutboundName := ""
		alive, total := 0, 0
		for _, v := range status {
			if !outboundsList.contains(v.OutboundTag) {
				continue
			}
			total++
			if v.Alive {
				alive++
			}
			if v.Alive && v.Delay < leastPing {
				selectedOutboundName = v.OutboundTag
				leastPing = v.Delay
			}
		}
		if selectedOutboundName != "" {
			l.vupenLogPickChange(selectedOutboundName, leastPing, alive, total)
		}
		return selectedOutboundName
	}

	// No way to understand observeReport
	return ""
}

type outboundList []string

func (o outboundList) contains(name string) bool {
	for _, v := range o {
		if v == name {
			return true
		}
	}
	return false
}
