package router

import (
	"context"

	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/extension"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet"
)

// Vupen (ядро 74, АВТО 4.1): эпохи сети (transport/internet/tuning_vupen_netepoch.go)
// действуют только в экземплярах ядра с АВТО 4.1 — где в конфиге есть хотя бы
// одно новое поле: vupenSpill / vupenSticky у балансировщика или vupenOnDemand
// у burstObservatory (сводка шага 2, раздел 1). Экземпляры PROXY-ping, проверки
// ТСПУ, обычного режима и «Для опытных» этих полей не получают — их соединения
// не трогаются.

func init() {
	internet.VupenSetNetEpochHooks(&internet.VupenNetEpochHooks{Auto41: vupenNetEpochAuto41})
}

// vupenAuto41Fields — есть ли у балансировщиков конфига поля АВТО 4.1.
func vupenAuto41Fields(config *Config) bool {
	for _, br := range config.GetBalancingRule() {
		if br.GetVupenSpill() != nil || br.GetVupenSticky() != nil {
			return true
		}
	}
	return false
}

// vupenOnDemander — обсерватория burst (без импорта: burst зависит от транспорта).
type vupenOnDemander interface{ VupenOnDemand() bool }

// vupenNetEpochAuto41 — включён ли АВТО 4.1 в экземпляре ядра соединения.
func vupenNetEpochAuto41(ctx context.Context) bool {
	inst := core.FromContext(ctx)
	if inst == nil {
		return false
	}
	if r, ok := inst.GetFeature(routing.RouterType()).(*Router); ok && r.vupenAuto41.Load() {
		return true
	}
	if o, ok := inst.GetFeature(extension.ObservatoryType()).(vupenOnDemander); ok && o.VupenOnDemand() {
		return true
	}
	return false
}
