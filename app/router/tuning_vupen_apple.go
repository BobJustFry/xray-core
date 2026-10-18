package router

import (
	"context"
	"sync/atomic"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/transport/internet"
)

// Vupen (T-079, вариант 2 владельца): «Apple через VPN при белых списках».
//
// Приложение (xray_config_builder.dart) отправляет домены Apple напрямую
// отдельным правилом и помечает его ruleTag VupenAppleDirectRuleTag. Пока
// включён режим 1 (VupenSetAppleViaVpnMode(1), прежний VupenSetAppleViaVpnOnLte(true))
// и АВТО 4.1 перелит в мобильную группу (vupenSticky.spillTarget() — то же, что
// VupenAutoState показывает как tier "lte"/spilled), либо включён режим 2
// (T-084: «Вручную» выбран узел мобильной группы), это правило пропускается:
// трафик Apple идёт дальше по правилам — в балансировщик или выбранный узел, то
// есть через VPN. Режим 0 — правило действует всегда (Apple напрямую). Ядро не перезапускается, открытые соединения не трогаются —
// по новому решению идут только новые.

// VupenAppleDirectRuleTag — ruleTag правила «Apple напрямую», которым управляет настройка.
const VupenAppleDirectRuleTag = "vupen-apple-direct"

// Режимы настройки «Apple через VPN при белых списках» (T-084).
const (
	// VupenAppleModeOff — правило «Apple напрямую» действует всегда.
	VupenAppleModeOff = 0
	// VupenAppleModeOnLte — правило пропускается, пока АВТО 4.1 в мобильной группе (перелито).
	VupenAppleModeOnLte = 1
	// VupenAppleModeAlways — правило пропускается всегда (приложение: «Вручную»
	// выбран узел мобильной группы — это тоже узел белых списков).
	VupenAppleModeAlways = 2
)

var (
	vupenAppleMode atomic.Int32
	// vupenAppleGen — поколение настройки: после её смены каждое ядро снова пишет
	// своё решение в журнал (CR-103: состояние журнала — у Router).
	vupenAppleGen atomic.Int64
)

// VupenSetAppleViaVpnMode — режим настройки (на процесс: переживает перезапуск
// ядра; ядро не перезапускается, открытые соединения не трогаются). Режим вне
// 0…2 не меняет ничего (false). Возвращает, изменился ли режим.
func VupenSetAppleViaVpnMode(mode int) bool {
	if mode < VupenAppleModeOff || mode > VupenAppleModeAlways {
		errors.LogWarning(context.Background(), "[route] apple-via-vpn mode ", mode, " ignored (want 0, 1 or 2)")
		return false
	}
	if int(vupenAppleMode.Swap(int32(mode))) == mode {
		return false
	}
	vupenAppleGen.Add(1)
	internet.VupenBumpRouteGeneration() // T-083 (S4): запомненные маршруты Apple — по новому режиму
	errors.LogWarning(context.Background(), "[route] apple-via-vpn mode: ", vupenAppleModeName(mode))
	return true
}

func vupenAppleModeName(mode int) string {
	switch mode {
	case VupenAppleModeOnLte:
		return "1 (via VPN while AUTO is on the LTE group)"
	case VupenAppleModeAlways:
		return "2 (always via VPN: whitelist node chosen manually)"
	}
	return "0 (off: Apple direct)"
}

// VupenAppleViaVpnMode — текущий режим.
func VupenAppleViaVpnMode() int { return int(vupenAppleMode.Load()) }

// VupenSetAppleViaVpnOnLte — прежний вызов (T-079): true → режим 1, false → 0.
func VupenSetAppleViaVpnOnLte(on bool) bool {
	if on {
		return VupenSetAppleViaVpnMode(VupenAppleModeOnLte)
	}
	return VupenSetAppleViaVpnMode(VupenAppleModeOff)
}

// VupenAppleViaVpnOnLte — настройка включена (режим 1 или 2).
func VupenAppleViaVpnOnLte() bool { return vupenAppleMode.Load() != VupenAppleModeOff }

// vupenSkipRule — правило пропустить при выборе маршрута (дёшево: при
// выключенной настройке — одно атомарное чтение).
func (r *Router) vupenSkipRule(rule *Rule) bool {
	mode := vupenAppleMode.Load()
	if mode == VupenAppleModeOff || rule.RuleTag != VupenAppleDirectRuleTag {
		return false
	}
	viaVpn := r.vupenAppleViaVpnNow(mode)
	d := vupenAppleGen.Load() * 4 // поколение настройки × решение: 1 — напрямую, 2 — через VPN
	if viaVpn {
		d += 2
	} else {
		d++
	}
	if r.vupenAppleLog.Swap(d) != d {
		how := "direct"
		switch {
		case viaVpn && mode == VupenAppleModeAlways:
			how = "via VPN (whitelist node chosen manually)"
		case viaVpn:
			how = "via VPN (LTE tier)"
		}
		errors.LogWarning(context.Background(), "[route] apple-direct: ", how)
	}
	return viaVpn
}

// vupenAppleViaVpnNow — правило «Apple напрямую» сейчас пропускается.
func (r *Router) vupenAppleViaVpnNow(mode int32) bool {
	switch mode {
	case VupenAppleModeAlways:
		return true
	case VupenAppleModeOnLte:
		return r.vupenOnLte()
	}
	return false
}

// vupenOnLte — АВТО 4.1 сейчас выбирает узлы мобильной группы (перелито, сеть сотовая).
func (r *Router) vupenOnLte() bool {
	p := r.balancers.Load()
	if p == nil {
		return false
	}
	for _, b := range *p {
		if b != nil && b.vupen != nil && b.vupen.spillTarget() != nil {
			return true
		}
	}
	return false
}
