package router

import (
	"context"
	"sync/atomic"

	"github.com/xtls/xray-core/common/errors"
)

// Vupen (T-079, вариант 2 владельца): «Apple через VPN при белых списках».
//
// Приложение (xray_config_builder.dart) отправляет домены Apple напрямую
// отдельным правилом и помечает его ruleTag VupenAppleDirectRuleTag. Пока
// включена настройка (VupenSetAppleViaVpnOnLte) и АВТО 4.1 перелит в мобильную
// группу (vupenSticky.spillTarget() — то же, что VupenAutoState показывает как
// tier "lte"/spilled), это правило пропускается: трафик Apple идёт дальше по
// правилам — в балансировщик, то есть через VPN. Иначе правило действует
// (Apple напрямую). Ядро не перезапускается, открытые соединения не трогаются —
// по новому решению идут только новые.

// VupenAppleDirectRuleTag — ruleTag правила «Apple напрямую», которым управляет настройка.
const VupenAppleDirectRuleTag = "vupen-apple-direct"

var (
	vupenAppleViaVpnOnLte atomic.Bool
	// vupenAppleGen — поколение настройки: после её смены каждое ядро снова пишет
	// своё решение в журнал (CR-103: состояние журнала — у Router).
	vupenAppleGen atomic.Int64
)

// VupenSetAppleViaVpnOnLte — настройка «Apple через VPN при белых списках» (на
// процесс: переживает перезапуск ядра). Возвращает, изменилась ли она.
func VupenSetAppleViaVpnOnLte(on bool) bool {
	if vupenAppleViaVpnOnLte.Swap(on) == on {
		return false
	}
	vupenAppleGen.Add(1)
	state := "off"
	if on {
		state = "on"
	}
	errors.LogWarning(context.Background(), "[route] apple-via-vpn-on-lte: ", state)
	return true
}

// VupenAppleViaVpnOnLte — значение настройки.
func VupenAppleViaVpnOnLte() bool { return vupenAppleViaVpnOnLte.Load() }

// vupenSkipRule — правило пропустить при выборе маршрута (дёшево: при
// выключенной настройке — одно атомарное чтение).
func (r *Router) vupenSkipRule(rule *Rule) bool {
	if !vupenAppleViaVpnOnLte.Load() || rule.RuleTag != VupenAppleDirectRuleTag {
		return false
	}
	viaVpn := r.vupenOnLte()
	d := vupenAppleGen.Load() * 4 // поколение настройки × решение: 1 — напрямую, 2 — через VPN
	if viaVpn {
		d += 2
	} else {
		d++
	}
	if r.vupenAppleLog.Swap(d) != d {
		how := "direct"
		if viaVpn {
			how = "via VPN (LTE tier)"
		}
		errors.LogWarning(context.Background(), "[route] apple-direct: ", how)
	}
	return viaVpn
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
