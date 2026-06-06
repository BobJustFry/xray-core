// Vupen sniff-timing tuning + диагностический инструментарий.
//
// Этот файл — точка концентрации правок Vupen в форке BobJustFry/xray-core
// (на базе remnawave/xray-core). Держим здесь:
//   - VupenSniffPhase1Deadline (200ms) / VupenSniffPhase2Deadline (1500ms):
//     двухфазный sniff; UDP:53 skip; лог second-round ok/timeout.
//   - vupenDebugSniff: helper для debug-логов внутри sniff-цикла, чтобы можно
//     было точечно (по vSupport-архивам) видеть на каком этапе и сколько
//     миллисекунд теряется.
//
// Зачем 800ms вместо upstream-овых 200ms:
//   В iOS Network Extension с TUN-inbound'ом первый TLS ClientHello от
//   приложения (Safari/Chrome) приходит в gVisor TCP stack через цепочку
//   NEPacketTunnelFlow → socketpair → gVisor. Для большинства соединений
//   эта цепочка отрабатывает за <50ms, но для ~6% (наблюдается на IP-чекерах
//   2ip.ru / yandex.ru/internet/ и при медленном спутниковом outbound-канале,
//   который влияет на CPU scheduling Network Extension) первый application-байт
//   от клиента приходит в gVisor ПОЗЖЕ 200ms. Тогда sniff отдаёт
//   errSniffingTimeout (тихо, без лога), dispatcher маршрутизирует по голому
//   destination IP, и domain-rules (geosite:ru, domain:2ip.ru и т.п.)
//   не срабатывают.
//
//   800ms — компромисс: ×4 от upstream, всё ещё в разумных пределах для
//   ожидания первых байт TCP-сессии. Не-TLS трафик (Bittorrent / голый TCP)
//   защищён лимитом totalAttempt>=1 в самом sniffer-цикле и не страдает от
//   увеличения этой константы.
package dispatcher

import (
	"context"
	"encoding/binary"
	"fmt"
	stdnet "net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/platform"
	"github.com/xtls/xray-core/common/session"
)

// vupenSniffMissAttr — в Content.Attributes после sniff без домена (маршрут по IP).
const vupenSniffMissAttr = "vupen_sniff_miss"

// vupenSniffDomainAttr / vupenSniffProtocolAttr — подсказки для лога direct-miss.
const (
	vupenSniffDomainAttr   = "vupen_sniff_domain"
	vupenSniffProtocolAttr = "vupen_sniff_protocol"
)

// vupenDirectMissLogMarker — парсится во Flutter (баннер + вкладка «Ошибки снифф»).
const vupenDirectMissLogMarker = "[Vupen routing] direct-miss:"

// vupenSniffRoutingMissLogName — App Group, рядом с xray/ (см. VupenXraySupport.sniffRoutingMissLogName).
const vupenSniffRoutingMissLogName = "vupen_sniff_routing_miss.log"

var (
	vupenSniffMissLogMu         sync.Mutex
	vupenSniffMissLogPathCached string
)

// VupenSniffPhase1Deadline / VupenSniffPhase2Deadline — двухфазный sniff (не-DNS).
var (
	VupenSniffPhase1Deadline = 200 * time.Millisecond
	VupenSniffPhase2Deadline = 1500 * time.Millisecond
)

// vupenSniffSecondRoundOkMarker / TimeoutMarker — UI (синий / красный) во Flutter.
const (
	vupenSniffSecondRoundOkMarker      = "[Vupen sniff] second-round ok:"
	vupenSniffSecondRoundTimeoutMarker = "[Vupen sniff] second-round timeout:"
	vupenSniffEarlyExitMarker          = "[Vupen sniff] early-exit:"
)

// errSniffingHopeless — домен извлечь нельзя, ждать фазу 2 бессмысленно.
var errSniffingHopeless = errors.New("hopeless sniff: no domain extractable")

// vupenSniffSecondRoundAttr — фаза 2 была запущена (успех или финальный timeout).
const vupenSniffSecondRoundAttr = "vupen_sniff_second_round"

// vupenSniffSkipResolverIPs — публичные DNS (DoH/DoT/QUIC на любых портах).
var vupenSniffSkipResolverIPs = []stdnet.IP{
	stdnet.ParseIP("1.1.1.1"),
	stdnet.ParseIP("1.0.0.1"),
	stdnet.ParseIP("8.8.8.8"),
	stdnet.ParseIP("8.8.4.4"),
}

func vupenIsSniffSkipResolverIP(addr net.Address) bool {
	if !addr.Family().IsIP() {
		return false
	}
	ip := addr.IP()
	if ip == nil {
		return false
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	for _, resolver := range vupenSniffSkipResolverIPs {
		if resolver != nil && ip4.Equal(resolver.To4()) {
			return true
		}
	}
	return false
}

// vupenShouldSkipSniff — DNS без sniff: UDP:53, TCP:853 (DoT), whitelist резолверов.
// vupenSniffMayNeedMoreTLS — не делать hopeless exit, пока буфер похож на неполный TLS ClientHello.
func vupenSniffMayNeedMoreTLS(payload []byte) bool {
	if len(payload) == 0 {
		return false
	}
	if payload[0] != 0x16 {
		return false
	}
	if len(payload) < 5 {
		return true
	}
	if payload[1] != 0x03 {
		return false
	}
	headerLen := int(binary.BigEndian.Uint16(payload[3:5]))
	return 5+headerLen > len(payload)
}

func vupenShouldSkipSniff(destination net.Destination) bool {
	if destination.Network == net.Network_UDP && destination.Port == 53 {
		return true
	}
	if destination.Network == net.Network_TCP && destination.Port == 853 {
		return true
	}
	return vupenIsSniffSkipResolverIP(destination.Address)
}

// vupenDebugLogSniffOutcome — единая точка debug-лога по итогу одной попытки
// sniff-чтения. Вызывается из sniffer() внутри цикла; loglevel: debug в
// xray-конфиге обязателен, иначе лог проглатывается.
//
// Поля:
//   stage      — "start" | "iter" | "timeout" | "success"
//   attempt    — текущее значение totalAttempt
//   payloadLen — сколько байт сейчас в буфере sniffer'а
//   cacheUsed  — сколько ms потрачено на cReader.Cache() в этой итерации
//   phase      — 1 | 2 (фаза sniff)
//   budgetMs   — остаток budget фазы после итерации
func vupenDebugLogSniffOutcome(
	ctx context.Context,
	stage string,
	phase int,
	attempt int,
	payloadLen int32,
	cacheUsed time.Duration,
	budget time.Duration,
	sniffErr error,
) {
	errors.LogDebug(ctx,
		"[Vupen sniff] stage=", stage,
		" phase=", phase,
		" attempt=", attempt,
		" payload=", payloadLen,
		" cache_used_ms=", cacheUsed.Milliseconds(),
		" budget_ms=", budget.Milliseconds(),
		" sniff_err=", sniffErr,
	)
}

func vupenSniffDestinationString(ctx context.Context) string {
	outbounds := session.OutboundsFromContext(ctx)
	if len(outbounds) == 0 {
		return ""
	}
	dest := outbounds[len(outbounds)-1].OriginalTarget
	if !dest.IsValid() {
		return ""
	}
	return dest.String()
}

func vupenLogSniffEarlyExit(ctx context.Context, phase int, exitType string, payloadLen int32, sniffErr error) {
	dest := vupenSniffDestinationString(ctx)
	line := vupenSniffEarlyExitMarker + " type=" + exitType +
		" phase=" + strconv.Itoa(phase) +
		" payload=" + strconv.FormatInt(int64(payloadLen), 10) +
		" sniff_err=" + fmt.Sprint(sniffErr)
	if dest != "" {
		line += ", " + dest
	}
	errors.LogInfo(ctx, line)
}

func vupenLogSniffSecondRoundOk(ctx context.Context, phase1Elapsed, phase2Elapsed, totalElapsed time.Duration) {
	dest := vupenSniffDestinationString(ctx)
	totalMs := totalElapsed.Milliseconds()
	line := vupenSniffSecondRoundOkMarker + " успешный sniff на 2-й фазе, выход за " +
		strconv.FormatInt(totalMs, 10) + " ms (фаза 1: " +
		strconv.FormatInt(phase1Elapsed.Milliseconds(), 10) + " ms, фаза 2: " +
		strconv.FormatInt(phase2Elapsed.Milliseconds(), 10) + " ms)"
	if hint := vupenSniffMissDomainForLog(ctx); hint != "domain=—" {
		line += ", " + hint
	}
	if dest != "" {
		line += ", " + dest
	}
	vupenAppendSniffRoutingInfoLog(line)
	errors.LogInfo(ctx, line)
}

func vupenLogSniffSecondRoundTimeout(ctx context.Context) {
	dest := vupenSniffDestinationString(ctx)
	line := vupenSniffSecondRoundTimeoutMarker + " sniff timeout на 2-й фазе, " +
		vupenSniffMissDomainForLog(ctx) + ", " + dest
	vupenAppendSniffRoutingMissLog(line)
	errors.LogError(ctx, line)
}

func vupenAppendSniffRoutingInfoLog(line string) {
	path := vupenSniffMissLogFile()
	if path == "" || line == "" {
		return
	}
	vupenSniffMissLogMu.Lock()
	defer vupenSniffMissLogMu.Unlock()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	ts := time.Now().Format("2006/01/02 15:04:05.000000")
	_, _ = f.WriteString(ts + " " + line + "\n")
}

func vupenSniffResultDomain(result SniffResult) string {
	if result == nil {
		return ""
	}
	return result.Domain()
}

// vupenRecordSniffDomainHint сохраняет последний непустой домен/протокол из sniff.
func vupenRecordSniffDomainHint(ctx context.Context, result SniffResult) {
	content := session.ContentFromContext(ctx)
	if content == nil || result == nil {
		return
	}
	if domain := vupenSniffResultDomain(result); domain != "" {
		content.SetAttribute(vupenSniffDomainAttr, domain)
	}
	if proto := result.Protocol(); proto != "" {
		content.SetAttribute(vupenSniffProtocolAttr, proto)
	}
}

// vupenSniffMissDomainForLog — строка для vupen_sniff_routing_miss.log и direct-miss.
func vupenSniffMissDomainForLog(ctx context.Context) string {
	domain := ""
	proto := ""
	content := session.ContentFromContext(ctx)
	if content != nil {
		domain = content.Attribute(vupenSniffDomainAttr)
		proto = content.Attribute(vupenSniffProtocolAttr)
	}
	if domain == "" {
		outbounds := session.OutboundsFromContext(ctx)
		if len(outbounds) > 0 {
			ob := outbounds[len(outbounds)-1]
			if ob.RouteTarget.IsValid() && ob.RouteTarget.Address.Family().IsDomain() {
				domain = ob.RouteTarget.Address.Domain()
			} else if ob.OriginalTarget.IsValid() && ob.OriginalTarget.Address.Family().IsDomain() {
				domain = ob.OriginalTarget.Address.Domain()
			}
		}
	}
	if domain == "" {
		return "domain=—"
	}
	if proto != "" {
		return "domain=" + domain + ", proto=" + proto
	}
	return "domain=" + domain
}

func vupenMarkSniffMissIfNoDomain(content *session.Content, destination net.Destination, sniffEnabled bool) {
	if !sniffEnabled || content == nil {
		return
	}
	if !destination.Address.Family().IsDomain() {
		content.SetAttribute(vupenSniffMissAttr, "1")
	}
}

func vupenSniffMissLogFile() string {
	if vupenSniffMissLogPathCached != "" {
		return vupenSniffMissLogPathCached
	}
	datDir := os.Getenv(platform.AssetLocation)
	if datDir == "" {
		return ""
	}
	vupenSniffMissLogPathCached = filepath.Clean(filepath.Join(datDir, "..", vupenSniffRoutingMissLogName))
	return vupenSniffMissLogPathCached
}

func vupenAppendSniffRoutingMissLog(line string) {
	path := vupenSniffMissLogFile()
	if path == "" || line == "" {
		return
	}
	vupenSniffMissLogMu.Lock()
	defer vupenSniffMissLogMu.Unlock()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	ts := time.Now().Format("2006/01/02 15:04:05.000000")
	_, _ = f.WriteString(ts + " [SniffError] " + line + "\n")
}

func vupenMaybeLogDirectMissToProxy(ctx context.Context, destination net.Destination, outTag string) {
	content := session.ContentFromContext(ctx)
	if content == nil || content.Attribute(vupenSniffMissAttr) != "1" {
		return
	}
	if destination.Address.Family().IsDomain() {
		return
	}
	if outTag != "proxy" {
		return
	}
	detail := strings.Join([]string{
		"sniff не распознал домен",
		vupenSniffMissDomainForLog(ctx),
		destination.String() + " → detour [" + outTag + "] (должен был direct по домену)",
	}, ", ")
	vupenAppendSniffRoutingMissLog(vupenDirectMissLogMarker + " " + detail)
	errors.LogError(ctx,
		vupenDirectMissLogMarker,
		" ",
		detail,
	)
}
