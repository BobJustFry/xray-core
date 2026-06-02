// Vupen sniff-timing tuning + диагностический инструментарий.
//
// Этот файл — точка концентрации правок Vupen в форке BobJustFry/xray-core
// (на базе remnawave/xray-core). Держим здесь:
//   - VupenSniffCacheDeadline: переопределяемый дефолт таймаута sniff-цикла
//     (используется в default.go::sniffer вместо upstream-овых 200ms).
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
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/platform"
	"github.com/xtls/xray-core/common/session"
)

// vupenSniffMissAttr — в Content.Attributes после sniff без домена (маршрут по IP).
const vupenSniffMissAttr = "vupen_sniff_miss"

// vupenDirectMissLogMarker — парсится во Flutter (баннер + вкладка «Ошибки снифф»).
const vupenDirectMissLogMarker = "[Vupen routing] direct-miss:"

// vupenSniffRoutingMissLogName — App Group, рядом с xray/ (см. VupenXraySupport.sniffRoutingMissLogName).
const vupenSniffRoutingMissLogName = "vupen_sniff_routing_miss.log"

var (
	vupenSniffMissLogMu         sync.Mutex
	vupenSniffMissLogPathCached string
)

// VupenSniffCacheDeadline — переопределяемый дефолт, который app/dispatcher.sniffer
// использует вместо хардкоженных 200ms. Переменная, а не const — чтобы можно
// было править ad-hoc (например через рантайм-эксперимент, A/B на стороне
// libXray и пр.) без рекомпиляции этого пакета.
var VupenSniffCacheDeadline = 1500 * time.Millisecond

// vupenDebugLogSniffOutcome — единая точка debug-лога по итогу одной попытки
// sniff-чтения. Вызывается из sniffer() внутри цикла; loglevel: debug в
// xray-конфиге обязателен, иначе лог проглатывается.
//
// Поля:
//   stage      — "start" | "iter" | "timeout" | "success"
//   attempt    — текущее значение totalAttempt
//   payloadLen — сколько байт сейчас в буфере sniffer'а
//   cacheUsed  — сколько ms потрачено на cReader.Cache() в этой итерации
//   budgetMs   — сколько ms осталось от VupenSniffCacheDeadline после итерации
//   sniffErr   — что вернул sniffer.Sniff (ErrNoClue / ErrProtoNeedMoreData / nil / др.)
func vupenDebugLogSniffOutcome(
	ctx context.Context,
	stage string,
	attempt int,
	payloadLen int32,
	cacheUsed time.Duration,
	budget time.Duration,
	sniffErr error,
) {
	errors.LogDebug(ctx,
		"[Vupen sniff] stage=", stage,
		" attempt=", attempt,
		" payload=", payloadLen,
		" cache_used_ms=", cacheUsed.Milliseconds(),
		" budget_ms=", budget.Milliseconds(),
		" sniff_err=", sniffErr,
	)
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
	detail := "sniff не распознал домен, " + destination.String() +
		" → detour [" + outTag + "] (должен был direct по домену)"
	vupenAppendSniffRoutingMissLog(vupenDirectMissLogMarker + " " + detail)
	errors.LogError(ctx,
		vupenDirectMissLogMarker,
		" ",
		detail,
	)
}
