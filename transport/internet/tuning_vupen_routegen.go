package internet

import (
	"sync/atomic"
	"time"
)

// Vupen (T-083, S4): поколение маршрутов — меняется, когда прежние решения
// маршрута больше не годятся для повторов того же потока: смена сети (эпоха),
// смена узла или группы АВТО 4.1, настройка «Apple через VPN». Память маршрута
// диспетчера (app/dispatcher) берёт только решения текущего поколения.
var vupenRouteGen atomic.Uint64

// VupenBumpRouteGeneration — прежние решения маршрута устарели.
func VupenBumpRouteGeneration() { vupenRouteGen.Add(1) }

// VupenRouteGeneration — текущее поколение маршрутов.
func VupenRouteGeneration() uint64 { return vupenRouteGen.Load() }

// VupenNetChangedWithin — сеть сменилась (не первое сообщение платформы) не
// дольше d назад; ago — сколько прошло (T-083, S3: ошибки соединений на смене сети).
func VupenNetChangedWithin(d time.Duration) (bool, time.Duration) {
	s := vupenNet
	s.mu.Lock()
	epoch, at := s.epoch, s.changedAt
	s.mu.Unlock()
	if epoch < 2 || at.IsZero() {
		return false, 0
	}
	ago := vupenNetNow().Sub(at)
	return ago <= d, ago
}
