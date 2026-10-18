package websocket

import (
	"context"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
)

// Vupen (T-083, S3): соединение WebSocket, которое устанавливалось на смене сети
// (Wi-Fi ↔ LTE), не может установиться — это ожидаемо. Строка — Warning с
// префиксом [netchange], чтобы её не путали с отказом узла.
var vupenWSNetChangeWindow = 15 * time.Second

func vupenWSDialError(ctx context.Context, dest net.Destination, err error) error {
	if changed, ago := internet.VupenNetChangedWithin(vupenWSNetChangeWindow); changed {
		errors.LogWarning(ctx, "[netchange] websocket dial to ", dest, " failed ", ago.Round(time.Millisecond),
			" after a network change (expected while the network switches): ", err)
	}
	return errors.New("failed to dial WebSocket").Base(err)
}
