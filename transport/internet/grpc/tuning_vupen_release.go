package grpc

import (
	"google.golang.org/grpc"

	"github.com/xtls/xray-core/transport/internet"
)

// Vupen (T-075): закрытый outbound освобождает свои gRPC-клиенты
// (transport/internet/tuning_vupen_release.go). Без этого каждое временное ядро
// (пинг, проверка узла) оставляло в globalDialerMap открытый ClientConn с пятью
// горутинами до ResetTransportPool, а обёртка Android его не зовёт никогда.
func init() { internet.VupenRegisterStreamRelease(vupenReleaseGRPC) }

func vupenReleaseGRPC(ss *internet.MemoryStreamConfig) {
	var closing []*grpc.ClientConn
	globalDialerAccess.Lock()
	for k, client := range globalDialerMap {
		if k.MemoryStreamConfig == ss {
			delete(globalDialerMap, k)
			if client != nil {
				closing = append(closing, client)
			}
		}
	}
	globalDialerAccess.Unlock()
	for _, client := range closing {
		_ = client.Close()
	}
}
