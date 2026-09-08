package tun

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"syscall"
	"time"

	xerrors "github.com/xtls/xray-core/common/errors"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

var ErrQueueEmpty = errors.New("queue is empty")

type GVisorDevice interface {
	WritePacket(packet *stack.PacketBuffer) tcpip.Error
	ReadPacket() (byte, *stack.PacketBuffer, error)
	Wait()
}

// LinkEndpoint implements GVisor stack.LinkEndpoint
var _ stack.LinkEndpoint = (*LinkEndpoint)(nil)

type LinkEndpoint struct {
	deviceMTU        uint32
	device           GVisorDevice
	dispatcherCancel context.CancelFunc
}

func (e *LinkEndpoint) MTU() uint32 {
	return e.deviceMTU
}

func (e *LinkEndpoint) SetMTU(_ uint32) {
	// not Implemented, as it is not expected GVisor will be asking tun device to be modified
}

func (e *LinkEndpoint) MaxHeaderLength() uint16 {
	return 0
}

func (e *LinkEndpoint) LinkAddress() tcpip.LinkAddress {
	return ""
}

func (e *LinkEndpoint) SetLinkAddress(_ tcpip.LinkAddress) {
	// not Implemented, as it is not expected GVisor will be asking tun device to be modified
}

func (e *LinkEndpoint) Capabilities() stack.LinkEndpointCapabilities {
	return stack.CapabilityRXChecksumOffload
}

func (e *LinkEndpoint) Attach(dispatcher stack.NetworkDispatcher) {
	if e.dispatcherCancel != nil {
		e.dispatcherCancel()
		e.dispatcherCancel = nil
	}

	if dispatcher != nil {
		ctx, cancel := context.WithCancel(context.Background())
		go e.dispatchLoop(ctx, dispatcher)
		e.dispatcherCancel = cancel
	}
}

func (e *LinkEndpoint) IsAttached() bool {
	return e.dispatcherCancel != nil
}

func (e *LinkEndpoint) Wait() {
}

func (e *LinkEndpoint) ARPHardwareType() header.ARPHardwareType {
	return header.ARPHardwareNone
}

func (e *LinkEndpoint) AddHeader(buffer *stack.PacketBuffer) {
	// tun interface doesn't have link layer header, it will be added by the OS
}

func (e *LinkEndpoint) ParseHeader(ptr *stack.PacketBuffer) bool {
	return true
}

func (e *LinkEndpoint) Close() {
	if e.dispatcherCancel != nil {
		e.dispatcherCancel()
		e.dispatcherCancel = nil
	}
}

func (e *LinkEndpoint) SetOnCloseAction(_ func()) {
}

func (e *LinkEndpoint) WritePackets(packetBufferList stack.PacketBufferList) (int, tcpip.Error) {
	var n int
	var err tcpip.Error

	for _, packetBuffer := range packetBufferList.AsSlice() {
		err = e.device.WritePacket(packetBuffer)
		if err != nil {
			tunStats.writeDrops.Add(1)
			return n, &tcpip.ErrAborted{}
		}
		tunStats.writePackets.Add(1)
		n++
	}

	return n, nil
}

// isTunReadFatal — дескриптор закрыт или EOF: повторять нечего.
func isTunReadFatal(err error) bool {
	if errors.Is(err, io.EOF) || errors.Is(err, os.ErrClosed) || errors.Is(err, net.ErrClosed) {
		return true
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errno == syscall.EBADF
	}
	return false
}

func (e *LinkEndpoint) dispatchLoop(ctx context.Context, dispatcher stack.NetworkDispatcher) {
	var networkProtocolNumber tcpip.NetworkProtocolNumber
	var version byte
	var packet *stack.PacketBuffer
	var err error
	var backoff time.Duration
	// Счётчик, а не флаг: после hot reload старый цикл ещё может сидеть в Read,
	// и heartbeat должен показать 2 — это утечка, а не норма.
	tunStats.readerAlive.Add(1)
	defer tunStats.readerAlive.Add(-1)

	for {
		select {
		case <-ctx.Done():
			return
		default:
			version, packet, err = e.device.ReadPacket()
			// on "queue empty", ask device to yield slightly and continue
			if errors.Is(err, ErrQueueEmpty) {
				e.device.Wait()
				continue
			}
			// Vupen: раньше любая ошибка чтения молча завершала цикл — TUN мёртв,
			// ядро живо, в логе пусто. Теперь: ошибка пишется в лог (первая и каждая
			// сотая), временная — повтор с паузой до 250 мс, и только закрытый
			// дескриптор останавливает цикл. Счётчик readerAlive виден в heartbeat.
			if err != nil {
				n := tunStats.readErrors.Add(1)
				fatal := isTunReadFatal(err)
				if fatal || logEvery(n) {
					suffix := " — retry"
					if fatal {
						suffix = " — reader stops"
					}
					xerrors.LogError(ctx, "[tun] read failed (", n, "): ", err.Error(), suffix)
				}
				if fatal {
					e.Attach(nil)
					return
				}
				backoff = backoff*2 + 5*time.Millisecond
				if backoff > 250*time.Millisecond {
					backoff = 250 * time.Millisecond
				}
				time.Sleep(backoff)
				continue
			}
			backoff = 0
			tunStats.readPackets.Add(1)

			// extract network protocol number from the packet first byte
			// (which is returned separately, since it is so incredibly hard to extract one byte from
			// stack.PacketBuffer without additional memory allocation and full copying it back and forth)
			switch version {
			case 4:
				networkProtocolNumber = header.IPv4ProtocolNumber
			case 6:
				networkProtocolNumber = header.IPv6ProtocolNumber
			default:
				// discard unknown network protocol packet
				packet.DecRef()
				continue
			}

			// dispatch the buffer to the stack
			dispatcher.DeliverNetworkPacket(networkProtocolNumber, packet)
			// signal the buffer that it can be released
			packet.DecRef()
		}
	}
}
