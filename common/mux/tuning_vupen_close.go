package mux

import "io"

// Vupen (T-075, аудит T-071): outbound закрывается (Handler.Close зовёт
// common.Close(h.mux)) — его mux-соединения закрываются сразу. Раньше у
// ClientManager не было Close, и воркеры жили после закрытия ядра до двух тиков
// простоя (16 с каждый) вместе с соединением к узлу и буферами.

// Close закрывает все воркеры менеджера.
func (m *ClientManager) Close() error {
	if m == nil {
		return nil
	}
	if c, ok := m.Picker.(io.Closer); ok {
		return c.Close()
	}
	return nil
}

// Close закрывает воркеры и останавливает их чистку.
func (p *IncrementalWorkerPicker) Close() error {
	p.access.Lock()
	workers := p.workers
	p.workers = nil
	cleanup := p.cleanupTask
	p.access.Unlock()
	if cleanup != nil {
		_ = cleanup.Close()
	}
	for _, w := range workers {
		_ = w.Close()
	}
	return nil
}
