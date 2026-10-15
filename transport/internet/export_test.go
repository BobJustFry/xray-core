package internet

// Только для тестов (файл _test.go не попадает в сборку ядра).

// VupenNetEpochResetForTest — сбросить состояние эпох сети процесса, как будто
// VupenSetUplink ещё не вызывался. Для тестов других пакетов этого каталога
// (package internet_test), которым состояние процесса досталось от соседнего теста.
func VupenNetEpochResetForTest() { vupenNet.resetForTest() }

// resetForTest — сброс на месте, под блокировкой (указатель vupenNet не меняется:
// его читают DialSystem и очистки сборщика мусора в других горутинах).
func (s *vupenNetState) resetForTest() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopPending != nil {
		s.stopPending()
	}
	s.active.Store(false)
	s.snap.Store(nil)
	s.current, s.base = vupenNetID{}, vupenNetID{}
	s.epoch, s.sweeps = 0, 0
	s.stopPending = nil
	s.entries = map[uint64]*vupenNetEntry{}
	s.index = map[any]uint64{}
	s.untrackedLog = false
}
