package mux_test

import (
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/mux"
	"github.com/xtls/xray-core/testing/mocks"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

// Vupen (T-075): закрытие outbound'а закрывает его mux-воркеры сразу.
func TestVupenClientManagerCloseClosesWorkers(t *testing.T) {
	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()
	r, w := pipe.New(pipe.WithoutSizeLimit())
	worker, err := mux.NewClientWorker(transport.Link{Reader: r, Writer: w}, mux.ClientStrategy{MaxConcurrency: 4, MaxConnection: 4})
	common.Must(err)
	factory := mocks.NewMuxClientWorkerFactory(mockCtl)
	factory.EXPECT().Create().Return(worker, nil)
	m := &mux.ClientManager{Enabled: true, Picker: &mux.IncrementalWorkerPicker{Factory: factory}}
	got, err := m.Picker.PickAvailable()
	common.Must(err)
	if got != worker || worker.Closed() {
		t.Fatal("setup")
	}
	common.Must(common.Close(m))
	select {
	case <-worker.WaitClosed():
	case <-time.After(2 * time.Second):
		t.Fatal("worker still open after ClientManager.Close")
	}
	// Запись по ссылке воркера тоже закрыта (соединение к узлу уходит).
	if _, err := r.ReadMultiBuffer(); err == nil {
		t.Fatal("the worker link is not interrupted")
	}
}

// Выключенный mux (Picker nil) — Close без паники.
func TestVupenClientManagerCloseDisabled(t *testing.T) {
	common.Must((&mux.ClientManager{Enabled: false}).Close())
	var m *mux.ClientManager
	common.Must(m.Close())
}
