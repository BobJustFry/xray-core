package burst

// Vupen (ядро 74, АВТО 4.1): по этому признаку app/router узнаёт, что
// экземпляр ядра работает в АВТО 4.1 (эпохи сети, transport/internet).
// На поведение обсерватории не влияет.

// VupenOnDemand — в конфиге burstObservatory стоит vupenOnDemand.
func (o *Observer) VupenOnDemand() bool {
	return o != nil && o.config.GetVupenOnDemand()
}
