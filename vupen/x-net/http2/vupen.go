package http2

// VupenRequestBodyScratchMax caps the per-stream request-body scratch buffer
// in (*clientStream).frameScratchBufferLen (upstream: a 512 KiB constant).
//
// Exported on purpose: libXray reports it in its core-info string, which both
// proves at compile time that this copy of x/net is the one linked (stock x/net
// has no such symbol) and shows the effective value in the tunnel log.
var VupenRequestBodyScratchMax = 64 << 10
