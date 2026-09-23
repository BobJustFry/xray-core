package http2

// VupenRequestBodyScratchMax caps the per-stream request-body scratch buffer
// in (*clientStream).frameScratchBufferLen (upstream: a 512 KiB constant).
//
// Exported on purpose: libXray reports it in its core-info string, which both
// proves at compile time that this copy of x/net is the one linked (stock x/net
// has no such symbol) and shows the effective value in the tunnel log.
var VupenRequestBodyScratchMax = 64 << 10

// The patched method must be compiled into the core. Go 1.27 skips
// transport.go unless x/net is built as "http2legacy" — which is how the patch
// sat dead from the v26.9.9 merge (2026-09-09) to 2026-09-23 while core-info
// kept printing the value above. Our copy compiles transport.go always (see
// VUPEN.md); if an x/net update brings the upstream constraint back, this
// line stops compiling instead of shipping a core without the patch.
var _ = (*clientStream).frameScratchBufferLen
