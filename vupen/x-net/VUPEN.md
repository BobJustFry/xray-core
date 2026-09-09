# golang.org/x/net — Vupen copy

Base: golang.org/x/net **v0.58.0** (the version `ios/Vendor/xray-core/go.mod` pins),
copied verbatim from the Go module cache minus `*_test.go` and `testdata/`.

Wired in with a directory `replace` (no go.sum entries needed):

- `ios/Vendor/xray-core/go.mod`: `replace golang.org/x/net => ./vupen/x-net`
- `ios/Vendor/libXray/go.mod`:   `replace golang.org/x/net => ../xray-core/vupen/x-net`

Replace directives apply only to the main module, which is why both files carry it.

## The one patch

`http2/transport.go`, `(*clientStream).frameScratchBufferLen`: cap `512 << 10` -> `64 << 10`.

Why: the scratch buffer for writing a request body is sized by the peer's
SETTINGS_MAX_FRAME_SIZE, capped at 512 KiB. With XHTTP `stream-one` every
tunnelled TCP connection is one streaming POST of unknown length, so the buffer
lives as long as the connection. Against a server that advertises large frames
that is 512 KiB per live connection: the 2026-09-07 heap profile from the iOS
extension had 100% of the live heap (37 MB, 74 objects of exactly 512 KiB) in
`writeRequestBody`, and the extension was killed at the ~50 MB wall.

## Updating

Copy the new upstream version over this directory (same exclusions), re-apply the
patch above, update `Base:` here. Check `libXray/go.mod`'s indirect x/net version
too; the replace wins regardless, but keep the copy at or above what dependents ask
for.
