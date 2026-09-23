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

## Go 1.27: our copy always builds the legacy transport

Since v26.9.8 the fork's `go.mod` says `go 1.27`, so every build runs on Go 1.27
(an older installed Go downloads it). Upstream x/net then compiles
`transport_wrap.go` / `server_wrap.go` (`//go:build go1.27 && !http2legacy`)
instead of `transport.go`, `client_conn_pool.go`, `server.go`, `config.go` and the
`writesched*.go` files (`//go:build !(go1.27 && !http2legacy)`). Two things break:

- the patch above lives in `transport.go`, so it is **not compiled** — net/http's
  HTTP/2 client in Go 1.27 uses 512 KiB again. It went dead with the v26.9.9 merge
  (2026-09-09) while `VupenRequestBodyScratchMax` kept printing 64 KiB in
  core-info, until 2026-09-23;
- `http2.Transport` becomes a wrapper around `net/http.Transport`, which dials
  once per waiting request while no HTTP/2 connection exists: a hanging TLS
  handshake gives every XHTTP session its own TCP connection and
  `xmux.maxConnections` stops limiting anything (XTLS/Xray-core#6797).

Upstream's own fix is building with `-tags http2legacy`. We do not rely on the tag
for this copy: gomobile overwrites `GOFLAGS` with its platform tags for Apple
targets, and a command-line `-tags` there would replace those platform tags. So
the constraints are edited in the files themselves — the 9 legacy files have no
`//go:build` line (always built) and the 2 wrap files are `//go:build ignore`,
each with a `// Vupen:` note naming the upstream constraint. This covers Apple and
Windows (both link this copy) no matter how Go is invoked.

Android does not use this copy (AndroidLibXrayLite pins upstream x/net), so
`android/libv2ray-patch/build.ps1` passes `-tags http2legacy` to `gomobile bind`.

`http2/vupen.go` references `(*clientStream).frameScratchBufferLen`: if an x/net
update brings the upstream constraints back, the build fails with
`undefined: clientStream` instead of shipping a core without the patch. The build
reports (`scripts/build_windows_installer.ps1`, `scripts/build_android_apk.ps1`)
also check the binary: `golang.org/x/net/http2.(*clientConnPool).getClientConn`
present, `golang.org/x/net/http2.transportConfig` absent.

On every x/net update: re-apply the constraint edits together with the patch.

## Updating

Copy the new upstream version over this directory (same exclusions), re-apply the
patch above, update `Base:` here. Check `libXray/go.mod`'s indirect x/net version
too; the replace wins regardless, but keep the copy at or above what dependents ask
for.
