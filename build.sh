#!/bin/bash
# Builds both halves of STRS (SuperTransferSpeeds). Needs Go on the PATH.
set -e
cd "$(dirname "$0")"
export GOFLAGS=-buildvcs=false

echo "=== vet ==="
go vet ./...

# Windows icon and manifest: rsrc turns them into a resource object that the
# linker picks up because of the _windows_amd64 suffix in its name.
if command -v rsrc >/dev/null 2>&1; then
  [ -f assets/logo.ico ] || go run ./tools/mkico assets/logo-src.jpg assets/logo.ico
  rsrc -manifest assets/app.manifest -ico assets/logo.ico -o cmd/transfer/rsrc_windows_amd64.syso -arch amd64
  rsrc -manifest assets/app.manifest -ico assets/logo.ico -o cmd/transferserver/rsrc_windows_amd64.syso -arch amd64
  echo "icon: embedded from assets/logo.ico"
else
  echo "icon: rsrc not installed (go install github.com/akavel/rsrc@latest), building without one"
fi

mkdir -p dist
# Linux binaries are fully static (no libc), so one file runs on Arch, Ubuntu,
# Debian and anything else with a 64-bit Intel/AMD kernel, old or new.
echo "=== relay (linux) ==="
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o dist/supertransfer-relay ./cmd/transferserver
echo "=== client (linux) ==="
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o dist/STRS-linux ./cmd/transfer
echo "=== client (windows) ==="
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.defaultServer=127.0.0.1:8443" -o dist/STRS.exe ./cmd/transfer

( cd dist && sha256sum STRS.exe STRS-linux supertransfer-relay > SHA256SUMS )
echo "done: dist/"
