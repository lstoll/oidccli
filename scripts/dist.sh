#!/usr/bin/env bash
# Cross-compile oidccli and pack per-platform tar.gz archives into dist/.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

VERSION="${VERSION:-$(git -C "$ROOT" describe --tags --always --dirty 2>/dev/null || echo 0.0.0)}"
VERSION="${VERSION#v}"
export VERSION

mkdir -p "$ROOT/dist"
rm -f "$ROOT/dist"/oidccli-*.tar.gz "$ROOT/dist"/SHA256SUMS

export CGO_ENABLED=0
for spec in darwin/arm64 darwin/amd64 linux/arm64 linux/amd64; do
	goos="${spec%/*}"
	goarch="${spec#*/}"
	tmp="$(mktemp -d)"
	GOOS="$goos" GOARCH="$goarch" go build -trimpath -ldflags="-s -w" -o "$tmp/oidccli" .
	tar -C "$tmp" -czf "$ROOT/dist/oidccli-${VERSION}-${goos}-${goarch}.tar.gz" oidccli
	rm -rf "$tmp"
done

python3 - "$ROOT/dist" <<'PY'
import hashlib, pathlib, sys
dist = pathlib.Path(sys.argv[1])
lines = []
for p in sorted(dist.glob("oidccli-*.tar.gz")):
    digest = hashlib.sha256(p.read_bytes()).hexdigest()
    lines.append(f"{digest}  {p.name}\n")
(dist / "SHA256SUMS").write_text("".join(lines))
print("".join(lines), end="")
PY

echo "wrote dist/ for ${VERSION}"
