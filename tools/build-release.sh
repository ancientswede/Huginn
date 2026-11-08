#!/bin/bash
# build-release.sh OUTDIR — build the files attached to a GitHub release (part of Huginn, AGPL-3.0-or-later).
#
#   huginn_all.deb       the Debian package
#   docker-compose.yml   runs the published image, no repository needed
#   huginn.env.example   the settings to copy to .env next to it
#   SHA256SUMS
#
# Every file is named here, so nothing else in the working tree can end up in a release.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
[ $# -eq 1 ] || { echo "Usage: $0 OUTDIR" >&2; exit 2; }
mkdir -p "$1"
OUT="$(cd "$1" && pwd)"
VER=$(sed -nE 's/^HUGINN_VERSION = "([^"]+)".*/\1/p' "$ROOT/app.py" | head -1)
[ -n "$VER" ] || { echo "No HUGINN_VERSION in app.py" >&2; exit 1; }

umask 022
PKG=$(mktemp -d)
trap 'rm -rf "$PKG"' EXIT
chmod 755 "$PKG"               # mktemp makes it private, and this folder stands for / in the package
D="$PKG/usr/share/huginn"
install -d "$D/static" "$D/systemd" "$PKG/usr/sbin" "$PKG/usr/share/doc/huginn" "$PKG/DEBIAN"
install -m 644 "$ROOT/app.py" "$D/app.py"
install -m 644 "$ROOT"/static/* "$D/static/"
install -m 644 "$ROOT/systemd/huginn.service" "$D/systemd/huginn.service"
install -m 755 "$ROOT/install-huginn.sh" "$ROOT/update-huginn.sh" "$D/"
install -m 755 "$ROOT/packaging/deb/huginn-setup" "$ROOT/packaging/deb/huginn-rollback" "$PKG/usr/sbin/"
install -m 644 "$ROOT/LICENSE" "$PKG/usr/share/doc/huginn/copyright"
install -m 755 "$ROOT/packaging/deb/postinst" "$ROOT/packaging/deb/prerm" "$ROOT/packaging/deb/postrm" "$PKG/DEBIAN/"
SIZE=$(du -sk --exclude=DEBIAN "$PKG" | cut -f1)
sed -e "s/@VERSION@/$VER/" -e "s/@SIZE@/$SIZE/" "$ROOT/packaging/deb/control" > "$PKG/DEBIAN/control"
dpkg-deb --root-owner-group -Zxz --build "$PKG" "$OUT/huginn_all.deb" >/dev/null

# Without the repository there is nothing to build from, so the build line has to go.
sed -e '/^    build: \.$/d' \
    -e 's|^#   cp docker/.env.example .env |#   cp huginn.env.example .env |' "$ROOT/docker-compose.yml" > "$OUT/docker-compose.yml"
if grep -qE '^ +build:|docker/\.env' "$OUT/docker-compose.yml"; then
  echo "docker-compose.yml still refers to the repository" >&2
  exit 1
fi
install -m 644 "$ROOT/docker/.env.example" "$OUT/huginn.env.example"

(cd "$OUT" && sha256sum huginn_all.deb docker-compose.yml huginn.env.example > SHA256SUMS)
echo "Huginn $VER: $OUT"
