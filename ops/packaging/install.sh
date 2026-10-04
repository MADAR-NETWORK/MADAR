#!/bin/sh
# Madar Ops installer — https://madar-network.com/ops/
# Downloads the static binary for this CPU, checks its SHA-256 against the published list, installs a locked-down systemd service.
# Re-running upgrades the binary and keeps your configuration.
set -eu
BASE="https://madar-network.com/downloads/ops"
[ "$(id -u)" -eq 0 ] || { echo "run as root: curl -fsSL $BASE/install.sh | sudo sh"; exit 1; }
case "$(uname -m)" in
  x86_64|amd64) FILE=madar-ops-linux-x86_64 ;;
  aarch64|arm64) FILE=madar-ops-linux-arm64 ;;
  *) echo "unsupported CPU: $(uname -m)"; exit 1 ;;
esac
command -v systemctl >/dev/null || { echo "systemd is required"; exit 1; }
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
fetch() { if command -v curl >/dev/null; then curl -fsSL "$1" -o "$2"; else wget -qO "$2" "$1"; fi; }
echo "downloading $FILE"
fetch "$BASE/$FILE" "$TMP/madar-ops"
fetch "$BASE/SHA256SUMS" "$TMP/SHA256SUMS"
WANT=$(grep " $FILE\$" "$TMP/SHA256SUMS" | cut -d' ' -f1)
GOT=$(sha256sum "$TMP/madar-ops" | cut -d' ' -f1)
[ -n "$WANT" ] && [ "$WANT" = "$GOT" ] || { echo "CHECKSUM MISMATCH — not installing"; exit 1; }
install -m 755 "$TMP/madar-ops" /usr/local/bin/madar-ops
id madar-ops >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin madar-ops
install -d -m 750 -o root -g madar-ops /etc/madar-ops
NEW=0
if [ ! -f /etc/madar-ops/madar-ops.toml ]; then
  (cd /etc/madar-ops && /usr/local/bin/madar-ops init madar-ops.toml >/dev/null)
  NEW=1
fi
chown root:madar-ops /etc/madar-ops/madar-ops.toml; chmod 640 /etc/madar-ops/madar-ops.toml
fetch "$BASE/madar-ops.service" /etc/systemd/system/madar-ops.service
systemctl daemon-reload
if [ "$NEW" = 1 ]; then
  echo
  echo "Installed. Next:"
  echo "  1) edit /etc/madar-ops/madar-ops.toml  (your node RPC + an alert channel)"
  echo "  2) madar-ops check /etc/madar-ops/madar-ops.toml"
  echo "  3) madar-ops test-alert /etc/madar-ops/madar-ops.toml"
  echo "  4) systemctl enable --now madar-ops"
else
  systemctl restart madar-ops 2>/dev/null || true
  echo "Upgraded to $(/usr/local/bin/madar-ops --version 2>/dev/null || echo latest) — configuration kept."
fi
