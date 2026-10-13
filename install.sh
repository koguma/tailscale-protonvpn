#!/bin/sh
# tailscale-protonvpn installer.
#
#   curl -fsSL https://raw.githubusercontent.com/koguma/tailscale-protonvpn/main/install.sh | sudo sh
#
# Environment overrides:
#   TAILSCALE_PROTONVPN_VERSION=v1.0.0   install a specific release (default: latest)
#   TAILSCALE_PROTONVPN_ARGS="--https-port 8443"   extra flags for `tailscale-protonvpn install`
set -eu

REPO="${TAILSCALE_PROTONVPN_REPO:-koguma/tailscale-protonvpn}"
VERSION="${TAILSCALE_PROTONVPN_VERSION:-latest}"

say() { printf '\033[1m%s\033[0m\n' "$*"; }
die() { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(uname -s)" = Linux ] || die "tailscale-protonvpn only runs on Linux"
[ "$(id -u)" -eq 0 ] || die "run as root, e.g.: curl -fsSL ... | sudo sh"
command -v systemctl >/dev/null 2>&1 || die "systemd is required"
command -v tailscale >/dev/null 2>&1 || die "Tailscale isn't installed: https://tailscale.com/download/linux"

case "$(uname -m)" in
  x86_64 | amd64) ARCH=amd64 ;;
  aarch64 | arm64) ARCH=arm64 ;;
  *) die "unsupported CPU architecture: $(uname -m) (supported: x86_64, arm64)" ;;
esac

# --- dependencies: iproute2 and iptables (nft backend is fine) ---
missing_ip=0 missing_ipt=0
command -v ip >/dev/null 2>&1 || missing_ip=1
{ command -v iptables-restore && command -v ip6tables-restore; } >/dev/null 2>&1 || missing_ipt=1
if [ $missing_ip = 1 ] || [ $missing_ipt = 1 ]; then
  say "Installing dependencies…"
  # shellcheck disable=SC2086 # $pkgs is a space-separated package list
  if command -v apt-get >/dev/null 2>&1; then
    pkgs=""; [ $missing_ip = 1 ] && pkgs="$pkgs iproute2"; [ $missing_ipt = 1 ] && pkgs="$pkgs iptables"
    DEBIAN_FRONTEND=noninteractive apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq $pkgs
  elif command -v dnf >/dev/null 2>&1; then
    pkgs=""; [ $missing_ip = 1 ] && pkgs="$pkgs iproute"; [ $missing_ipt = 1 ] && pkgs="$pkgs iptables-nft"
    dnf install -y -q $pkgs
  elif command -v yum >/dev/null 2>&1; then
    pkgs=""; [ $missing_ip = 1 ] && pkgs="$pkgs iproute"; [ $missing_ipt = 1 ] && pkgs="$pkgs iptables"
    yum install -y -q $pkgs
  elif command -v pacman >/dev/null 2>&1; then
    pkgs=""; [ $missing_ip = 1 ] && pkgs="$pkgs iproute2"; [ $missing_ipt = 1 ] && pkgs="$pkgs iptables-nft"
    pacman -Sy --noconfirm --needed $pkgs
  elif command -v zypper >/dev/null 2>&1; then
    pkgs=""; [ $missing_ip = 1 ] && pkgs="$pkgs iproute2"; [ $missing_ipt = 1 ] && pkgs="$pkgs iptables"
    zypper --non-interactive install $pkgs
  else
    die "please install iproute2 and iptables, then re-run"
  fi
fi

# --- download and verify ---
if [ -n "${TAILSCALE_PROTONVPN_BASE_URL:-}" ]; then
  BASE="$TAILSCALE_PROTONVPN_BASE_URL" # e.g. a mirror, or a local http server for testing
elif [ "$VERSION" = latest ]; then
  BASE="https://github.com/$REPO/releases/latest/download"
else
  BASE="https://github.com/$REPO/releases/download/$VERSION"
fi
BIN="tailscale-protonvpn-linux-$ARCH"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

fetch() {
  if command -v curl >/dev/null 2>&1; then curl -fsSL -o "$2" "$1"
  elif command -v wget >/dev/null 2>&1; then wget -qO "$2" "$1"
  else die "curl or wget is required"; fi
}

say "Downloading tailscale-protonvpn ($VERSION, $ARCH)…"
fetch "$BASE/$BIN" "$TMP/tailscale-protonvpn" || die "download failed: $BASE/$BIN"
fetch "$BASE/checksums.txt" "$TMP/checksums.txt" || die "download failed: $BASE/checksums.txt"
want="$(grep " $BIN\$" "$TMP/checksums.txt" | cut -d' ' -f1)"
[ -n "$want" ] || die "no checksum for $BIN in checksums.txt"
got="$(sha256sum "$TMP/tailscale-protonvpn" | cut -d' ' -f1)"
[ "$want" = "$got" ] || die "checksum mismatch for $BIN"
chmod +x "$TMP/tailscale-protonvpn"

say "Installing…"
# shellcheck disable=SC2086
"$TMP/tailscale-protonvpn" install ${TAILSCALE_PROTONVPN_ARGS:-}
