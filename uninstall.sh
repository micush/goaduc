#!/usr/bin/env bash
# goaduc uninstaller. Installed as /usr/local/share/goaduc/uninstall.sh and
# linked as /usr/local/sbin/goaduc-uninstall.
#
#   sudo goaduc-uninstall [--purge] [-y] [--dry-run]
#
# Without --purge the config (/etc/goaduc) and state (web certificate, audit
# log in /var/lib/goaduc) are kept so a later reinstall picks them up.
# The service user/group are removed only with --purge, and only if the
# installer created them.

set -euo pipefail

P=${GOADUC_PREFIX:-}
SHARE=$P/usr/local/share/goaduc
MANIFEST=$SHARE/install.manifest
SYSTEMCTL=${GOADUC_SYSTEMCTL:-systemctl}

if [ -t 1 ]; then B=$'\033[1m'; R=$'\033[31m'; Y=$'\033[33m'; G=$'\033[32m'; N=$'\033[0m'; else B=; R=; Y=; G=; N=; fi
step() { printf '%s==>%s %s%s%s\n' "$G" "$N" "$B" "$*" "$N"; }
info() { printf '    %s\n' "$*"; }
warn() { printf '%swarning:%s %s\n' "$Y" "$N" "$*" >&2; }
die()  { printf '%serror:%s %s\n' "$R" "$N" "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

PURGE=0; YES=0; DRY=0
while [ $# -gt 0 ]; do
  case $1 in
    --purge) PURGE=1;;
    -y|--yes) YES=1;;
    --dry-run) DRY=1;;
    -h|--help) echo "Usage: sudo goaduc-uninstall [--purge] [-y] [--dry-run]"; exit 0;;
    *) die "unknown option: $1";;
  esac
  shift
done

run() { if [ "$DRY" = 1 ]; then printf '    [dry-run] %s\n' "$*"; else "$@"; fi; }

if [ "$(id -u)" -ne 0 ] && [ "$DRY" = 0 ] && [ -z "$P" ]; then
  have sudo && exec sudo -E bash "${BASH_SOURCE[0]}" "$@"
  die "must be run as root"
fi

[ -f "$MANIFEST" ] || die "no install manifest at $MANIFEST — is goaduc installed?"
mget() { ( . "$MANIFEST"; eval "printf '%s' \"\${$1:-}\"" ); }
BIN=$(mget BIN); UNIT=$(mget UNIT); CONF_DIR=$(mget CONF_DIR); STATE_DIR=$(mget STATE_DIR)
SVC_USER=$(mget SVC_USER); SVC_GROUP=$(mget SVC_GROUP)
USER_CREATED=$(mget USER_CREATED); GROUP_CREATED=$(mget GROUP_CREATED)

if [ "$PURGE" = 1 ] && [ "$YES" = 0 ] && [ "$DRY" = 0 ]; then
  [ -t 0 ] || die "--purge deletes $CONF_DIR and $STATE_DIR (including the web certificate); pass -y to confirm"
  read -r -p "    Delete $CONF_DIR and $STATE_DIR? [y/N] " a || a=""
  [[ $a =~ ^[Yy] ]] || die "aborted"
fi

step "Removing goaduc"
if [ -d /run/systemd/system ] && have "$SYSTEMCTL"; then
  run "$SYSTEMCTL" disable --now goaduc.service >/dev/null 2>&1 || true
fi
[ -n "$UNIT" ] && [ -f "$UNIT" ] && { run rm -f "$UNIT"; info "removed $UNIT"; }
if [ -d /run/systemd/system ] && have "$SYSTEMCTL"; then run "$SYSTEMCTL" daemon-reload || true; fi
[ -n "$BIN" ] && [ -e "$BIN" ] && { run rm -f "$BIN"; info "removed $BIN"; }
run rm -f "$(dirname "${BIN:-/nonexistent}")/goaduc-uninstall"

if [ "$PURGE" = 1 ]; then
  [ -n "$CONF_DIR" ] && [ -d "$CONF_DIR" ] && { run rm -rf "$CONF_DIR"; info "removed $CONF_DIR"; }
  [ -n "$STATE_DIR" ] && [ -d "$STATE_DIR" ] && { run rm -rf "$STATE_DIR"; info "removed $STATE_DIR"; }
  if [ "$USER_CREATED" = 1 ] && [ -n "$SVC_USER" ] && id -u "$SVC_USER" >/dev/null 2>&1; then
    run userdel "$SVC_USER" 2>/dev/null || true; info "removed user $SVC_USER"
  fi
  if [ "$GROUP_CREATED" = 1 ] && [ -n "$SVC_GROUP" ] && getent group "$SVC_GROUP" >/dev/null 2>&1; then
    run groupdel "$SVC_GROUP" 2>/dev/null || true; info "removed group $SVC_GROUP"
  fi
else
  # remember whether the installer created the service user/group, for a later --purge
  if [ -d "$CONF_DIR" ] && [ "$DRY" = 0 ]; then cp -p "$MANIFEST" "$CONF_DIR/.install-manifest"; fi
  info "kept $CONF_DIR and $STATE_DIR (use --purge to remove)"
fi

# the share dir last: this script lives there
run rm -rf "$SHARE"
info "removed $SHARE"
step "goaduc uninstalled"
