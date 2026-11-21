#!/usr/bin/env bash
# goaduc installer / upgrader.
#
# Builds goaduc from the source tree this script sits in and installs it as a
# systemd service running as an unprivileged 'goaduc' user. Supports
# Ubuntu, Debian, Fedora, RHEL, Rocky, Alma, Arch and Manjaro (and derivatives
# that declare them in ID_LIKE). If goaduc is already installed it is upgraded
# in place: the config file, web certificate and audit log are kept, the
# previous binary is saved, and the upgrade is rolled back automatically if the
# new version fails to start.
#
#   sudo ./install.sh [options]        see --help
#
# goaduc has no third-party Go dependencies, so the only build prerequisite is
# a Go toolchain (>= 1.24); no C compiler is needed.
#
# On a Samba domain controller (SYSVOL found) the service runs as root, because editing Group Policy settings means
# writing files in SYSVOL; elsewhere it runs as the unprivileged 'goaduc' user (see --run-as).
#
# Test hooks (not for normal use): GOADUC_OS_RELEASE, GOADUC_SYSTEMCTL,
# GOADUC_FORCE_SYSTEMD, GOADUC_ASSUME_MISSING, GOADUC_FORCE_GO_DOWNLOAD,
# GOADUC_GO_BASE_URL, GOADUC_SETTLE, GOADUC_PREFIX (install under a scratch root).

set -euo pipefail
umask 022

# ── fixed layout ─────────────────────────────────────────────────────────────
P=${GOADUC_PREFIX:-}
BIN_DIR=$P/usr/local/sbin
BIN=$BIN_DIR/goaduc
SHARE=$P/usr/local/share/goaduc
MANIFEST=$SHARE/install.manifest
UNIT_NAME=goaduc.service
UNIT=$P/etc/systemd/system/$UNIT_NAME
CONF_DIR=$P/etc/goaduc
CONF=$CONF_DIR/goaduc.conf
LDAP_CA_DEST=$CONF_DIR/ldap-ca.pem
SVC_USER=goaduc
SVC_GROUP=goaduc
STATE_DIR=$P/var/lib/goaduc
SAMBA_CA=/var/lib/samba/private/tls/ca.pem
SAMBA_SYSVOL=/var/lib/samba/sysvol
DEFAULT_PORT=8443

GO_MIN=1.24
GO_VERSION=1.24.7
GO_BASE=${GOADUC_GO_BASE_URL:-https://go.dev/dl}
SYSTEMCTL=${GOADUC_SYSTEMCTL:-systemctl}
OS_RELEASE=${GOADUC_OS_RELEASE:-/etc/os-release}
SETTLE=${GOADUC_SETTLE:-3}

SRC=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

# ── output ───────────────────────────────────────────────────────────────────
if [ -t 1 ]; then B=$'\033[1m'; R=$'\033[31m'; Y=$'\033[33m'; G=$'\033[32m'; N=$'\033[0m'; else B=; R=; Y=; G=; N=; fi
step() { printf '%s==>%s %s%s%s\n' "$G" "$N" "$B" "$*" "$N"; }
info() { printf '    %s\n' "$*"; }
warn() { printf '%swarning:%s %s\n' "$Y" "$N" "$*" >&2; }
die()  { printf '%serror:%s %s\n' "$R" "$N" "$*" >&2; exit 1; }

usage() {
  cat <<EOF
goaduc installer

Usage: sudo ./install.sh [options]

  --server URL      LDAP server goaduc talks to, e.g. ldaps://dc1.example.com:636
                    (default: ldaps://<this host's FQDN>:636, or what an existing
                    install already uses). Asked interactively on a first install
                    when run from a terminal.
  --ca FILE         PEM CA certificate that signed the DC's certificate; copied to
                    $LDAP_CA_DEST. On a Samba DC $SAMBA_CA is used
                    automatically when --ca is not given.
  --insecure-ldap   do not verify the DC's certificate (not recommended)
  --starttls        use StartTLS on an ldap:// URL
  --listen ADDR     web UI listen address (default :$DEFAULT_PORT, HTTPS)
  --sysvol DIR      the SYSVOL directory, for editing Group Policy settings
                    (default: $SAMBA_SYSVOL when it exists, else not editable)
  --run-as WHO      root | service | auto (default auto): run the service as root
                    (needed to write SYSVOL) or as the unprivileged '$SVC_USER' user.
                    auto = root when SYSVOL is present, otherwise the service user.
  --no-start        install and enable the service but do not start/restart it
  --force           reinstall even if this version is already installed, and
                    allow a downgrade
  --skip-deps       don't install build prerequisites (you provide curl/tar and
                    Go >= $GO_MIN)
  --go PATH         use this 'go' binary instead of searching / downloading
  --no-keep-go      remove a downloaded Go toolchain after the build. By default
                    it is kept in $SHARE/go so later upgrades (and the web UI's
                    Update page, which builds the new release) need no download.
  -y, --yes         don't ask questions
  --dry-run         show what would be done, change nothing
  -h, --help        this help

The web UI uses HTTPS with a self-signed certificate that goaduc generates on
first start (kept in $STATE_DIR/tls). To use your own, set
ADUC_TLS_CERT and ADUC_TLS_KEY in $CONF.

Supported: Ubuntu, Debian, Fedora, RHEL, Rocky, Alma, Arch, Manjaro.
EOF
}

# ── arguments ────────────────────────────────────────────────────────────────
OPT_SERVER=""; OPT_CA=""; OPT_INSECURE=0; OPT_STARTTLS=0; OPT_LISTEN=""; OPT_SYSVOL=""; OPT_RUNAS=""
KEEP_GO=1; NO_START=0; FORCE=0; SKIP_DEPS=0; ASSUME_YES=0; DRY=0; OPT_GO=""
while [ $# -gt 0 ]; do
  case $1 in
    --server)      [ $# -ge 2 ] || die "--server needs a URL"; OPT_SERVER=$2; shift 2;;
    --server=*)    OPT_SERVER=${1#*=}; shift;;
    --ca)          [ $# -ge 2 ] || die "--ca needs a file"; OPT_CA=$2; shift 2;;
    --ca=*)        OPT_CA=${1#*=}; shift;;
    --insecure-ldap) OPT_INSECURE=1; shift;;
    --starttls)    OPT_STARTTLS=1; shift;;
    --listen)      [ $# -ge 2 ] || die "--listen needs an address"; OPT_LISTEN=$2; shift 2;;
    --listen=*)    OPT_LISTEN=${1#*=}; shift;;
    --sysvol)      [ $# -ge 2 ] || die "--sysvol needs a directory"; OPT_SYSVOL=$2; shift 2;;
    --sysvol=*)    OPT_SYSVOL=${1#*=}; shift;;
    --run-as)      [ $# -ge 2 ] || die "--run-as needs root, service or auto"; OPT_RUNAS=$2; shift 2;;
    --run-as=*)    OPT_RUNAS=${1#*=}; shift;;
    --no-start)    NO_START=1; shift;;
    --no-keep-go)  KEEP_GO=0; shift;;
    --force)       FORCE=1; shift;;
    --skip-deps)   SKIP_DEPS=1; shift;;
    --go)          [ $# -ge 2 ] || die "--go needs a path"; OPT_GO=$2; shift 2;;
    --go=*)        OPT_GO=${1#*=}; shift;;
    -y|--yes)      ASSUME_YES=1; shift;;
    --dry-run)     DRY=1; shift;;
    -h|--help)     usage; exit 0;;
    *)             usage >&2; die "unknown option: $1";;
  esac
done

# ── helpers ──────────────────────────────────────────────────────────────────
have() { command -v "$1" >/dev/null 2>&1; }

# run a state-changing command (printed, not executed, under --dry-run)
run() {
  if [ "$DRY" = 1 ]; then printf '    [dry-run] %s\n' "$*"; return 0; fi
  "$@"
}

confirm() { # confirm "question" -> 0 if yes; never prompts without a terminal
  [ "$ASSUME_YES" = 1 ] && return 0
  [ -t 0 ] || return 1
  local a; read -r -p "    $1 [y/N] " a || return 1
  [[ $a =~ ^[Yy] ]]
}

# write_file PATH MODE  (content on stdin); only touches the file if it changed.
# Echoes "created", "updated" or "unchanged".
write_file() {
  local path=$1 mode=$2 tmp
  [ "$DRY" = 1 ] || mkdir -p "$(dirname "$path")"
  tmp=$(mktemp "$path.XXXXXX.tmp" 2>/dev/null || mktemp)
  cat >"$tmp"
  if [ -f "$path" ] && cmp -s "$tmp" "$path"; then
    rm -f "$tmp"; echo unchanged; return 0
  fi
  local what=created; [ -f "$path" ] && what=updated
  if [ "$DRY" = 1 ]; then rm -f "$tmp"; echo "$what"; return 0; fi
  chmod "$mode" "$tmp"
  mv -f "$tmp" "$path" || { rm -f "$tmp"; return 1; }
  echo "$what"
}

sha() { sha256sum "$1" | awk '{print $1}'; }

# Treat a tool as missing when the test hook says so.
assumed_missing() { [[ ",${GOADUC_ASSUME_MISSING:-}," == *",$1,"* ]]; }

# conf_get KEY  -> value of KEY in the existing config file (empty if unset)
conf_get() {
  [ -f "$CONF" ] || return 0
  sed -n "s/^$1=//p" "$CONF" | tail -1 | sed 's/^"\(.*\)"$/\1/'
}

# ── root ─────────────────────────────────────────────────────────────────────
if [ "$(id -u)" -ne 0 ] && [ "$DRY" = 0 ] && [ -z "$P" ]; then
  if have sudo; then
    info "re-running with sudo…"
    exec sudo -E bash "${BASH_SOURCE[0]}" "$@"
  fi
  die "must be run as root (sudo ./install.sh)"
fi

[ -f "$SRC/go.mod" ] && [ -f "$SRC/VERSION" ] && [ -f "$SRC/main.go" ] ||
  die "run this script from the top of the goaduc tree (go.mod, VERSION and main.go not found next to it)"
NEW_VER=$(tr -d '[:space:]' <"$SRC/VERSION")
[[ $NEW_VER =~ ^[0-9]+$ ]] || die "bad VERSION file: '$NEW_VER'"

# ── distro ───────────────────────────────────────────────────────────────────
detect_family() {
  [ -r "$OS_RELEASE" ] || die "cannot read $OS_RELEASE — unsupported system"
  local id like name
  # shellcheck disable=SC1090
  eval "$(. "$OS_RELEASE"; printf 'id=%q like=%q name=%q' "${ID:-}" "${ID_LIKE:-}" "${PRETTY_NAME:-${ID:-linux}}")"
  OS_NAME=$name
  local tok
  for tok in $id $like; do
    case $tok in
      ubuntu|debian|linuxmint|pop|raspbian|kali|elementary|zorin|neon) FAMILY=debian; return;;
      fedora)                                                           FAMILY=fedora; return;;
      rhel|centos|rocky|almalinux|ol)                                   FAMILY=rhel;   return;;
      arch|manjaro|endeavouros|garuda|cachyos)                          FAMILY=arch;   return;;
    esac
  done
  die "unsupported distribution '$name' (ID=$id ID_LIKE=$like). Supported: Ubuntu, Debian, Fedora, RHEL, Rocky, Alma, Arch, Manjaro."
}
detect_family
case $FAMILY in
  debian) PM=apt;;
  fedora|rhel) if have dnf; then PM=dnf; elif have yum; then PM=yum; else die "neither dnf nor yum found"; fi;;
  arch)   PM=pacman;;
esac

if { [ -d /run/systemd/system ] && have "$SYSTEMCTL"; } || [ -n "${GOADUC_FORCE_SYSTEMD:-}" ]; then
  HAVE_SYSTEMD=1
else
  HAVE_SYSTEMD=0
fi

step "goaduc v$NEW_VER on $OS_NAME ($FAMILY family, package manager: $PM)"
[ "$DRY" = 1 ] && info "dry run: nothing will be changed"

# ── existing installation? ───────────────────────────────────────────────────
OLD_VER=""; MODE=fresh
if [ -x "$BIN" ]; then
  OLD_VER=$("$BIN" --version 2>/dev/null | sed -n 's/^goaduc v\([0-9][0-9]*\).*/\1/p' | head -1 || true)
  OLD_VER=${OLD_VER:-0}
fi
if [ -n "$OLD_VER" ]; then
  if [ "$OLD_VER" -lt "$NEW_VER" ]; then
    MODE=upgrade; info "installed: v$OLD_VER → upgrading to v$NEW_VER"
  elif [ "$OLD_VER" -eq "$NEW_VER" ] && [ "$FORCE" = 0 ]; then
    info "goaduc v$OLD_VER is already installed and up to date (use --force to reinstall/repair)."
    exit 0
  elif [ "$OLD_VER" -gt "$NEW_VER" ] && [ "$FORCE" = 0 ]; then
    die "installed v$OLD_VER is newer than this source (v$NEW_VER); use --force to downgrade"
  else
    MODE=reinstall; info "installed: v$OLD_VER — reinstalling v$NEW_VER (--force)"
  fi
else
  info "no existing installation found: fresh install"
fi

# values remembered from a previous install (so upgrades keep them)
# (a plain uninstall leaves a copy of the manifest in the config dir for this)
USER_CREATED=0; GROUP_CREATED=0
for m in "$MANIFEST" "$CONF_DIR/.install-manifest"; do
  if [ -f "$m" ]; then
    # shellcheck disable=SC1090
    USER_CREATED=$( . "$m"; echo "${USER_CREATED:-0}" )
    # shellcheck disable=SC1090
    GROUP_CREATED=$( . "$m"; echo "${GROUP_CREATED:-0}" )
    break
  fi
done

WAS_ACTIVE=0
if [ "$HAVE_SYSTEMD" = 1 ]; then
  "$SYSTEMCTL" is-active --quiet "$UNIT_NAME" 2>/dev/null && WAS_ACTIVE=1 || true
fi

# ── build prerequisites ──────────────────────────────────────────────────────
TMP=""
cleanup() { [ -n "$TMP" ] && rm -rf "$TMP"; return 0; }
trap cleanup EXIT
TMP=$(mktemp -d "${TMPDIR:-/var/tmp}/goaduc-build.XXXXXX")

pkg_install() {
  [ $# -gt 0 ] || return 0
  case $PM in
    apt)
      run env DEBIAN_FRONTEND=noninteractive apt-get update -qq
      run env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$@";;
    dnf|yum) run "$PM" install -y "$@";;
    pacman)
      run pacman -S --needed --noconfirm "$@" ||
        die "pacman could not install: $* — if the package database is stale run 'pacman -Syu' first, then re-run this script";;
  esac
}

install_deps() {
  local pkgs=()
  if assumed_missing tar || ! have tar; then pkgs+=(tar gzip); fi
  if [ "$NEED_DOWNLOAD" = 1 ] && ! { have curl || have wget; }; then
    pkgs+=(curl ca-certificates)
  fi
  if assumed_missing openssl || ! have openssl; then pkgs+=(openssl); fi
  if [ ${#pkgs[@]} -eq 0 ]; then info "build prerequisites already present"; return 0; fi
  info "installing: ${pkgs[*]}"
  pkg_install "${pkgs[@]}"
}

# ── Go toolchain (>= $GO_MIN) ────────────────────────────────────────────────
go_ok() {
  local bin=$1 v
  [ -x "$bin" ] || return 1
  v=$("$bin" version 2>/dev/null | awk '{print $3}' | sed 's/^go//')
  [[ $v =~ ^[0-9]+\.[0-9]+ ]] || return 1
  [ "$(printf '%s\n%s\n' "$GO_MIN" "$v" | sort -V | head -1)" = "$GO_MIN" ]
}

find_go() {
  local c
  if [ -n "$OPT_GO" ]; then
    go_ok "$OPT_GO" || die "$OPT_GO is not a Go >= $GO_MIN"
    GO=$OPT_GO; return 0
  fi
  [ -n "${GOADUC_FORCE_GO_DOWNLOAD:-}" ] && return 1
  for c in "$(command -v go 2>/dev/null || true)" /usr/local/go/bin/go /usr/lib/go/bin/go /usr/lib/golang/bin/go /snap/bin/go /usr/lib/go-*/bin/go "$SHARE/go/bin/go"; do
    [ -n "$c" ] && go_ok "$c" && { GO=$c; return 0; }
  done
  return 1
}

fetch() { # fetch URL DEST
  if have curl; then curl -fsSL --retry 3 -o "$2" "$1"; else wget -q -O "$2" "$1"; fi
}

download_go() {
  local arch file
  case $(uname -m) in
    x86_64|amd64)   arch=amd64;;
    aarch64|arm64)  arch=arm64;;
    armv7l|armv6l)  arch=armv6l;;
    i?86)           arch=386;;
    riscv64)        arch=riscv64;;
    *) die "no Go toolchain for $(uname -m); install Go >= $GO_MIN yourself and re-run with --go /path/to/go";;
  esac
  file=go${GO_VERSION}.linux-${arch}.tar.gz
  info "no Go >= $GO_MIN on this system; fetching the official go$GO_VERSION toolchain (kept in $SHARE/go unless --no-keep-go)"
  have curl || have wget || die "need curl or wget to download Go (or pass --go PATH)"
  if [ "$DRY" = 1 ]; then info "[dry-run] download $GO_BASE/$file and verify its sha256"; GO=$TMP/goroot/go/bin/go; return 0; fi
  fetch "$GO_BASE/$file" "$TMP/$file"               || die "could not download $GO_BASE/$file"
  fetch "$GO_BASE/$file.sha256" "$TMP/$file.sha256" || die "could not download the checksum $GO_BASE/$file.sha256"
  local want got
  want=$(awk '{print $1; exit}' "$TMP/$file.sha256"); got=$(sha "$TMP/$file")
  [ -n "$want" ] && [ "$want" = "$got" ] || die "checksum mismatch for $file (wanted '$want', got '$got') — refusing to use it"
  mkdir -p "$TMP/goroot"
  tar -xzf "$TMP/$file" -C "$TMP/goroot"
  GO=$TMP/goroot/go/bin/go
  go_ok "$GO" || die "downloaded toolchain does not run on this system"
}

# Prefer the distribution's own Go package when it is recent enough; the
# official tarball is the fallback for distros that ship an older Go.
pkg_version_ok() { # VERSION-STRING -> 0 if >= GO_MIN
  local v=${1#*:}; v=${v%%[~+-]*}
  [[ $v =~ ^[0-9]+\.[0-9]+ ]] && [ "$(printf '%s\n%s\n' "$GO_MIN" "$v" | sort -V | head -1)" = "$GO_MIN" ]
}
try_distro_go() {
  local p cand
  [ -z "${GOADUC_FORCE_GO_DOWNLOAD:-}" ] || return 1
  case $FAMILY in
    debian) set -- golang-1.25-go golang-1.24-go golang-go;;
    fedora|rhel) set -- golang;;
    arch) set -- go;;
    *) return 1;;
  esac
  for p in "$@"; do
    if [ "$FAMILY" = debian ] && [ "$DRY" = 0 ]; then
      cand=$(apt-cache policy "$p" 2>/dev/null | awk '/Candidate:/{print $2}')
      { [ -n "$cand" ] && [ "$cand" != "(none)" ] && pkg_version_ok "$cand"; } || continue
    fi
    info "installing Go from the distribution package: $p"
    if (pkg_install "$p") && { [ "$DRY" = 1 ] || find_go; }; then return 0; fi
    info "package $p did not give a usable Go >= $GO_MIN"
  done
  return 1
}

GO=""; NEED_DOWNLOAD=0
if [ "$SKIP_DEPS" = 0 ] || [ -z "$OPT_GO" ]; then
  find_go >/dev/null 2>&1 || NEED_DOWNLOAD=1
fi
step "Build prerequisites"
if [ "$SKIP_DEPS" = 1 ]; then
  info "skipped (--skip-deps)"
else
  install_deps
fi
step "Go toolchain"
if find_go; then info "using $GO ($("$GO" version | awk '{print $3}'))"
elif [ "$SKIP_DEPS" = 0 ] && [ -z "$OPT_GO" ] && try_distro_go && [ "$DRY" = 0 ]; then
  find_go; info "using $GO ($("$GO" version | awk '{print $3}'))"
else
  [ "$DRY" = 1 ] && [ "$SKIP_DEPS" = 0 ] && [ -z "$OPT_GO" ] && [ -z "${GOADUC_FORCE_GO_DOWNLOAD:-}" ] && info "[dry-run] (if the package gives no Go >= $GO_MIN, the official toolchain is downloaded instead)"
  download_go
fi

# ── build (before touching the installed system) ─────────────────────────────
step "Building goaduc v$NEW_VER"
NEWBIN=$TMP/goaduc
if [ "$DRY" = 1 ]; then
  info "[dry-run] CGO_ENABLED=0 $GO build -trimpath -o goaduc ."
else
  ( cd "$SRC" &&
    GOTOOLCHAIN=local CGO_ENABLED=0 GOCACHE="$TMP/gocache" GOPATH="$TMP/gopath" GOFLAGS=-mod=mod \
    "$GO" build -trimpath -ldflags='-s -w' -o "$NEWBIN" . ) ||
    die "build failed — the installed version (if any) was not touched"
  [ "$("$NEWBIN" --version)" = "goaduc v$NEW_VER" ] || die "built binary reports '$("$NEWBIN" --version)', expected 'goaduc v$NEW_VER'"
  info "built $(du -h "$NEWBIN" | cut -f1) static binary"
fi

# ── settings: server URL, CA ─────────────────────────────────────────────────
step "Directory settings"
SERVER=${OPT_SERVER:-$(conf_get ADUC_SERVER)}
if [ -z "$SERVER" ]; then
  HOSTFQDN=$(hostname -f 2>/dev/null || hostname)
  SERVER="ldaps://$HOSTFQDN:636"
  if [ "$ASSUME_YES" = 0 ] && [ -t 0 ] && [ "$DRY" = 0 ]; then
    read -r -p "    LDAP server URL [$SERVER]: " ans || ans=""
    [ -n "$ans" ] && SERVER=$ans
  fi
fi
case $SERVER in ldap://*|ldaps://*) ;; *) die "server URL must start with ldap:// or ldaps:// (got '$SERVER')";; esac
info "LDAP server: $SERVER"

CA_SRC=$OPT_CA
if [ -z "$CA_SRC" ] && [ ! -f "$LDAP_CA_DEST" ] && [ -r "$SAMBA_CA" ]; then
  CA_SRC=$SAMBA_CA; info "found the Samba CA at $SAMBA_CA"
fi
[ -z "$CA_SRC" ] || [ -r "$CA_SRC" ] || die "CA file $CA_SRC is not readable"

LISTEN=${OPT_LISTEN:-$(conf_get ADUC_LISTEN)}; LISTEN=${LISTEN:-:$DEFAULT_PORT}
LPORT=${LISTEN##*:}
[[ $LPORT =~ ^[0-9]+$ ]] || die "bad listen address '$LISTEN'"

SYSVOL=${OPT_SYSVOL:-$(conf_get ADUC_SYSVOL)}
if [ -z "$SYSVOL" ] && [ -d "$SAMBA_SYSVOL" ]; then SYSVOL=$SAMBA_SYSVOL; info "found SYSVOL at $SYSVOL"; fi
[ -z "$SYSVOL" ] || [ -d "$SYSVOL" ] || die "SYSVOL directory $SYSVOL does not exist"
RUN_AS=${OPT_RUNAS:-auto}
case $RUN_AS in
  root|service) ;;
  auto) if [ -n "$SYSVOL" ]; then RUN_AS=root; else RUN_AS=service; fi;;
  *) die "--run-as must be root, service or auto (got '$RUN_AS')";;
esac
if [ "$RUN_AS" = root ]; then
  info "service runs as root (it writes Group Policy settings into SYSVOL)"
elif [ -n "$SYSVOL" ]; then
  warn "running as the '$SVC_USER' user: Group Policy settings in $SYSVOL can be read but not written"
else
  info "no SYSVOL here: Group Policy settings can't be edited from this host (the rest works)"
fi

INSECURE=$OPT_INSECURE; [ "$INSECURE" = 1 ] || { [ "$(conf_get ADUC_INSECURE)" = 1 ] && INSECURE=1; } || true
STARTTLS=$OPT_STARTTLS; [ "$STARTTLS" = 1 ] || { [ "$(conf_get ADUC_STARTTLS)" = 1 ] && STARTTLS=1; } || true
if [ ! -f "$LDAP_CA_DEST" ] && [ -z "$CA_SRC" ] && [ "$INSECURE" = 0 ] && [[ $SERVER == ldaps://* || $STARTTLS = 1 ]]; then
  warn "no CA file for the directory's certificate. If it is self-signed, sign-in will fail until you pass --ca FILE (or --insecure-ldap)."
fi
[ "$INSECURE" = 1 ] && warn "LDAP certificate verification is disabled (--insecure-ldap)"

# ── install files ────────────────────────────────────────────────────────────
step "Installing files"
run mkdir -p "$BIN_DIR" "$SHARE"

# service account (no shell, no home); not needed when the service runs as root
if [ "$RUN_AS" = root ]; then
  info "running as root: no service user needed"
elif id -u "$SVC_USER" >/dev/null 2>&1; then
  info "user $SVC_USER exists"
else
  if ! getent group "$SVC_GROUP" >/dev/null 2>&1; then
    run groupadd --system "$SVC_GROUP"; GROUP_CREATED=1
  fi
  NOLOGIN=/usr/sbin/nologin; [ -x "$NOLOGIN" ] || NOLOGIN=/sbin/nologin; [ -x "$NOLOGIN" ] || NOLOGIN=/bin/false
  run useradd --system --gid "$SVC_GROUP" --no-create-home --home-dir "$STATE_DIR" --shell "$NOLOGIN" "$SVC_USER"
  USER_CREATED=1
  info "created system user $SVC_USER"
fi

# web certificate lives here
if [ "$RUN_AS" = root ]; then run install -d -m 0700 "$STATE_DIR"; else run install -d -m 0700 -o "$SVC_USER" -g "$SVC_GROUP" "$STATE_DIR"; fi
run install -d -m 0755 "$CONF_DIR"

# keep the previous binary for rollback, then replace atomically
HAD_BIN=0
if [ -x "$BIN" ]; then
  HAD_BIN=1
  run cp -p "$BIN" "$SHARE/goaduc.prev"
  info "previous binary saved to $SHARE/goaduc.prev"
fi
run install -m 0755 "$NEWBIN" "$BIN.new"
run mv -f "$BIN.new" "$BIN"
info "installed $BIN"

# keep a downloaded Go so later upgrades need no download
GO_KEPT=0
if [ "${GO#"$TMP"/}" != "$GO" ]; then
  if [ "$KEEP_GO" = 1 ]; then
    if [ "$DRY" = 1 ]; then info "[dry-run] keep the downloaded Go in $SHARE/go"; else
      rm -rf "$SHARE/go.new" && mv "$TMP/goroot/go" "$SHARE/go.new" && rm -rf "$SHARE/go" && mv "$SHARE/go.new" "$SHARE/go"
      GO_KEPT=1; info "kept the Go toolchain in $SHARE/go (--no-keep-go to skip)"
    fi
  else
    info "downloaded Go not kept (--no-keep-go)"
  fi
elif [ "$GO" = "$SHARE/go/bin/go" ]; then
  GO_KEPT=1
fi

# LDAP CA
if [ -n "$CA_SRC" ]; then
  run install -m 0644 "$CA_SRC" "$LDAP_CA_DEST"
  info "LDAP CA installed: $LDAP_CA_DEST"
fi

# config (EnvironmentFile): rewritten on every run from the remembered/new values,
# but only the settings the installer manages; extra lines the admin added are kept.
EXTRA=""
if [ -f "$CONF" ]; then
  EXTRA=$(grep -Ev '^(#|$|ADUC_(SERVER|LISTEN|CA|INSECURE|STARTTLS|DATA_DIR|SYSVOL)=)' "$CONF" || true)
fi
{
  echo "# goaduc configuration — read by systemd as EnvironmentFile. Restart after editing:"
  echo "#   systemctl restart goaduc"
  echo "ADUC_SERVER=$SERVER"
  echo "ADUC_LISTEN=$LISTEN"
  echo "ADUC_DATA_DIR=$STATE_DIR"
  [ -n "$SYSVOL" ] && echo "ADUC_SYSVOL=$SYSVOL"
  if [ -f "$LDAP_CA_DEST" ] || [ -n "$CA_SRC" ]; then echo "ADUC_CA=$LDAP_CA_DEST"; fi
  [ "$INSECURE" = 1 ] && echo "ADUC_INSECURE=1"
  [ "$STARTTLS" = 1 ] && echo "ADUC_STARTTLS=1"
  if [ -n "$EXTRA" ]; then echo; echo "# --- kept from the previous config ---"; echo "$EXTRA"; fi
  if ! grep -q '^ADUC_AUDIT_LOG=' <<<"$EXTRA"; then
    echo
    echo "# Uncomment to keep a JSON-lines audit log of every change:"
    echo "#ADUC_AUDIT_LOG=$STATE_DIR/audit.log"
  fi
  if ! grep -q '^ADUC_NO_UPDATE=' <<<"$EXTRA"; then
    echo "# Uncomment to turn off the Update page (software updates from the web UI), or to fetch releases from another repo:"
    echo "#ADUC_NO_UPDATE=1"
    echo "#ADUC_UPDATE_REPO=owner/repo"
  fi
  if ! grep -q '^ADUC_TLS_CERT=' <<<"$EXTRA"; then
    echo "# Uncomment to use your own web certificate instead of the self-signed one:"
    echo "#ADUC_TLS_CERT=/etc/goaduc/web.crt"
    echo "#ADUC_TLS_KEY=/etc/goaduc/web.key"
  fi
} | { res=$(write_file "$CONF" 0644); info "config $CONF: $res"; }

# docs and the uninstaller (so removal works without the source tree)
run install -m 0644 "$SRC/VERSION" "$SHARE/VERSION"
for f in README.md CHANGELOG.md LICENSE; do
  [ -f "$SRC/$f" ] && run install -m 0644 "$SRC/$f" "$SHARE/$f"
done
if [ -f "$SRC/uninstall.sh" ]; then
  run install -m 0755 "$SRC/uninstall.sh" "$SHARE/uninstall.sh"
  run ln -sf "$SHARE/uninstall.sh" "$BIN_DIR/goaduc-uninstall"
fi

# SELinux labels (RHEL family)
if have restorecon; then run restorecon -RF "$BIN" "$SHARE" "$CONF_DIR" "$STATE_DIR" >/dev/null 2>&1 || true; fi

# ── systemd unit ─────────────────────────────────────────────────────────────
UNIT_USER_LINES=""
[ "$RUN_AS" = service ] && UNIT_USER_LINES="User=$SVC_USER
Group=$SVC_GROUP
"
UNIT_BODY="[Unit]
Description=goaduc - web-based Active Directory administration for Samba AD
Documentation=file://$SHARE/README.md
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
${UNIT_USER_LINES}EnvironmentFile=$CONF
ExecStart=$BIN
Restart=on-failure
RestartSec=2
TimeoutStopSec=15
LimitNOFILE=65536
# the web UI may be put on a port below 1024
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target"

ROLLED_BACK=0
if [ "$HAVE_SYSTEMD" = 1 ]; then
  step "systemd service"
  res=$(printf '%s\n' "$UNIT_BODY" | write_file "$UNIT" 0644)
  info "unit $UNIT: $res"
  run "$SYSTEMCTL" daemon-reload
  run "$SYSTEMCTL" enable "$UNIT_NAME" >/dev/null 2>&1 || warn "could not enable $UNIT_NAME"

  start_wanted=1
  [ "$NO_START" = 1 ] && start_wanted=0
  # an upgrade keeps the service in the state it was found in
  if [ "$MODE" != fresh ] && [ "$WAS_ACTIVE" = 0 ]; then start_wanted=0; fi

  if [ "$start_wanted" = 1 ]; then
    if [ "$WAS_ACTIVE" = 1 ]; then run "$SYSTEMCTL" restart "$UNIT_NAME" || true; else run "$SYSTEMCTL" start "$UNIT_NAME" || true; fi
    if [ "$DRY" = 0 ]; then
      sleep "$SETTLE"
      if ! "$SYSTEMCTL" is-active --quiet "$UNIT_NAME"; then
        errmsg="goaduc v$NEW_VER failed to start"
        if [ "$HAD_BIN" = 1 ] && [ -x "$SHARE/goaduc.prev" ]; then
          warn "$errmsg — rolling back to the previous binary"
          cp -p "$SHARE/goaduc.prev" "$BIN.new" && mv -f "$BIN.new" "$BIN"
          [ "${OLD_VER:-0}" != 0 ] && echo "$OLD_VER" >"$SHARE/VERSION"
          "$SYSTEMCTL" restart "$UNIT_NAME" || true
          sleep "$SETTLE"
          ROLLED_BACK=1
          if "$SYSTEMCTL" is-active --quiet "$UNIT_NAME"; then
            die "$errmsg; the previous version was restored and is running. See: journalctl -u goaduc -n 50"
          fi
          die "$errmsg and the restored previous version is not running either. See: journalctl -u goaduc -n 50"
        fi
        die "$errmsg. See: journalctl -u goaduc -n 50"
      fi
      info "service is running"
    fi
  else
    info "service not (re)started"
  fi
else
  step "systemd"
  warn "systemd is not running here — unit file not installed. Start it yourself, e.g.: set -a; . $CONF; set +a; $([ "$RUN_AS" = service ] && echo "runuser -u $SVC_USER -- ")$BIN"
fi

# ── manifest ─────────────────────────────────────────────────────────────────
if [ "$DRY" = 0 ]; then
  {
    echo "VERSION=$NEW_VER"
    echo "INSTALLED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "FAMILY=$FAMILY"
    echo "BIN=$BIN"
    echo "SHARE=$SHARE"
    echo "UNIT=$UNIT"
    echo "CONF_DIR=$CONF_DIR"
    echo "STATE_DIR=$STATE_DIR"
    echo "RUN_AS=$RUN_AS"
    echo "SYSVOL=$SYSVOL"
    echo "SVC_USER=$SVC_USER"
    echo "USER_CREATED=$USER_CREATED"
    echo "SVC_GROUP=$SVC_GROUP"
    echo "GROUP_CREATED=$GROUP_CREATED"
    echo "GO_KEPT=$GO_KEPT"
  } >"$MANIFEST"
  chmod 0644 "$MANIFEST"
fi

# ── summary ──────────────────────────────────────────────────────────────────
step "Done: goaduc v$NEW_VER ($MODE)"
HOST=$(hostname -f 2>/dev/null || hostname)
info "web UI:  https://$HOST:$LPORT   (sign in with an AD account, e.g. administrator@your.realm)"
CERT=$STATE_DIR/tls/server.crt
if [ "$DRY" = 0 ] && [ "$HAVE_SYSTEMD" = 1 ] && [ "$NO_START" = 0 ]; then
  for _ in 1 2 3 4 5; do [ -f "$CERT" ] && break; sleep 1; done
fi
if [ -f "$CERT" ] && have openssl; then
  info "certificate: self-signed. SHA-256 fingerprint (compare with what your browser shows):"
  info "  $(openssl x509 -in "$CERT" -noout -fingerprint -sha256 | sed 's/^.*=//')"
else
  info "certificate: self-signed, generated on first start in $STATE_DIR/tls (the browser will warn once)"
fi
if have firewall-cmd && firewall-cmd --state >/dev/null 2>&1; then
  info "firewalld is active; open the port, e.g.: firewall-cmd --permanent --add-port=$LPORT/tcp && firewall-cmd --reload"
elif have ufw && ufw status 2>/dev/null | grep -q '^Status: active'; then
  info "ufw is active; open the port, e.g.: ufw allow $LPORT/tcp"
else
  info "port used: tcp/$LPORT (open it if a firewall is active)"
fi
info "config: $CONF     logs: journalctl -u goaduc -f"
info "uninstall: sudo goaduc-uninstall   (add --purge to remove config and certificate too)"
[ "$ROLLED_BACK" = 1 ] && warn "rolled back"
exit 0
