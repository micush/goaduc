#!/usr/bin/env bash
# goaduc web installer: downloads the latest tagged release from GitHub and runs
# its install.sh (install or in-place upgrade).
#
#   curl -fsSL https://raw.githubusercontent.com/micush/goaduc/HEAD/get.sh | sudo bash
#   curl -fsSL https://raw.githubusercontent.com/micush/goaduc/HEAD/get.sh | sudo bash -s -- --server ldaps://dc1.example.com:636
#   curl -fsSL https://raw.githubusercontent.com/micush/goaduc/HEAD/get.sh | sudo bash -s -- --version v14
#
# Everything after `--` goes to install.sh (see its --help), except:
#   --version TAG   install this tag instead of the latest one
#
# The latest tag is the newest GitHub release if there is one, otherwise the
# highest tag that looks like v<number>. Needs curl or wget, tar and the
# network; install.sh installs the rest.
#
# Test hooks (not for normal use): GOADUC_GET_REPO, GOADUC_GET_API, GOADUC_GET_HOST.

set -euo pipefail

main() {
  local repo=${GOADUC_GET_REPO:-micush/goaduc}
  local api=${GOADUC_GET_API:-https://api.github.com}
  local host=${GOADUC_GET_HOST:-https://github.com}
  local want="" args=() tag tmp rc

  if [ -t 2 ]; then B=$'\033[1m'; R=$'\033[31m'; G=$'\033[32m'; N=$'\033[0m'; else B=; R=; G=; N=; fi
  step() { printf '%s==>%s %s%s%s\n' "$G" "$N" "$B" "$*" "$N" >&2; }
  die()  { printf '%serror:%s %s\n' "$R" "$N" "$*" >&2; exit 1; }

  while [ $# -gt 0 ]; do
    case $1 in
      --version) [ $# -ge 2 ] || die "--version needs a tag"; want=$2; shift 2;;
      --version=*) want=${1#--version=}; shift;;
      *) args+=("$1"); shift;;
    esac
  done

  command -v tar >/dev/null 2>&1 || die "tar is required"
  if command -v curl >/dev/null 2>&1; then
    fetch() { curl -fsSL --retry 3 --connect-timeout 15 "$1"; }
  elif command -v wget >/dev/null 2>&1; then
    fetch() { wget -qO- --tries=3 --timeout=15 "$1"; }
  else
    die "curl or wget is required"
  fi

  # Tag names are used in a URL and a path: plain tag characters only.
  valid_tag() { [[ $1 =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]; }

  latest_tag() {
    local t json
    # 1. the newest published release
    json=$(fetch "$api/repos/$repo/releases/latest" 2>/dev/null || true)
    t=$(printf '%s' "$json" | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)
    if [ -n "$t" ] && valid_tag "$t"; then printf '%s\n' "$t"; return 0; fi
    # 2. otherwise the highest v<number> tag
    json=$(fetch "$api/repos/$repo/tags?per_page=100" 2>/dev/null || true)
    t=$(printf '%s' "$json" | grep -o '"name"[[:space:]]*:[[:space:]]*"[^"]*"' |
        sed 's/.*:[[:space:]]*"\(.*\)"/\1/' | grep -E '^v?[0-9]+(\.[0-9]+)*$' | sort -V | tail -n1)
    if [ -n "$t" ]; then printf '%s\n' "$t"; return 0; fi
    return 1
  }

  if [ -n "$want" ]; then
    tag=$want
  else
    step "Looking up the latest goaduc version"
    tag=$(latest_tag) || die "could not find a tagged version of $repo (no network, GitHub rate limit, or no tags yet)"
  fi
  valid_tag "$tag" || die "bad tag name: $tag"

  tmp=$(mktemp -d "${TMPDIR:-/tmp}/goaduc-get.XXXXXX") || die "cannot create a temporary directory"
  trap 'rm -rf "$tmp"' EXIT

  step "Downloading goaduc $tag"
  fetch "$host/$repo/archive/refs/tags/$tag.tar.gz" >"$tmp/src.tgz" || die "download of $tag failed"
  mkdir "$tmp/tree"
  tar -xzf "$tmp/src.tgz" -C "$tmp/tree" --strip-components=1 || die "$tag is not a valid archive"
  rm -f "$tmp/src.tgz"

  # the project may sit at the top of the repository or in a goaduc/ folder
  local root=$tmp/tree
  [ -f "$root/install.sh" ] || { [ -f "$tmp/tree/goaduc/install.sh" ] && root=$tmp/tree/goaduc; }
  [ -f "$root/install.sh" ] && [ -f "$root/VERSION" ] ||
    die "$tag does not look like a goaduc release (install.sh or VERSION missing)"
  local ver; ver=$(tr -d '[:space:]' <"$root/VERSION")
  [[ $ver =~ ^[0-9]+$ ]] || die "$tag has a bad VERSION: '$ver'"
  step "Installing goaduc v$ver"

  # Keep the terminal for install.sh's questions and sudo; the script itself
  # may be what is on our stdin.
  local in=/dev/null
  if ( : </dev/tty ) 2>/dev/null; then in=/dev/tty; fi
  rc=0
  bash "$root/install.sh" ${args[@]+"${args[@]}"} <"$in" || rc=$?
  exit "$rc"
}

# Everything is inside main and runs only once the whole file has arrived, so a
# connection that drops half way through a `curl | bash` runs nothing.
main "$@"
