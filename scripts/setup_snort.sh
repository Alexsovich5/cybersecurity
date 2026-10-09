#!/bin/bash
# Build and install DAQ 2.0.6 and Snort 2.9.11.1 from checksum-verified source
# tarballs on CentOS 7, create the snort user and directories, and install the
# configuration and local rules.
#
# Usage: setup_snort.sh [--prefix DIR] [--src-dir DIR] [--config-dir DIR] [--no-deps]
#   --prefix DIR      install prefix for DAQ and Snort (default /usr/local)
#   --src-dir DIR     where tarballs are downloaded and built (default /usr/local/src/snort-build)
#   --config-dir DIR  directory holding snort.conf and rules/local.rules
#                     (default: the repository's config directory)
#   --no-deps         do not install the yum build dependencies
#
# The build is skipped when /etc/snort/.installed-2.9.11.1 exists and
# `snort -V` reports 2.9.11.1. Users, directories and configuration are
# reconciled on every run.
set -euo pipefail

SNORT_VERSION=2.9.11.1
SNORT_SHA256=9f6b3aeac5a109f55504bd370564ac431cb1773507929dc461626898f33f46cd
DAQ_VERSION=2.0.6
DAQ_SHA256=b40e1d1273e08aaeaa86e69d4f28d535b7e53bdb3898adf539266b63137be7cb
DIST_URL=http://distcache.freebsd.org/ports-distfiles

BUILD_DEPS=(
  gcc-4.8.5-28.el7 gcc-c++-4.8.5-28.el7 make-3.82-23.el7 flex-2.5.37-3.el7
  bison-3.0.4-1.el7 libpcap-devel-1.5.3-11.el7 pcre-devel-8.32-17.el7
  libdnet-devel-1.12-0.13.1.el7 zlib-devel-1.2.7-17.el7 openssl-devel-1.0.2k-12.el7
)

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
PREFIX=/usr/local
SRC_DIR=/usr/local/src/snort-build
CONFIG_DIR="$SCRIPT_DIR/../config"
INSTALL_DEPS=1

ETC_DIR=/etc/snort
MARKER="$ETC_DIR/.installed-$SNORT_VERSION"

usage() {
  sed -n '6,11p' "$0" | sed 's/^# \{0,1\}//'
}

log() {
  echo "setup_snort: $*"
}

die() {
  echo "setup_snort: $*" >&2
  exit 1
}

retry() {
  local attempt
  for attempt in 1 2 3; do
    if "$@"; then
      return 0
    fi
    [ "$attempt" -lt 3 ] && sleep 5
  done
  return 1
}

parse_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      --prefix) [ $# -ge 2 ] || die "--prefix needs a value"; PREFIX=$2; shift 2 ;;
      --src-dir) [ $# -ge 2 ] || die "--src-dir needs a value"; SRC_DIR=$2; shift 2 ;;
      --config-dir) [ $# -ge 2 ] || die "--config-dir needs a value"; CONFIG_DIR=$2; shift 2 ;;
      --no-deps) INSTALL_DEPS=0; shift ;;
      -h|--help) usage; exit 0 ;;
      *) usage >&2; die "unknown option: $1" ;;
    esac
  done
}

# Succeeds when the snort binary under $PREFIX reports $SNORT_VERSION.
snort_version_ok() {
  local out
  [ -x "$PREFIX/bin/snort" ] || return 1
  out=$("$PREFIX/bin/snort" -V 2>&1) || { echo "$out" >&2; return 1; }
  [[ "$out" == *"Version $SNORT_VERSION "* ]]
}

installed_version_ok() {
  [ -f "$MARKER" ] && snort_version_ok
}

install_deps() {
  log "installing build dependencies"
  retry yum install -y "${BUILD_DEPS[@]}" || die "yum install of build dependencies failed"
}

fetch() {
  local name=$1 sha=$2 file="$SRC_DIR/$1.tar.gz"
  if [ -f "$file" ] && echo "$sha  $file" | sha256sum -c --quiet - >/dev/null 2>&1; then
    return 0
  fi
  log "downloading $name"
  retry curl -fsSL -o "$file" "$DIST_URL/$name.tar.gz" || die "download of $name failed"
  echo "$sha  $file" | sha256sum -c --quiet - || die "checksum mismatch for $name"
}

# build NAME JOBS [CONFIGURE_ARGS...]
build() {
  local name=$1 jobs=$2
  shift 2
  log "building $name"
  rm -rf "${SRC_DIR:?}/$name"
  tar -xzf "$SRC_DIR/$name.tar.gz" -C "$SRC_DIR"
  (
    cd "$SRC_DIR/$name"
    ./configure --prefix="$PREFIX" "$@"
    make -j"$jobs"
    make install
  )
  ldconfig
  rm -rf "${SRC_DIR:?}/$name"
}

build_snort() {
  mkdir -p "$SRC_DIR"
  # DAQ's libsfbpf lands in $PREFIX/lib, which is not on EL7's default
  # linker path.
  echo "$PREFIX/lib" > /etc/ld.so.conf.d/snort.conf
  fetch "daq-$DAQ_VERSION" "$DAQ_SHA256"
  fetch "snort-$SNORT_VERSION" "$SNORT_SHA256"
  # DAQ's libsfbpf makefile races on the generated tokdefs.h, so it is built serially.
  build "daq-$DAQ_VERSION" 1
  PATH="$PREFIX/bin:$PATH" build "snort-$SNORT_VERSION" "$(nproc)" --disable-open-appid --enable-sourcefire
  # The rules files shipped with the source tree are needed by snort.conf.
  tar -xzf "$SRC_DIR/snort-$SNORT_VERSION.tar.gz" -C "$SRC_DIR" "snort-$SNORT_VERSION/etc"
}

create_user() {
  getent group snort >/dev/null || groupadd -r snort
  getent passwd snort >/dev/null || useradd -r -g snort -s /sbin/nologin -d /var/log/snort -c "Snort IDS" snort
}

create_dirs() {
  mkdir -p "$ETC_DIR/rules" "$ETC_DIR/so_rules" "$ETC_DIR/preproc_rules" \
           /var/log/snort "$PREFIX/lib/snort_dynamicrules"
  chown -R snort:snort /var/log/snort
  chmod 750 /var/log/snort
}

# Copies $1 to $2 only when the content differs.
install_file() {
  if ! cmp -s "$1" "$2"; then
    install -m 0644 "$1" "$2"
    log "installed $2"
  fi
}

install_config() {
  local etc_src="$SRC_DIR/snort-$SNORT_VERSION/etc" f
  if [ -d "$etc_src" ]; then
    for f in "$etc_src"/*.config "$etc_src"/*.map; do
      install_file "$f" "$ETC_DIR/$(basename "$f")"
    done
    rm -rf "${SRC_DIR:?}/snort-$SNORT_VERSION"
  fi
  [ -f "$CONFIG_DIR/snort.conf" ] || die "missing $CONFIG_DIR/snort.conf"
  [ -f "$CONFIG_DIR/rules/local.rules" ] || die "missing $CONFIG_DIR/rules/local.rules"
  install_file "$CONFIG_DIR/snort.conf" "$ETC_DIR/snort.conf"
  install_file "$CONFIG_DIR/rules/local.rules" "$ETC_DIR/rules/local.rules"
  for f in white_list.rules black_list.rules; do
    [ -e "$ETC_DIR/rules/$f" ] || touch "$ETC_DIR/rules/$f"
  done
}

main() {
  parse_args "$@"
  [ "$(id -u)" -eq 0 ] || die "must be run as root"

  if installed_version_ok; then
    log "snort $SNORT_VERSION already installed, skipping build"
  else
    rm -f "$MARKER"
    if [ "$INSTALL_DEPS" -eq 1 ]; then
      install_deps
    fi
    build_snort
  fi

  create_user
  create_dirs
  install_config

  if [ ! -f "$MARKER" ]; then
    snort_version_ok || die "installed snort is not $SNORT_VERSION"
    touch "$MARKER"
    log "installed snort $SNORT_VERSION"
  fi
}

main "$@"
