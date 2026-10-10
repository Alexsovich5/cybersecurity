#!/bin/bash
# Build and install OSSEC HIDS 2.9.4 in local mode from a checksum-verified
# source tarball on CentOS 7, then install ossec.conf and the local rules.
#
# Usage: deploy_ossec.sh [--src-dir DIR] [--config-dir DIR] [--no-deps]
#   --src-dir DIR     where the tarball is downloaded and built (default /usr/local/src/ossec-build)
#   --config-dir DIR  directory holding ossec.conf and ossec_local_rules.xml
#                     (default: the repository's config directory)
#   --no-deps         do not install the yum build dependencies
#
# The build is skipped when /etc/ossec-init.conf already reports v2.9.4.
# ossec.conf and local_rules.xml are reconciled on every run.
set -euo pipefail

OSSEC_VERSION=2.9.4
OSSEC_SHA256=3a8df000cd2cd3430f0d9a41034df025951579e15dea8e57ad7e7d0291fec7b6
OSSEC_URL="https://github.com/ossec/ossec-hids/archive/$OSSEC_VERSION.tar.gz"

BUILD_DEPS=(gcc-4.8.5-28.el7 make-3.82-23.el7 openssl-devel-1.0.2k-12.el7)

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
SRC_DIR=/usr/local/src/ossec-build
CONFIG_DIR="$SCRIPT_DIR/../config"
INSTALL_DEPS=1

OSSEC_DIR=/var/ossec
INIT_CONF=/etc/ossec-init.conf

usage() {
  sed -n '5,9p' "$0" | sed 's/^# \{0,1\}//'
}

log() {
  echo "deploy_ossec: $*"
}

die() {
  echo "deploy_ossec: $*" >&2
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
      --src-dir) [ $# -ge 2 ] || die "--src-dir needs a value"; SRC_DIR=$2; shift 2 ;;
      --config-dir) [ $# -ge 2 ] || die "--config-dir needs a value"; CONFIG_DIR=$2; shift 2 ;;
      --no-deps) INSTALL_DEPS=0; shift ;;
      -h|--help) usage; exit 0 ;;
      *) usage >&2; die "unknown option: $1" ;;
    esac
  done
}

installed_version_ok() {
  [ -f "$INIT_CONF" ] && grep -q "^VERSION=\"v$OSSEC_VERSION\"" "$INIT_CONF"
}

install_deps() {
  log "installing build dependencies"
  retry yum install -y "${BUILD_DEPS[@]}" || die "yum install of build dependencies failed"
}

fetch() {
  local file=$1
  if [ -f "$file" ] && echo "$OSSEC_SHA256  $file" | sha256sum -c --quiet - >/dev/null 2>&1; then
    return 0
  fi
  log "downloading ossec-hids $OSSEC_VERSION"
  retry curl -fsSL -o "$file" "$OSSEC_URL" || die "download of ossec-hids failed"
  echo "$OSSEC_SHA256  $file" | sha256sum -c --quiet - || die "checksum mismatch for ossec-hids"
}

# Answers for install.sh, so it runs without prompting.
write_preloaded_vars() {
  cat > "$1/etc/preloaded-vars.conf" <<'VARS'
USER_LANGUAGE="en"
USER_NO_STOP="y"
USER_INSTALL_TYPE="local"
USER_DIR="/var/ossec"
USER_ENABLE_EMAIL="n"
USER_ENABLE_ACTIVE_RESPONSE="n"
USER_ENABLE_SYSCHECK="y"
USER_ENABLE_ROOTCHECK="y"
USER_UPDATE_RULES="y"
VARS
}

build_ossec() {
  local tree="$SRC_DIR/ossec-hids-$OSSEC_VERSION"
  mkdir -p "$SRC_DIR"
  fetch "$SRC_DIR/ossec-hids-$OSSEC_VERSION.tar.gz"
  rm -rf "$tree"
  tar -xzf "$SRC_DIR/ossec-hids-$OSSEC_VERSION.tar.gz" -C "$SRC_DIR"
  write_preloaded_vars "$tree"
  log "building and installing ossec-hids $OSSEC_VERSION (local)"
  (cd "$tree" && ./install.sh </dev/null)
  rm -rf "$tree"
}

# install_file SRC DEST: copies only when the content differs, owned root:ossec.
install_file() {
  if ! cmp -s "$1" "$2"; then
    install -m 0440 -o root -g ossec "$1" "$2"
    log "installed $2"
  fi
}

install_config() {
  [ -f "$CONFIG_DIR/ossec.conf" ] || die "missing $CONFIG_DIR/ossec.conf"
  [ -f "$CONFIG_DIR/ossec_local_rules.xml" ] || die "missing $CONFIG_DIR/ossec_local_rules.xml"
  install_file "$CONFIG_DIR/ossec.conf" "$OSSEC_DIR/etc/ossec.conf"
  install_file "$CONFIG_DIR/ossec_local_rules.xml" "$OSSEC_DIR/rules/local_rules.xml"
}

main() {
  parse_args "$@"
  [ "$(id -u)" -eq 0 ] || die "must be run as root"

  if installed_version_ok; then
    log "ossec-hids $OSSEC_VERSION already installed, skipping build"
  else
    if [ "$INSTALL_DEPS" -eq 1 ]; then
      install_deps
    fi
    build_ossec
    installed_version_ok || die "install did not record v$OSSEC_VERSION in $INIT_CONF"
  fi

  install_config
}

main "$@"
