#!/bin/sh
set -eu
SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
PKG_DIR=$(dirname "$SCRIPT_DIR")
INSTALL_LOG="$PKG_DIR/log/install.log"
mkdir -p "$PKG_DIR/log"
for arch in aarch64 x86_64; do
  bin="$PKG_DIR/app/bin/port-guard-$arch"
  if [ -f "$bin" ]; then chmod 755 "$bin"; else
    printf '%s POST_INST warning: port-guard-%s missing\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$arch" >> "$INSTALL_LOG"
  fi
done
printf '%s POST_INST completed\n' "$(date '+%Y-%m-%d %H:%M:%S')" >> "$INSTALL_LOG"
