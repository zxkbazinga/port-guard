#!/bin/sh
set -eu
SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
PKG_DIR=$(dirname "$SCRIPT_DIR")
mkdir -p "$PKG_DIR/log"
rm -f "$PKG_DIR/app/cache/port-guard.pid"
printf '%s POST_UNINST completed\n' "$(date '+%Y-%m-%d %H:%M:%S')" >> "$PKG_DIR/log/install.log"
