#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
PKG_DIR=$(dirname "$SCRIPT_DIR")
PIDFILE="$PKG_DIR/app/cache/port-guard.pid"
RUN_LOG="$PKG_DIR/log/run.log"

log() {
  mkdir -p "$PKG_DIR/log"
  printf '%s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >> "$RUN_LOG"
}

if [ ! -f "$PIDFILE" ]; then
  log "No pidfile found, nothing to stop"
  exit 0
fi

PID=$(cat "$PIDFILE" 2>/dev/null || true)
if [ -n "$PID" ] && kill -0 "$PID" 2>/dev/null; then
  kill "$PID" 2>/dev/null || true
  # 等待最多 5 秒优雅退出
  i=0
  while [ "$i" -lt 10 ] && kill -0 "$PID" 2>/dev/null; do
    sleep 0.5
    i=$((i + 1))
  done
  if kill -0 "$PID" 2>/dev/null; then
    kill -9 "$PID" 2>/dev/null || true
  fi
  log "port-guard stopped, pid=$PID"
else
  log "Process $PID not running"
fi
rm -f "$PIDFILE"
exit 0
