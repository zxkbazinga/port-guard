#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
PKG_DIR=$(dirname "$SCRIPT_DIR")
APP_DIR="$PKG_DIR/app"
BIN_DIR="$APP_DIR/bin"
DATA_DIR="$APP_DIR/data"
PIDFILE="$APP_DIR/cache/port-guard.pid"
RUN_LOG="$PKG_DIR/log/run.log"

log() {
  mkdir -p "$PKG_DIR/log"
  printf '%s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >> "$RUN_LOG"
}

# 逐行解析 KEY=VALUE，避免 source 时特殊字符造成注入
load_env_file() {
  [ -f "$1" ] || return 0
  while IFS= read -r line || [ -n "$line" ]; do
    line=${line%"$(printf '\r')"}
    case "$line" in '' | '#'*) continue ;; *=*) ;; *) continue ;; esac
    key=${line%%=*}
    value=${line#*=}
    case "$key" in '' | *[!A-Za-z0-9_]*) continue ;; esac
    export "$key=$value"
  done < "$1"
}

select_binary() {
  machine=$(uname -m 2>/dev/null || true)
  case "$machine" in
    aarch64 | arm64) bin="$BIN_DIR/port-guard-aarch64" ;;
    x86_64 | amd64)  bin="$BIN_DIR/port-guard-x86_64" ;;
    *) log "Unsupported architecture: ${machine:-unknown}"; exit 1 ;;
  esac
  if [ ! -x "$bin" ]; then
    log "Binary missing or not executable: $bin"
    exit 1
  fi
  printf '%s' "$bin"
}

mkdir -p "$DATA_DIR" "$APP_DIR/cache" "$PKG_DIR/log"

# 先加载默认值，再用爱快写入的 environment 覆盖
load_env_file "$APP_DIR/.env"
load_env_file "$APP_DIR/environment"

: "${APP_PORT_WEB:=8080}"
: "${PG_IKUAI_HOST:=127.0.0.1}"
: "${PG_IKUAI_PASSWORD:=}"

BIN=$(select_binary)

# 已在运行则不重复启动
if [ -f "$PIDFILE" ]; then
  OLD_PID=$(cat "$PIDFILE" 2>/dev/null || true)
  if [ -n "$OLD_PID" ] && kill -0 "$OLD_PID" 2>/dev/null; then
    log "port-guard already running, pid=$OLD_PID"
    exit 0
  fi
  rm -f "$PIDFILE"
fi

# 导出给 Go 程序读取的配置（环境变量方式）
export PG_IKUAI_HOST PG_IKUAI_PORT PG_IKUAI_USERNAME PG_IKUAI_PASSWORD
export PG_BAN_MINUTES PG_BAN_MODE PG_DETECTION_ENABLED
export PG_SNIFFER_ENABLED PG_SNIFFER_IFACE
export PG_SYSLOG_ENABLED PG_SYSLOG_PORT
export PG_CONN_POLL_ENABLED PG_PORT_REFRESH_ENABLED
export PG_WINDOW_SECONDS PG_SYN_FLOOD_THRESHOLD PG_PORT_SCAN_THRESHOLD
export PG_CONN_RATE_THRESHOLD PG_UDP_FLOOD_THRESHOLD
export PG_WHITELIST PG_WEB_USERNAME PG_IGNORE_PRIVATE_IPS

log "Starting port-guard on :${APP_PORT_WEB} (data=$DATA_DIR)"
"$BIN" --listen ":${APP_PORT_WEB}" --data "$DATA_DIR" --log-level info >> "$RUN_LOG" 2>&1 &
PID=$!
printf '%s\n' "$PID" > "$PIDFILE"

sleep 1
if kill -0 "$PID" 2>/dev/null; then
  log "port-guard started, pid=$PID"
  exit 0
fi
rm -f "$PIDFILE"
log "port-guard failed to start, see $RUN_LOG"
exit 1
