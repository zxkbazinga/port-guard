#!/bin/sh
# 把编译好的静态二进制打包成爱快 v4 原生应用 .ipkg
# 用法: ./scripts/build-ipkg.sh <version> <amd64_binary> <arm64_binary> [output_dir]
set -eu

VERSION=${1:?用法: build-ipkg.sh <version> <amd64_binary> <arm64_binary> [output_dir]}
BIN_AMD64=${2:?缺少 amd64 二进制路径}
BIN_ARM64=${3:?缺少 arm64 二进制路径}
OUTPUT_DIR=${4:-ikuai-support/dist}

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
PROJECT_ROOT=$(dirname "$SCRIPT_DIR")
SUPPORT_DIR="$PROJECT_ROOT/ikuai-support"
PACKAGE_SRC="$SUPPORT_DIR/port-guard"
STAGING_ROOT="$SUPPORT_DIR/.staging"
STAGING_PKG="$STAGING_ROOT/port-guard"

rm -rf "$STAGING_ROOT"
mkdir -p "$STAGING_PKG" "$OUTPUT_DIR"
cp -R "$PACKAGE_SRC"/. "$STAGING_PKG"/
find "$STAGING_PKG" -name .gitkeep -delete
rm -f "$STAGING_PKG/ui/ico/README.md"

# Git 不跟踪空目录，CI 干净 checkout 时这些运行时目录可能不存在
mkdir -p "$STAGING_PKG/app/bin" "$STAGING_PKG/app/data" \
  "$STAGING_PKG/app/cache" "$STAGING_PKG/app/config" \
  "$STAGING_PKG/log" "$STAGING_PKG/ui/ico"

# 同步 manifest 版本号
sed -e "s/\"version\"[[:space:]]*:[[:space:]]*\"[^\"]*\"/\"version\": \"$VERSION\"/" \
  "$PACKAGE_SRC/manifest.json" > "$STAGING_PKG/manifest.json"

# 注入双架构二进制
cp "$BIN_AMD64" "$STAGING_PKG/app/bin/port-guard-x86_64"
cp "$BIN_ARM64" "$STAGING_PKG/app/bin/port-guard-aarch64"
chmod 755 "$STAGING_PKG"/app/bin/port-guard-*
chmod 755 "$STAGING_PKG"/scripts/*.sh

OUTPUT="$OUTPUT_DIR/port-guard-$VERSION-ikuai.ipkg"
(cd "$STAGING_ROOT" && tar -czf "$OUTPUT" port-guard)
echo "$OUTPUT"
