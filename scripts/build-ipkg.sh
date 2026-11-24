#!/bin/sh
# 把爱快 Docker 应用目录打包成 .ipkg
# 用法: ./scripts/build-ipkg.sh <version> <amd64_binary> <arm64_binary> [output_dir]
# 说明: 独立二进制由 Release 单独上传；ipkg 只引用 GHCR 镜像，不再内嵌二进制。
set -eu

VERSION=${1:?用法: build-ipkg.sh <version> <amd64_binary> <arm64_binary> [output_dir]}
BIN_AMD64=${2:?缺少 amd64 二进制路径}
BIN_ARM64=${3:?缺少 arm64 二进制路径}
OUTPUT_DIR=${4:-ikuai-support/dist}

# 保留参数兼容性（Release workflow 仍会传入），但包内不再使用
: "$BIN_AMD64" "$BIN_ARM64"

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
PROJECT_ROOT=$(dirname "$SCRIPT_DIR")
SUPPORT_DIR="$PROJECT_ROOT/ikuai-support"
PACKAGE_SRC="$SUPPORT_DIR/port-guard"
STAGING_ROOT="$SUPPORT_DIR/.staging"
STAGING_PKG="$STAGING_ROOT/port-guard"

rm -rf "$STAGING_ROOT"
mkdir -p "$STAGING_PKG" "$OUTPUT_DIR"
# tar 在子 shell 中会 cd 到 staging 目录，输出路径必须先转成绝对路径
OUTPUT_DIR=$(CDPATH= cd "$OUTPUT_DIR" && pwd)

cp -R "$PACKAGE_SRC"/. "$STAGING_PKG"/
find "$STAGING_PKG" -name .gitkeep -delete
rm -f "$STAGING_PKG/ui/ico/README.md"

# Git 不跟踪空目录，CI 干净 checkout 时这些运行时目录可能不存在
mkdir -p "$STAGING_PKG/app/data" "$STAGING_PKG/app/config" \
  "$STAGING_PKG/app/cache" "$STAGING_PKG/log" "$STAGING_PKG/ui/ico"

# 同步版本号与 GHCR 镜像标签
IMAGE="ghcr.io/zxkbazinga/port-guard:$VERSION"
sed -e "s/\"version\"[[:space:]]*:[[:space:]]*\"[^\"]*\"/\"version\": \"$VERSION\"/" \
    -e "s#\"image\"[[:space:]]*:[[:space:]]*\"[^\"]*\"#\"image\": \"$IMAGE\"#" \
    "$PACKAGE_SRC/manifest.json" > "$STAGING_PKG/manifest.json"
sed "s|image: ghcr.io/zxkbazinga/port-guard:.*|image: $IMAGE|" \
    "$PACKAGE_SRC/app/docker-compose.yaml" > "$STAGING_PKG/app/docker-compose.yaml.tmp"
mv "$STAGING_PKG/app/docker-compose.yaml.tmp" "$STAGING_PKG/app/docker-compose.yaml"

OUTPUT="$OUTPUT_DIR/port-guard-$VERSION-ikuai.ipkg"
(cd "$STAGING_ROOT" && tar -czf "$OUTPUT" port-guard)
echo "$OUTPUT"
