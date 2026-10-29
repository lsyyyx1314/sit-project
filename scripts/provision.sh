#!/usr/bin/env bash
# SIT 项目环境供给（C++ 实现，Ubuntu 24.04）
#
# 依赖极简：g++ >= 11、make、iproute2。不装 Mininet / OVS / Python 运行时。
#
# 用法： bash scripts/provision.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SUDO="${SUDO:-sudo}"

say() { printf '\n\033[1;36m[%s]\033[0m %s\n' "$(date +%H:%M:%S)" "$*"; }
die() { printf '\033[1;31m[FAIL]\033[0m %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------- 预检
say "0/4 环境预检"
. /etc/os-release
echo "  OS     : ${PRETTY_NAME:-unknown}"
echo "  Kernel : $(uname -r)"
echo "  CPU    : $(nproc) 核"
echo "  Disk   : $(df -h / | awk 'NR==2{print $4" 可用 / "$5" 已用"}')"

# ---------------------------------------------------------------- 工具链
say "1/4 安装工具链"
if ! command -v g++ >/dev/null 2>&1; then
  $SUDO apt-get update -y
  DEBIAN_FRONTEND=noninteractive $SUDO -E apt-get install -y --no-install-recommends \
    g++ make binutils iproute2
fi
GXX_VER=$(g++ -dumpversion | cut -d. -f1)
echo "  g++    : $(g++ --version | head -1)"
echo "  make   : $(make --version | head -1)"
[ "$GXX_VER" -ge 11 ] || die "需要 g++ >= 11（当前 $GXX_VER），__int128 与 C++17 依赖"

# ---------------------------------------------------------------- 编译
say "2/4 编译"
make -C "$ROOT/cpp" all
ls -1 "$ROOT/cpp/build"

# ---------------------------------------------------------------- 测试
say "3/4 单元测试（含黄金向量交叉校验）"
make -C "$ROOT/cpp" test

# ---------------------------------------------------------------- 摘要
say "4/4 基准摘要"
"$ROOT/cpp/build/bench" --trials 500 | sed -n '1,18p'

say "供给完成"
echo "  编译产物 : $ROOT/cpp/build/"
echo "  端到端   : sudo make e2e"
