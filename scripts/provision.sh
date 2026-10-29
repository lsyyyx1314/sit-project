#!/usr/bin/env bash
# =============================================================================
#  SIT 开发环境一键供给  (Ubuntu 24.04 / noble)
#  用法:  bash scripts/provision.sh
#         SKIP_APT=1 bash scripts/provision.sh   # 仅建 venv 与装 pip 依赖
#  幂等：可重复执行
# =============================================================================
set -euo pipefail

# sudo 调用方式：默认 "sudo"，在无 tty 的自动化环境中可传 SUDO="sudo -A"
SUDO="${SUDO:-sudo}"

PROJ="${PROJ:-$HOME/SIT}"
PIP_MIRROR="${PIP_MIRROR:-https://pypi.tuna.tsinghua.edu.cn/simple}"
APT_PKGS=(mininet openvswitch-switch python3-venv python3-dev
          iperf3 net-tools tcpdump build-essential)
PIP_PKGS=(os-ken networkx scapy matplotlib pandas numpy pytest)

mkdir -p "$PROJ/logs"
LOG="$PROJ/logs/provision-$(date +%Y%m%d-%H%M%S).log"
exec > >(tee -a "$LOG") 2>&1

say() { printf '\n\033[1;36m[%s]\033[0m %s\n' "$(date +%H:%M:%S)" "$*"; }
warn() { printf '\033[1;33m[WARN]\033[0m %s\n' "$*"; }

# ---------------------------------------------------------------- 0. 预检
say "0/6 环境预检"
. /etc/os-release
echo "  OS      : ${PRETTY_NAME:-unknown}"
echo "  Kernel  : $(uname -r)"
echo "  CPU     : $(nproc) 核"
echo "  Memory  : $(free -h | awk 'NR==2{print $2}')"
echo "  Disk    : $(df -h / | awk 'NR==2{print $4" 可用 / "$5" 已用"}')"

AVAIL_MB=$(df -m / | awk 'NR==2{print $4}')
if [ "$AVAIL_MB" -lt 1500 ]; then
  warn "根分区可用 ${AVAIL_MB}MB (<1.5GB)，Mininet/OVS 安装可能失败"
fi

# ---------------------------------------------------------------- 1. pip 镜像
say "1/6 配置 pip 镜像 -> $PIP_MIRROR"
mkdir -p "$HOME/.config/pip"
PIP_HOST=$(echo "$PIP_MIRROR" | awk -F/ '{print $3}')
cat > "$HOME/.config/pip/pip.conf" <<EOF
[global]
index-url = $PIP_MIRROR
trusted-host = $PIP_HOST
timeout = 60
EOF
echo "  -> ~/.config/pip/pip.conf 已写入 (host=$PIP_HOST)"

# ---------------------------------------------------------------- 2. 系统包
if [ "${SKIP_APT:-0}" = "1" ]; then
  say "2/6 跳过 apt 安装 (SKIP_APT=1)"
else
  say "2/6 更新索引并安装系统包"
  $SUDO apt-get update -y
  echo "  -> 安装: ${APT_PKGS[*]}"
  DEBIAN_FRONTEND=noninteractive $SUDO -E apt-get install -y --no-install-recommends "${APT_PKGS[@]}"
fi

# ---------------------------------------------------------------- 3. 版本核对
say "3/6 工具版本核对"
for b in mn ovs-vsctl ovs-ofctl iperf3; do
  printf '  %-10s ' "$b"
  if command -v "$b" >/dev/null 2>&1; then
    "$b" --version 2>&1 | head -1
  else
    echo "未安装"
  fi
done

# ---------------------------------------------------------------- 4. venv
say "4/6 创建虚拟环境 $PROJ/.venv"
if [ ! -d "$PROJ/.venv" ]; then
  python3 -m venv "$PROJ/.venv"
fi
# shellcheck disable=SC1091
. "$PROJ/.venv/bin/activate"
echo "  python: $(python -V 2>&1)  ->  $(command -v python)"
python -m pip install -q --upgrade pip wheel

echo "  -> 安装 pip 依赖: ${PIP_PKGS[*]}"
python -m pip install "${PIP_PKGS[@]}"

# ---------------------------------------------------------------- 5. 冒烟
say "5/6 冒烟测试"
$SUDO modprobe openvswitch 2>/dev/null || warn "modprobe openvswitch 失败"
$SUDO systemctl enable --now openvswitch-switch 2>/dev/null || warn "openvswitch-switch 服务启动异常"

if $SUDO ovs-vsctl show >/tmp/ovs_show.txt 2>&1; then
  echo "  OVS: ok"
else
  warn "ovs-vsctl 异常，见 /tmp/ovs_show.txt"
  cat /tmp/ovs_show.txt || true
fi

echo "  -> Mininet pingall"
if $SUDO mn --test pingall >/tmp/mn_smoke.log 2>&1; then
  echo "  Mininet: 通过"
  grep -E 'Results' /tmp/mn_smoke.log | head -2 || true
else
  warn "Mininet 冒烟未通过，见 /tmp/mn_smoke.log"
  tail -15 /tmp/mn_smoke.log || true
fi

# ---------------------------------------------------------------- 6. 锁版本
say "6/6 写版本锁"
LOCK="$PROJ/docs/env.lock.txt"
mkdir -p "$PROJ/docs"
{
  echo "# 环境版本锁  生成于 $(date '+%Y-%m-%d %H:%M:%S')"
  echo "os: $(. /etc/os-release; echo "$PRETTY_NAME")"
  echo "kernel: $(uname -r)"
  echo "cpu_cores: $(nproc)"
  echo "memory: $(free -h | awk 'NR==2{print $2}')"
  echo ""
  echo "## python"
  python -m pip freeze | sed 's/^/pip: /'
  echo ""
  echo "## apt"
  for b in mn ovs-vsctl iperf3; do
    command -v "$b" >/dev/null 2>&1 && echo "apt: $($b --version 2>&1 | head -1)" || echo "apt: $b MISSING"
  done
} > "$LOCK"
echo "  -> $LOCK"

say "供给完成。日志: $LOG"
echo ""
echo "下一步:"
echo "  . $PROJ/.venv/bin/activate"
echo "  python -m pytest tests/ -q"
