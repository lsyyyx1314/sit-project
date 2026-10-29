#!/usr/bin/env bash
# MPV-2 端到端验证（C++ 实现，无 Python 依赖）
#
# 拓扑：
#     h1 --- s1 --- s2 --- s4 --- h2
#              \            /
#               +--- s3 ----+
#
# 两轮：
#   R1 正常     转发表与候选路径一致 → 双向全部通过
#   R2 标签错配 s1 的 tag=0 改走 P1 分支，s3/s4 的 tag=0 同步改，
#               使错标路径在数据面自洽 → 正向全部失败且可定位
#
# 用法： sudo bash cpp/scripts/e2e.sh
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="$ROOT/build"
WORK="${WORK:-/tmp/mpv_cpp_e2e}"
SEED=20260501
H1MAC=00:00:00:00:00:01
H2MAC=00:00:00:00:00:02
SW=(s1 s2 s3 s4)

log() { printf '\n\033[1;36m== %s ==\033[0m\n' "$*"; }
die() { printf '\033[1;31m[FAIL]\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "需要 root：sudo bash cpp/scripts/e2e.sh"

# ---------------------------------------------------------------- 构建
log "构建"
make -C "$ROOT" all -s || die "编译失败"
[ -x "$BUILD/vswitch" ] || die "缺少 build/vswitch"

rm -rf "$WORK"; mkdir -p "$WORK"

# ---------------------------------------------------------------- 拓扑
cleanup() {
  for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null; done
  sleep 0.2
  for ns in h1 h2; do ip netns del "$ns" 2>/dev/null; done
  for i in "${IFACES[@]:-}"; do ip link del "$i" 2>/dev/null; done
}
trap cleanup EXIT

setup_topo() {
  cleanup
  PIDS=(); IFACES=()
  ip netns add h1; ip netns add h2
  # 关掉 IPv6，避免 ND 报文混进来干扰统计
  for ns in h1 h2; do ip netns exec "$ns" sysctl -qw net.ipv6.conf.all.disable_ipv6=1; done

  # 主机侧 veth 移入 netns，交换机侧留在根命名空间
  veth() { # $1=host端 $2=switch端 [$3=netns]
    ip link add "$1" type veth peer name "$2" || die "建链 $1-$2 失败"
    IFACES+=("$2")
    ip link set "$2" up
    if [ -n "${3:-}" ]; then
      ip link set "$1" netns "$3"
      ip netns exec "$3" ip link set "$1" up
    else
      IFACES+=("$1")
      ip link set "$1" up   # 交换机互联：两端都要 up，否则 sendto 报 Network is down
    fi
  }

  veth h1e s1p1 h1
  veth s1p2 s2p1
  veth s1p3 s3p1
  veth s2p2 s4p1
  veth s3p2 s4p2
  veth h2e s4p3 h2

  ip netns exec h1 ip link set h1e address "$H1MAC"
  ip netns exec h2 ip link set h2e address "$H2MAC"
  ip netns exec h1 ip addr add 10.0.0.1/24 dev h1e
  ip netns exec h2 ip addr add 10.0.0.2/24 dev h2e
  ip netns exec h1 ip link set lo up
  ip netns exec h2 ip link set lo up
  ip netns exec h1 ip neigh replace 10.0.0.2 lladdr "$H2MAC" dev h1e
  ip netns exec h2 ip neigh replace 10.0.0.1 lladdr "$H1MAC" dev h2e
}

# ---------------------------------------------------------------- 转发表
write_tables() { # $1 = normal|tamper
  local mode="$1"

  # 正向 dst=H2
  cat > "$WORK/s1.tbl" <<EOF
$H2MAC 0 $([ "$mode" = tamper ] && echo 3 || echo 2) 1 0 1
$H2MAC 1 3 1 0 1
$H1MAC 0 1 3 1 2
$H1MAC 1 1 3 1 3
EOF
  cat > "$WORK/s2.tbl" <<EOF
$H2MAC 0 2 2 0 1
$H1MAC 0 1 2 0 2
EOF
  if [ "$mode" = tamper ]; then
    cat > "$WORK/s3.tbl" <<EOF
$H2MAC 0 2 2 0 1
$H2MAC 1 2 2 0 1
$H1MAC 1 1 2 0 2
EOF
    cat > "$WORK/s4.tbl" <<EOF
$H2MAC 0 3 3 1 2
$H2MAC 1 3 3 1 2
$H1MAC 0 1 1 0 3
$H1MAC 1 2 1 0 3
EOF
  else
    cat > "$WORK/s3.tbl" <<EOF
$H2MAC 1 2 2 0 1
$H1MAC 1 1 2 0 2
EOF
    cat > "$WORK/s4.tbl" <<EOF
$H2MAC 0 3 3 1 1
$H2MAC 1 3 3 1 2
$H1MAC 0 1 1 0 3
$H1MAC 1 2 1 0 3
EOF
  fi
}

write_cand() {
  cat > "$WORK/cand.txt" <<EOF
DIR $H2MAC 2
PATH 1:1:2 2:1:2 4:1:3
PATH 1:1:3 3:1:2 4:2:3
DIR $H1MAC 2
PATH 4:3:1 2:2:1 1:2:1
PATH 4:3:2 3:2:1 1:3:1
EOF
}

start_switches() {
  PIDS=()
  "$BUILD/vswitch" --sid 1 --seed $SEED --table "$WORK/s1.tbl" \
    --report "$WORK/report.txt" --paths 2 --force-tag 0 \
    --port 1:s1p1 --port 2:s1p2 --port 3:s1p3 &
  PIDS+=($!)
  "$BUILD/vswitch" --sid 2 --seed $SEED --table "$WORK/s2.tbl" \
    --report "$WORK/report.txt" --paths 2 --force-tag 0 \
    --port 1:s2p1 --port 2:s2p2 &
  PIDS+=($!)
  "$BUILD/vswitch" --sid 3 --seed $SEED --table "$WORK/s3.tbl" \
    --report "$WORK/report.txt" --paths 2 --force-tag 0 \
    --port 1:s3p1 --port 2:s3p2 &
  PIDS+=($!)
  "$BUILD/vswitch" --sid 4 --seed $SEED --table "$WORK/s4.tbl" \
    --report "$WORK/report.txt" --paths 2 --force-tag 0 \
    --port 1:s4p1 --port 2:s4p2 --port 3:s4p3 &
  PIDS+=($!)
}

run_round() { # $1=名称 $2=normal|tamper
  local name="$1" mode="$2"
  log "$name"
  : > "$WORK/report.txt"
  write_tables "$mode"
  setup_topo
  start_switches
  sleep 0.8

  ip netns exec h1 ping -c 20 -i 0.05 -W 1 10.0.0.2 >/dev/null 2>&1 || true
  sleep 0.5

  for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done
  wait 2>/dev/null || true
  PIDS=()

  "$BUILD/verify_reports" --cand "$WORK/cand.txt" --report "$WORK/report.txt" --seed $SEED
  local rc=$?
  echo "    (上报 $(wc -l < "$WORK/report.txt") 条)"
  return $rc
}

# ---------------------------------------------------------------- 主流程
printf '================================================================\n'
printf 'MPV-2 端到端验证 · C++ 软件虚拟交换机 4 台 · 双向双路径\n'
printf '================================================================\n'

write_cand
run_round "R1 正常转发" normal
R1=$?
run_round "R2 标签错配" tamper
R2=$?

echo
if [ "$R1" -ne 0 ]; then
  die "R1 未通过（正常转发不应有失败）"
fi
if [ "$R2" -eq 0 ]; then
  die "R2 未检出（故障注入后应全部失败）"
fi
echo "结论：R1 全通、R2 全检出并定位 —— 端到端验证成立"
