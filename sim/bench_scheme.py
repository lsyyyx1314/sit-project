"""MPV-2 性能与复杂度基准。

产出
----
1. 控制器验证时延：MPV-2 tag(O(1)) / MPV-2 scan(O(k)) / MPV-1 线性(O(k·n))
2. 流级压缩：包数 → 上报条目数 → 判定耗时
3. 数据平面逐跳开销
4. 头部长度对照

用法
----
    python -m sim.bench_scheme --json
"""

from __future__ import annotations

import argparse
import json
import platform
import random
import statistics
import time
from pathlib import Path as FsPath
from typing import Dict, List

from mpv.core import KeyRing, PathSet, forward as hc_forward
from mpv.core.keys import Hop, Path
from mpv.core.scheme import (
    HEADER_BYTES as M2_BYTES,
    ExpectationTable,
    FlowAccumulator,
    compression_ratio,
    forward as m2_forward,
    verify_flow,
    verify_scan,
    verify_tag,
)
from mpv.core.verify import verify_candidates

P = 0
KS = (1, 2, 4, 8, 16, 32, 64)


def _path(kr: KeyRing, i: int, n_hops: int = 7, prefix: int = 3) -> Path:
    """构造第 i 条候选路径：前 prefix 跳共享，其余按 i 的进制位分化。

    分化位用 11 进制展开，保证 i 不同则路径不同（i < 11^(n_hops-prefix-1)）。
    """
    tail = n_hops - prefix - 1
    sids = [1, 2, 3][:prefix]
    x = i
    for _ in range(tail):
        sids.append(4 + (x % 11))   # 池 4..14
        x //= 11
    sids.append(16)
    # 端口也随 i 变化，进一步降低重名概率
    return tuple(
        Hop(sid=sd, in_port=1, out_port=2 + ((i + j) % 2))
        for j, sd in enumerate(sids)
    )


def _p95(xs: List[float]) -> float:
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(len(xs) * 0.95))]


def _timeit(fn, repeat: int = 200) -> Dict[str, float]:
    xs = []
    for _ in range(repeat):
        t0 = time.perf_counter()
        fn()
        xs.append((time.perf_counter() - t0) * 1e6)
    return {"p50": round(statistics.median(xs), 2), "p95": round(_p95(xs), 2)}


def run(seed: int, n_hops: int) -> Dict[str, object]:
    rng = random.Random(seed)
    kr = KeyRing.generate(n_switches=16, ports_per_switch=4, seed=seed)

    # ---------------------------------------------------------- 1. 验证时延
    latency: Dict[int, Dict[str, Dict[str, float]]] = {}
    for k in KS:
        cands = [_path(kr, i, n_hops) for i in range(k)]
        assert len(set(cands)) == k, f"候选路径出现重复：k={k}"
        table = ExpectationTable(kr, cands)
        ps = PathSet(kr, cands)
        # 固定为最坏情况：包走最后一条候选路径 —— 线性扫描必须走完全部 k 条
        worst = k - 1
        hdrs = [m2_forward(kr, cands[worst], tag=worst) for _ in range(8)]
        hc_hdrs = [hc_forward(kr, cands[worst]) for _ in range(8)]

        row: Dict[str, Dict[str, float]] = {}
        h0, hc0 = hdrs[0], hc_hdrs[0]
        row["mpv2_tag"] = _timeit(lambda: verify_tag(table, h0), repeat=400)
        row["mpv2_scan"] = _timeit(lambda: verify_scan(table, h0), repeat=400)
        row["mpv1_linear"] = _timeit(lambda: verify_candidates(kr, cands, hc0), repeat=200)
        row["mpv1_pathset"] = _timeit(lambda: ps.match(hc0), repeat=200)
        latency[k] = row

    # ---------------------------------------------------------- 2. 流级压缩
    cands8 = [_path(kr, i, n_hops) for i in range(8)]
    table8 = ExpectationTable(kr, cands8)
    flow: Dict[int, Dict[str, object]] = {}
    for packets in (100, 1000, 10000):
        acc = FlowAccumulator()
        hdrs = [m2_forward(kr, cands8[rng.randrange(8)], tag=rng.randrange(8)) for _ in range(packets)]
        t0 = time.perf_counter()
        for h in hdrs:
            acc.add(h)
        acc_us = (time.perf_counter() - t0) * 1e6
        rep = acc.report()
        t0 = time.perf_counter()
        ok, checks = verify_flow(table8, rep)
        ver_us = (time.perf_counter() - t0) * 1e6
        flow[packets] = {
            "entries": rep.entries,
            "ok": ok,
            "checks": checks,
            "compression": round(compression_ratio(rep), 1),
            "accumulate_us_total": round(acc_us, 1),
            "accumulate_us_per_packet": round(acc_us / packets, 3),
            "verify_us": round(ver_us, 2),
            "baseline_verify_us": round(
                packets * latency[8]["mpv1_linear"]["p50"] / 1, 1
            ),
        }

    # ---------------------------------------------------------- 3. 复杂度（解析）
    ops = {
        "switch_ops_per_packet": {
            "mpv2": n_hops,          # 每跳 1 次模乘 + 1 次模加
            "mpv1": n_hops,          # 每跳 1 次 blake2b
        },
        "controller_ops_per_packet": {
            "mpv2_tag": 1,           # 1 次乘加
            "mpv2_scan": len(KS),    # k 次乘加（此处给出 k 上限）
            "mpv1_linear": None,     # k·n 次摘要，随 k 变化见延迟表
        },
    }

    return {
        "host": platform.platform(),
        "python": platform.python_version(),
        "n_hops": n_hops,
        "header_bytes": {"mpv2": M2_BYTES, "mpv1": 16},
        "latency_us": latency,
        "flow": flow,
        "ops": ops,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=20260501)
    ap.add_argument("--hops", type=int, default=7)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    r = run(args.seed, args.hops)

    print("=" * 78)
    print(f"MPV-2 性能基准（{r['n_hops']} 跳） | {r['host']}")
    print("=" * 78)
    print()
    print("表 1  控制器单次验证时延（us，P50 / P95）")
    print("| k  | MPV-2 tag | MPV-2 scan | MPV-1 线性 | MPV-1 前缀树 |")
    print("| -- | --------- | ---------- | ---------- | ------------ |")
    for k, row in r["latency_us"].items():
        print(
            f"| {k:<2} | {row['mpv2_tag']['p50']:6.2f}/{row['mpv2_tag']['p95']:<6.2f} "
            f"| {row['mpv2_scan']['p50']:6.2f}/{row['mpv2_scan']['p95']:<6.2f} "
            f"| {row['mpv1_linear']['p50']:6.2f}/{row['mpv1_linear']['p95']:<6.2f} "
            f"| {row['mpv1_pathset']['p50']:6.2f}/{row['mpv1_pathset']['p95']:<6.2f} |"
        )
    print()
    print("表 2  流级压缩（8 条候选路径）")
    print("| 包数 | 上报条目 | 压缩比 | 判定耗时(us) | 逐包基线(us) | 加速 |")
    print("| ---- | -------- | ------ | ------------ | ------------ | ---- |")
    for packets, f in r["flow"].items():
        speed = f["baseline_verify_us"] / f["verify_us"] if f["verify_us"] else 0
        print(
            f"| {packets:<4} | {f['entries']:>8} | {f['compression']:>5.1f}× "
            f"| {f['verify_us']:>12.1f} | {f['baseline_verify_us']:>12.1f} | {speed:>5.0f}× |"
        )
    print()
    print("表 3  头部长度")
    for k, v in r["header_bytes"].items():
        print(f"  {k:<6} {v} 字节")

    if args.json:
        out = FsPath("results")
        out.mkdir(exist_ok=True)
        p = out / "scheme_bench.json"
        p.write_text(json.dumps(r, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"\n结果已写入 {p}")


if __name__ == "__main__":
    main()
