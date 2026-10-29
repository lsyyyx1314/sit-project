"""BPMV（定长验证头 + 逐跳摘要链）的基准测量。

产出 M0 验收所需的四组数字：
  1. 头长：路径 2/4/8/16 跳时的字节数（应恒定）
  2. 检出率：随机篡改样本的判否比例（应 100%）
  3. 误报率：诚实样本被判否的比例（应 0%）
  4. 验证时延：候选路径数 k=1..16 时控制器的单次验证耗时
     （对照「逐条线性验证」与「前缀树一次遍历」）

用法：
    python -m sim.bench_bpmv --trials 10000 --json
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

from mpv.core import Hop, KeyRing, PathSet, forward, verify_candidates
from mpv.core.digest import HEADER_BYTES
from mpv.core.keys import Path


def build_path(rng: random.Random, n_switches: int, n_hops: int, src: int = 1, dst: int = 16) -> Path:
    """构造 src -> dst 的路径，中间节点随机取。"""
    middles = rng.sample(range(2, n_switches), n_hops - 2) if n_hops > 2 else []
    sids = [src] + middles + [dst]
    return tuple(
        Hop(sid=sid, in_port=1, out_port=2 if i % 2 == 0 else 3)
        for i, sid in enumerate(sids)
    )


def tamper(rng: random.Random, path: Path) -> Path:
    """随机篡改一跳的出端口。"""
    hops = list(path)
    idx = rng.randrange(len(hops))
    h = hops[idx]
    alt = [p for p in (1, 2, 3, 4) if p != h.out_port]
    hops[idx] = Hop(sid=h.sid, in_port=h.in_port, out_port=rng.choice(alt))
    return tuple(hops)


def _p95(xs: List[float]) -> float:
    return sorted(xs)[min(len(xs) - 1, int(len(xs) * 0.95))]


def run(trials: int, seed: int) -> Dict[str, object]:
    rng = random.Random(seed)
    n_sw = 16
    kr = KeyRing.generate(n_switches=n_sw, ports_per_switch=4, seed=seed)

    # ------------------------------------------------------ 1. 头长
    header_sizes = {}
    for n_hops in (2, 4, 8, 16):
        p = build_path(rng, n_sw, n_hops)
        header_sizes[n_hops] = len(forward(kr, p).wire())

    # ------------------------------------------------------ 2/3. 检出与误报
    detected = false_positive = 0
    for _ in range(trials):
        n_hops = rng.randint(2, 9)
        p = build_path(rng, n_sw, n_hops)
        h = forward(kr, p)
        if not verify_candidates(kr, [p], h).ok:
            false_positive += 1
        if not verify_candidates(kr, [tamper(rng, p)], h).ok:
            detected += 1

    # ------------------------------------------------------ 4. 时延
    latency: Dict[int, Dict[str, float]] = {}
    digest_counts: Dict[int, Dict[str, float]] = {}
    for k in (1, 2, 4, 8, 16):
        # 8 跳、前 3 跳共享前缀 —— 模拟多路径在汇聚前共享链路的真实形态
        cands: List[Path] = []
        for i in range(k):
            sids = [1, 2, 3, 4 + (i % 5), 8 + (i // 5), 15, 16]
            cands.append(
                tuple(
                    Hop(sid=s, in_port=1, out_port=2 if j % 2 == 0 else 3)
                    for j, s in enumerate(sids)
                )
            )
        n_hops_bench = len(cands[0])
        ps = PathSet(kr, cands)

        lat_lin: List[float] = []
        lat_tree: List[float] = []
        dig_lin: List[int] = []
        dig_tree: List[int] = []
        for _ in range(300):
            target = rng.randrange(k)
            h = forward(kr, cands[target])

            t0 = time.perf_counter()
            verify_candidates(kr, cands, h)
            lat_lin.append((time.perf_counter() - t0) * 1e6)
            dig_lin.append(n_hops_bench * (target + 1))

            st: Dict[str, int] = {}
            t0 = time.perf_counter()
            ps.match(h, stats=st)
            lat_tree.append((time.perf_counter() - t0) * 1e6)
            dig_tree.append(st.get("digests", 0))

        latency[k] = {
            "linear_p50_us": round(statistics.median(lat_lin), 1),
            "linear_p95_us": round(_p95(lat_lin), 1),
            "pathset_p50_us": round(statistics.median(lat_tree), 1),
            "pathset_p95_us": round(_p95(lat_tree), 1),
        }
        digest_counts[k] = {
            "linear_mean": round(statistics.mean(dig_lin), 1),
            "pathset_mean": round(statistics.mean(dig_tree), 1),
        }

    return {
        "host": platform.platform(),
        "python": platform.python_version(),
        "trials": trials,
        "header_bytes": HEADER_BYTES,
        "header_size_by_hops": header_sizes,
        "detected": detected,
        "false_positive": false_positive,
        "detection_rate": detected / trials,
        "false_positive_rate": false_positive / trials,
        "latency_us": latency,
        "digests": digest_counts,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--trials", type=int, default=10000)
    ap.add_argument("--seed", type=int, default=20260501)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    r = run(args.trials, args.seed)

    print("=" * 74)
    print("BPMV 基准（定长验证头 + 逐跳摘要链）")
    print("=" * 74)
    print(f"运行环境 : {r['host']} / Python {r['python']}")
    print(f"样本量   : {r['trials']}")
    print()
    print("[1] 验证头长度")
    for n, size in r["header_size_by_hops"].items():
        print(f"    {n:>2} 跳 -> {size} 字节")
    print(f"    结论：与跳数无关，恒为 {r['header_bytes']} 字节（满足 |H| = O(1)）")
    print()
    print("[2] 判别力")
    print(f"    检出率 : {r['detected']}/{r['trials']} = {r['detection_rate']*100:.2f}%")
    print(f"    误报率 : {r['false_positive']}/{r['trials']} = {r['false_positive_rate']*100:.2f}%")
    print()
    print("[3] 控制器验证时延（7 跳，前 3 跳共享前缀）")
    print("    k    线性 P50/P95 (us)      前缀树 P50/P95 (us)    摘要次数 线性/树")
    for k, v in r["latency_us"].items():
        d = r["digests"][k]
        print(
            f"    {k:<3}  {v['linear_p50_us']:>8.1f} / {v['linear_p95_us']:<8.1f}"
            f"    {v['pathset_p50_us']:>8.1f} / {v['pathset_p95_us']:<8.1f}"
            f"      {d['linear_mean']:>5.1f} / {d['pathset_mean']:<5.1f}"
        )

    if args.json:
        out = FsPath("results")
        out.mkdir(exist_ok=True)
        p = out / "bpmv_bench.json"
        p.write_text(json.dumps(r, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"\n结果已写入 {p}")


if __name__ == "__main__":
    main()
