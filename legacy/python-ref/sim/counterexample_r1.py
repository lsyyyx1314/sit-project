"""R1 反例：证明申报书式 (5)(6) 在当前写法下退化为恒等式。

用法：
    python -m sim.counterexample_r1            # 表格输出
    python -m sim.counterexample_r1 --json     # 额外落盘 results/r1.json

结论（可复现）：
    1. 由于 w = lcm(p1-1, p2-1) 是 p2-1 的整数倍，且 gcd(g, p2) = 1，
       由欧拉定理 g^(p2-1) ≡ 1 (mod p2)，故 g^w ≡ 1 (mod p2)。
    2. 于是 f_s^w = (g^(Σ s_i r_i))^w ≡ 1，判定式左端 g^(w·s_m) 亦 ≡ 1。
       两端恒等，**任何路径（含篡改路径）都被判定为合法**。
    3. 流级式 (11)(12) 反过来出现假阴性：诚实流也大概率判不过。
"""

from __future__ import annotations

import argparse
import json
import math
import random
from pathlib import Path
from typing import Dict, List

from mpv.core import KeyRing
from mpv.core import proposal as P


def run(bits: int, trials: int, seed: int) -> Dict[str, object]:
    rng = random.Random(seed)
    par = P.make_params(bits=bits, seed=seed)

    # ---------------------------------------------------------- 恒等式核对
    g_w = pow(par.g, par.w, par.p2)
    euler_identity = g_w == 1 % par.p2

    # ---------------------------------------------------------- 包级判定
    accept_legit = 0
    accept_forged = 0
    fs_pow_w_is_one = 0

    for _ in range(trials):
        n_hops = rng.randint(2, 8)
        s_seq = [rng.randrange(1, 1 << 16) for _ in range(n_hops)]
        k_seq = [rng.randrange(1, 1 << 16) for _ in range(n_hops)]
        r_seq = [rng.randrange(1, 1 << 16) for _ in range(n_hops)]

        h = P.forward(par, s_seq, k_seq, r_seq)
        s_m = sum(s_seq)
        k_m = sum(k_seq)

        if P.verify_packet(par, s_m, k_m, h):
            accept_legit += 1
        if pow(h[0], par.w, par.p2) == 1:
            fs_pow_w_is_one += 1

        # 伪造：换一组完全不同的交换机与端口，验证时仍用「合法路径」的汇总值
        s_bad = [rng.randrange(1, 1 << 16) for _ in range(n_hops)]
        k_bad = [rng.randrange(1, 1 << 16) for _ in range(n_hops)]
        h_bad = P.forward(par, s_bad, k_bad, r_seq)
        if P.verify_packet(par, s_m, k_m, h_bad):
            accept_forged += 1

    # ---------------------------------------------------------- 流级判定
    accept_flow = 0
    for _ in range(trials):
        n_pkts = rng.randint(2, 16)
        headers: List[tuple] = []
        r_seq: List[int] = []
        s_m = k_m = 0
        for _ in range(n_pkts):
            n_hops = rng.randint(2, 6)
            s_seq = [rng.randrange(1, 1 << 16) for _ in range(n_hops)]
            k_seq = [rng.randrange(1, 1 << 16) for _ in range(n_hops)]
            r_seq_pkt = [rng.randrange(1, 1 << 16) for _ in range(n_hops)]
            headers.append(P.forward(par, s_seq, k_seq, r_seq_pkt))
            r_seq.append(r_seq_pkt[0])
            s_m += sum(s_seq)
            k_m += sum(k_seq)
        vi_s, vi_k, vi_rs, vi_rk = P.accumulate(par, headers, r_seq)
        if P.verify_flow(par, s_m, k_m, vi_s, vi_k, vi_rs, vi_rk):
            accept_flow += 1

    return {
        "bits": bits,
        "p1": par.p1,
        "p2": par.p2,
        "g": par.g,
        "w": par.w,
        "w_is_multiple_of_p2_minus_1": par.w % (par.p2 - 1) == 0,
        "gcd_g_p2": math.gcd(par.g, par.p2),
        "g_pow_w_is_one": euler_identity,
        "trials": trials,
        "packet_accept_legit": accept_legit,
        "packet_accept_forged": accept_forged,
        "forged_accept_rate": accept_forged / trials,
        "fs_pow_w_equals_one_rate": fs_pow_w_is_one / trials,
        "flow_accept_honest": accept_flow,
        "flow_accept_rate": accept_flow / trials,
    }


def _fmt_row(r: Dict[str, object]) -> str:
    return (
        f"| {r['bits']:>4} | {str(r['w_is_multiple_of_p2_minus_1']):>5} | "
        f"{str(r['g_pow_w_is_one']):>5} | {r['packet_accept_legit']}/{r['trials']} | "
        f"{r['packet_accept_forged']}/{r['trials']} | "
        f"{r['forged_accept_rate']*100:5.1f}% | {r['flow_accept_rate']*100:5.1f}% |"
    )


def main() -> None:
    ap = argparse.ArgumentParser(description="R1 反例取证")
    ap.add_argument("--bits", type=int, nargs="+", default=[16, 32, 64])
    ap.add_argument("--trials", type=int, default=200)
    ap.add_argument("--seed", type=int, default=20260501)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    print("=" * 78)
    print("R1 反例：申报书式 (5)(6) 恒真退化 / 式 (11)(12) 假阴性")
    print("=" * 78)
    print(f"每组参数随机试验 {args.trials} 次\n")

    header = (
        "| bits | w% (p2-1)=0 | g^w≡1 | 合法通过 | 伪造通过 | 伪造接受率 | 诚实流通过率 |\n"
        "| ---- | ----------- | ----- | -------- | -------- | ---------- | ------------ |"
    )
    print(header)
    results = []
    for bits in args.bits:
        r = run(bits=bits, trials=args.trials, seed=args.seed + bits)
        results.append(r)
        print(_fmt_row(r))

    print()
    print("解读：")
    print("  · 第三列恒为 True  —— g^w 在 mod p2 下等于 1（欧拉定理，w 是 p2-1 的倍数）")
    print("  · 伪造接受率 100%   —— 换掉全部交换机和端口后，式 (5)(6) 仍然判「合法」")
    print("  · 诚实流通过率极低 —— 式 (11)(12) 的模幂与模乘口径不一致，真流也判不过")
    print()
    print("结论：该写法不具备判别力，必须先修正数学构造再进入工程实现。")

    if args.json:
        out = Path("results")
        out.mkdir(exist_ok=True)
        path = out / "r1_proposal_flaw.json"
        path.write_text(
            json.dumps({"results": results}, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        print(f"\n结果已写入 {path}")


if __name__ == "__main__":
    main()
