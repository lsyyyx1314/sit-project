"""攻击矩阵：同一套攻击下对比三种实现。

对比对象
--------
A. 申报书原式      mpv.core.proposal    —— 式 (1)(3)(5)(6) 原样实现
B. 摘要链（MPV-1） mpv.core.header/verify —— 定长头 + 逐跳 blake2b 链
C. MPV-2           mpv.core.scheme      —— 线性化模运算 + 位置权重 + path_tag

为什么要做矩阵而不是单点测试
--------------------------
"能检出篡改" 只是最低要求。真正要回答的是：
  1. 换一种攻击手法还检不检得出；
  2. 检出是在什么判定模式下取得的（O(1) 还是 O(k)）；
  3. 有没有哪类攻击是某个方案的结构性盲区（例如原式的恒真退化）。

攻击分类
--------
结构性攻击：改端口、换交换机、换顺序、删跳、插跳、整条替换、截断
数据性攻击：翻转 V、篡改 nonce、篡改 path_tag
语义性攻击：路径集合外的合法路径、跨路径重放

用法
----
    python -m sim.attack_matrix --trials 2000 --json
"""

from __future__ import annotations

import argparse
import json
import platform
import random
from dataclasses import dataclass
from pathlib import Path as FsPath
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from mpv.core import KeyRing
from mpv.core import proposal as PROP
from mpv.core.header import forward as hc_forward
from mpv.core.keys import Hop, Path
from mpv.core.verify import verify_path as hc_verify
from mpv.core.scheme import (
    ExpectationTable,
    Header2,
    forward as m2_forward,
    verify_scan,
    verify_tag,
)

# ---------------------------------------------------------------------------
# 统一适配层
# ---------------------------------------------------------------------------


class Scheme:
    name = ""
    short = ""

    def build(self, path: Path, nonce: int) -> object:
        raise NotImplementedError

    def verify(self, legit: Path, hdr: object) -> bool:
        raise NotImplementedError

    @property
    def header_bytes(self) -> int:
        raise NotImplementedError


class ProposalScheme(Scheme):
    """申报书原式：验证头 (f_s, f_k)，模幂累积，用 w 消随机数。"""

    name = "申报书原式"
    short = "A"

    def __init__(self, kr: KeyRing, par: PROP.Params):
        self.kr = kr
        self.par = par

    def _seq(self, path: Path):
        s_seq = [h.sid * 1000 + h.in_port * 10 + h.out_port for h in path]
        k_seq = [
            (self.kr.port_key(h.sid, h.in_port, h.out_port) % 60000) + 1 for h in path
        ]
        return s_seq, k_seq

    def _rs(self, n: int, nonce: int):
        rng = random.Random(nonce)
        return [rng.randrange(1, 60000) for _ in range(n)]

    def build(self, path: Path, nonce: int) -> Tuple:
        s_seq, k_seq = self._seq(path)
        return PROP.forward(self.par, s_seq, k_seq, self._rs(len(path), nonce))

    def verify(self, legit: Path, hdr: Tuple) -> bool:
        s_seq, k_seq = self._seq(legit)
        return PROP.verify_packet(self.par, sum(s_seq), sum(k_seq), hdr)

    def tamper(self, hdr, rng):
        fs, fk = hdr
        return ((fs + 1) % self.par.p2, fk)

    @property
    def header_bytes(self) -> int:
        return 16  # 两个 8 字节字段


class ChainScheme(Scheme):
    """MPV-1：定长头 + 逐跳带密钥摘要链。"""

    name = "摘要链 MPV-1"
    short = "B"

    def __init__(self, kr: KeyRing):
        self.kr = kr

    def build(self, path: Path, nonce: int):
        return hc_forward(self.kr, path, nonce=nonce)

    def verify(self, legit: Path, hdr) -> bool:
        return hc_verify(self.kr, legit, hdr)

    def tamper(self, hdr, rng):
        from mpv.core.header import Header

        return Header(nonce=hdr.nonce, tag=hdr.tag ^ 1)

    @property
    def header_bytes(self) -> int:
        return 16


class MPV2Scheme(Scheme):
    """MPV-2：线性化模运算 + 位置权重 + path_tag。"""

    name = "MPV-2"
    short = "C"

    def __init__(self, kr: KeyRing):
        self.kr = kr

    def build(self, path: Path, nonce: int):
        return m2_forward(self.kr, path, tag=0, nonce=nonce)

    def verify(self, legit: Path, hdr) -> bool:
        table = ExpectationTable(self.kr, [legit])
        return verify_tag(table, hdr).ok

    def tamper(self, hdr, rng):
        return Header2(nonce=hdr.nonce, acc=hdr.acc ^ 1, tag=hdr.tag)

    @property
    def header_bytes(self) -> int:
        return Header2.size_bytes


# ---------------------------------------------------------------------------
# 攻击构造
# ---------------------------------------------------------------------------


def _flip_out(path: Path, idx: int, rng: random.Random) -> Path:
    h = list(path)
    x = h[idx]
    alt = [p for p in (1, 2, 3, 4) if p != x.out_port]
    h[idx] = Hop(sid=x.sid, in_port=x.in_port, out_port=rng.choice(alt))
    return tuple(h)


def _flip_in(path: Path, idx: int, rng: random.Random) -> Path:
    h = list(path)
    x = h[idx]
    alt = [p for p in (1, 2, 3, 4) if p != x.in_port]
    h[idx] = Hop(sid=x.sid, in_port=rng.choice(alt), out_port=x.out_port)
    return tuple(h)


def _bypass(path: Path, idx: int, kr: KeyRing, rng: random.Random) -> Path:
    h = list(path)
    used = {x.sid for x in path}
    pool = [s for s in range(1, 17) if s not in used]
    if not pool:
        return tuple(h)
    h[idx] = Hop(sid=rng.choice(pool), in_port=1, out_port=2)
    return tuple(h)


def _reorder(path: Path, idx: int, rng: random.Random) -> Path:
    h = list(path)
    if idx + 1 >= len(h):
        idx = len(h) - 2
    h[idx], h[idx + 1] = h[idx + 1], h[idx]
    return tuple(h)


def _delete(path: Path, idx: int, rng: random.Random) -> Path:
    h = list(path)
    if len(h) <= 2:
        return tuple(h)
    del h[idx]
    return tuple(h)


def _insert(path: Path, idx: int, kr: KeyRing, rng: random.Random) -> Path:
    h = list(path)
    used = {x.sid for x in path}
    pool = [s for s in range(1, 17) if s not in used]
    if not pool:
        return tuple(h)
    h.insert(idx, Hop(sid=rng.choice(pool), in_port=1, out_port=3))
    return tuple(h)


def _replace(path: Path, kr: KeyRing, rng: random.Random) -> Path:
    used = {x.sid for x in path}
    pool = [s for s in range(1, 17) if s not in used]
    rng.shuffle(pool)
    n = len(path)
    sids = [path[0].sid] + pool[: n - 2] + [path[-1].sid]
    return tuple(
        Hop(sid=s, in_port=1, out_port=2 if i % 2 == 0 else 3)
        for i, s in enumerate(sids)
    )


def _truncate(path: Path, rng: random.Random) -> Path:
    return path[:-1] if len(path) > 2 else path


ATTACKS: List[Tuple[str, str, Callable]] = [
    ("S1", "改出端口", lambda p, kr, r: _flip_out(p, r.randrange(len(p)), r)),
    ("S2", "改入端口", lambda p, kr, r: _flip_in(p, r.randrange(len(p)), r)),
    ("S3", "交换机旁路", lambda p, kr, r: _bypass(p, r.randrange(len(p)), kr, r)),
    ("S4", "跳序交换", lambda p, kr, r: _reorder(p, r.randrange(max(1, len(p) - 1)), r)),
    ("S5", "删除一跳", lambda p, kr, r: _delete(p, r.randrange(1, max(2, len(p) - 1)), r)),
    ("S6", "插入一跳", lambda p, kr, r: _insert(p, r.randrange(1, max(2, len(p) - 1)), kr, r)),
    ("S7", "整条替换", lambda p, kr, r: _replace(p, kr, r)),
    ("S8", "截断路径", lambda p, kr, r: _truncate(p, r)),
]


def _rand_path(kr: KeyRing, rng: random.Random, n_hops: Optional[int] = None) -> Path:
    n = n_hops or rng.randint(3, 7)
    sids = [1] + rng.sample(range(2, 16), n - 2) + [16]
    return tuple(
        Hop(sid=s, in_port=1, out_port=2 if i % 2 == 0 else 3)
        for i, s in enumerate(sids)
    )


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------


def run_matrix(schemes: Sequence[Scheme], trials: int, seed: int) -> Dict[str, object]:
    rng = random.Random(seed)
    kr = KeyRing.generate(n_switches=16, ports_per_switch=4, seed=seed)

    # 诚实样本接受率 + 误报率
    honest_accept: Dict[str, int] = {s.short: 0 for s in schemes}
    for _ in range(trials):
        p = _rand_path(kr, rng)
        nonce = rng.getrandbits(56)
        for s in schemes:
            if s.verify(p, s.build(p, nonce)):
                honest_accept[s.short] += 1

    # 结构性攻击
    rows: List[Dict[str, object]] = []
    for code, desc, fn in ATTACKS:
        detected = {s.short: 0 for s in schemes}
        for _ in range(trials):
            p = _rand_path(kr, rng)
            nonce = rng.getrandbits(56)
            bad = fn(p, kr, rng)
            if bad == p:
                continue  # 攻击退化为无操作
            for s in schemes:
                if not s.verify(p, s.build(bad, nonce)):
                    detected[s.short] += 1
        rows.append({"code": code, "desc": desc, "detected": detected})

    # 数据性攻击：直接篡改已生成的验证头
    header_rows: List[Dict[str, object]] = []
    for code, desc in (("S9", "验证头比特翻转"), ("S10", "随机伪造验证头")):
        detected = {s.short: 0 for s in schemes}
        for _ in range(trials):
            p = _rand_path(kr, rng)
            nonce = rng.getrandbits(56)
            for s in schemes:
                hdr = s.build(p, nonce)
                if code == "S9":
                    bad = s.tamper(hdr, rng)
                else:
                    # 随机伪造：必须确保伪造路径与合法路径不同，否则本身就不是攻击
                    forged = _rand_path(kr, rng)
                    guard = 0
                    while forged == p and guard < 16:
                        forged = _rand_path(kr, rng)
                        guard += 1
                    bad = s.build(forged, rng.getrandbits(56))
                if not s.verify(p, bad):
                    detected[s.short] += 1
        header_rows.append({"code": code, "desc": desc, "detected": detected})

    return {
        "trials": trials,
        "host": platform.platform(),
        "header_bytes": {s.short: s.header_bytes for s in schemes},
        "honest_accept": honest_accept,
        "rows": rows + header_rows,
    }


def run_mpv2_specific(trials: int, seed: int) -> Dict[str, object]:
    """MPV-2 专项：多路径集合、tag 篡改、跨路径重放、流级混合。"""
    from mpv.core.scheme import FlowAccumulator, compression_ratio, verify_flow

    rng = random.Random(seed + 7)
    kr = KeyRing.generate(n_switches=16, ports_per_switch=4, seed=seed)
    cands = [_rand_path(kr, rng, 5) for _ in range(8)]
    table = ExpectationTable(kr, cands)

    # 1) 合法集合内：任一路径 + 正确 tag → 通过
    ok_honest = 0
    for _ in range(trials):
        i = rng.randrange(len(cands))
        h = m2_forward(kr, cands[i], tag=i)
        if verify_tag(table, h).ok:
            ok_honest += 1

    # 2) tag 篡改：把 tag 改到另一条合法路径
    tag_reject = 0
    for _ in range(trials):
        i = rng.randrange(len(cands))
        j = (i + 1 + rng.randrange(len(cands) - 1)) % len(cands)
        h = m2_forward(kr, cands[i], tag=i)
        if not verify_tag(table, Header2(h.nonce, h.acc, j)).ok:
            tag_reject += 1

    # 3) 集合外路径：路径不在候选集
    out_reject = 0
    legal = set(cands)
    for _ in range(trials):
        bad = _replace(cands[0], kr, rng)
        guard = 0
        while bad in legal and guard < 64:
            bad = _replace(cands[0], kr, rng)
            guard += 1
        h = m2_forward(kr, bad, tag=0)
        if not verify_scan(table, h).ok:
            out_reject += 1

    # 4) 跨路径重放：拿 A 路径的头，声称走 B 路径
    replay_reject = 0
    for _ in range(trials):
        i = rng.randrange(len(cands))
        j = (i + 1) % len(cands)
        h = m2_forward(kr, cands[i], tag=j)
        if not verify_tag(table, h).ok:
            replay_reject += 1

    # 5) 流级：混合路径聚合
    acc = FlowAccumulator()
    for _ in range(400):
        i = rng.randrange(len(cands))
        acc.add(m2_forward(kr, cands[i], tag=i))
    rep = acc.report()
    flow_ok, flow_checks = verify_flow(table, rep)

    return {
        "candidates": len(cands),
        "honest_accept": ok_honest / trials,
        "tag_tamper_detect": tag_reject / trials,
        "out_of_set_detect": out_reject / trials,
        "replay_detect": replay_reject / trials,
        "flow_ok": flow_ok,
        "flow_entries": rep.entries,
        "flow_packets": rep.packets,
        "flow_compression": round(compression_ratio(rep), 1),
        "flow_checks": flow_checks,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--trials", type=int, default=2000)
    ap.add_argument("--seed", type=int, default=20260501)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    kr = KeyRing.generate(n_switches=16, ports_per_switch=4, seed=args.seed)
    par = PROP.make_params(bits=64, seed=args.seed)
    schemes: List[Scheme] = [ProposalScheme(kr, par), ChainScheme(kr), MPV2Scheme(kr)]

    res = run_matrix(schemes, args.trials, args.seed)
    spec = run_mpv2_specific(args.trials, args.seed)

    print("=" * 76)
    print(f"攻击矩阵  每组攻击 {args.trials} 次  |  {res['host']}")
    print("=" * 76)
    print()
    print("表 1  结构性攻击检出率（数值越高越好，100% 为合格）")
    print()
    def pad(text: str, width: int) -> str:
        w = sum(2 if ord(c) > 0x2E80 else 1 for c in text)
        return text + " " * max(0, width - w)

    print("| 编号 | 攻击手法     | 申报书原式 | 摘要链 MPV-1 | MPV-2 |")
    print("| ---- | ------------ | ---------- | ------------ | ----- |")
    for row in res["rows"]:
        d = row["detected"]
        n = args.trials
        print(
            f"| {row['code']:<4} | {pad(row['desc'], 12)} | "
            f"{d['A']/n*100:9.1f}% | {d['B']/n*100:11.1f}% | {d['C']/n*100:5.1f}% |"
        )

    print()
    print("表 2  诚实样本接受率（应 100%）与头部开销")
    for s in schemes:
        print(
            f"  {s.name:<12} 接受率 {res['honest_accept'][s.short]/args.trials*100:6.2f}%"
            f"   头部 {res['header_bytes'][s.short]} 字节"
        )

    print()
    print("表 3  MPV-2 专项（多路径集合）")
    print(f"  候选路径数            : {spec['candidates']}")
    print(f"  集合内合法包接受率    : {spec['honest_accept']*100:.2f}%")
    print(f"  tag 篡改检出率        : {spec['tag_tamper_detect']*100:.2f}%")
    print(f"  集合外路径检出率      : {spec['out_of_set_detect']*100:.2f}%")
    print(f"  跨路径重放检出率      : {spec['replay_detect']*100:.2f}%")
    print(
        f"  流级：{spec['flow_packets']} 包 → {spec['flow_entries']} 条，"
        f"压缩 {spec['flow_compression']}×，判定 {spec['flow_checks']} 次，"
        f"结果 {'通过' if spec['flow_ok'] else '拒绝'}"
    )

    if args.json:
        out = FsPath("results")
        out.mkdir(exist_ok=True)
        p = out / "attack_matrix.json"
        p.write_text(
            json.dumps({"matrix": res, "mpv2": spec}, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        print(f"\n结果已写入 {p}")


if __name__ == "__main__":
    main()
