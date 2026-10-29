"""MPV-2：面向 SDN 多路径的可验证定长验证头（R1 修正后的构造）。

一、为什么要重写

申报书原式 (5)(6) 把随机数 r_i 放进指数：f_s = g^(Σ s_i·r_i)，再用统一指数 w
试图把 r_i 消掉。但 w = lcm(p1−1, p2−1) 是 p2−1 的倍数，由欧拉定理 g^w ≡ 1，
判定式两端恒为 1，任何路径都能通过（见 sim/counterexample_r1.py）。

根因不是参数选得不好，而是**「用指数承载随机量、再想办法消掉」这条路本身不成立**：
模幂把加法结构破坏了，消不掉；能消掉的只有线性结构。

二、MPV-2 的核心思想

把随机性从指数搬到**线性项**上，问题自然消失：

    每个跳的贡献     c_i = (a_i + b_i · h) mod p ,   h = H(nonce) 为公开哈希
    验证头累积       V   = Σ_i c_i · ρ^(i−1)  mod p
    控制器期望值     E(P, h) = A_P + B_P · h

其中 (a_i, b_i) 是跳 i 的密钥导出量，ρ 是公开底数，A_P、B_P 只依赖路径本身，
可在流建立时预计算（与 nonce 无关）。

三、性质

1. **不需要消去随机数**：h 是公开的，控制器直接代入即可，不存在恒等式退化。
2. **定长**：V ∈ Z_p 恒为 64 bit，与跳数无关。
3. **顺序敏感**：ρ^(i−1) 的位置权重使跳序进入结果，交换两跳必然改变 V。
4. **不可伪造**：篡改者需要知道至少一个诚实跳的 (a_i, b_i) 才能把 V 调整到
   另一条路径的期望值；只知道自己的密钥无法完成跨跳补偿。
5. **一次判定**：验证头携带 path_tag（背离点由组表 bucket 写入），控制器
   只需 1 次乘加即可判定，与候选路径数 k 无关；tag 不可信时退化为 k 次扫描。

四、与申报书术语的对应

    k_si   = k_i ⊕ k_i^in ⊕ k_i^out   （式 2，保留）
    c_i    = a_i + b_i·h                （替代式 3 的 g^(s_i·r_i)）
    E(P)   = A_P + B_P·h                （替代式 5/6）
    VI     = Σ_packets V                （式 7–10 的线性化版本）
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from hashlib import blake2b
from typing import ClassVar, Dict, List, Optional, Sequence, Tuple

from .keys import Hop, KeyRing, Path

# ---------------------------------------------------------------------------
# 域参数
# ---------------------------------------------------------------------------

# 2^64 − 59 是已知的 64 位素数，保证 V 恰好占 64 bit。
P = (1 << 64) - 59

# 公开底数，取自黄金比例常数的奇数化，要求 ≠ 0,1
RHO = 0x9E3779B97F4A7C15 % P

NONCE_BITS = 56
TAG_BITS = 8
HEADER_BYTES = 16  # 7 + 8 + 1

assert RHO not in (0, 1)


def _h(nonce: int) -> int:
    """公开哈希 H(nonce) → Z_p。任何人都能算，因此控制器可代入。"""
    d = blake2b(digest_size=8)
    d.update(b"mpv2-h")
    d.update(nonce.to_bytes(7, "big"))
    return int.from_bytes(d.digest(), "big") % P


def _prf(key: int, label: bytes) -> int:
    """从端口密钥派生域元素。"""
    d = blake2b(digest_size=8, key=(key % (1 << 256)).to_bytes(32, "big"))
    d.update(label)
    return int.from_bytes(d.digest(), "big") % P


# ---------------------------------------------------------------------------
# 验证头
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Header2:
    """MPV-2 定长验证头：nonce(56) + V(64) + path_tag(8) = 16 字节。"""

    nonce: int
    acc: int
    tag: int

    size_bytes: ClassVar[int] = HEADER_BYTES

    def wire(self) -> bytes:
        return (
            (self.nonce % (1 << NONCE_BITS)).to_bytes(NONCE_BITS // 8, "big")
            + (self.acc % P).to_bytes(8, "big")
            + (self.tag % (1 << TAG_BITS)).to_bytes(TAG_BITS // 8, "big")
        )

    def __str__(self) -> str:  # pragma: no cover
        return f"H2(n={self.nonce:014x}, V={self.acc:016x}, t={self.tag})"


# ---------------------------------------------------------------------------
# 密钥与逐跳贡献
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class HopKey:
    a: int
    b: int


def hop_key(kr: KeyRing, hop: Hop) -> HopKey:
    """把式 (2) 的端口密钥派生为 (a, b)。"""
    ks = kr.port_key(hop.sid, hop.in_port, hop.out_port)
    return HopKey(a=_prf(ks, b"a"), b=_prf(ks, b"b"))


def contribution(kr: KeyRing, hop: Hop, h: int) -> int:
    """单跳贡献 c_i = a_i + b_i·h mod p。"""
    k = hop_key(kr, hop)
    return (k.a + k.b * h) % P


# ---------------------------------------------------------------------------
# 路径期望值（与 nonce 无关，可预计算）
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PathExpectation:
    """一条候选路径的期望值 E(h) = A + B·h。

    A、B 在流建立时算好，逐包只需一次乘加 —— 这是 CPMV「一次验证」的落地形式。
    """

    path: Path
    A: int
    B: int
    tag: int = 0

    def expect(self, h: int) -> int:
        return (self.A + self.B * h) % P


def expectation(kr: KeyRing, path: Path, tag: int = 0) -> PathExpectation:
    A = B = 0
    w = 1
    for hop in path:
        k = hop_key(kr, hop)
        A = (A + k.a * w) % P
        B = (B + k.b * w) % P
        w = w * RHO % P
    return PathExpectation(path=path, A=A, B=B, tag=tag)


class ExpectationTable:
    """候选路径集合的期望值表（CPMV 的核心数据结构）。"""

    def __init__(self, kr: KeyRing, candidates: Sequence[Path]):
        if not candidates:
            raise ValueError("候选路径集合不能为空")
        if len(candidates) > (1 << TAG_BITS):
            raise ValueError(f"候选路径数超过 {1 << TAG_BITS}")
        self.kr = kr
        self.candidates: List[Path] = list(candidates)
        self.table: List[PathExpectation] = [
            expectation(kr, p, tag=i) for i, p in enumerate(self.candidates)
        ]

    def __len__(self) -> int:
        return len(self.table)

    def by_tag(self, tag: int) -> Optional[PathExpectation]:
        return self.table[tag] if 0 <= tag < len(self.table) else None


# ---------------------------------------------------------------------------
# 数据平面：入口初始化与逐跳更新
# ---------------------------------------------------------------------------


def ingress(kr: KeyRing, hop: Hop, tag: int, nonce: Optional[int] = None) -> Header2:
    """入口交换机初始化验证头（替代式 3）。"""
    if nonce is None:
        nonce = secrets.randbits(NONCE_BITS)
    h = _h(nonce)
    acc = contribution(kr, hop, h)  # ρ^0 = 1
    return Header2(nonce=nonce, acc=acc, tag=tag)


def advance(kr: KeyRing, hop: Hop, hdr: Header2, position: int) -> Header2:
    """第 position 跳（1-based）更新：V += c_i · ρ^(position−1)。"""
    h = _h(hdr.nonce)
    c = contribution(kr, hop, h)
    acc = (hdr.acc + c * pow(RHO, position - 1, P)) % P
    return Header2(nonce=hdr.nonce, acc=acc, tag=hdr.tag)


def forward(kr: KeyRing, path: Path, tag: int = 0, nonce: Optional[int] = None) -> Header2:
    """跑完整条路径，返回出口处的验证头。"""
    if not path:
        raise ValueError("path 不能为空")
    hdr = ingress(kr, path[0], tag=tag, nonce=nonce)
    for i, hop in enumerate(path[1:], start=2):
        hdr = advance(kr, hop, hdr, i)
    return hdr


# ---------------------------------------------------------------------------
# 控制平面：判定
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Verdict2:
    ok: bool
    mode: str                    # "tag"（O(1)）或 "scan"（O(k)）
    matched_index: Optional[int]
    matched_path: Optional[Path]
    checks: int                  # 实际执行的乘加次数，用于开销统计

    def __bool__(self) -> bool:  # pragma: no cover
        return self.ok


def verify_tag(
    table: ExpectationTable, hdr: Header2
) -> Verdict2:
    """快速判定：只检查验证头自带的 path_tag，O(1)。"""
    exp = table.by_tag(hdr.tag)
    if exp is None:
        return Verdict2(False, "tag", None, None, 0)
    h = _h(hdr.nonce)
    ok = exp.expect(h) == hdr.acc
    return Verdict2(ok, "tag", hdr.tag if ok else None, exp.path if ok else None, 1)


def verify_scan(table: ExpectationTable, hdr: Header2) -> Verdict2:
    """完整判定：遍历候选集，O(k)。用于 tag 不可信的场合。"""
    h = _h(hdr.nonce)
    for i, exp in enumerate(table.table):
        if exp.expect(h) == hdr.acc:
            return Verdict2(True, "scan", i, exp.path, i + 1)
    return Verdict2(False, "scan", None, None, len(table))


# ---------------------------------------------------------------------------
# 流级压缩（CFMV）
# ---------------------------------------------------------------------------


@dataclass
class FlowReport:
    """出口交换机上报的流级摘要。体积与包数无关，只与命中的路径数有关。"""

    sums: Dict[int, int]      # tag -> Σ V
    hsums: Dict[int, int]     # tag -> Σ h
    counts: Dict[int, int]    # tag -> 包数

    @property
    def packets(self) -> int:
        return sum(self.counts.values())

    @property
    def entries(self) -> int:
        return len(self.counts)


class FlowAccumulator:
    """逐包累加，出口交换机侧使用。"""

    def __init__(self) -> None:
        self._sums: Dict[int, int] = {}
        self._hsums: Dict[int, int] = {}
        self._counts: Dict[int, int] = {}

    def add(self, hdr: Header2) -> None:
        t = hdr.tag
        self._sums[t] = (self._sums.get(t, 0) + hdr.acc) % P
        self._hsums[t] = (self._hsums.get(t, 0) + _h(hdr.nonce)) % P
        self._counts[t] = self._counts.get(t, 0) + 1

    def report(self) -> FlowReport:
        return FlowReport(
            sums=dict(self._sums),
            hsums=dict(self._hsums),
            counts=dict(self._counts),
        )


def verify_flow(
    table: ExpectationTable, rep: FlowReport, strict: bool = True
) -> Tuple[bool, int]:
    """流级判定：对每个命中路径做一次 O(1) 线性检查。

    Σ_p V_p = A_j·count_j + B_j·Σ_p h_p  mod p
    """
    checks = 0
    for tag, cnt in rep.counts.items():
        exp = table.by_tag(tag)
        if exp is None:
            if strict:
                return False, checks
            continue
        lhs = rep.sums[tag]
        rhs = (exp.A * cnt + exp.B * rep.hsums[tag]) % P
        checks += 1
        if lhs != rhs:
            return False, checks
    return True, checks


def compression_ratio(rep: FlowReport) -> float:
    """压缩比 = 包数 / 上报条目数。"""
    return rep.packets / rep.entries if rep.entries else 0.0
