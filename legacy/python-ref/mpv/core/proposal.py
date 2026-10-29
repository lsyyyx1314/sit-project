"""申报书原始构造的忠实实现（用于 R1 反例取证）。

本模块**刻意按申报书式 (1)(3)(5)(6)(11)(12) 原样实现**，不做任何修补。
它的用途只有一个：用可执行代码证明该构造在当前写法下不可用。

对应关系：
    式 (1)  w = lcm(p1-1, p2-1)
    式 (3)  (f_s, f_k) ← (g^(s_i·r_i) mod p2, g^(k_si·r_i) mod p2)
    式 (5)  g^(w·s_m) mod p2 == f_s^w mod p2
    式 (6)  g^(w·k_m) mod p2 == f_k^w mod p2
    式 (7)-(10) VI_s ← (f_s + VI_s) mod p2 ...
    式 (11) VI_s mod p2 == (g^(s_m) · VI_rs) mod p2
    式 (12) VI_k mod p2 == (g^(k_m) · VI_rk) mod p2
    式 (13) g^x mod p2 == g^(x mod φ(p2)) mod p2

注意式 (3) 之后没有给出中间跳更新式，这里按正文「非交换性二元组乘法」
的字面含义取「模乘累积」，即
    f_s ← f_s · g^(s_j·r_j) mod p2
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass
from typing import List, Sequence, Tuple

Pair = Tuple[int, int]


# --------------------------------------------------------------------- 素数
def _is_probable_prime(n: int, rounds: int = 24) -> bool:
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    rng = random.Random(n)
    for _ in range(rounds):
        a = rng.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def gen_prime(bits: int, rng: random.Random) -> int:
    while True:
        cand = rng.getrandbits(bits) | (1 << (bits - 1)) | 1
        if _is_probable_prime(cand):
            return cand


# --------------------------------------------------------------------- 参数
@dataclass(frozen=True)
class Params:
    p1: int
    p2: int
    g: int
    w: int
    modulus_power: int  # 式(5) 里的 p2 幂次记号，此处固定为 1


def make_params(bits: int = 16, seed: int = 20260501) -> Params:
    rng = random.Random(seed)
    p1 = gen_prime(bits, rng)
    p2 = gen_prime(bits, rng)
    if p1 == p2:
        return make_params(bits, seed + 1)
    w = math.lcm(p1 - 1, p2 - 1)
    g = 2
    while math.gcd(g, p2) != 1:
        g += 1
    return Params(p1=p1, p2=p2, g=g, w=w, modulus_power=1)


# --------------------------------------------------------------------- 头
def init_header(par: Params, s_i: int, k_si: int, r_i: int) -> Pair:
    """式 (3)：入口初始化。"""
    return (
        pow(par.g, (s_i * r_i) % (par.p2 - 1), par.p2),
        pow(par.g, (k_si * r_i) % (par.p2 - 1), par.p2),
    )


def update_header(
    par: Params, h: Pair, s_i: int, k_si: int, r_i: int
) -> Pair:
    """中间跳模乘累积（申报书未给出该式，此处取模乘累积）。"""
    fs, fk = h
    return (
        fs * pow(par.g, (s_i * r_i) % (par.p2 - 1), par.p2) % par.p2,
        fk * pow(par.g, (k_si * r_i) % (par.p2 - 1), par.p2) % par.p2,
    )


def forward(
    par: Params,
    s_seq: Sequence[int],
    k_seq: Sequence[int],
    r_seq: Sequence[int],
) -> Pair:
    h = init_header(par, s_seq[0], k_seq[0], r_seq[0])
    for s_i, k_si, r_i in zip(s_seq[1:], k_seq[1:], r_seq[1:]):
        h = update_header(par, h, s_i, k_si, r_i)
    return h


# --------------------------------------------------------------------- 验证
def verify_packet(par: Params, s_m: int, k_m: int, h: Pair) -> bool:
    """式 (5)(6)：控制器的包级判定。"""
    fs, fk = h
    left_s = pow(par.g, (par.w * s_m) % (par.p2 - 1), par.p2)
    left_k = pow(par.g, (par.w * k_m) % (par.p2 - 1), par.p2)
    right_s = pow(fs, par.w, par.p2)
    right_k = pow(fk, par.w, par.p2)
    return left_s == right_s and left_k == right_k


def verify_flow(
    par: Params,
    s_m: int,
    k_m: int,
    vi_s: int,
    vi_k: int,
    vi_rs: int,
    vi_rk: int,
) -> bool:
    """式 (11)(12)：控制器的流级判定。"""
    lhs_s = vi_s % par.p2
    lhs_k = vi_k % par.p2
    rhs_s = pow(par.g, s_m, par.p2) * vi_rs % par.p2
    rhs_k = pow(par.g, k_m, par.p2) * vi_rk % par.p2
    return lhs_s == rhs_s and lhs_k == rhs_k


def accumulate(
    par: Params,
    headers: Sequence[Pair],
    r_seq: Sequence[int],
) -> Tuple[int, int, int, int]:
    """式 (7)-(10)：出口交换机按流累积。"""
    vi_s = vi_k = vi_rs = vi_rk = 0
    for (fs, fk), r in zip(headers, r_seq):
        vi_s = (fs + vi_s) % par.p2
        vi_k = (fk + vi_k) % par.p2
        vi_rs = (r + vi_rs) % par.p2
        vi_rk = (r + vi_rk) % par.p2
    return vi_s, vi_k, vi_rs, vi_rk


def euler_opt(par: Params, x: int) -> Tuple[int, int]:
    """式 (13)：Euler 优化前后对比，返回 (直接计算, 优化后指数)。"""
    direct = pow(par.g, x, par.p2)
    phi = par.p2 - 1
    reduced = pow(par.g, x % phi, par.p2)
    return direct, reduced


class FlowState:
    """出口交换机的流级状态（式 7-10 的增量形式）。"""

    def __init__(self, par: Params):
        self.par = par
        self.vi_s = 0
        self.vi_k = 0
        self.vi_rs = 0
        self.vi_rk = 0
        self.count = 0

    def accumulate(self, h: Pair, r: int) -> None:
        fs, fk = h
        self.vi_s = (fs + self.vi_s) % self.par.p2
        self.vi_k = (fk + self.vi_k) % self.par.p2
        self.vi_rs = (r + self.vi_rs) % self.par.p2
        self.vi_rk = (r + self.vi_rk) % self.par.p2
        self.count += 1
