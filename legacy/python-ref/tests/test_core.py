"""core 层单元测试。

覆盖计划书 M0 的四条验收：
  1. 定长头：跳数变化不影响头长
  2. 顺序敏感：交换两跳顺序必须判否
  3. 篡改检出：端口改、交换机换、跳被删，均须判否
  4. 候选集验证：合法路径中唯一定位命中项
"""

from __future__ import annotations

import random

import pytest

from mpv.core import KeyRing, Hop, forward, verify_candidates, verify_path, verify_cached
from mpv.core.digest import HEADER_BYTES
from mpv.core.keys import Path


def make_path(kr: KeyRing, sids, ports=None) -> Path:
    """按交换机序列构造路径，端口按 in=1/out=2 轮换。"""
    hops = []
    for i, sid in enumerate(sids):
        hops.append(Hop(sid=sid, in_port=1, out_port=2 if i % 2 == 0 else 3))
    return tuple(hops)


@pytest.fixture(scope="module")
def kr() -> KeyRing:
    return KeyRing.generate(n_switches=16, ports_per_switch=4, seed=0xC0FFEE)


# --------------------------------------------------------------- 定长
@pytest.mark.parametrize("n_hops", [2, 4, 8, 16])
def test_header_length_is_constant(kr: KeyRing, n_hops: int) -> None:
    path = make_path(kr, list(range(1, n_hops + 1)))
    h = forward(kr, path)
    assert len(h.wire()) == HEADER_BYTES == 16
    assert h.size_bytes == 16


def test_header_length_independent_of_path_count(kr: KeyRing) -> None:
    """路径数从 1 增到 32，头长不变。"""
    lengths = set()
    for k in (1, 2, 4, 8, 16, 32):
        path = make_path(kr, [1, 2, 3])
        lengths.add(len(forward(kr, path).wire()))
    assert lengths == {16}


# --------------------------------------------------------------- 正例
def test_honest_path_verifies(kr: KeyRing) -> None:
    path = make_path(kr, [1, 5, 9, 13])
    h = forward(kr, path)
    assert verify_path(kr, path, h)


# --------------------------------------------------------------- R2 顺序
def test_order_sensitivity(kr: KeyRing) -> None:
    """同一组交换机，换顺序必须判否 —— 这是「非交换性」的可执行定义。"""
    a = make_path(kr, [1, 2, 3, 4])
    b = make_path(kr, [2, 1, 3, 4])
    h = forward(kr, a)
    assert verify_path(kr, a, h)
    assert not verify_path(kr, b, h)


def test_reverse_path_rejected(kr: KeyRing) -> None:
    p = make_path(kr, [1, 2, 3, 4, 5])
    rev = tuple(reversed(p))
    h = forward(kr, p)
    assert not verify_path(kr, rev, h)


# --------------------------------------------------------------- 篡改
def test_port_tamper_rejected(kr: KeyRing) -> None:
    path = make_path(kr, [1, 2, 3, 4])
    h = forward(kr, path)
    tampered = list(path)
    hop = tampered[2]
    tampered[2] = Hop(sid=hop.sid, in_port=hop.in_port, out_port=1)  # 改出端口
    assert not verify_path(kr, tuple(tampered), h)


def test_switch_substitution_rejected(kr: KeyRing) -> None:
    path = make_path(kr, [1, 2, 3, 4])
    h = forward(kr, path)
    tampered = list(path)
    tampered[1] = Hop(sid=9, in_port=1, out_port=2)  # 换成旁路交换机
    assert not verify_path(kr, tuple(tampered), h)


def test_hop_deletion_rejected(kr: KeyRing) -> None:
    path = make_path(kr, [1, 2, 3, 4, 5])
    h = forward(kr, path)
    shortened = (path[0], path[1], path[3], path[4])
    assert not verify_path(kr, shortened, h)


def test_tamper_detection_rate(kr: KeyRing) -> None:
    """随机篡改 2000 例，检出率必须 100%。"""
    rng = random.Random(7)
    detected = 0
    total = 2000
    for _ in range(total):
        n = rng.randint(2, 8)
        sids = rng.sample(range(1, 17), n)
        path = make_path(kr, sids)
        h = forward(kr, path)
        # 篡改：随机改一跳的端口
        idx = rng.randrange(n)
        hop = path[idx]
        new_out = rng.choice([p for p in (1, 2, 3, 4) if p != hop.out_port])
        bad = list(path)
        bad[idx] = Hop(sid=hop.sid, in_port=hop.in_port, out_port=new_out)
        if not verify_path(kr, tuple(bad), h):
            detected += 1
    assert detected == total, f"检出率 {detected}/{total}"


# --------------------------------------------------------------- 候选集
def test_verify_candidates_unique_hit(kr: KeyRing) -> None:
    paths = [make_path(kr, s) for s in ([1, 2, 5], [1, 3, 5], [1, 4, 5], [1, 2, 4, 5])]
    h = forward(kr, paths[2])
    v = verify_candidates(kr, paths, h)
    assert v.ok and v.matched_index == 2


def test_verify_candidates_miss(kr: KeyRing) -> None:
    paths = [make_path(kr, [1, 2, 5]), make_path(kr, [1, 3, 5])]
    h = forward(kr, make_path(kr, [1, 4, 6]))
    v = verify_candidates(kr, paths, h)
    assert not v.ok


def test_cached_matches_linear(kr: KeyRing) -> None:
    paths = [make_path(kr, s) for s in ([1, 2, 3, 7], [1, 2, 4, 7], [1, 5, 6, 7])]
    h = forward(kr, paths[1])
    assert verify_cached(kr, paths, h).matched_index == verify_candidates(kr, paths, h).matched_index == 1


# --------------------------------------------------------------- 随机性
def test_same_path_different_nonce(kr: KeyRing) -> None:
    path = make_path(kr, [1, 2, 3])
    h1 = forward(kr, path)
    h2 = forward(kr, path)
    assert h1 != h2          # nonce 随机，头必不同
    assert verify_path(kr, path, h1) and verify_path(kr, path, h2)


# --------------------------------------------------------------- 前缀树
def test_pathset_matches_linear(kr: KeyRing) -> None:
    from mpv.core import PathSet

    paths = [make_path(kr, s) for s in ([1, 2, 3, 7], [1, 2, 4, 7], [1, 5, 6, 7])]
    ps = PathSet(kr, paths)
    for i, p in enumerate(paths):
        h = forward(kr, p)
        v = ps.match(h)
        assert v.ok and v.matched_index == i


def test_pathset_rejects_unknown(kr: KeyRing) -> None:
    from mpv.core import PathSet

    paths = [make_path(kr, [1, 2, 3, 7]), make_path(kr, [1, 2, 4, 7])]
    ps = PathSet(kr, paths)
    h = forward(kr, make_path(kr, [1, 5, 6, 8]))
    assert not ps.match(h).ok


def test_pathset_uses_fewer_digests(kr: KeyRing) -> None:
    """共享前缀越长，前缀树的摘要次数优势越明显。"""
    from mpv.core import PathSet

    prefix = [1, 2, 3]
    paths = [make_path(kr, prefix + [4 + i, 15]) for i in range(8)]
    ps = PathSet(kr, paths)
    h = forward(kr, paths[7])
    st = {}
    v = ps.match(h, stats=st)
    assert v.ok and v.matched_index == 7
    assert st["digests"] < 5 * len(paths)   # 线性需 40 次
