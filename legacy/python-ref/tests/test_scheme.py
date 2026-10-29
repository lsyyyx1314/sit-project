"""MPV-2 算法测试：正确性、顺序绑定、不可伪造、流级压缩。

这一层只做「单点断言」，大样本统计与攻击矩阵在 sim/attack_matrix.py。
"""

from __future__ import annotations

import random

import pytest

from mpv.core import KeyRing
from mpv.core.keys import Hop, Path
from mpv.core.scheme import (
    HEADER_BYTES,
    P,
    ExpectationTable,
    FlowAccumulator,
    Header2,
    advance,
    compression_ratio,
    expectation,
    forward,
    ingress,
    verify_flow,
    verify_scan,
    verify_tag,
)


def path_of(kr: KeyRing, sids) -> Path:
    return tuple(
        Hop(sid=s, in_port=1, out_port=2 if i % 2 == 0 else 3)
        for i, s in enumerate(sids)
    )


@pytest.fixture(scope="module")
def kr() -> KeyRing:
    return KeyRing.generate(n_switches=16, ports_per_switch=4, seed=0xBEEF)


@pytest.fixture(scope="module")
def paths(kr: KeyRing):
    """源 1 → 目的 16 的 4 条候选路径。"""
    return [
        path_of(kr, [1, 2, 3, 16]),
        path_of(kr, [1, 4, 5, 16]),
        path_of(kr, [1, 6, 7, 8, 16]),
        path_of(kr, [1, 9, 10, 16]),
    ]


@pytest.fixture(scope="module")
def table(kr: KeyRing, paths):
    return ExpectationTable(kr, paths)


# ------------------------------------------------------------------ 定长
@pytest.mark.parametrize("n", [2, 4, 8, 16])
def test_header_is_16_bytes(kr: KeyRing, n: int) -> None:
    p = path_of(kr, list(range(1, n + 1)))
    h = forward(kr, p, tag=3)
    assert len(h.wire()) == HEADER_BYTES == 16
    assert h.size_bytes == 16


# ------------------------------------------------------------------ 正确性
def test_honest_packet_passes_tag_mode(kr, table, paths) -> None:
    for i, p in enumerate(paths):
        h = forward(kr, p, tag=i)
        v = verify_tag(table, h)
        assert v.ok and v.matched_index == i and v.checks == 1


def test_honest_packet_passes_scan_mode(kr, table, paths) -> None:
    for i, p in enumerate(paths):
        h = forward(kr, p, tag=i)
        v = verify_scan(table, h)
        assert v.ok and v.matched_index == i


def test_expectation_matches_forward(kr, paths) -> None:
    """双实现交叉校验：预计算期望值必须与逐跳累积完全一致。"""
    rng = random.Random(11)
    for p in paths:
        for _ in range(50):
            nonce = rng.getrandbits(56)
            h = forward(kr, p, tag=0, nonce=nonce)
            exp = expectation(kr, p)
            from mpv.core.scheme import _h

            assert exp.expect(_h(nonce)) == h.acc


# ------------------------------------------------------------------ 顺序
def test_order_binding(kr) -> None:
    a = path_of(kr, [1, 2, 3, 16])
    b = path_of(kr, [1, 3, 2, 16])
    h = forward(kr, a, tag=0)
    assert verify_tag(ExpectationTable(kr, [a]), h).ok
    assert not verify_tag(ExpectationTable(kr, [b]), h).ok


# ------------------------------------------------------------------ 攻击
def test_port_tamper_rejected(kr, table, paths) -> None:
    p = list(paths[0])
    h = forward(kr, tuple(p), tag=0)
    p[1] = Hop(sid=p[1].sid, in_port=1, out_port=1)  # 改出端口
    assert not verify_tag(ExpectationTable(kr, [tuple(p)]), h).ok


def test_switch_substitution_rejected(kr, table, paths) -> None:
    p = list(paths[0])
    h = forward(kr, tuple(p), tag=0)
    p[1] = Hop(sid=12, in_port=1, out_port=2)
    assert not verify_tag(ExpectationTable(kr, [tuple(p)]), h).ok


def test_hop_deletion_rejected(kr, table, paths) -> None:
    p = paths[2]  # 5 跳
    h = forward(kr, p, tag=2)
    shorter = (p[0], p[1], p[3], p[4])
    assert not verify_tag(ExpectationTable(kr, [shorter]), h).ok


def test_header_bitflip_rejected(kr, table, paths) -> None:
    h = forward(kr, paths[0], tag=0)
    bad = Header2(nonce=h.nonce, acc=(h.acc ^ 1), tag=h.tag)
    assert not verify_tag(table, bad).ok


def test_nonce_tamper_rejected(kr, table, paths) -> None:
    h = forward(kr, paths[0], tag=0)
    bad = Header2(nonce=h.nonce ^ 1, acc=h.acc, tag=h.tag)
    assert not verify_tag(table, bad).ok


def test_tag_tamper_rejected(kr, table, paths) -> None:
    """把 tag 改到另一条合法路径上 —— V 与那条路径不符，必须拒绝。"""
    h = forward(kr, paths[0], tag=0)
    bad = Header2(nonce=h.nonce, acc=h.acc, tag=1)
    assert not verify_tag(table, bad).ok
    # 但完整扫描仍能认出它确实走了一条合法路径
    assert verify_scan(table, bad).matched_index == 0


# ------------------------------------------------------------------ 流级
def test_flow_aggregation_roundtrip(kr, table, paths) -> None:
    rng = random.Random(3)
    acc = FlowAccumulator()
    for _ in range(200):
        i = rng.randrange(len(paths))
        acc.add(forward(kr, paths[i], tag=i))
    rep = acc.report()
    ok, checks = verify_flow(table, rep)
    assert ok and checks == rep.entries
    assert rep.packets == 200
    assert compression_ratio(rep) > 20


def test_flow_detects_tamper(kr, table, paths) -> None:
    acc = FlowAccumulator()
    for _ in range(50):
        acc.add(forward(kr, paths[0], tag=0))
    acc.add(forward(kr, paths[1], tag=1))  # 混入一条非法 tag 的包
    rep = acc.report()
    rep.sums[1] = (rep.sums[1] + 1) % P  # 篡改累计值
    ok, _ = verify_flow(table, rep)
    assert not ok


def test_flow_multipath_supported(kr, table, paths) -> None:
    """同一流的不同包走不同合法路径，流级判定仍应通过。"""
    acc = FlowAccumulator()
    for i, p in enumerate(paths):
        for _ in range(10):
            acc.add(forward(kr, p, tag=i))
    ok, checks = verify_flow(table, acc.report())
    assert ok and checks == len(paths)


# ------------------------------------------------------------------ 边界
def test_empty_path_rejected(kr) -> None:
    with pytest.raises(ValueError):
        forward(kr, ())


def test_tag_out_of_range(kr, table) -> None:
    h = forward(kr, table.candidates[0], tag=0)
    assert not verify_tag(table, Header2(h.nonce, h.acc, 200)).ok


def test_multiple_hop_update_equivalence(kr) -> None:
    """逐跳更新与一次性 forward 等价。"""
    p = path_of(kr, [1, 2, 3, 4, 16])
    nonce = 0x123456789A
    h = ingress(kr, p[0], tag=0, nonce=nonce)
    for i, hop in enumerate(p[1:], start=2):
        h = advance(kr, hop, h, i)
    assert h == forward(kr, p, tag=0, nonce=nonce)
