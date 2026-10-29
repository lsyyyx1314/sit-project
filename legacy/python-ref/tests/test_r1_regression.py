"""回归测试：确认申报书原始构造 (R1) 确实不具备判别力。

这些用例不是在验证「功能正确」，而是在把已知缺陷钉死：
一旦有人改动 proposal.py 使缺陷消失，测试会失败并提醒重新评估。
"""

from __future__ import annotations

import random

from mpv.core import proposal as P


def test_w_is_multiple_of_p2_minus_1() -> None:
    par = P.make_params(bits=16, seed=1)
    assert par.w % (par.p2 - 1) == 0


def test_g_pow_w_is_one() -> None:
    par = P.make_params(bits=16, seed=1)
    assert pow(par.g, par.w, par.p2) == 1


def test_forged_path_accepted() -> None:
    """换掉全部交换机和端口，式 (5)(6) 仍然判「合法」。"""
    par = P.make_params(bits=16, seed=1)
    rng = random.Random(3)
    s_legit = [11, 22, 33]
    k_legit = [101, 202, 303]
    r_seq = [7, 8, 9]

    s_bad = [44, 55, 66]
    k_bad = [404, 505, 606]
    h_bad = P.forward(par, s_bad, k_bad, r_seq)

    assert P.verify_packet(par, sum(s_legit), sum(k_legit), h_bad) is True


def test_honest_flow_often_rejected() -> None:
    """式 (11)(12) 口径不一致：诚实流也大概率判不过（假阴性）。"""
    par = P.make_params(bits=16, seed=1)
    rng = random.Random(5)
    ok = 0
    n = 100
    for _ in range(n):
        s_seq = [rng.randrange(1, 1000) for _ in range(3)]
        k_seq = [rng.randrange(1, 1000) for _ in range(3)]
        r_seq = [rng.randrange(1, 1000) for _ in range(3)]
        h = P.forward(par, s_seq, k_seq, r_seq)
        vi_s, vi_k, vi_rs, vi_rk = P.accumulate(par, [h], [r_seq[0]])
        if P.verify_flow(par, sum(s_seq), sum(k_seq), vi_s, vi_k, vi_rs, vi_rk):
            ok += 1
    assert ok <= 1, f"诚实流意外通过 {ok}/{n}，式 (11)(12) 可能已被修正，请复核"


def test_euler_optimization_is_sound() -> None:
    """式 (13) 本身是成立的，可作为后续实现的正确性对照。"""
    par = P.make_params(bits=32, seed=1)
    for x in (0, 1, 2, 1000, par.p2 + 12345, 10**12):
        assert P.euler_opt(par, x)[0] == P.euler_opt(par, x)[1]
