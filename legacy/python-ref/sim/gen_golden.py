"""生成 C++ 实现的黄金测试向量（一次性）。

输出纯文本 results/golden_vectors.txt，便于 C++ 侧用 ifstream 直接读取，
不引入 JSON 依赖。

格式：
    P <域素数>
    RHO <底数>
    SEED <种子>
    HOP <sid> <in> <out> <ks> <a> <b>
    PATH <A> <B> <n> <sid:in:out> ...
    VEC <path_idx> <nonce> <h> <acc>
"""

from __future__ import annotations

from pathlib import Path

from mpv.core import KeyRing
from mpv.core.keys import Hop
from mpv.core.scheme import P, RHO, _h, expectation, forward, hop_key

SEED = 20260501
NONCES = [0x0123456789ABCD, 0xFEDCBA987654, 0, 1, 0x7FFFFFFFFFFF]
PATHS = [
    [(1, 1, 2), (2, 1, 2), (15, 1, 2)],
    [(1, 1, 3), (3, 2, 3), (4, 1, 2), (16, 2, 3)],
    [(1, 1, 2), (5, 3, 1), (6, 1, 2), (7, 2, 3), (8, 1, 2), (15, 3, 2)],
]


def main() -> None:
    kr = KeyRing.generate(n_switches=16, ports_per_switch=4, seed=SEED)
    lines = [f"P {P}", f"RHO {RHO}", f"SEED {SEED}"]

    for sid in range(1, 17):
        for inp in range(1, 5):
            for outp in range(1, 5):
                if inp == outp:
                    continue
                k = hop_key(kr, Hop(sid=sid, in_port=inp, out_port=outp))
                lines.append(
                    f"HOP {sid} {inp} {outp} "
                    f"{kr.port_key(sid, inp, outp)} {k.a} {k.b}"
                )

    for idx, spec in enumerate(PATHS):
        path = tuple(Hop(sid=s, in_port=i, out_port=o) for s, i, o in spec)
        e = expectation(kr, path)
        hop_txt = " ".join(f"{s}:{i}:{o}" for s, i, o in spec)
        lines.append(f"PATH {e.A} {e.B} {len(spec)} {hop_txt}")
        for n in NONCES:
            hdr = forward(kr, path, tag=0, nonce=n)
            lines.append(f"VEC {idx} {n} {_h(n)} {hdr.acc}")

    out = Path("results/golden_vectors.txt")
    out.parent.mkdir(exist_ok=True)
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"写出 {out}（{len(lines)} 行）")


if __name__ == "__main__":
    main()
