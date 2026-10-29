"""密钥体系。

对应申报书式 (2)：

    k_si = k_i ⊕ k_i^in ⊕ k_i^out

设计意图是把「交换机身份」和「端口转发行为」绑定：一旦入端口或出端口被
篡改，k_si 变化，验证必然失败。

说明：面向上万级密钥时 XOR 熵不足，因此在原型里把 XOR 结果再过一道
密钥派生（blake2b），得到 64 位端口密钥。这一改动不影响式 (2) 的语义，
只是把「可预测」提升为「不可预测」。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import blake2b
from typing import Dict, List, Optional, Sequence, Tuple

import secrets


def _derive(seed: int, label: str) -> int:
    h = blake2b(digest_size=8)
    h.update(seed.to_bytes(32, "big"))
    h.update(label.encode("utf-8"))
    return int.from_bytes(h.digest(), "big")


@dataclass(frozen=True)
class Switch:
    """一台交换机：身份密钥 + 各端口密钥。"""

    sid: int
    key: int
    port_keys: Dict[int, int] = field(default_factory=dict)


class KeyRing:
    """全网密钥集合。控制器与交换机共享，但不外泄。"""

    def __init__(self, switches: Sequence[Switch], seed: Optional[int] = None):
        self.switches: Dict[int, Switch] = {s.sid: s for s in switches}
        self.seed = seed

    # ---------------------------------------------------------------- 构造
    @classmethod
    def generate(
        cls,
        n_switches: int,
        ports_per_switch: int = 4,
        seed: Optional[int] = None,
    ) -> "KeyRing":
        seed = secrets.randbits(256) if seed is None else seed
        switches: List[Switch] = []
        for sid in range(1, n_switches + 1):
            k_i = _derive(seed, f"switch:{sid}")
            ports = {
                p: _derive(seed, f"port:{sid}:{p}")
                for p in range(1, ports_per_switch + 1)
            }
            switches.append(Switch(sid=sid, key=k_i, port_keys=ports))
        return cls(switches, seed=seed)

    # ---------------------------------------------------------------- 查表
    def identity(self, sid: int) -> int:
        return self.switches[sid].key

    def port(self, sid: int, port: int) -> int:
        return self.switches[sid].port_keys[port]

    def port_key(self, sid: int, in_port: int, out_port: int) -> int:
        """式 (2)：k_si = k_i ⊕ k_i^in ⊕ k_i^out，再派生为 64 位。"""
        s = self.switches[sid]
        raw = s.key ^ s.port_keys[in_port] ^ s.port_keys[out_port]
        return _derive(raw, f"ks:{sid}:{in_port}:{out_port}")

    # ---------------------------------------------------------------- 序列化
    def to_dict(self) -> dict:
        return {
            "seed": self.seed,
            "switches": [
                {
                    "sid": s.sid,
                    "key": s.key,
                    "port_keys": {str(k): v for k, v in s.port_keys.items()},
                }
                for s in self.switches.values()
            ],
        }


@dataclass(frozen=True)
class Hop:
    """一跳：交换机 + 入端口 + 出端口。"""

    sid: int
    in_port: int
    out_port: int

    def __str__(self) -> str:  # pragma: no cover - 仅用于日志
        return f"S{self.sid}:{self.in_port}->{self.out_port}"


Path = Tuple[Hop, ...]
