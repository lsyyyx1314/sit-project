"""定长验证头与逐跳更新。

设计要点（对应计划书 R1、R2 的修正）：

* **长度恒定**：头部只有 nonce 与 tag 两个 64 位字段，共 HEADER_BYTES 字节。
  无论路径 2 跳还是 16 跳，长度不变，直接满足式 (4) 的 |H| = O(1)。

* **入口初始化**（对应式 3）：入口交换机选取一次性随机数 r 作为 nonce，
  并用「入口端口密钥」派生初始 tag：

      tag_0 = D( K_entry , nonce )

* **逐跳更新**（补上申报书缺失的更新式）：

      tag_i = D( K_i , nonce || tag_{i-1} )

  其中 D 是带密钥的定长摘要，K_i = k_si 为式 (2) 的端口密钥。

* **非交换性（R2 的解法）**：式中的 tag_{i-1} 参与前一跳摘要的输入，
  因此 tag_i 依赖完整的前缀序列。交换任意两跳的顺序都会改变中间状态，
  最终 tag 必然不同——这是「非交换性」在工程上的可验证形式，且不需要
  在数据平面做模幂运算（规避 R4）。

* **随机性（R1 的解法）**：随机数只以 nonce 明文出现，不进入需要「消去」
  的指数位置。控制器知道 nonce，因此可以复算任意候选路径的 tag，
  既不需要「消去 r」，也不会出现 g^w ≡ 1 退化为恒等式的漏洞。
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import ClassVar, Optional

from .digest import HEADER_BYTES, NONCE_BITS, keyed_digest, nonce_bytes, tag_bytes
from .keys import Hop, KeyRing


@dataclass(frozen=True)
class Header:
    """定长验证头。"""

    nonce: int
    tag: int

    # 长度恒为 HEADER_BYTES，与路径长度无关
    size_bytes: ClassVar[int] = HEADER_BYTES

    def wire(self) -> bytes:
        """线上字节表示，用于抓包比对长度。"""
        return nonce_bytes(self.nonce) + tag_bytes(self.tag)

    def __str__(self) -> str:  # pragma: no cover - 日志用
        return f"H(n={self.nonce:016x}, t={self.tag:016x})"


def _payload(nonce: int, tag: Optional[int]) -> bytes:
    b = nonce_bytes(nonce)
    if tag is not None:
        b += tag_bytes(tag)
    return b


def ingress_init(kr: KeyRing, hop: Hop, nonce: Optional[int] = None) -> Header:
    """入口交换机初始化验证头（对应式 3）。

    nonce 由入口交换机生成，攻击者可见但不可预测；tag 由端口密钥派生，
    没有密钥就无法为任意 nonce 计算合法 tag。
    """
    if nonce is None:
        nonce = secrets.randbits(NONCE_BITS)
    key = kr.port_key(hop.sid, hop.in_port, hop.out_port)
    return Header(nonce=nonce, tag=keyed_digest(key, _payload(nonce, None)))


def hop_update(kr: KeyRing, hop: Hop, h: Header) -> Header:
    """中间交换机逐跳更新（申报书缺失的更新式）。"""
    key = kr.port_key(hop.sid, hop.in_port, hop.out_port)
    return Header(nonce=h.nonce, tag=keyed_digest(key, _payload(h.nonce, h.tag)))


def forward(kr: KeyRing, path, nonce: Optional[int] = None) -> Header:
    """把整条路径跑一遍，返回出口处的验证头（用于测试与仿真）。"""
    if not path:
        raise ValueError("path 不能为空")
    h = ingress_init(kr, path[0], nonce=nonce)
    for hop in path[1:]:
        h = hop_update(kr, hop, h)
    return h
