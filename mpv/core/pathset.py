"""候选路径集合的前缀树（PathSet）。

动机：SDN 多路径场景中，同一对源/目的的候选路径集在一段时间内是稳定的，
而验证头里的 nonce 是逐包变化的。因此「路径结构」可以预先建好，
每包只做一次遍历——这是 CPMV「多路径一次验证」在工程上可落地的形态。

结构：
    每个节点代表一个路径前缀，children 以 (sid, in_port, out_port) 为键，
    leaf_index 记录以该前缀结尾的候选路径下标。

代价：
    线性遍历 k 条 n 跳路径需 k·n 次摘要；
    前缀树在共享前缀处只算一次，实际摘要次数 = 树中被访问的节点数。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from .digest import keyed_digest, nonce_bytes, tag_bytes
from .header import Header
from .keys import Hop, KeyRing, Path
from .verify import Verdict

HopKey = Tuple[int, int, int]


@dataclass
class _Node:
    children: Dict[HopKey, "_Node"] = field(default_factory=dict)
    leaf_index: Optional[int] = None


def _key(h: Hop) -> HopKey:
    return (h.sid, h.in_port, h.out_port)


class PathSet:
    """可复用的候选路径集合。"""

    def __init__(self, kr: KeyRing, candidates: Sequence[Path]):
        self.kr = kr
        self.candidates: List[Path] = list(candidates)
        self.root = _Node()
        for idx, path in enumerate(self.candidates):
            node = self.root
            for hop in path:
                node = node.children.setdefault(_key(hop), _Node())
            node.leaf_index = idx

    # ------------------------------------------------------------------
    def match(self, h: Header, stats: Optional[Dict[str, int]] = None) -> Verdict:
        """深度优先遍历，命中即返回。"""
        digests = 0
        node = self.root
        tag_prev: Optional[int] = None
        stack: List[Tuple[_Node, Optional[int]]] = [(node, tag_prev)]

        # 迭代式 DFS，避免递归深度带来的开销
        while stack:
            node, tag_prev = stack.pop()
            for key, child in node.children.items():
                sid, in_port, out_port = key
                k = self.kr.port_key(sid, in_port, out_port)
                if tag_prev is None:
                    tag = keyed_digest(k, nonce_bytes(h.nonce))
                else:
                    tag = keyed_digest(
                        k, nonce_bytes(h.nonce) + tag_bytes(tag_prev)
                    )
                digests += 1
                if child.leaf_index is not None and tag == h.tag:
                    if stats is not None:
                        stats["digests"] = digests
                    idx = child.leaf_index
                    return Verdict(ok=True, matched_index=idx, matched_path=self.candidates[idx])
                if child.children:
                    stack.append((child, tag))
        if stats is not None:
            stats["digests"] = digests
        return Verdict(ok=False, matched_index=None, matched_path=None)
