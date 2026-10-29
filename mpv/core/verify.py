"""控制器侧验证。

对应申报书 5.1.2 / 5.1.3 的「统一验证」思想，但落到可证明正确的构造上。

控制器持有全网密钥，因此可以：

1. 对**一条**候选路径复算出口 tag，与上报值比对 —— 这就是 BPMV 的判定。
2. 对**一个候选路径集合**逐条复算，返回命中的路径下标 —— 这就是
   「验证合法路径集合」而非「验证固定路径」。
3. 当路径数很多时，用 ``verify_cached`` 复用前缀摘要，避免重复计算，
   把单次验证成本从 O(k·n) 降到 O(k·n) 但常数更小（前缀共享）。

R1 的教训在这里体现为：判定式中没有需要「消去」的随机量，
因此不存在恒真退化的可能。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from .digest import keyed_digest, nonce_bytes, tag_bytes
from .header import Header
from .keys import Hop, KeyRing, Path


@dataclass(frozen=True)
class Verdict:
    ok: bool
    matched_index: Optional[int]
    matched_path: Optional[Path]

    def __bool__(self) -> bool:  # pragma: no cover - 便利语法
        return self.ok


def recompute_tag(kr: KeyRing, path: Path, nonce: int) -> int:
    """按路径复算出口 tag。"""
    if not path:
        raise ValueError("path 不能为空")
    first = path[0]
    tag = keyed_digest(
        kr.port_key(first.sid, first.in_port, first.out_port),
        nonce_bytes(nonce),
    )
    for hop in path[1:]:
        tag = keyed_digest(
            kr.port_key(hop.sid, hop.in_port, hop.out_port),
            nonce_bytes(nonce) + tag_bytes(tag),
        )
    return tag


def verify_path(kr: KeyRing, path: Path, h: Header) -> bool:
    """BPMV 基础判定：上报头是否与给定路径一致。"""
    return recompute_tag(kr, path, h.nonce) == h.tag


def verify_candidates(
    kr: KeyRing,
    candidates: Sequence[Path],
    h: Header,
) -> Verdict:
    """多路径判定：在合法路径集合中查找匹配项。

    这正是「从验证固定路径到验证合法路径集合」的接口级体现。
    """
    for idx, p in enumerate(candidates):
        if verify_path(kr, p, h):
            return Verdict(ok=True, matched_index=idx, matched_path=p)
    return Verdict(ok=False, matched_index=None, matched_path=None)


def verify_cached(
    kr: KeyRing,
    candidates: Sequence[Path],
    h: Header,
) -> Verdict:
    """带前缀缓存的候选集验证。

    多条候选路径在 SDN 多路径场景中通常共享前缀（源→汇聚点）。
    缓存前缀摘要可把重复计算摊掉，是 CPMV「一次验证」在工程上的
    低成本近似：路径数 k 增大时，实际摘要次数远小于 k·n。
    """
    cache: Dict[Tuple[int, ...], int] = {}
    for idx, p in enumerate(candidates):
        tag = _recompute_cached(kr, p, h.nonce, cache)
        if tag == h.tag:
            return Verdict(ok=True, matched_index=idx, matched_path=p)
    return Verdict(ok=False, matched_index=None, matched_path=None)


def _recompute_cached(
    kr: KeyRing,
    path: Path,
    nonce: int,
    cache: Dict[Tuple[int, ...], int],
) -> int:
    prefix: List[Hop] = []
    tag = 0
    for hop in path:
        prefix.append(hop)
        k = tuple((x.sid, x.in_port, x.out_port) for x in prefix)
        if k in cache:
            tag = cache[k]
            continue
        if len(prefix) == 1:
            tag = keyed_digest(
                kr.port_key(hop.sid, hop.in_port, hop.out_port),
                nonce_bytes(nonce),
            )
        else:
            tag = keyed_digest(
                kr.port_key(hop.sid, hop.in_port, hop.out_port),
                nonce_bytes(nonce) + tag_bytes(tag),
            )
        cache[k] = tag
    return tag


def digest_ops(n_candidates: int, path_len: int, shared_prefix: int) -> int:
    """估算摘要次数，用于 CPMV 开销对比（解析模型，非实测）。"""
    if n_candidates <= 0:
        return 0
    return shared_prefix + n_candidates * max(0, path_len - shared_prefix)
