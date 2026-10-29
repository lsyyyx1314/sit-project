"""定长摘要原语。

验证头的核心约束是 **长度恒定**：无论路径 2 跳还是 16 跳，头部都只占
NONCE_BITS + TAG_BITS 位。因此这里不使用任何随输入增长的编码，只生成
固定 64 位的带密钥摘要。
"""

from __future__ import annotations

from hashlib import blake2b

NONCE_BITS = 64
TAG_BITS = 64
NONCE_BYTES = NONCE_BITS // 8
TAG_BYTES = TAG_BITS // 8

# 验证头总长（字节）。计划书 3.4 节要求 |H| = O(1)，该常量即该结论的落地形式。
HEADER_BYTES = NONCE_BYTES + TAG_BYTES


def keyed_digest(key: int, payload: bytes) -> int:
    """带密钥的 64 位摘要。

    key 会被规整为 32 字节 big-endian 作为 blake2b 的密钥，
    因此任意整数密钥都可用（包括超过 64 位的端口密钥）。
    """
    k = (key % (1 << 256)).to_bytes(32, "big")
    h = blake2b(digest_size=TAG_BYTES, key=k)
    h.update(payload)
    return int.from_bytes(h.digest(), "big")


def nonce_bytes(nonce: int) -> bytes:
    return (nonce % (1 << NONCE_BITS)).to_bytes(NONCE_BYTES, "big")


def tag_bytes(tag: int) -> bytes:
    return (tag % (1 << TAG_BITS)).to_bytes(TAG_BYTES, "big")
