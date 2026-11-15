// BLAKE2b（RFC 7693）—— 支持可变摘要长度与密钥模式。
//
// 之所以自己实现而不是依赖 OpenSSL：MPV-2 需要 digest_size=8、keylen=32 的
// 带密钥 BLAKE2b，OpenSSL 的 EVP 接口只暴露 digest_size=64 的定长版本。
// 该实现与 Python 的 hashlib.blake2b(digest_size=8, key=...) 逐位一致，
// 由 cpp/tests/golden 交叉校验。
#pragma once

#include <cstddef>
#include <cstdint>

namespace mpv {

// out 至少 outlen 字节（outlen ≤ 64）。
// key 可为 nullptr，keylen ≤ 64。
void blake2b(uint8_t* out, size_t outlen,
             const void* in, size_t inlen,
             const void* key, size_t keylen);

// 便捷封装：返回 64 位大端摘要（等价于 digest_size=8 后按大端解释）。
uint64_t blake2b_u64(const void* in, size_t inlen);

}  // namespace mpv
