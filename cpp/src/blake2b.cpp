#include "blake2b.h"

#include <cstring>

namespace mpv {
namespace {

constexpr uint64_t IV[8] = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
    0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
    0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL};

constexpr uint8_t SIGMA[12][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
    {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
    {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
    {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
    {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
    {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
    {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
    {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
    {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3}};

inline uint64_t rotr64(uint64_t x, int n) {
  return (x >> n) | (x << (64 - n));
}

inline uint64_t load64(const uint8_t* p) {
  uint64_t v = 0;
  for (int i = 7; i >= 0; --i) v = (v << 8) | p[i];
  return v;
}

inline void store64(uint8_t* p, uint64_t v) {
  for (int i = 0; i < 8; ++i) {
    p[i] = static_cast<uint8_t>(v & 0xff);
    v >>= 8;
  }
}

inline void G(uint64_t* v, int a, int b, int c, int d, uint64_t x, uint64_t y) {
  v[a] = v[a] + v[b] + x;
  v[d] = rotr64(v[d] ^ v[a], 32);
  v[c] = v[c] + v[d];
  v[b] = rotr64(v[b] ^ v[c], 24);
  v[a] = v[a] + v[b] + y;
  v[d] = rotr64(v[d] ^ v[a], 16);
  v[c] = v[c] + v[d];
  v[b] = rotr64(v[b] ^ v[c], 63);
}

void compress(uint64_t* h, const uint8_t block[128], uint64_t t, bool last) {
  uint64_t v[16];
  uint64_t m[16];
  for (int i = 0; i < 8; ++i) v[i] = h[i];
  for (int i = 0; i < 8; ++i) v[i + 8] = IV[i];
  v[12] ^= t;
  v[13] ^= 0;
  if (last) v[14] = ~v[14];
  for (int i = 0; i < 16; ++i) m[i] = load64(block + i * 8);

  for (int r = 0; r < 12; ++r) {
    const uint8_t* s = SIGMA[r];
    G(v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
    G(v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
    G(v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
    G(v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
    G(v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
    G(v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
    G(v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
    G(v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
  }
  for (int i = 0; i < 8; ++i) h[i] ^= v[i] ^ v[i + 8];
}

}  // namespace

void blake2b(uint8_t* out, size_t outlen, const void* in, size_t inlen,
             const void* key, size_t keylen) {
  uint64_t h[8];
  std::memcpy(h, IV, sizeof(h));
  h[0] ^= 0x01010000ULL ^ (static_cast<uint64_t>(keylen) << 8) ^
          static_cast<uint64_t>(outlen);

  uint8_t block[128];
  uint64_t t = 0;
  const uint8_t* msg = static_cast<const uint8_t*>(in);

  if (keylen > 0) {
    std::memset(block, 0, sizeof(block));
    std::memcpy(block, key, keylen);
    t += 128;
    compress(h, block, t, inlen == 0);
    if (inlen == 0) {
      // 密钥块即最后一块
      for (size_t i = 0; i < outlen; ++i)
        out[i] = static_cast<uint8_t>((h[i / 8] >> (8 * (i % 8))) & 0xff);
      return;
    }
  }

  size_t i = 0;
  while (inlen - i > 128) {
    t += 128;
    compress(h, msg + i, t, false);
    i += 128;
  }
  size_t rem = inlen - i;
  std::memset(block, 0, sizeof(block));
  std::memcpy(block, msg + i, rem);
  t += rem;
  compress(h, block, t, true);

  for (size_t k = 0; k < outlen; ++k)
    out[k] = static_cast<uint8_t>((h[k / 8] >> (8 * (k % 8))) & 0xff);
}

uint64_t blake2b_u64(const void* in, size_t inlen) {
  uint8_t buf[8];
  blake2b(buf, 8, in, inlen, nullptr, 0);
  uint64_t v = 0;
  for (int i = 0; i < 8; ++i) v = (v << 8) | buf[i];  // 大端
  return v;
}

}  // namespace mpv
