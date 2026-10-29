// MPV-2：面向 SDN 多路径的可验证定长验证头。
//
// 与 Python 参考实现（mpv/core/scheme.py）逐位一致，交叉校验见
// cpp/tests/golden_vectors.txt。
//
// 核心思想：把随机性放在**线性项**而不是指数上，控制器直接代入即可，
// 不存在"消去随机数"的问题，也就不会出现 g^w ≡ 1 的恒真退化。
//
//     h    = H(nonce)                      公开哈希，人人可算
//     c_i  = (a_i + b_i·h) mod p           单跳贡献
//     V    = Σ c_i · ρ^(i-1)  mod p        逐跳累积
//     E(P) = A_P + B_P·h                   控制器期望值（与 nonce 无关）
#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace mpv {

constexpr uint64_t P = 18446744073709551557ULL;   // 2^64 - 59，64 位素数
constexpr uint64_t RHO = 11400714819323198485ULL; // 0x9E3779B97F4A7C15 mod P

constexpr int NONCE_BITS = 56;
constexpr int TAG_BITS = 8;
constexpr int HEADER_BYTES = 16; // 7 + 8 + 1

struct Hop {
  uint32_t sid;
  uint32_t in_port;
  uint32_t out_port;
  bool operator==(const Hop& o) const {
    return sid == o.sid && in_port == o.in_port && out_port == o.out_port;
  }
};

using Path = std::vector<Hop>;

struct HopKey {
  uint64_t a;
  uint64_t b;
};

// ---------------------------------------------------------------- 模运算
uint64_t mulmod(uint64_t a, uint64_t b);
uint64_t addmod(uint64_t a, uint64_t b);
uint64_t powmod(uint64_t base, uint64_t exp);

// ---------------------------------------------------------------- 密钥
class KeyRing {
 public:
  // 与 Python 侧 KeyRing.generate 行为一致：由 seed 派生每台交换机的
  // 身份密钥与各端口密钥。
  static KeyRing generate(uint32_t n_switches, uint32_t ports_per_switch,
                          uint64_t seed);

  uint64_t port_key(const Hop& h) const; // 式 (2)：k_i ⊕ k_in ⊕ k_out 再派生
  HopKey hop_key(const Hop& h) const;

 private:
  struct SwitchKeys {
    uint64_t key;
    std::unordered_map<uint32_t, uint64_t> ports;
  };
  std::unordered_map<uint32_t, SwitchKeys> switches_;
};

// ---------------------------------------------------------------- 公开哈希
uint64_t h_of(uint64_t nonce); // H(nonce) mod P

// ---------------------------------------------------------------- 验证头
struct Header {
  uint64_t nonce; // 56 bit
  uint64_t acc;   // V
  uint8_t tag;    // 路径编号
};

void encode_header(const Header& h, uint8_t out[HEADER_BYTES]);
Header decode_header(const uint8_t in[HEADER_BYTES]);

// ---------------------------------------------------------------- 数据面
uint64_t contribution(const KeyRing& kr, const Hop& h, uint64_t hh);
Header ingress(const KeyRing& kr, const Hop& h, uint8_t tag, uint64_t nonce);
Header advance(const KeyRing& kr, const Hop& h, const Header& hdr, uint32_t pos);
Header forward(const KeyRing& kr, const Path& path, uint8_t tag, uint64_t nonce);

// ---------------------------------------------------------------- 控制面
struct Expectation {
  uint64_t A;
  uint64_t B;
  uint64_t expect(uint64_t hh) const { return addmod(A, mulmod(B, hh)); }
};

Expectation expectation(const KeyRing& kr, const Path& path);

struct Verdict {
  bool ok = false;
  int matched = -1;
  int checks = 0;
};

class ExpectationTable {
 public:
  ExpectationTable(const KeyRing& kr, const std::vector<Path>& paths);
  size_t size() const { return table_.size(); }
  const Path& path(size_t i) const { return paths_[i]; }
  // tag 模式：只检查上报的 tag，O(1)
  Verdict verify_tag(const Header& hdr) const;
  // scan 模式：遍历候选集，O(k)
  Verdict verify_scan(const Header& hdr) const;

 private:
  std::vector<Path> paths_;
  std::vector<Expectation> table_;
};

}  // namespace mpv
