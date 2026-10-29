#include "mpv2.h"

#include <cstring>

#include "blake2b.h"

namespace mpv {
namespace {

// Python: seed.to_bytes(32, "big")
void put_u64_be32(uint8_t* dst, uint64_t v) {
  std::memset(dst, 0, 32);
  for (int i = 0; i < 8; ++i) dst[31 - i] = static_cast<uint8_t>((v >> (8 * i)) & 0xff);
}

void put_u56_be(uint8_t* dst, uint64_t v) {
  for (int i = 0; i < 7; ++i)
    dst[6 - i] = static_cast<uint8_t>((v >> (8 * i)) & 0xff);
}

// keys.py::_derive —— 无密钥 blake2b，输入 seed(32B) || label
uint64_t derive(uint64_t seed, const std::string& label) {
  uint8_t buf[32 + 128];
  put_u64_be32(buf, seed);
  size_t n = label.size() > 128 ? 128 : label.size();
  std::memcpy(buf + 32, label.data(), n);
  return blake2b_u64(buf, 32 + n);
}

// scheme.py::_prf —— 带密钥 blake2b，key = ks(32B)，data = label
uint64_t prf(uint64_t key, const char* label, size_t len) {
  uint8_t k[32];
  put_u64_be32(k, key);
  uint8_t out[8];
  blake2b(out, 8, label, len, k, 32);
  uint64_t v = 0;
  for (int i = 0; i < 8; ++i) v = (v << 8) | out[i];
  return v % P;
}

}  // namespace

// ---------------------------------------------------------------- 模运算
uint64_t mulmod(uint64_t a, uint64_t b) {
  return static_cast<uint64_t>((static_cast<unsigned __int128>(a) * b) % P);
}

uint64_t addmod(uint64_t a, uint64_t b) {
  // 直接用 128 位中间量，避免 a+b 溢出 2^64 时的手工修正
  return static_cast<uint64_t>(
      (static_cast<unsigned __int128>(a) + static_cast<unsigned __int128>(b)) % P);
}

uint64_t powmod(uint64_t base, uint64_t exp) {
  uint64_t r = 1 % P;
  base %= P;
  while (exp) {
    if (exp & 1) r = mulmod(r, base);
    base = mulmod(base, base);
    exp >>= 1;
  }
  return r;
}

// ---------------------------------------------------------------- 密钥
KeyRing KeyRing::generate(uint32_t n_switches, uint32_t ports_per_switch,
                          uint64_t seed) {
  KeyRing kr;
  for (uint32_t sid = 1; sid <= n_switches; ++sid) {
    SwitchKeys sk;
    sk.key = derive(seed, "switch:" + std::to_string(sid));
    for (uint32_t p = 1; p <= ports_per_switch; ++p)
      sk.ports[p] = derive(seed, "port:" + std::to_string(sid) + ":" + std::to_string(p));
    kr.switches_[sid] = std::move(sk);
  }
  return kr;
}

uint64_t KeyRing::port_key(const Hop& h) const {
  const SwitchKeys& sk = switches_.at(h.sid);
  uint64_t raw = sk.key ^ sk.ports.at(h.in_port) ^ sk.ports.at(h.out_port);
  return derive(raw, "ks:" + std::to_string(h.sid) + ":" +
                        std::to_string(h.in_port) + ":" + std::to_string(h.out_port));
}

HopKey KeyRing::hop_key(const Hop& h) const {
  uint64_t ks = port_key(h);
  return HopKey{prf(ks, "a", 1), prf(ks, "b", 1)};
}

// ---------------------------------------------------------------- 哈希
uint64_t h_of(uint64_t nonce) {
  uint8_t buf[6 + 7];
  std::memcpy(buf, "mpv2-h", 6);
  put_u56_be(buf + 6, nonce);
  return blake2b_u64(buf, 6 + 7) % P;
}

// ---------------------------------------------------------------- 头部编解码
void encode_header(const Header& h, uint8_t out[HEADER_BYTES]) {
  put_u56_be(out, h.nonce);
  for (int i = 0; i < 8; ++i)
    out[7 + i] = static_cast<uint8_t>((h.acc >> (8 * (7 - i))) & 0xff);
  out[15] = h.tag;
}

Header decode_header(const uint8_t in[HEADER_BYTES]) {
  Header h{};
  for (int i = 0; i < 7; ++i) h.nonce = (h.nonce << 8) | in[i];
  for (int i = 0; i < 8; ++i) h.acc = (h.acc << 8) | in[7 + i];
  h.tag = in[15];
  return h;
}

// ---------------------------------------------------------------- 数据面
uint64_t contribution(const KeyRing& kr, const Hop& h, uint64_t hh) {
  HopKey k = kr.hop_key(h);
  return addmod(k.a, mulmod(k.b, hh));
}

Header ingress(const KeyRing& kr, const Hop& h, uint8_t tag, uint64_t nonce) {
  Header hdr{};
  hdr.nonce = nonce;
  hdr.tag = tag;
  hdr.acc = contribution(kr, h, h_of(nonce)); // ρ^0 = 1
  return hdr;
}

Header advance(const KeyRing& kr, const Hop& h, const Header& hdr, uint32_t pos) {
  uint64_t c = contribution(kr, h, h_of(hdr.nonce));
  Header out = hdr;
  out.acc = addmod(hdr.acc, mulmod(c, powmod(RHO, pos - 1)));
  return out;
}

Header forward(const KeyRing& kr, const Path& path, uint8_t tag, uint64_t nonce) {
  Header hdr = ingress(kr, path.front(), tag, nonce);
  for (size_t i = 1; i < path.size(); ++i)
    hdr = advance(kr, path[i], hdr, static_cast<uint32_t>(i + 1));
  return hdr;
}

// ---------------------------------------------------------------- 控制面
Expectation expectation(const KeyRing& kr, const Path& path) {
  uint64_t A = 0, B = 0, w = 1;
  for (const Hop& h : path) {
    HopKey k = kr.hop_key(h);
    A = addmod(A, mulmod(k.a, w));
    B = addmod(B, mulmod(k.b, w));
    w = mulmod(w, RHO);
  }
  return Expectation{A, B};
}

ExpectationTable::ExpectationTable(const KeyRing& kr,
                                   const std::vector<Path>& paths)
    : paths_(paths) {
  table_.reserve(paths.size());
  for (const Path& p : paths) table_.push_back(expectation(kr, p));
}

Verdict ExpectationTable::verify_tag(const Header& hdr) const {
  Verdict v;
  if (hdr.tag >= table_.size()) return v;
  uint64_t hh = h_of(hdr.nonce);
  v.checks = 1;
  if (table_[hdr.tag].expect(hh) == hdr.acc) {
    v.ok = true;
    v.matched = hdr.tag;
  }
  return v;
}

Verdict ExpectationTable::verify_scan(const Header& hdr) const {
  Verdict v;
  uint64_t hh = h_of(hdr.nonce);
  for (size_t i = 0; i < table_.size(); ++i) {
    v.checks = static_cast<int>(i + 1);
    if (table_[i].expect(hh) == hdr.acc) {
      v.ok = true;
      v.matched = static_cast<int>(i);
      return v;
    }
  }
  return v;
}

// ---------------------------------------------------------------- CFMV
// 判定式：N·A_P + B_P·Σh ≡ ΣV (mod p)
// 来源：Σ_i (A + B·h_i) = N·A + B·Σh，线性性把 N 次逐包判定压成 1 次。
Verdict ExpectationTable::verify_flow(uint8_t tag, uint64_t n, uint64_t sum_h,
                                      uint64_t sum_v) const {
  Verdict v;
  if (tag >= table_.size() || n == 0) return v;
  v.checks = 1;
  const Expectation& e = table_[tag];
  uint64_t lhs = addmod(mulmod(n % P, e.A), mulmod(e.B, sum_h));
  if (lhs == sum_v) {
    v.ok = true;
    v.matched = tag;
  }
  return v;
}

Verdict ExpectationTable::verify_flow_scan(uint64_t n, uint64_t sum_h,
                                           uint64_t sum_v) const {
  Verdict v;
  if (n == 0) return v;
  for (size_t i = 0; i < table_.size(); ++i) {
    v.checks = static_cast<int>(i + 1);
    const Expectation& e = table_[i];
    uint64_t lhs = addmod(mulmod(n % P, e.A), mulmod(e.B, sum_h));
    if (lhs == sum_v) {
      v.ok = true;
      v.matched = static_cast<int>(i);
      return v;
    }
  }
  return v;
}

// ---------------------------------------------------------------- 重放窗口
// 环形缓冲线性扫描：容量 4096、包速率 ≤ 10^5/s 时，平均扫描 ~2000 次比较，
// 远小于一次 blake2b；不需要哈希表。
bool NonceWindow::see(uint64_t nonce) {
  for (size_t i = 0; i < ring_.size(); ++i) {
    size_t idx = (head_ + i) % ring_.size();
    if (ring_[idx] == nonce && ring_[idx] != 0) return false;
  }
  ring_[head_] = nonce;
  head_ = (head_ + 1) % ring_.size();
  return true;
}

}  // namespace mpv
