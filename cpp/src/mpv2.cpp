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
// P = 2^64 − 59 是广义梅森素数：2^64 ≡ 59 (mod P)。
// 128 位积按此恒等式两次折叠即得余数，避免通用 128-bit 取模
// （实测 6.6ns → 3.1ns @3.8GHz）；数学上与 (a*b) % P 完全等价，
// 黄金向量与 712 项断言回归把关。回卷边界情形显式处理（见各步注释）。
uint64_t mulmod(uint64_t a, uint64_t b) {
  unsigned __int128 c = (unsigned __int128)a * b;
  uint64_t hi = (uint64_t)(c >> 64), lo = (uint64_t)c;
  // 第一次折叠：hi·2^64 + lo ≡ hi·59 + lo（≤ 59·(2^64−1)+2^64−1 < 2^71，不溢出）
  unsigned __int128 t = (unsigned __int128)hi * 59 + lo;
  // 第二次折叠：t ≡ lo(t) + hi(t)·59（hi(t) ≤ 59；此加法至多回卷一次）
  uint64_t k = (uint64_t)(t >> 64) * 59;
  uint64_t r = (uint64_t)t + k;
  if (r < k)
    r += 59;  // 回卷：真实值 = 2^64 + (r − k) ≡ 59 + r ≤ 3539 < P，无需再减
  else if (r >= P)
    r -= P;  // 未回卷：真实值 < 2^64 < 2P，至多减一次
  return r;
}

uint64_t addmod(uint64_t a, uint64_t b) {
  // a+b = 2^64·进位 + r，进位时 2^64 ≡ 59；补偿后仍可能再回卷一次
  // （r ≤ 2^64−2，59+r ≤ 2^64+57），二次回卷后 ≤ 116 < P
  uint64_t r = a + b;
  uint64_t c = (r < a) ? 59u : 0u;
  uint64_t s = r + c;
  if (s < r)
    s += 59;
  else if (s >= P)
    s -= P;
  return s;
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
  // 备忘录：同一 (sid,in,out) 的 hop_key 恒定（3 次 blake2b），数据面逐包
  // 逐跳都会取用——缓存把每跳的密钥派生从 3 次哈希降到 1 次查表。
  // 线程约定：单线程访问（dashboard 的控制器调用经互斥串行化）。
  uint32_t k = (uint32_t)((h.sid << 16) | (h.in_port << 8) | h.out_port);
  auto it = hop_cache_.find(k);
  if (it != hop_cache_.end()) return it->second;
  uint64_t ks = port_key(h);
  HopKey hk{prf(ks, "a", 1), prf(ks, "b", 1)};
  hop_cache_.emplace(k, hk);
  return hk;
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
  return verify_tag(hdr, h_of(hdr.nonce));
}

Verdict ExpectationTable::verify_tag(const Header& hdr, uint64_t hh) const {
  Verdict v;
  if (hdr.tag >= table_.size()) return v;
  v.checks = 1;
  if (table_[hdr.tag].expect(hh) == hdr.acc) {
    v.ok = true;
    v.matched = hdr.tag;
  }
  return v;
}

Verdict ExpectationTable::verify_scan(const Header& hdr) const {
  return verify_scan(hdr, h_of(hdr.nonce));
}

Verdict ExpectationTable::verify_scan(const Header& hdr, uint64_t hh) const {
  Verdict v;
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
// 平坦存储（M5.15）：环形缓冲（到达顺序，O(1) 淘汰最旧）+ 开链桶索引
// （O(1) 判重）。节点即 ring 槽位本身（无逐条目 malloc），桶数 ≥ 2×容量
// （负载 ≤ 0.5）。对比此前的节点式 unordered_set：内存 ~229KB → ~80KB/方向
//（容量 4096），稳态零分配。
// 语义不变：容量 W 内重复判重放；淘汰后的陈旧 nonce 再次出现按新包处理。
// 此前的两个缺陷（M5.11 修复）：O(W) 线性扫描；nonce==0 特例绕过。
struct NonceWindow::Impl {
  std::vector<uint64_t> ring;   // cap：到达顺序
  std::vector<int32_t> bucket;  // 2^k：桶头（节点下标），-1 空
  std::vector<int32_t> next;    // cap：桶内链表 next
  uint64_t mask = 0;
  size_t head = 0;              // 下一个写入位置（满时即最旧元素）
};

// splitmix64 终混（桶索引用；nonce 已是 56bit 高熵值）
inline uint32_t nwin_hash(uint64_t x, uint64_t mask) {
  x ^= x >> 30;
  x *= 0xbf58476d1ce4e5b9ULL;
  x ^= x >> 27;
  x *= 0x94d049bb133111ebULL;
  x ^= x >> 31;
  return (uint32_t)(x & mask);
}

NonceWindow::NonceWindow(size_t capacity)
    : impl_(new Impl), cap_(capacity ? capacity : 1) {
  impl_->ring.assign(cap_, 0);
  impl_->next.assign(cap_, -1);
  size_t b = 2;
  while (b < cap_ * 2) b <<= 1;
  impl_->bucket.assign(b, -1);
  impl_->mask = b - 1;
}

NonceWindow::NonceWindow(NonceWindow&& o) noexcept
    : impl_(o.impl_), cap_(o.cap_), n_(o.n_) {
  o.impl_ = nullptr;
  o.n_ = 0;
}

NonceWindow& NonceWindow::operator=(NonceWindow&& o) noexcept {
  if (this != &o) {
    delete impl_;  // 此处 Impl 已是完整类型
    impl_ = o.impl_;
    cap_ = o.cap_;
    n_ = o.n_;
    o.impl_ = nullptr;
    o.n_ = 0;
  }
  return *this;
}

NonceWindow::~NonceWindow() { delete impl_; }

bool NonceWindow::see(uint64_t nonce) {
  uint32_t b = nwin_hash(nonce, impl_->mask);
  for (int32_t j = impl_->bucket[b]; j >= 0; j = impl_->next[j])
    if (impl_->ring[(size_t)j] == nonce) return false;  // 窗口内重复：重放
  if (n_ == cap_) {
    // 淘汰最旧（节点下标 = head）：从其所在桶链摘除
    uint32_t ob = nwin_hash(impl_->ring[impl_->head], impl_->mask);
    int32_t* link = &impl_->bucket[ob];
    while (*link >= 0 && (size_t)*link != impl_->head) link = &impl_->next[*link];
    if (*link >= 0) *link = impl_->next[*link];
  } else {
    ++n_;
  }
  impl_->ring[impl_->head] = nonce;
  impl_->next[impl_->head] = impl_->bucket[b];
  impl_->bucket[b] = (int32_t)impl_->head;
  impl_->head = (impl_->head + 1) % cap_;
  return true;
}

}  // namespace mpv
