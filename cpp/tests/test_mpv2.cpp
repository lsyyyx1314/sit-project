// MPV-2 C++ 实现测试。
//
// 两部分：
//   1. 黄金向量交叉校验 —— 与 Python 参考实现逐位对比（密钥派生、期望值、
//      逐跳累积、公开哈希）。这是"两套独立实现给出同一结果"的证据。
//   2. 功能与对抗断言 —— 顺序绑定、篡改检出、候选集判定、流级聚合。
//
// 运行： ./build/tests ../results/golden_vectors.txt
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "mpv2.h"

using namespace mpv;

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond, msg)                                        \
  do {                                                          \
    if (cond) {                                                 \
      ++g_pass;                                                 \
    } else {                                                    \
      ++g_fail;                                                 \
      std::printf("  [FAIL] %s  (%s:%d)\n", msg, __FILE__, __LINE__); \
    }                                                           \
  } while (0)

#define CHECK_EQ(a, b, msg)                                              \
  do {                                                                   \
    unsigned long long va = (unsigned long long)(a), vb = (unsigned long long)(b); \
    if (va == vb) {                                                      \
      ++g_pass;                                                          \
    } else {                                                             \
      ++g_fail;                                                          \
      std::printf("  [FAIL] %s  期望 %llu 实得 %llu (%s:%d)\n", msg, va, vb, \
                  __FILE__, __LINE__);                                   \
    }                                                                    \
  } while (0)

// ---------------------------------------------------------------------------
// 黄金向量
// ---------------------------------------------------------------------------

static bool load_golden(const char* path, uint64_t& seed,
                        std::vector<Path>& paths) {
  std::ifstream in(path);
  if (!in) {
    std::printf("无法打开黄金向量文件: %s\n", path);
    return false;
  }
  std::vector<std::string> lines;
  {
    std::string l;
    while (std::getline(in, l))
      if (!l.empty()) lines.push_back(l);
  }
  for (const std::string& l : lines) {
    if (l.rfind("SEED ", 0) == 0) {
      std::sscanf(l.c_str(), "SEED %llu", (unsigned long long*)&seed);
      break;
    }
  }
  KeyRing kr_all = KeyRing::generate(16, 4, seed);

  for (const std::string& line : lines) {
    if (line.empty()) continue;
    std::istringstream ss(line);
    std::string kind;
    ss >> kind;

    if (kind == "HOP") {
      uint32_t sid, ip, op;
      unsigned long long ks, a, b;
      ss >> sid >> ip >> op >> ks >> a >> b;
      Hop h{sid, ip, op};

      // 密钥材料：由 seed 派生，需要与 Python 完全一致
      CHECK_EQ(kr_all.port_key(h), ks, "port_key");
      HopKey hk = kr_all.hop_key(h);
      CHECK_EQ(hk.a, a, "hop_key.a");
      CHECK_EQ(hk.b, b, "hop_key.b");
    } else if (kind == "PATH") {
      unsigned long long A, B;
      int n;
      ss >> A >> B >> n;
      Path p;
      for (int i = 0; i < n; ++i) {
        std::string tok;
        ss >> tok;
        int sid = 0, ip = 0, op = 0;
        std::sscanf(tok.c_str(), "%d:%d:%d", &sid, &ip, &op);
        p.push_back(Hop{(uint32_t)sid, (uint32_t)ip, (uint32_t)op});
      }
      Expectation e = expectation(kr_all, p);
      CHECK_EQ(e.A, A, "expectation.A");
      CHECK_EQ(e.B, B, "expectation.B");
      paths.push_back(p);
    } else if (kind == "VEC") {
      int idx;
      unsigned long long nonce, hv, acc;
      ss >> idx >> nonce >> hv >> acc;
      CHECK_EQ(h_of(nonce), hv, "h_of(nonce)");
      Header hdr = forward(kr_all, paths.at(idx), 0, nonce);
      CHECK_EQ(hdr.acc, acc, "forward().acc");
    }
  }
  return true;
}

// ---------------------------------------------------------------------------
// 功能与对抗
// ---------------------------------------------------------------------------

static Path make_path(std::initializer_list<uint32_t> sids) {
  Path p;
  uint32_t i = 0;
  for (uint32_t s : sids) {
    p.push_back(Hop{s, 1, (i % 2 == 0) ? 2u : 3u});
    ++i;
  }
  return p;
}

static void functional_tests() {
  KeyRing kr = KeyRing::generate(16, 4, 0xC0FFEE);

  // 定长
  CHECK_EQ(HEADER_BYTES, 16, "头部长度 16 字节");
  uint8_t buf[HEADER_BYTES];
  Header hd = forward(kr, make_path({1, 2, 3, 4}), 0, 0x123456789AULL);
  encode_header(hd, buf);
  Header back = decode_header(buf);
  CHECK(back.nonce == hd.nonce && back.acc == hd.acc && back.tag == hd.tag,
        "头部编解码往返一致");

  // 诚实通过
  Path p = make_path({1, 5, 9, 13});
  std::vector<Path> one{p};
  ExpectationTable t1(kr, one);
  Header honest = forward(kr, p, 0, 42);
  CHECK(t1.verify_tag(honest).ok, "诚实路径 tag 模式通过");
  CHECK(t1.verify_scan(honest).ok, "诚实路径 scan 模式通过");

  // 顺序敏感
  Path swapped = make_path({5, 1, 9, 13});
  std::vector<Path> two{swapped};
  ExpectationTable t2(kr, two);
  CHECK(!t2.verify_tag(honest).ok, "跳序交换被拒绝");

  // 端口篡改
  Path tampered = p;
  tampered[2].out_port = 1;
  std::vector<Path> three{tampered};
  ExpectationTable t3(kr, three);
  CHECK(!t3.verify_tag(honest).ok, "端口篡改被拒绝");

  // 交换机旁路
  Path bypass = p;
  bypass[1] = Hop{14, 1, 2};
  std::vector<Path> four{bypass};
  ExpectationTable t4(kr, four);
  CHECK(!t4.verify_tag(honest).ok, "交换机旁路被拒绝");

  // 头部比特翻转
  Header flipped = honest;
  flipped.acc ^= 1;
  CHECK(!t1.verify_tag(flipped).ok, "验证头比特翻转被拒绝");

  // 候选集定位
  std::vector<Path> cands{make_path({1, 2, 5}), make_path({1, 3, 5}),
                          make_path({1, 4, 5})};
  ExpectationTable t5(kr, cands);
  Header h2 = forward(kr, cands[1], 1, 777);
  Verdict v = t5.verify_tag(h2);
  CHECK(v.ok && v.matched == 1, "候选集命中唯一下标");

  // tag 篡改：V 属于路径 1，tag 声称 0
  Header spoof = h2;
  spoof.tag = 0;
  CHECK(!t5.verify_tag(spoof).ok, "tag 篡改被拒绝");
  CHECK(t5.verify_scan(spoof).matched == 1, "scan 仍能识别真实路径");

  // 大样本检出率
  int trials = 3000, detected = 0, counted = 0;
  uint64_t s = 12345;
  auto next = [&s]() {
    s = s * 6364136223846793005ULL + 1442695040888963407ULL;
    return s;
  };
  for (int i = 0; i < trials; ++i) {
    Path base = make_path({1, (uint32_t)(2 + next() % 8), (uint32_t)(10 + next() % 5), 16});
    Header hh = forward(kr, base, 0, next() & ((1ULL << 56) - 1));
    Path bad = base;
    uint32_t idx = (uint32_t)(next() % bad.size());
    bad[idx].out_port = 1 + (uint32_t)(next() % 4);
    if (bad[idx].out_port == base[idx].out_port) bad[idx].out_port = 3;
    if (bad == base) continue; // 篡改退化为无操作，不计入分母
    ++counted;
    std::vector<Path> tb{bad};
    ExpectationTable tbad(kr, tb);
    if (!tbad.verify_tag(hh).ok) ++detected;
  }
  CHECK_EQ(detected, counted, "随机篡改检出率 100%");
}

int main(int argc, char** argv) {
  const char* golden = (argc > 1) ? argv[1] : "../results/golden_vectors.txt";

  std::printf("== 1. 黄金向量交叉校验（C++ vs Python 参考实现）==\n");
  uint64_t seed = 0;
  std::vector<Path> paths;
  if (!load_golden(golden, seed, paths)) return 2;
  std::printf("   已比对 %d 项\n", g_pass);

  int before = g_pass;
  std::printf("== 2. 功能与对抗断言 ==\n");
  functional_tests();
  std::printf("   新增 %d 项\n", g_pass - before);

  std::printf("\n结果：通过 %d，失败 %d\n", g_pass, g_fail);
  return g_fail == 0 ? 0 : 1;
}
