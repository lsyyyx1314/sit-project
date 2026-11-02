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
#include "controller.h"

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

// ---------------------------------------------------------------------------
// CFMV 流级压缩 + 重放窗口
// ---------------------------------------------------------------------------

static void flow_tests() {
  KeyRing kr = KeyRing::generate(16, 4, 0xF10A5);
  Path p = make_path({1, 6, 11, 16});
  std::vector<Path> cands{p, make_path({1, 7, 12, 16})};
  ExpectationTable tb(kr, cands);

  // N 包聚合后一次判定通过，且窗口内每个包逐包判定也通过
  FlowAgg agg;
  for (uint64_t i = 0; i < 50; ++i) {
    Header h = forward(kr, p, 0, 1000 + i);
    agg.add(h.nonce, h.acc);
    CHECK(tb.verify_tag(h).ok, "流内单包逐包判定应通过");
  }
  Verdict v = tb.verify_flow(0, agg.n, agg.sum_h, agg.sum_v);
  CHECK(v.ok, "流级聚合判定通过");
  CHECK_EQ(v.checks, 1, "流级判定检查次数为 1");

  // 线性恒等式：ΣV == N·A + B·Σh（CFMV 的数学根基）
  Expectation e = expectation(kr, p);
  CHECK_EQ(addmod(mulmod(agg.n % P, e.A), mulmod(e.B, agg.sum_h)), agg.sum_v,
           "CFMV 线性恒等式 ΣV = N·A + B·Σh");

  // 聚合域篡改：动任何一个分量都会破坏恒等式
  FlowAgg bad = agg;
  bad.sum_v = addmod(bad.sum_v, 1);
  CHECK(!tb.verify_flow(0, bad.n, bad.sum_h, bad.sum_v).ok, "聚合 sum_v 篡改被拒");
  FlowAgg bad2 = agg;
  bad2.sum_h = addmod(bad2.sum_h, 7);
  CHECK(!tb.verify_flow(0, bad2.n, bad2.sum_h, bad2.sum_v).ok, "聚合 sum_h 篡改被拒");
  CHECK(!tb.verify_flow(0, agg.n + 1, agg.sum_h, agg.sum_v).ok, "窗口包数篡改被拒");
  CHECK(!tb.verify_flow(1, agg.n, agg.sum_h, agg.sum_v).ok, "流级误配候选被拒");

  // 大窗口（512 包）仍然一次判定
  FlowAgg big;
  for (uint64_t i = 0; i < 512; ++i) {
    Header h = forward(kr, p, 0, 5000 + i);
    big.add(h.nonce, h.acc);
  }
  CHECK(tb.verify_flow(0, big.n, big.sum_h, big.sum_v).ok,
        "512 包窗口一次判定通过");

  // 重放窗口
  NonceWindow w(64);
  CHECK(w.see(12345), "新 nonce 接受");
  CHECK(!w.see(12345), "重复 nonce 拒绝");
  bool all_new = true;
  for (uint64_t i = 0; i < 63; ++i) all_new = all_new && w.see(700 + i);
  CHECK(all_new, "窗口未满时新 nonce 全部接受");
  CHECK(!w.see(12345), "未滑出窗口的重复仍被拒绝");
}

// ---------------------------------------------------------------------------
// 控制器：上报解析、重放拦截、取证定位
// ---------------------------------------------------------------------------

static void controller_tests() {
  const char* MAC = "aa:aa:aa:aa:aa:01";
  Path p0 = make_path({1, 2, 3, 4});
  Path p1 = make_path({1, 5, 3, 4});
  std::vector<Direction> dirs{{MAC, {p0, p1}}};
  const uint64_t SEED = 999;
  KeyRing kr = KeyRing::generate(16, 4, SEED);
  Controller ctl(SEED, dirs);

  // 诚实包：先取证后上报（与真实时序一致）
  Header h = forward(kr, p0, 0, 777);
  char line[160];
  uint64_t hh = h_of(777);
  uint64_t e = 0;
  for (size_t j = 0; j < p0.size(); ++j) {
    e = addmod(e, mulmod(contribution(kr, p0[j], hh), powmod(RHO, (uint64_t)j)));
    std::snprintf(line, sizeof(line), "TRACE %s %u %u %u 0 777 %zu %llu", MAC,
                  p0[j].sid, p0[j].in_port, p0[j].out_port, j + 1,
                  (unsigned long long)e);
    ctl.feed(line);
  }
  std::snprintf(line, sizeof(line), "4 0 %llu %llu %s",
                (unsigned long long)h.nonce, (unsigned long long)h.acc, MAC);
  Event ev = ctl.feed(line);
  CHECK(ev.kind == "packet" && ev.ok, "控制器判定诚实包通过");
  CHECK_EQ(ev.suspect_sid, -1, "诚实包无嫌疑交换机");

  // 重放同一行 → nonce 窗口拦截
  ev = ctl.feed(line);
  CHECK(ev.replay, "重放被 nonce 窗口拦截");

  // 中间篡改：s2 翻转 1 比特 → 取证定位 s2
  Header bad = forward(kr, p0, 0, 888);
  bad.acc ^= 1;
  uint64_t h8 = h_of(888);
  uint64_t e1 = contribution(kr, p0[0], h8);
  uint64_t e2 = addmod(e1, mulmod(contribution(kr, p0[1], h8), RHO));
  std::snprintf(line, sizeof(line), "TRACE %s 1 1 2 0 888 1 %llu", MAC,
                (unsigned long long)e1);
  ctl.feed(line);
  std::snprintf(line, sizeof(line), "TRACE %s 2 1 3 0 888 2 %llu", MAC,
                (unsigned long long)(e2 ^ 1));
  ctl.feed(line);
  std::snprintf(line, sizeof(line), "4 0 %llu %llu %s",
                (unsigned long long)bad.nonce, (unsigned long long)bad.acc, MAC);
  ev = ctl.feed(line);
  CHECK(!ev.ok, "中间篡改包被拒");
  CHECK_EQ(ev.suspect_sid, 2, "取证定位到 s2");

  // 出口上报篡改：各跳取证全部正常但最终上报被改 → 定位到出口 s4
  Header fine = forward(kr, p0, 0, 999);
  hh = h_of(999);
  e = 0;
  for (size_t j = 0; j < p0.size(); ++j) {
    e = addmod(e, mulmod(contribution(kr, p0[j], hh), powmod(RHO, (uint64_t)j)));
    std::snprintf(line, sizeof(line), "TRACE %s %u %u %u 0 999 %zu %llu", MAC,
                  p0[j].sid, p0[j].in_port, p0[j].out_port, j + 1,
                  (unsigned long long)e);
    ctl.feed(line);
  }
  std::snprintf(line, sizeof(line), "4 0 %llu %llu %s",
                (unsigned long long)fine.nonce,
                (unsigned long long)(fine.acc ^ 2), MAC);
  ev = ctl.feed(line);
  CHECK(!ev.ok, "出口上报篡改被拒");
  CHECK_EQ(ev.suspect_sid, 4, "取证定位到出口 s4");

  // 多故障：s1 改端口（改道）+ s4 篡改 —— 定位应同时报出 {1, 4}
  // 实际路由 s1(1,3) → s5(1,2) → s4(2,3)，仅在 s4 处翻转 1 比特
  {
    const unsigned long long n7 = 1111;
    uint64_t h7 = h_of(n7);
    uint64_t v1 = contribution(kr, Hop{1, 1, 3}, h7);
    uint64_t v2 = addmod(v1, mulmod(contribution(kr, Hop{5, 1, 2}, h7), RHO));
    uint64_t v3 = addmod(v2, mulmod(contribution(kr, Hop{4, 2, 3}, h7),
                                    mulmod(RHO, RHO)));
    uint64_t v3t = v3 ^ 1;
    std::snprintf(line, sizeof(line), "TRACE %s 1 1 3 0 1111 1 %llu", MAC,
                  (unsigned long long)v1);
    ctl.feed(line);
    std::snprintf(line, sizeof(line), "TRACE %s 5 1 2 0 1111 2 %llu", MAC,
                  (unsigned long long)v2);
    ctl.feed(line);
    std::snprintf(line, sizeof(line), "TRACE %s 4 2 3 0 1111 3 %llu", MAC,
                  (unsigned long long)v3t);
    ctl.feed(line);
    std::snprintf(line, sizeof(line), "4 0 %llu %llu %s", n7,
                  (unsigned long long)v3t, MAC);
    Event ev7 = ctl.feed(line);
    CHECK(!ev7.ok, "多故障包被拒");
    CHECK_EQ(ev7.suspects.size(), 2, "多故障定位报出两个嫌疑");
    CHECK_EQ(ev7.suspects.empty() ? -1 : ev7.suspects[0], 1, "改道嫌疑 s1");
    CHECK_EQ(ev7.suspects.size() > 1 ? ev7.suspects[1] : -1, 4, "篡改嫌疑 s4");
    CHECK_EQ(ev7.suspect_sid, 1, "首个嫌疑 = s1");
  }

  // 流级：F L O W 行一次判定
  FlowAgg agg;
  for (uint64_t i = 0; i < 10; ++i) {
    Header x = forward(kr, p0, 0, 2000 + i);
    agg.add(x.nonce, x.acc);
    char pl[160];
    std::snprintf(pl, sizeof(pl), "1 0 %llu %llu %s",
                  (unsigned long long)x.nonce, (unsigned long long)x.acc, MAC);
    ctl.feed(pl);
  }
  std::snprintf(line, sizeof(line), "FLOW %s 0 %llu %llu %llu", MAC,
                (unsigned long long)agg.n, (unsigned long long)agg.sum_h,
                (unsigned long long)agg.sum_v);
  ev = ctl.feed(line);
  CHECK(ev.kind == "flow" && ev.ok, "FLOW 行流级判定通过");
  const DirStat& st = ctl.stat(0);
  CHECK_EQ(st.cfmv_checks, 1, "流级判定仅 1 次");
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

  before = g_pass;
  std::printf("== 3. CFMV 流级压缩与重放窗口 ==\n");
  flow_tests();
  std::printf("   新增 %d 项\n", g_pass - before);

  before = g_pass;
  std::printf("== 4. 控制器判定与取证定位 ==\n");
  controller_tests();
  std::printf("   新增 %d 项\n", g_pass - before);

  std::printf("\n结果：通过 %d，失败 %d\n", g_pass, g_fail);
  return g_fail == 0 ? 0 : 1;
}
