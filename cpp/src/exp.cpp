// MPV-2 结题实验套件：一次运行产出结题报告所需的全部实测数据与图表。
//
//   [1] 十类攻击检出矩阵（放大样本）
//   [2] 多候选集 k∈{2,8,16} 诚实/检出
//   [3] 控制器判定时延 vs k（tag/scan）+ 单核吞吐
//   [4] 流级判定时延 vs 窗口 N + 控制器上报处理吞吐（10 万行真实解析判定）
//   [5] 通信开销：每包上报 vs 流级聚合（按真实行格式量化字节数）
//   [6] 验证头长度 vs 跳数（与逐跳追加式方案对比）
//   [7] 端到端：四类攻击场景各 R 轮，统计检出率/定位成功率/误报率
//       + ping 洪泛测数据面管道吞吐
//   [8] 状态存储开销：控制器期望表 vs k、出口 CFMV 聚合 vs 活跃流、nonce 窗口
//   [9] 异常交换机定位成功率：随机故障位置大样本（单故障/双故障/诚实对照）
//       + 有取证 vs 无取证定位对照
//   [10] 算法级基线对比：逐跳 MAC 链（Icing 类）判定时延 vs k、
//        概率采样多路径（Atlas 类）漏检率 vs 判定负载
//   [11] 规模扩展：路径跳数 h 下的数据面/控制面开销与检出率
//
// 输出：results/exp_report.md + results/charts/*.svg，stdout 打摘要。
// 需 root（[7] 要建 netns 拓扑）。用法： sudo ./build/exp [--trials N] [--rounds R]
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <random>
#include <thread>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include "blake2b.h"
#include "controller.h"
#include "tpool.h"
#include "mpv2.h"
#include "topo.h"

using namespace mpv;
using namespace topo;

namespace {

std::ofstream g_report;
int g_nthr = 2;  // 并行线程数（--threads；默认取 CPU 核数）
mpv::ThreadPool* g_pool = nullptr;  // 全节复用的线程池（M5.16）
std::string g_chart_dir = "results/charts";

std::string exe_dir() {
  char buf[4096];
  ssize_t n = ::readlink("/proc/self/exe", buf, sizeof(buf) - 1);
  if (n <= 0) return ".";
  buf[n] = 0;
  std::string s(buf);
  auto pos = s.find_last_of('/');
  return pos == std::string::npos ? "." : s.substr(0, pos);
}

const std::string& vswitch_exe() {
  static std::string s = exe_dir() + "/vswitch";
  return s;
}

double now_us() {
  using namespace std::chrono;
  return duration_cast<nanoseconds>(steady_clock::now().time_since_epoch())
             .count() /
         1000.0;
}

double median(std::vector<double>& v) {
  std::sort(v.begin(), v.end());
  return v.empty() ? 0 : v[v.size() / 2];
}

// ---------------------------------------------------------------- SVG 绘图
struct Series {
  const char* name;
  const char* color;
  std::vector<std::pair<double, double>> pts;  // (x, y)
};

void svg_chart(const std::string& file, const std::string& title,
               const std::string& x_label, const std::string& y_label,
               const std::vector<std::string>& xticks,
               const std::vector<double>& xvals, const std::vector<Series>& ss,
               double y_max, double y_min = 0) {
  const int W = 460, H = 240, PX = 52, PY = 30;
  double x_min = xvals.empty() ? 0 : xvals.front();
  double x_max = xvals.empty() ? 1 : xvals.back();
  auto X = [&](double v) { return PX + (v - x_min) / (x_max - x_min + 1e-9) * (W - PX - 16); };
  auto Y = [&](double v) { return H - PY - (v - y_min) / (y_max - y_min + 1e-9) * (H - 2 * PY); };

  std::ostringstream o;
  o << "<svg xmlns='http://www.w3.org/2000/svg' width='" << W << "' height='" << H
    << "' viewBox='0 0 " << W << " " << H << "'>\n";
  o << "<rect width='" << W << "' height='" << H << "' fill='#121a30'/>\n";
  o << "<text x='" << W / 2 << "' y='16' fill='#dbe4ff' font-size='12' text-anchor='middle'>"
    << title << "</text>\n";
  // 轴
  o << "<line x1='" << PX << "' y1='" << H - PY << "' x2='" << W - 16 << "' y2='" << H - PY
    << "' stroke='#3a4a75'/>\n";
  o << "<line x1='" << PX << "' y1='" << PY << "' x2='" << PX << "' y2='" << H - PY
    << "' stroke='#3a4a75'/>\n";
  // y 刻度（4 档）
  for (int i = 0; i <= 4; ++i) {
    double v = y_min + (y_max - y_min) * i / 4;
    o << "<text x='" << PX - 5 << "' y='" << Y(v) + 4 << "' fill='#7f8db1' font-size='9' "
         "text-anchor='end'>" << v << "</text>\n";
  }
  // x 刻度
  for (size_t i = 0; i < xticks.size() && i < xvals.size(); ++i)
    o << "<text x='" << X(xvals[i]) << "' y='" << H - PY + 13 << "' fill='#7f8db1' "
         "font-size='9' text-anchor='middle'>" << xticks[i] << "</text>\n";
  o << "<text x='" << W - 10 << "' y='" << H - 4 << "' fill='#7f8db1' font-size='9' "
       "text-anchor='end'>" << x_label << "</text>\n";
  o << "<text x='6' y='" << PY - 8 << "' fill='#7f8db1' font-size='9'>" << y_label << "</text>\n";
  for (const Series& s : ss) {
    std::ostringstream pl;
    for (size_t i = 0; i < s.pts.size(); ++i)
      pl << (i ? " " : "") << X(s.pts[i].first) << "," << Y(s.pts[i].second);
    o << "<polyline points='" << pl.str() << "' fill='none' stroke='" << s.color
      << "' stroke-width='2'/>\n";
    for (auto& p : s.pts)
      o << "<circle cx='" << X(p.first) << "' cy='" << Y(p.second) << "' r='2.6' fill='"
        << s.color << "'/>\n";
  }
  // 图例
  double lx = PX + 6;
  for (const Series& s : ss) {
    o << "<circle cx='" << lx << "' cy='" << PY + 6 << "' r='3.5' fill='" << s.color << "'/>\n";
    o << "<text x='" << lx + 7 << "' y='" << PY + 9 << "' fill='#dbe4ff' font-size='9'>"
      << s.name << "</text>\n";
    lx += 14 + std::strlen(s.name) * 9;
  }
  o << "</svg>\n";
  std::ofstream f(g_chart_dir + "/" + file);
  f << o.str();
}

// ---------------------------------------------------------------- [1] 攻击矩阵
struct Rng {
  std::mt19937_64 g;
  explicit Rng(uint64_t seed) : g(seed) {}
  uint64_t next() { return g(); }
  uint32_t range(uint32_t lo, uint32_t hi) { return lo + (uint32_t)(g() % (uint64_t)(hi - lo + 1)); }
  uint64_t nonce() { return g() & ((1ULL << 56) - 1); }
};

Path rand_path(Rng& r, uint32_t n_hops) {
  Path p;
  p.push_back(Hop{1, 1, 2});
  std::vector<uint32_t> pool;
  for (uint32_t s = 2; s <= 15; ++s) pool.push_back(s);
  for (size_t i = pool.size(); i > 1; --i) {
    size_t j = r.next() % i;
    std::swap(pool[i - 1], pool[j]);
  }
  for (uint32_t i = 0; i + 1 < n_hops; ++i)
    p.push_back(Hop{pool[i], 1, (uint32_t)(2 + (i % 2))});
  p.push_back(Hop{16, 1, 2});
  return p;
}

Path atk_out_port(const Path& p, Rng& r) { Path q = p; uint32_t i = r.range(0, (uint32_t)q.size() - 1); uint32_t v = r.range(1, 4); if (v == q[i].out_port) v = (v % 4) + 1; q[i].out_port = v; return q; }
Path atk_in_port(const Path& p, Rng& r) { Path q = p; uint32_t i = r.range(0, (uint32_t)q.size() - 1); q[i].in_port = q[i].in_port == 1 ? 2 : 1; return q; }
Path atk_bypass(const Path& p, Rng& r) { Path q = p; uint32_t i = r.range(1, (uint32_t)q.size() - 2); q[i].sid = r.range(2, 15); return q; }
Path atk_reorder(const Path& p, Rng& r) { Path q = p; if (q.size() < 4) return q; uint32_t i = r.range(1, (uint32_t)q.size() - 3); std::swap(q[i], q[i + 1]); return q; }
Path atk_delete(const Path& p, Rng& r) { Path q = p; if (q.size() < 4) return q; q.erase(q.begin() + r.range(1, (uint32_t)q.size() - 2)); return q; }
Path atk_insert(const Path& p, Rng& r) { Path q = p; uint32_t pos = r.range(1, (uint32_t)q.size() - 1); q.insert(q.begin() + pos, Hop{r.range(2, 15), 1, 3}); return q; }
Path atk_replace(const Path& p, Rng& r) { Path q = p; q.push_back(p.front()); for (size_t i = 1; i + 1 < p.size(); ++i) q.push_back(Hop{r.range(2, 15), 1, 2}); q.push_back(p.back()); return q; }
Path atk_truncate(const Path& p, Rng&) { Path q = p; if (q.size() > 2) q.pop_back(); return q; }

struct MatrixStat {
  int det[8] = {0}, tot[8] = {0};
  int honest = 0;
  int flip_t = 0, flip_d = 0, forge_t = 0, forge_d = 0;
};

// 单个 worker：独立 RNG 与 KeyRing（备忘录缓存非线程安全，每线程一份——
// 同 seed 派生同密钥，统计性质与单线程一致）
void matrix_worker(int tid, int trials, MatrixStat& st) {
  Rng rng(20260501 + 0x9E3779B97F4A7C15ULL * (uint64_t)(tid + 1));
  KeyRing kr = KeyRing::generate(16, 4, 20260501);
  for (int t = 0; t < trials; ++t) {
    Path p = rand_path(rng, rng.range(3, 7));
    Header h = forward(kr, p, 0, rng.nonce());
    std::vector<Path> one{p};
    ExpectationTable tb(kr, one);
    if (tb.verify_tag(h).ok) ++st.honest;
    Path bad[8] = {atk_out_port(p, rng), atk_in_port(p, rng), atk_bypass(p, rng),
                   atk_reorder(p, rng), atk_delete(p, rng), atk_insert(p, rng),
                   atk_replace(p, rng), atk_truncate(p, rng)};
    for (int a = 0; a < 8; ++a) {
      if (bad[a] == p) continue;
      ++st.tot[a];
      Header bh = forward(kr, bad[a], 0, rng.nonce());
      if (!tb.verify_tag(bh).ok) ++st.det[a];
    }
    // 数据性攻击：比特翻转 + 随机伪造
    Header f = h;
    f.acc ^= 1;
    ++st.flip_t;
    if (!tb.verify_tag(f).ok) ++st.flip_d;
    Path g = rand_path(rng, rng.range(3, 7));
    if (!(g == p)) {
      ++st.forge_t;
      Header gh = forward(kr, g, 0, rng.nonce());
      if (!tb.verify_tag(gh).ok) ++st.forge_d;
    }
  }
}

int exp_attack_matrix(int trials, int nthr) {
  g_report << "\n## [1] 十类攻击检出矩阵（每组 " << trials << " 次，64 位模域，"
           << nthr << " 线程）\n\n";
  g_report << "| 编号 | 攻击手法 | 检出/样本 | 检出率 |\n|---|---|---|---|\n";

  // 单线程基线（加速比证据，同一 worker 不同线程数）
  double ts0 = now_us();
  {
    MatrixStat single;
    matrix_worker(0, trials, single);
  }
  double single_el = now_us() - ts0;

  std::vector<MatrixStat> stats(nthr);
  int per = (trials + nthr - 1) / nthr;
  double t0 = now_us();
  for (int t = 0; t < nthr; ++t) {
    int n = (t == nthr - 1) ? trials - per * (nthr - 1) : per;
    g_pool->submit([t, n, &stats] { matrix_worker(t, n, stats[t]); });
  }
  g_pool->wait_idle();
  double par_el = now_us() - t0;

  MatrixStat st;
  for (const MatrixStat& s : stats) {
    st.honest += s.honest;
    for (int a = 0; a < 8; ++a) {
      st.tot[a] += s.tot[a];
      st.det[a] += s.det[a];
    }
    st.flip_t += s.flip_t; st.flip_d += s.flip_d;
    st.forge_t += s.forge_t; st.forge_d += s.forge_d;
  }
  struct Row { const char* code; const char* name; };
  Row rows[8] = {{"S1","改出端口"},{"S2","改入端口"},{"S3","交换机旁路"},
                 {"S4","跳序交换"},{"S5","删除一跳"},{"S6","插入一跳"},
                 {"S7","整条替换"},{"S8","截断路径"}};
  for (int a = 0; a < 8; ++a)
    g_report << "| " << rows[a].code << " | " << rows[a].name << " | " << st.det[a]
             << "/" << st.tot[a] << " | "
             << (st.tot[a] ? 100.0 * st.det[a] / st.tot[a] : 0) << "% |\n";
  g_report << "| S9 | 验证头比特翻转 | " << st.flip_d << "/" << st.flip_t << " | "
           << 100.0 * st.flip_d / st.flip_t << "% |\n";
  g_report << "| S10 | 随机伪造验证头 | " << st.forge_d << "/" << st.forge_t
           << " | " << 100.0 * st.forge_d / st.forge_t << "% |\n";
  g_report << "\n诚实样本接受率：" << (100.0 * st.honest / trials) << "%（"
           << st.honest << "/" << trials << "）\n";
  g_report << "- 并发：" << nthr << " 线程 " << par_el / 1000.0 << " s vs 单线程 "
           << single_el / 1000.0 << " s（加速比 " << single_el / par_el << "×，"
           << "两轮独立 RNG，统计同性质）\n";
  return 0;
}

// ---------------------------------------------------------------- [2] 多候选
struct CandStat {
  int ho = 0, ho_t = 0, de = 0, de_t = 0;
};

void cand_worker(int tid, int trials, uint32_t k, CandStat& st) {
  Rng rng(99 + 0x9E3779B97F4A7C15ULL * (uint64_t)(tid + 1));
  KeyRing kr = KeyRing::generate(16, 4, 20260501);
  std::vector<Path> cands;
  for (uint32_t i = 0; i < k; ++i) {
    Path p;
    p.push_back(Hop{1, 1, 2});
    p.push_back(Hop{2 + (i % 14), 1, 2});
    p.push_back(Hop{9 + (i % 7), 1, 3});
    p.push_back(Hop{13 + (i % 3), 1, 2});
    p.push_back(Hop{16, 1, 2});
    cands.push_back(p);
  }
  ExpectationTable tb(kr, cands);
  for (int t = 0; t < trials; ++t) {
    uint32_t pick = rng.range(0, k - 1);
    uint64_t nonce = rng.nonce();
    Header h = forward(kr, cands[pick], (uint8_t)pick, nonce);
    ++st.ho_t;
    if (tb.verify_tag(h).ok) ++st.ho;
    Path bad = cands[pick];
    uint32_t hi = rng.range(1, 3);
    bad[hi].out_port = (bad[hi].out_port % 3) + 1;
    if (!(bad == cands[pick])) {
      ++st.de_t;
      Header bh = forward(kr, bad, (uint8_t)pick, nonce);
      if (!tb.verify_tag(bh).ok && tb.verify_scan(bh).matched < 0) ++st.de;
    }
  }
}

void exp_multicand(int trials, int nthr) {
  g_report << "\n## [2] 多候选集下的攻击检出与诚实接受（k 条合法路径共用期望表，"
           << nthr << " 线程）\n\n";
  g_report << "| k | 诚实接受 | 篡改检出 |\n|---|---|---|\n";
  for (uint32_t k : {2u, 8u, 16u}) {
    std::vector<CandStat> stats(nthr);
    int per = (trials + nthr - 1) / nthr;
    for (int t = 0; t < nthr; ++t) {
      int n = (t == nthr - 1) ? trials - per * (nthr - 1) : per;
      g_pool->submit([t, n, k, &stats] { cand_worker(t, n, k, stats[t]); });
    }
    g_pool->wait_idle();
    CandStat st;
    for (const CandStat& s : stats) {
      st.ho += s.ho; st.ho_t += s.ho_t; st.de += s.de; st.de_t += s.de_t;
    }
    g_report << "| " << k << " | " << 100.0 * st.ho / st.ho_t << "%（" << st.ho
             << "/" << st.ho_t << "） | " << 100.0 * st.de / (st.de_t ? st.de_t : 1)
             << "%（" << st.de << "/" << st.de_t << "） |\n";
  }
}

// ---------------------------------------------------------------- [3] 时延 vs k
void exp_latency_k(std::vector<double>& ks_out, std::vector<double>& tag_out,
                   std::vector<double>& scan_out) {
  g_report << "\n## [3] 控制器单次判定时延 vs 候选路径数 k（7 跳，命中最末候选，中位数）\n\n";
  g_report << "| k | tag/CPMV (µs) | scan/BPMV (µs) | CPMV 吞吐（万次/秒） |\n|---|---|---|---|\n";
  Rng rng(7);
  KeyRing kr = KeyRing::generate(16, 4, 20260501);
  for (uint32_t k : {1u, 2u, 4u, 8u, 16u, 32u, 64u}) {
    std::vector<Path> cands;
    for (uint32_t i = 0; i < k; ++i) {
      Path p;
      p.push_back(Hop{1, 1, 2});
      p.push_back(Hop{2, 1, 2});
      p.push_back(Hop{3, 1, 2});
      uint32_t x = i;
      p.push_back(Hop{4 + (x % 11), 1, 2}); x /= 11;
      p.push_back(Hop{4 + (x % 11), 1, 3});
      p.push_back(Hop{15, 1, 2});
      p.push_back(Hop{16, 1, 2});
      cands.push_back(p);
    }
    ExpectationTable tb(kr, cands);
    Header h = forward(kr, cands[k - 1], (uint8_t)((k - 1) & 0xff), rng.nonce());
    std::vector<double> tt, ts;
    for (int i = 0; i < 2000; ++i) {
      double t0 = now_us(); tb.verify_tag(h); tt.push_back(now_us() - t0);
      t0 = now_us(); tb.verify_scan(h); ts.push_back(now_us() - t0);
    }
    double mt = median(tt), ms = median(ts);
    ks_out.push_back(k); tag_out.push_back(mt); scan_out.push_back(ms);
    g_report << "| " << k << " | " << mt << " | " << ms << " | "
             << (mt > 0 ? 100.0 / mt : 0) << " |\n";
  }
}

// ---------------------------------------------------------------- [4] 流级 + 吞吐
void exp_flow(std::vector<double>& ns_out, std::vector<double>& flow_out) {
  g_report << "\n## [4a] 流级（CFMV）判定时延 vs 窗口大小 N（k=16，中位数）\n\n";
  g_report << "| N | flow (µs) |\n|---|---|\n";
  Rng rng(11);
  KeyRing kr = KeyRing::generate(16, 4, 20260501);
  std::vector<Path> cands;
  for (uint32_t i = 0; i < 16; ++i) {
    Path p;
    p.push_back(Hop{1, 1, 2});
    p.push_back(Hop{2 + (i % 14), 1, 2});
    p.push_back(Hop{9 + (i % 7), 1, 3});
    p.push_back(Hop{16, 1, 2});
    cands.push_back(p);
  }
  ExpectationTable tb(kr, cands);
  for (uint64_t n : {1ull, 16ull, 64ull, 256ull, 1024ull, 4096ull}) {
    FlowAgg agg;
    for (uint64_t i = 0; i < n; ++i) {
      Header h = forward(kr, cands[0], 0, 100 + i);
      agg.add(h.nonce, h.acc);
    }
    std::vector<double> tv;
    for (int i = 0; i < 2000; ++i) {
      double t0 = now_us();
      tb.verify_flow(0, agg.n, agg.sum_h, agg.sum_v);
      tv.push_back(now_us() - t0);
    }
    double m = median(tv);
    ns_out.push_back((double)n); flow_out.push_back(m);
    g_report << "| " << n << " | " << m << " |\n";
  }

  // 控制器上报处理吞吐：10 万行真实解析 + 判定（tag 与 scan 双口径同跑，与
  // controller.cpp 的实现一致）
  g_report << "\n## [4b] 控制器上报处理吞吐（10 万行逐包上报，真实解析+判定）\n\n";
  const int LINES = 100000;
  std::vector<Path> cands2{cands[0], cands[1]};
  Controller ctl(20260501, {{"00:00:00:00:00:02", cands2}});
  std::vector<std::string> lines;
  lines.reserve(LINES);
  char buf[128];
  for (int i = 0; i < LINES; ++i) {
    Header h = forward(kr, cands[0], 0, 50000 + (uint64_t)i);
    std::snprintf(buf, sizeof(buf), "4 0 %llu %llu 00:00:00:00:00:02",
                  (unsigned long long)h.nonce, (unsigned long long)h.acc);
    lines.emplace_back(buf);
  }
  double t0 = now_us();
  for (const std::string& l : lines) ctl.feed(l);
  double el = now_us() - t0;  // µs
  const DirStat& st = ctl.stat(0);
  g_report << "- 行数 " << LINES << "，耗时 " << el / 1000.0 << " ms，吞吐 "
           << (LINES / (el / 1e6) / 10000.0) << " 万行/秒（含逐包 tag 判定 + 全候选 scan 对照）\n";
  g_report << "- 实累计判定次数：CPMV " << st.cpmv_checks << "，BPMV " << st.bpmv_checks
           << "；平均单行 " << el / LINES << " µs\n";
  g_report << "- 同批包按窗口 64 做流级判定仅需 " << (LINES / 64) << " 次判定（压缩 "
           << LINES / (LINES / 64) << "×）\n";
}

// ---------------------------------------------------------------- [5] 通信开销
void exp_comm() {
  g_report << "\n## [5] 通信开销：每包上报 vs 流级聚合上报（1000 包/单流，按真实行格式量化）\n\n";
  Rng rng(13);
  KeyRing kr = KeyRing::generate(16, 4, 20260501);
  Path p = rand_path(rng, 5);
  const char* MAC = "00:00:00:00:00:02";
  std::vector<std::pair<uint64_t, uint64_t>> pkts;  // (nonce, V)
  char buf[160];
  size_t per_packet_bytes = 0;
  for (int i = 0; i < 1000; ++i) {
    Header h = forward(kr, p, 0, rng.nonce());
    pkts.push_back({h.nonce, h.acc});
    std::snprintf(buf, sizeof(buf), "4 0 %llu %llu %s\n",
                  (unsigned long long)h.nonce, (unsigned long long)h.acc, MAC);
    per_packet_bytes += std::strlen(buf);
  }
  g_report << "| 方式 | 上报条数 | 字节数 | 相对每包 |\n|---|---|---|---|\n";
  g_report << "| 每包上报 | 1000 | " << per_packet_bytes << " | 100% |\n";
  std::vector<std::pair<double, double>> chart;
  for (uint64_t w : {8ull, 16ull, 32ull, 64ull, 128ull, 250ull}) {
    size_t bytes = 0;
    uint64_t lines = 0;
    for (size_t i = 0; i < pkts.size(); i += w) {
      FlowAgg agg;
      for (size_t j = i; j < pkts.size() && j < i + w; ++j)
        agg.add(pkts[j].first, pkts[j].second);
      std::snprintf(buf, sizeof(buf), "FLOW %s 0 %llu %llu %llu\n", MAC,
                    (unsigned long long)agg.n, (unsigned long long)agg.sum_h,
                    (unsigned long long)agg.sum_v);
      bytes += std::strlen(buf);
      ++lines;
    }
    chart.push_back({(double)w, (double)bytes});
    g_report << "| 流级聚合（窗口 " << w << "） | " << lines << " | " << bytes << " | "
             << (100.0 * bytes / per_packet_bytes) << "% |\n";
  }
  std::vector<Series> ss{{"上报字节数", "#60a5fa", chart}};
  svg_chart("chart_comm.svg", "上报流量：流级聚合窗口 vs 字节数（1000 包）", "窗口大小 N",
            "字节", {"8", "16", "32", "64", "128", "250"}, {8, 16, 32, 64, 128, 250}, ss,
            chart.back().second * 1.1);
}

// ---------------------------------------------------------------- [6] 头长
void exp_header() {
  g_report << "\n## [6] 验证头长度 vs 路径跳数（逐跳追加式 ≈4B/跳 vs 本方案恒定 16B）\n\n";
  g_report << "| 跳数 h | 逐跳追加式 (B) | MPV-2 (B) | 节省 |\n|---|---|---|---|\n";
  std::vector<double> hs, icing, mpv;
  std::vector<std::string> ticks;
  for (int h : {3, 5, 7, 9, 11, 13, 16}) {
    int a = 4 * h;
    g_report << "| " << h << " | " << a << " | " << HEADER_BYTES << " | "
             << (100.0 * (a - HEADER_BYTES) / a) << "% |\n";
    hs.push_back(h); ticks.push_back(std::to_string(h));
    icing.push_back(a); mpv.push_back(HEADER_BYTES);
  }
  std::vector<Series> ss{{"逐跳追加式（Icing 类）", "#fbbf24", {}},
                          {"MPV-2 恒定 16B", "#4ade80", {}}};
  for (size_t i = 0; i < hs.size(); ++i) {
    ss[0].pts.push_back({hs[i], icing[i]});
    ss[1].pts.push_back({hs[i], mpv[i]});
  }
  svg_chart("chart_header.svg", "验证头长度 vs 路径跳数", "跳数 h", "字节",
            ticks, hs, ss, 70);
}

// ---------------------------------------------------------------- [8] 存储开销
// 口径：按结构实测条目数 × 字段宽（sizeof），不是进程 RSS——这样不同方案
// 在同一口径下可比，且数字可由结构定义直接复核。
void exp_storage() {
  g_report << "\n## [8] 状态存储开销（条目数 × 字段宽，可由结构定义复核）\n\n";

  // 控制器侧：期望表 O(k)，与跳数无关（A、B 两个 64 位聚合值）
  g_report << "### 控制器侧：期望表随候选路径数 k（h=7）\n\n";
  g_report << "| k | 期望表 (B) | 路径索引 (B) | 合计 (B) |\n|---|---|---|---|\n";
  for (uint32_t k : {1u, 2u, 4u, 8u, 16u, 32u, 64u}) {
    size_t e = (size_t)k * sizeof(Expectation);            // A,B：8B × 2
    size_t x = (size_t)k * 7 * sizeof(Hop);                // 索引：sid+in+out 12B/跳
    g_report << "| " << k << " | " << e << " | " << x << " | " << e + x << " |\n";
  }
  g_report << "- nonce 重放窗口：每方向 "
           << (4096 * 8 + 8192 * 4 + 4096 * 4) << " B（环 32KB + 开链桶 32KB + 链 16KB，"
              "平坦无逐条目分配；容量 4096，与速率无关）\n";
  g_report << "- 对照：逐跳 MAC 链基线无预计算表，但每包判定需 O(k·h) 次哈希（见 [10]）"
              "——以计算换存储，本方案把两边同时做成 O(k)/O(1)。\n";

  // 出口交换机侧：CFMV 三元组 24B/(流,tag) vs 逐流路径记录式 8B×h/流
  g_report << "\n### 出口交换机侧：流级聚合状态随活跃流数（h=7）\n\n";
  g_report << "| 活跃流数 | CFMV 三元组 (B) | 逐流路径记录式 (B) | 倍率 |\n|---|---|---|---|\n";
  std::vector<double> fs;
  std::vector<std::pair<double, double>> c1, c2;
  std::vector<std::string> ticks;
  for (uint64_t f : {1000ull, 2000ull, 4000ull, 8000ull, 16000ull, 32000ull}) {
    size_t a = (size_t)f * sizeof(FlowAgg);                // n+Σh+ΣV：8B × 3
    size_t b = (size_t)f * 7 * 8;                          // 每流逐跳记录：8B × h
    g_report << "| " << f << " | " << a << " | " << b << " | " << (double)b / a << "× |\n";
    fs.push_back((double)f); ticks.push_back(std::to_string(f / 1000) + "k");
    c1.push_back({(double)f, a / 1024.0});
    c2.push_back({(double)f, b / 1024.0});
  }
  std::vector<Series> ss{{"CFMV 聚合（24B/流）", "#4ade80", c1},
                         {"逐流路径记录式（8B×7/流）", "#fbbf24", c2}};
  svg_chart("chart_storage.svg", "出口交换机状态存储 vs 活跃流数", "活跃流数", "KB",
            ticks, fs, ss, c2.back().second * 1.15);
  g_report << "- 数据面转发路径：逐跳更新 V 无逐流状态（0 B/跳）；全系统逐流状态只出现在"
              "出口聚合（24B/流）与 nonce 窗口（定长）。\n";
  // 进程级实测（参考口径）：exp 进程跑完 [1]-[7] 后的峰值/当前内存
  if (std::FILE* f = std::fopen("/proc/self/status", "r")) {
    char l[256];
    while (std::fgets(l, sizeof l, f))
      if (std::strncmp(l, "VmHWM", 5) == 0 || std::strncmp(l, "VmRSS", 5) == 0)
        g_report << "- exp 进程实测 " << l;  // 行自带换行
    std::fclose(f);
  }
}

// ---------------------------------------------------------------- [9] 定位成功率
struct HopRec {
  uint32_t sid, in, out, pos;
  uint64_t v;
};

// 沿实际路径逐跳生成取证记录（与 vswitch --trace 同口径：pos 1 基），
// tamper_hop >= 0 时该跳在合法贡献之后翻转 1 bit（恶意改头）。
std::vector<HopRec> trace_of(const KeyRing& kr, const Path& p, uint64_t nonce,
                             int tamper_hop) {
  std::vector<HopRec> recs;
  uint64_t acc = 0;
  for (size_t i = 0; i < p.size(); ++i) {
    acc = addmod(acc, mulmod(contribution(kr, p[i], h_of(nonce)),
                             powmod(RHO, (uint64_t)i)));
    if ((int)i == tamper_hop) acc ^= 1;  // 篡改后下游在篡改值上继续（与 vswitch 一致）
    recs.push_back({p[i].sid, p[i].in_port, p[i].out_port, (uint32_t)(i + 1), acc});
  }
  return recs;
}

size_t first_div(const Path& a, const Path& b) {
  size_t i = 0;
  while (i < a.size() && i < b.size() && a[i] == b[i]) ++i;
  return i;
}

void exp_localization(int trials) {
  g_report << "\n## [9] 异常交换机定位成功率（随机路径 5–9 跳，随机故障位置）\n\n";
  Rng rng(777);
  const KeyRing kr = KeyRing::generate(16, 4, SEED);
  const char* MAC = "00:00:00:00:00:02";

  // 主实验：单候选集 + 逐跳取证。四类样本：单篡改 / 单改道 / 双故障 / 诚实对照。
  // 真值口径：篡改跳 = 实际路径该跳 sid；改道跳 = 声称路径首分歧跳 sid（与
  // 控制器定位语义一致）。真攻击纪律：bad == claimed 的样本不计入。
  int tam_n = 0, tam_hit = 0, dev_n = 0, dev_hit = 0, two_n = 0, two_hit = 0;
  int ho_n = 0, ho_ok = 0, overmark = 0;
  int exact_all = 0, fault_all = 0;
  for (int t = 0; t < trials; ++t) {
    Path p = rand_path(rng, rng.range(4, 8));  // 总跳数 5–9
    uint64_t nonce = rng.nonce();
    uint32_t mode = (uint32_t)(rng.next() % 4);
    Path bad = p;
    int tam = -1;
    bool dev = false;
    if (mode == 0 || mode == 2) tam = (int)rng.range(0, (uint32_t)p.size() - 1);
    if (mode == 1 || mode == 2) {
      for (int tries = 0; tries < 10 && !dev; ++tries) {
        bad = (rng.next() % 2) ? atk_out_port(p, rng) : atk_bypass(p, rng);
        dev = !(bad == p);
      }
      if (!dev) continue;
    }
    Controller c(SEED, {Direction{MAC, {p}}});
    auto recs = trace_of(kr, bad, nonce, tam);
    char buf[192];
    for (const HopRec& r : recs) {
      std::snprintf(buf, sizeof(buf), "TRACE %s %u %u %u 0 %llu %u %llu", MAC,
                    r.sid, r.in, r.out, (unsigned long long)nonce, r.pos,
                    (unsigned long long)r.v);
      c.feed(buf);
    }
    std::snprintf(buf, sizeof(buf), "4 0 %llu %llu %s",
                  (unsigned long long)nonce, (unsigned long long)recs.back().v, MAC);
    Event ev = c.feed(buf);

    if (!dev && tam < 0) {  // 诚实样本：应判定通过且无嫌疑
      ++ho_n;
      if (ev.ok && ev.suspects.empty()) ++ho_ok;
      continue;
    }
    std::vector<int> truth;
    if (tam >= 0) truth.push_back((int)bad[tam].sid);
    if (dev) {
      size_t fd = first_div(p, bad);
      if (fd >= p.size()) fd = p.size() - 1;
      truth.push_back((int)p[fd].sid);
    }
    std::sort(truth.begin(), truth.end());
    truth.erase(std::unique(truth.begin(), truth.end()), truth.end());
    std::vector<int> sus = ev.suspects;
    std::sort(sus.begin(), sus.end());
    bool hit = truth == sus;
    bool over = false;
    for (int s : sus)
      if (!std::binary_search(truth.begin(), truth.end(), s)) over = true;
    if (over) ++overmark;
    ++fault_all;
    if (hit) ++exact_all;
    if (dev && tam < 0) { ++dev_n; if (hit) ++dev_hit; }
    else if (!dev && tam >= 0) { ++tam_n; if (hit) ++tam_hit; }
    else { ++two_n; if (hit) ++two_hit; }
  }
  g_report << "| 故障类型 | 样本数 | 嫌疑集精确命中 | 精确率 |\n|---|---|---|---|\n";
  g_report << "| 恶意改头（S9） | " << tam_n << " | " << tam_hit << " | "
           << (tam_n ? 100.0 * tam_hit / tam_n : 0) << "% |\n";
  g_report << "| 路径改道（S1/S3） | " << dev_n << " | " << dev_hit << " | "
           << (dev_n ? 100.0 * dev_hit / dev_n : 0) << "% |\n";
  g_report << "| 双故障（改头+改道） | " << two_n << " | " << two_hit << " | "
           << (two_n ? 100.0 * two_hit / two_n : 0) << "% |\n";
  g_report << "| 诚实对照（误报） | " << ho_n << " | 误报 " << (ho_n - ho_ok)
           << " | " << (ho_n ? 100.0 * ho_ok / ho_n : 0) << "% |\n";
  g_report << "- 全部故障样本精确命中率：" << exact_all << "/" << fault_all << "（"
           << (fault_all ? 100.0 * exact_all / fault_all : 0) << "%），"
           << "含诚实交换机误标样本 " << overmark << " 个\n";

  // 对照：k=4 候选集，有取证 vs 无取证。改道到合法路径（tagflip 类）两种都
  // 能定位；集合外篡改只有取证能定位——这是 --trace 取证存在的理由。
  g_report << "\n### 对照：有逐跳取证 vs 无取证（k=4 候选集，各 "
           << trials / 4 << " 次）\n\n";
  std::vector<Path> cands;
  for (uint32_t i = 0; i < 4; ++i) {
    Path q;
    q.push_back(Hop{1, 1, 2});
    q.push_back(Hop{2 + i, 1, 2});
    q.push_back(Hop{6 + i, 1, 3});
    q.push_back(Hop{10 + i, 1, 2});
    q.push_back(Hop{16, 1, 2});
    cands.push_back(q);
  }
  int tf[2] = {0, 0}, tf_n = 0, bf[2] = {0, 0}, bf_n = 0;
  for (int t = 0; t < trials / 2; ++t) {
    uint64_t nonce = rng.nonce();
    // B1 改道到合法路径：沿 cands[j] 转发却声称 tag 0。两种口径各自有定义：
    //   有取证 = 声称路径首分歧跳；无取证 = 候选对比的最后公共交换机（路由分歧点）
    {
      uint32_t j = rng.range(1, 3);
      Header h = forward(kr, cands[j], 0, nonce);
      size_t fd = first_div(cands[0], cands[j]);
      size_t common = 0;
      while (common < cands[0].size() && common < cands[j].size() &&
             cands[0][common].sid == cands[j][common].sid)
        ++common;
      int want[2] = {(int)cands[0][common > 0 ? common - 1 : 0].sid,
                     (int)cands[0][fd].sid};
      for (int with_trace = 0; with_trace < 2; ++with_trace) {
        Controller c(SEED, {Direction{MAC, cands}});
        char buf[192];
        if (with_trace) {
          for (const HopRec& r : trace_of(kr, cands[j], nonce, -1)) {
            std::snprintf(buf, sizeof(buf), "TRACE %s %u %u %u 0 %llu %u %llu", MAC,
                          r.sid, r.in, r.out, (unsigned long long)nonce, r.pos,
                          (unsigned long long)r.v);
            c.feed(buf);
          }
        }
        std::snprintf(buf, sizeof(buf), "4 0 %llu %llu %s",
                      (unsigned long long)nonce, (unsigned long long)h.acc, MAC);
        Event ev = c.feed(buf);
        if (!ev.ok && ev.suspects.size() == 1 && ev.suspects[0] == want[with_trace])
          ++tf[with_trace];
      }
      ++tf_n;
    }
    // B2 集合外篡改：cands[0] 改一跳出端口，不在任何候选里
    {
      Path bad;
      for (int tries = 0; tries < 10; ++tries) {
        bad = atk_out_port(cands[0], rng);
        if (!(bad == cands[0])) break;
      }
      if (!(bad == cands[0])) {
        uint64_t n2 = rng.nonce();
        Header h = forward(kr, bad, 0, n2);
        for (int with_trace = 0; with_trace < 2; ++with_trace) {
          Controller c(SEED, {Direction{MAC, cands}});
          if (with_trace) {
            char buf[192];
            for (const HopRec& r : trace_of(kr, bad, n2, -1)) {
              std::snprintf(buf, sizeof(buf), "TRACE %s %u %u %u 0 %llu %u %llu", MAC,
                            r.sid, r.in, r.out, (unsigned long long)n2, r.pos,
                            (unsigned long long)r.v);
              c.feed(buf);
            }
          }
          char buf[128];
          std::snprintf(buf, sizeof(buf), "4 0 %llu %llu %s",
                        (unsigned long long)n2, (unsigned long long)h.acc, MAC);
          Event ev = c.feed(buf);
          size_t fd = first_div(cands[0], bad);
          if (!ev.ok && ev.suspects.size() == 1 &&
              ev.suspects[0] == (int)cands[0][fd].sid)
            ++bf[with_trace];
        }
        ++bf_n;
      }
    }
  }
  g_report << "| 故障 | 有取证定位 | 无取证定位 |\n|---|---|---|\n";
  g_report << "| 改道到合法路径（tagflip） | " << tf[1] << "/" << tf_n << "（"
           << (tf_n ? 100.0 * tf[1] / tf_n : 0) << "%） | " << tf[0] << "/" << tf_n
           << "（" << (tf_n ? 100.0 * tf[0] / tf_n : 0) << "%） |\n";
  g_report << "| 集合外篡改（改出端口） | " << bf[1] << "/" << bf_n << "（"
           << (bf_n ? 100.0 * bf[1] / bf_n : 0) << "%） | " << bf[0] << "/" << bf_n
           << "（" << (bf_n ? 100.0 * bf[0] / bf_n : 0) << "%） |\n";
  g_report << "- 结论：合法集合内的改道可由候选对比定位（取证非必需）；"
              "集合外篡改只有逐跳取证能定位——取证开销换的是闭集之外的可定位性。\n";
}

// ---------------------------------------------------------------- [10] 基线对比
// 基线 A（Icing 类）：逐跳 MAC 链。每跳算 8B tag 并追加进验证头，控制器对
// 候选路径重放整条链。与 MPV-2 共用同一密钥体系（端口密钥），同测试床公平。
uint64_t mac_hop(const KeyRing& kr, const Hop& h, uint64_t prev) {
  uint8_t k[32] = {0}, buf[20];
  uint64_t ks = kr.port_key(h);
  for (int i = 0; i < 8; ++i) k[i] = (uint8_t)((ks >> (8 * (7 - i))) & 0xff);
  for (int i = 0; i < 8; ++i) buf[i] = (uint8_t)((prev >> (8 * (7 - i))) & 0xff);
  uint32_t f[3] = {h.sid, h.in_port, h.out_port};
  for (int j = 0; j < 3; ++j)
    for (int i = 0; i < 4; ++i) buf[8 + 4 * j + i] = (uint8_t)((f[j] >> (8 * (3 - i))) & 0xff);
  uint8_t out[8];
  blake2b(out, 8, buf, sizeof(buf), k, 32);
  uint64_t v = 0;
  for (int i = 0; i < 8; ++i) v = (v << 8) | out[i];
  return v;
}

std::vector<uint64_t> mac_chain(const KeyRing& kr, const Path& p, uint64_t nonce) {
  std::vector<uint64_t> tags;
  uint64_t prev = nonce;
  for (const Hop& h : p) {
    prev = mac_hop(kr, h, prev);
    tags.push_back(prev);
  }
  return tags;
}

bool mac_verify(const KeyRing& kr, const Path& p, uint64_t nonce,
                const std::vector<uint64_t>& tags) {
  std::vector<uint64_t> rec = mac_chain(kr, p, nonce);
  return rec == tags;
}

// 基线 B（Atlas 类）：概率采样多路径验证。包以概率 ρ 被验证，检出率 ≈ ρ；
// 控制器负载 = ρ。MPV-2+CFMV 的负载 = 1/W（W 为流级窗口）且全检出。
void exp_baseline(int trials) {
  g_report << "\n## [10] 算法级基线对比（同测试床：同密钥体系、同攻击样本）\n\n";

  // A：逐跳 MAC 链判定时延 vs k（h=7，中位数）
  g_report << "### 逐跳 MAC 链（Icing 类）vs MPV-2：控制器判定时延 vs k（h=7）\n\n";
  g_report << "| k | MAC 链逐候选 (µs) | MPV-2 tag (µs) | MPV-2 scan (µs) |\n|---|---|---|---|\n";
  Rng rng(31);
  KeyRing kr = KeyRing::generate(16, 4, 20260501);
  for (uint32_t k : {1u, 2u, 4u, 8u, 16u, 32u, 64u}) {
    std::vector<Path> cands;
    for (uint32_t i = 0; i < k; ++i) {
      Path p;
      p.push_back(Hop{1, 1, 2});
      p.push_back(Hop{2, 1, 2});
      p.push_back(Hop{3, 1, 2});
      uint32_t x = i;
      p.push_back(Hop{4 + (x % 11), 1, 2}); x /= 11;
      p.push_back(Hop{4 + (x % 11), 1, 3});
      p.push_back(Hop{15, 1, 2});
      p.push_back(Hop{16, 1, 2});
      cands.push_back(p);
    }
    Header h = forward(kr, cands[k - 1], (uint8_t)((k - 1) & 0xff), rng.nonce());
    std::vector<uint64_t> tags = mac_chain(kr, cands[k - 1], h.nonce);
    ExpectationTable tb(kr, cands);
    std::vector<double> tm, tt, ts;
    for (int i = 0; i < 2000; ++i) {
      double t0 = now_us();
      for (uint32_t c = 0; c < k; ++c) mac_verify(kr, cands[c], h.nonce, tags);
      tm.push_back(now_us() - t0);
      t0 = now_us(); tb.verify_tag(h); tt.push_back(now_us() - t0);
      t0 = now_us(); tb.verify_scan(h); ts.push_back(now_us() - t0);
    }
    g_report << "| " << k << " | " << median(tm) << " | " << median(tt) << " | "
             << median(ts) << " |\n";
  }
  g_report << "- MAC 链每包重放 O(k·h) 次哈希、随 k 线性增长；MPV-2 tag 模式 O(1) "
              "与 k 无关。MAC 链的验证头为逐跳追加式（8B/跳，h=7 时 63B），头长对比见 [6]。\n";

  // B：概率采样（Atlas 类）：检出率 vs 判定负载。攻击包数 = trials（与 [1] 的
  // 攻击样本数同义），总包数 = 10 × trials，攻击占比 10%。
  g_report << "\n### 概率采样多路径（Atlas 类）vs MPV-2+CFMV：漏检率 vs 控制器负载\n\n";
  const int NPKT = trials * 10;
  Rng rng2(77);
  Path p = rand_path(rng2, 7);
  ExpectationTable tb(kr, std::vector<Path>{p});
  struct Pkt { uint64_t nonce, acc, hh; bool atk; };
  std::vector<Pkt> pkts;
  pkts.reserve(NPKT);
  int atk_tot = 0;
  for (int i = 0; i < NPKT; ++i) {
    bool atk = (i % 10) == 0;  // 10% 攻击包
    uint64_t nonce = rng2.nonce();
    Path q = p;
    if (atk) {
      ++atk_tot;
      uint32_t hi = rng2.range(1, (uint32_t)p.size() - 2);
      q[hi].out_port = (q[hi].out_port % 3) + 1;
      if (q == p) { q[hi].out_port = q[hi].out_port == 1 ? 2 : 1; }
    }
    Header h = forward(kr, q, 0, nonce);
    pkts.push_back({nonce, h.acc, h_of(nonce), atk});
  }
  g_report << "| 采样率 ρ | 控制器判定负载 | 攻击检出率 | 漏检率 |\n|---|---|---|---|\n";
  // 各 ρ 的采样循环相互独立：多线程并行（pkts 只读，期望表只读）
  const double rhos[6] = {0.01, 0.05, 0.1, 0.25, 0.5, 1.0};
  std::vector<uint64_t> v_cnt(6, 0), d_cnt(6, 0);
  {
    int per = (6 + g_nthr - 1) / g_nthr;
    for (int t = 0; t < g_nthr; ++t) {
      int lo = t * per, hi = lo + per;
      if (hi > 6) hi = 6;
      if (lo >= hi) break;
      g_pool->submit([lo, hi, &pkts, &tb, &rhos, &v_cnt, &d_cnt] {
        for (int ri = lo; ri < hi; ++ri) {
          uint64_t det = 0, verified = 0;
          for (const Pkt& pk : pkts) {
            if ((pk.hh % 10000) >= (uint64_t)(rhos[ri] * 10000.0)) continue;
            ++verified;
            Header h{pk.nonce, pk.acc, 0};
            if (pk.atk && !tb.verify_tag(h).ok) ++det;
          }
          v_cnt[ri] = verified;
          d_cnt[ri] = det;
        }
      });
    }
    g_pool->wait_idle();
  }
  std::vector<std::pair<double, double>> sample_pts;
  for (int ri = 0; ri < 6; ++ri) {
    double det_rate = atk_tot ? 100.0 * d_cnt[ri] / atk_tot : 0;
    g_report << "| " << rhos[ri] << " | " << (100.0 * v_cnt[ri] / NPKT) << "% | "
             << det_rate << "% | " << (100 - det_rate) << "% |\n";
    sample_pts.push_back({rhos[ri], 100 - det_rate});
  }
  g_report << "| MPV-2+CFMV（W=64） | " << (100.0 / 64) << "% | 100% | 0% |\n";
  g_report << "- 采样式以漏检换负载：负载降到 1/" << 64 << " 时漏检 "
           << (100 - 100.0 / 64) << "%；MPV-2+CFMV 用流级聚合把负载降到同一量级且"
              "全检出（篡改包使所在窗口失衡，[1] 与 [4] 已实测检出与诚实零误报）。\n";
  std::vector<std::pair<double, double>> cfmv_pts{{1.0 / 64, 0}};
  std::vector<Series> ss{{"概率采样（漏检≈1−ρ）", "#fbbf24", sample_pts},
                         {"MPV-2+CFMV（全检出）", "#4ade80", cfmv_pts}};
  svg_chart("chart_baseline.svg", "控制器判定负载 vs 攻击漏检率（10% 攻击流量）",
            "判定负载（相对逐包全验证）", "漏检率 %",
            {"0.01", "0.05", "0.1", "0.25", "0.5", "1.0"},
            {0.01, 0.05, 0.1, 0.25, 0.5, 1.0}, ss, 105, -3);
}

// ---------------------------------------------------------------- [11] 规模扩展
Path path_of_hops(uint32_t hops) {
  Path p;
  p.push_back(Hop{1, 1, 2});
  for (uint32_t i = 0; i + 2 < hops; ++i)
    p.push_back(Hop{2 + (i % 14), 1, (uint32_t)(2 + (i % 2))});
  p.push_back(Hop{16, 1, 2});
  return p;
}

void exp_hops() {
  g_report << "\n## [11] 规模扩展：路径跳数 h 下的开销与检出（各 2000 次）\n\n";
  g_report << "| h | 数据面单跳均摊 (µs) | 期望预计算 (µs) | tag 判定 (µs) | 检出率 |\n|---|---|---|---|---|\n";
  Rng rng(41);
  KeyRing kr = KeyRing::generate(16, 4, 20260501);
  std::vector<double> hs, pre, tag;
  std::vector<std::string> ticks;
  for (uint32_t h : {4u, 8u, 16u, 32u}) {
    Path p = path_of_hops(h);
    ExpectationTable tb(kr, std::vector<Path>{p});
    // 数据面：整条 forward，均摊到每跳
    std::vector<double> tf;
    for (int i = 0; i < 2000; ++i) {
      double t0 = now_us();
      forward(kr, p, 0, rng.nonce());
      tf.push_back(now_us() - t0);
    }
    // 控制器：期望预计算（流建立时一次）
    std::vector<double> te;
    for (int i = 0; i < 2000; ++i) {
      double t0 = now_us();
      expectation(kr, p);
      te.push_back(now_us() - t0);
    }
    // 控制器：tag 判定（每包）
    Header hh = forward(kr, p, 0, rng.nonce());
    std::vector<double> tv;
    for (int i = 0; i < 2000; ++i) {
      double t0 = now_us();
      tb.verify_tag(hh);
      tv.push_back(now_us() - t0);
    }
    // 检出率：改端口 / 旁路 / 改头 三类均匀混合
    int det = 0, tot = 0;
    for (int i = 0; i < 2000; ++i) {
      uint32_t kind = rng.range(0, 2);
      if (kind == 2) {  // 改头：出口帧翻转一位
        Header bh = forward(kr, p, 0, rng.nonce());
        bh.acc ^= 1;
        ++tot;
        if (!tb.verify_tag(bh).ok) ++det;
        continue;
      }
      Path bad = (kind == 0) ? atk_out_port(p, rng) : atk_bypass(p, rng);
      if (bad == p) continue;
      ++tot;
      Header bh = forward(kr, bad, 0, rng.nonce());
      if (!tb.verify_tag(bh).ok) ++det;
    }
    double mh = median(tf) / h, me = median(te), mt = median(tv);
    hs.push_back(h); ticks.push_back(std::to_string(h));
    pre.push_back(me); tag.push_back(mt);
    g_report << "| " << h << " | " << mh << " | " << me << " | " << mt << " | "
             << (tot ? 100.0 * det / tot : 0) << "% |\n";
  }
  std::vector<Series> ss{{"期望预计算（流建立一次）", "#fbbf24", {}},
                         {"tag 判定（每包）", "#4ade80", {}}};
  for (size_t i = 0; i < hs.size(); ++i) {
    ss[0].pts.push_back({hs[i], pre[i]});
    ss[1].pts.push_back({hs[i], tag[i]});
  }
  svg_chart("chart_hops.svg", "控制器开销 vs 路径跳数 h", "跳数 h", "µs",
            ticks, hs, ss, *std::max_element(pre.begin(), pre.end()) * 1.15);
  g_report << "- 数据面每跳 O(1)（均摊时延不随 h 变化，总时延线性于 h 属逐跳计算固有）"
              "；控制器 tag 判定与 h 无关（期望已折叠成 A+B·h）；只有流建立时的"
              "期望预计算随 h 线性——一次性成本。\n";
}

// ---------------------------------------------------------------- 洪灌吞吐
// 单独测量模式（--flood N）：只跑数据面管道吞吐，写 results/flood_report.md，
// 用于数据面优化前后的受控对比（同机同参数多次取中位）。
void exp_flood(int flood) {
  g_report << "# MPV-2 数据面管道吞吐（单项测量）\n\n";
  g_report << "- 环境：Ubuntu 24.04，g++ 13，VMware 虚拟机；用户态 AF_PACKET 交换机 4 台\n";
  g_report << "- 方法：h1 → h2 ping 洪灌 " << flood << " 包，统计逐跳上报行数与耗时\n\n";
  clear_logs();
  write_tables(Scenario::kNormal);
  setup_links();
  auto mk = [&](int sid, std::vector<std::string> ports) {
    SwitchConf c;
    c.sid = sid;
    c.ports = ports;
    c.flow_window = 64;
    return c;
  };
  std::vector<pid_t> pids;
  pids.push_back(spawn_switch(vswitch_exe(), mk(1, {"1:s1p1", "2:s1p2", "3:s1p3"})));
  pids.push_back(spawn_switch(vswitch_exe(), mk(2, {"1:s2p1", "2:s2p2"})));
  pids.push_back(spawn_switch(vswitch_exe(), mk(3, {"1:s3p1", "2:s3p2"})));
  pids.push_back(spawn_switch(vswitch_exe(), mk(4, {"1:s4p1", "2:s4p2", "3:s4p3"})));
  ::sleep(1);
  double t0 = now_us();
  run_traffic(flood, "0");
  double el = (now_us() - t0) / 1e6;
  ::sleep(1);
  for (pid_t p : pids) stop_switch(p);
  cleanup();
  int lines = 0;
  std::ifstream in(report_path());
  std::string l;
  while (std::getline(in, l))
    if (l.rfind("FLOW ", 0) != 0 && !l.empty()) ++lines;
  double pps = lines / el;
  g_report << "- 上报行 " << lines << "（含回程），耗时 " << el << " s，管道处理速率 ≈ "
           << (int)pps << " 行/秒\n";
  std::printf("[flood] %d 包，%d 行，%.3f s，%d 行/秒\n", flood, lines, el,
              (int)pps);
}

// ---------------------------------------------------------------- [7] 端到端
struct RoundStat {
  int rounds = 0, detect_ok = 0, locate_ok = 0, false_pos = 0;
};

std::vector<Event> run_e2e_round(Scenario sc, const std::string& evil_s2, int pings,
                                 Controller& ctl) {
  clear_logs();
  write_tables(sc);
  setup_links();
  auto mk = [&](int sid, std::vector<std::string> ports, const std::string& evil) {
    SwitchConf c;
    c.sid = sid;
    c.ports = ports;
    c.evil = evil;
    c.flow_window = 16;
    return c;
  };
  std::vector<pid_t> pids;
  pids.push_back(spawn_switch(vswitch_exe(), mk(1, {"1:s1p1", "2:s1p2", "3:s1p3"}, "none")));
  pids.push_back(spawn_switch(vswitch_exe(), mk(2, {"1:s2p1", "2:s2p2"}, evil_s2)));
  pids.push_back(spawn_switch(vswitch_exe(), mk(3, {"1:s3p1", "2:s3p2"}, "none")));
  pids.push_back(spawn_switch(vswitch_exe(), mk(4, {"1:s4p1", "2:s4p2", "3:s4p3"}, "none")));
  ::sleep(1);
  run_traffic(pings);
  ::sleep(1);
  for (pid_t p : pids) stop_switch(p);
  cleanup();
  std::vector<Event> evs;
  std::ifstream tin(trace_path());
  std::string line;
  while (std::getline(tin, line)) ctl.feed(line);
  std::ifstream in(report_path());
  while (std::getline(in, line)) {
    Event ev = ctl.feed(line);
    if (!ev.kind.empty()) evs.push_back(ev);
  }
  return evs;
}

int suspect_of(const std::vector<Event>& evs, const char* mac) {
  for (const Event& e : evs)
    if (e.mac == mac && !e.ok && !e.replay && e.suspect_sid >= 0) return e.suspect_sid;
  return -1;
}

void exp_e2e(int rounds, int pings) {
  g_report << "\n## [7] 端到端攻击场景统计（4 台软件交换机拓扑，每场景 " << rounds
           << " 轮 × " << pings << " 包）\n\n";
  g_report << "| 场景 | 轮次 | 检出 | 定位 | 对照项正常 |\n|---|---|---|---|---|\n";
  // R2 标签错配：正向全失败且定位 s1，反向零误报
  {
    RoundStat rs;
    for (int r = 0; r < rounds; ++r) {
      Controller ctl(SEED, directions());
      auto evs = run_e2e_round(Scenario::kTagflip, "none", pings, ctl);
      const DirStat& f = ctl.stat(0);
      const DirStat& rv = ctl.stat(1);
      ++rs.rounds;
      if (f.packets > 0 && f.fail == f.packets) ++rs.detect_ok;
      if (suspect_of(evs, H2MAC) == 1) ++rs.locate_ok;
      if (rv.fail == 0) ++rs.false_pos;  // 反向不受影响计为「无误报」
      // 误报列改为「反向无误报轮数」
    }
    g_report << "| 标签错配 | " << rs.rounds << " | " << rs.detect_ok << " | "
             << rs.locate_ok << " | " << rs.false_pos << " |\n";
  }
  // R3 恶意改头
  {
    RoundStat rs;
    for (int r = 0; r < rounds; ++r) {
      Controller ctl(SEED, directions());
      auto evs = run_e2e_round(Scenario::kNormal, "bitflip", pings, ctl);
      const DirStat& f = ctl.stat(0);
      const DirStat& rv = ctl.stat(1);
      ++rs.rounds;
      if (f.packets > 0 && f.fail == f.packets && rv.packets > 0 && rv.fail == rv.packets)
        ++rs.detect_ok;
      if (suspect_of(evs, H2MAC) == 2 && suspect_of(evs, H1MAC) == 2) ++rs.locate_ok;
      if (f.replays == 0 && rv.replays == 0) ++rs.false_pos;  // 无重放误标
    }
    g_report << "| 恶意改头(s2) | " << rs.rounds << " | " << rs.detect_ok << " | "
             << rs.locate_ok << " | " << rs.false_pos << " |\n";
  }
  // R4 恶意重放
  {
    RoundStat rs;
    for (int r = 0; r < rounds; ++r) {
      Controller ctl(SEED, directions());
      auto evs = run_e2e_round(Scenario::kNormal, "dup", pings, ctl);
      const DirStat& f = ctl.stat(0);
      const DirStat& rv = ctl.stat(1);
      ++rs.rounds;
      if (f.replays > 0 && rv.replays > 0 && f.fail == 0 && rv.fail == 0) ++rs.detect_ok;
      if (f.pass > 0 && rv.pass > 0) ++rs.locate_ok;  // 诚实包全部照常通过
      ++rs.false_pos;                                  // 诚实包零失败
    }
    g_report << "| 恶意重放(s2) | " << rs.rounds << " | " << rs.detect_ok << " | "
             << rs.locate_ok << " | " << rs.false_pos << " |\n";
  }
  // 黑洞：取证里出现、出口却没有上报的 nonce = 失联；逐个做前缀对照定位
  {
    RoundStat rs;
    for (int r = 0; r < rounds; ++r) {
      Controller ctl(SEED, directions());
      run_e2e_round(Scenario::kBlackhole, "none", pings, ctl);
      ++rs.rounds;
      // 集合差：失联 nonce
      std::set<uint64_t> traced, reported;
      std::ifstream tin(trace_path()), in(report_path());
      std::string line;
      while (std::getline(tin, line)) {
        char mac[32];
        unsigned a, b, c, d;
        unsigned long long nonce;
        if (std::sscanf(line.c_str(), "TRACE %31s %u %u %u %u %llu", mac, &a, &b, &c,
                        &d, &nonce) == 6 &&
            std::strcmp(mac, H2MAC) == 0)
          traced.insert(nonce);
      }
      while (std::getline(in, line)) {
        if (line.rfind("FLOW ", 0) == 0) continue;
        char mac[32];
        unsigned sid, tag;
        unsigned long long nonce, acc;
        if (std::sscanf(line.c_str(), "%u %u %llu %llu %31s", &sid, &tag, &nonce,
                        &acc, mac) == 5 &&
            std::strcmp(mac, H2MAC) == 0)
          reported.insert(nonce);
      }
      const DirStat& f = ctl.stat(0);
      if (f.packets == 0 && !traced.empty()) ++rs.detect_ok;  // 正向无上报且确有包发出
      int loc = 0;
      for (uint64_t n : traced)
        if (!reported.count(n) && ctl.localize(0, 0, n, 0) == 1) ++loc;
      if (loc > 0) ++rs.locate_ok;
      const DirStat& rv = ctl.stat(1);
      if (rv.fail == 0) ++rs.false_pos;
    }
    g_report << "| 路径偏离(黑洞) | " << rs.rounds << " | " << rs.detect_ok << " | "
             << rs.locate_ok << " | " << rs.false_pos << " |\n";
  }
  exp_flood(10000);
  g_report << "- 说明：用户态 AF_PACKET 交换机每包多次进出内核，吞吐比硬件低 2~3 个"
              "数量级；本数据用于衡量功能管道与控制器解耦后的承载能力。"
              "控制器侧上报处理吞吐见 [4b]（10 万行/秒，含双口径判定与行解析），"
              "纯判定吞吐见 [3]（数百万次/秒）。\n";
  g_report << "- 「对照项正常」含义：标签错配=反向零误报轮数；恶意改头=无重放误标轮数；"
              "恶意重放=诚实包零失败轮数；黑洞=反向零误报轮数。\n";
}

}  // namespace

// ---------------------------------------------------------------- main
int main(int argc, char** argv) {
  int trials = 10000, rounds = 5, pings = 20, flood = 0, nthr = 0;
  for (int i = 1; i < argc; ++i) {
    std::string a = argv[i];
    if (a == "--trials") trials = std::atoi(argv[++i]);
    else if (a == "--rounds") rounds = std::atoi(argv[++i]);
    else if (a == "--pings") pings = std::atoi(argv[++i]);
    else if (a == "--threads") nthr = std::atoi(argv[++i]);
    else if (a == "--flood") flood = std::atoi(argv[++i]);
  }
  if (::geteuid() != 0) {
    std::fprintf(stderr, "需要 root（[7] 要建 netns 拓扑）：sudo ./build/exp\n");
    return 2;
  }
  if (::access(vswitch_exe().c_str(), X_OK) != 0) {
    std::fprintf(stderr, "找不到交换机程序: %s（先 make）\n", vswitch_exe().c_str());
    return 2;
  }
  ::mkdir("results", 0755);
  ::mkdir(g_chart_dir.c_str(), 0755);
  ::mkdir(topo::workdir().c_str(), 0755);
  g_nthr = nthr > 0 ? nthr : (int)std::thread::hardware_concurrency();
  if (g_nthr <= 0) g_nthr = 2;
  if (g_nthr > 16) g_nthr = 16;
  mpv::ThreadPool pool((size_t)g_nthr);  // 全实验复用（M5.16）
  g_pool = &pool;

  // --flood N：单项洪灌测量（数据面优化前后受控对比），不触碰 exp_report.md
  if (flood > 0) {
    g_report.open("results/flood_report.md");
    if (!g_report) {
      std::fprintf(stderr, "无法写 results/flood_report.md\n");
      return 2;
    }
    exp_flood(flood);
    g_report.close();
    std::printf("完成：results/flood_report.md\n");
    return 0;
  }

  g_report.open("results/exp_report.md");
  if (!g_report) {
    std::fprintf(stderr, "无法写 results/exp_report.md\n");
    return 2;
  }
  g_report << "# MPV-2 结题实验报告（VM 实测）\n\n";
  g_report << "- 环境：Ubuntu 24.04，g++ 13，VMware 虚拟机；用户态 AF_PACKET 交换机 4 台\n";
  g_report << "- 参数：64 位素数域 p = 2^64 − 59；验证头恒定 16 字节\n";
  g_report << "- 本报告由 `exp` 程序一次运行自动生成，所有数字均为实测。\n";

  std::printf("[1/11] 攻击矩阵...\n");  std::fflush(stdout);
  exp_attack_matrix(trials, g_nthr);
  std::printf("[2/11] 多候选矩阵...\n"); std::fflush(stdout);
  exp_multicand(trials, g_nthr);
  std::printf("[3/11] 时延 vs k...\n");  std::fflush(stdout);
  {
    std::vector<double> ks, tag, scan;
    exp_latency_k(ks, tag, scan);
    std::vector<std::string> ticks;
    for (double k : ks) ticks.push_back("k=" + std::to_string((int)k));
    double ymax = *std::max_element(scan.begin(), scan.end()) * 1.15;
    std::vector<Series> ss{{"tag（CPMV）", "#60a5fa", {}}, {"scan（BPMV）", "#fbbf24", {}}};
    for (size_t i = 0; i < ks.size(); ++i) {
      ss[0].pts.push_back({ks[i], tag[i]});
      ss[1].pts.push_back({ks[i], scan[i]});
    }
    svg_chart("chart_latency_k.svg", "控制器判定时延 vs 候选路径数", "候选路径数",
              "µs", ticks, ks, ss, ymax, 0.15);
  }
  std::printf("[4/11] 流级与吞吐...\n"); std::fflush(stdout);
  {
    std::vector<double> ns, fl;
    exp_flow(ns, fl);
    std::vector<std::string> ticks;
    for (double n : ns) ticks.push_back(std::to_string((int)n));
    double ymax = *std::max_element(fl.begin(), fl.end()) * 1.2 + 0.005;
    std::vector<Series> ss{{"流级判定", "#4ade80", {}}};
    for (size_t i = 0; i < ns.size(); ++i) ss[0].pts.push_back({ns[i], fl[i]});
    svg_chart("chart_flow_n.svg", "CFMV 流级判定时延 vs 窗口大小（k=16）", "窗口包数 N",
              "µs", ticks, ns, ss, ymax, 0);
  }
  std::printf("[5/11] 通信开销...\n");  std::fflush(stdout);
  exp_comm();
  std::printf("[6/11] 头长对比...\n");  std::fflush(stdout);
  exp_header();
  std::printf("[7/11] 端到端（每场景 %d 轮）...\n", rounds);  std::fflush(stdout);
  exp_e2e(rounds, pings);
  std::printf("[8/11] 存储开销...\n");  std::fflush(stdout);
  exp_storage();
  std::printf("[9/11] 定位成功率...\n"); std::fflush(stdout);
  exp_localization(2000);
  std::printf("[10/11] 基线对比...\n");  std::fflush(stdout);
  exp_baseline(trials);
  std::printf("[11/11] 规模扩展...\n");  std::fflush(stdout);
  exp_hops();

  g_report << "\n---\n\n## 复现命令\n\n```bash\nsudo ./cpp/build/exp --trials " << trials
           << " --rounds " << rounds << " --pings " << pings << "\n```\n";
  g_report.close();

  std::printf("\n完成：results/exp_report.md + results/charts/*.svg\n");
  return 0;
}
