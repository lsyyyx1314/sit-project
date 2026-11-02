// MPV-2 攻击矩阵与性能基准（C++ 实现，无 Python 依赖）。
//
// 用法： bench [--trials N] [--seed S]
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <random>
#include <string>
#include <vector>

#include "mpv2.h"

using namespace mpv;

namespace {

struct Rng {
  std::mt19937_64 g;
  explicit Rng(uint64_t seed) : g(seed) {}
  uint64_t next() { return g(); }
  uint32_t range(uint32_t lo, uint32_t hi) {  // [lo, hi]
    return lo + (uint32_t)(g() % (uint64_t)(hi - lo + 1));
  }
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

// 攻击：把路径改成"看起来合法但不是它"的样子
Path attack_out_port(const Path& p, Rng& r) {
  Path q = p;
  uint32_t i = r.range(0, (uint32_t)q.size() - 1);
  uint32_t v = r.range(1, 4);
  if (v == q[i].out_port) v = (v % 4) + 1;
  q[i].out_port = v;
  return q;
}
Path attack_in_port(const Path& p, Rng& r) {
  Path q = p;
  uint32_t i = r.range(0, (uint32_t)q.size() - 1);
  q[i].in_port = q[i].in_port == 1 ? 2 : 1;
  return q;
}
Path attack_bypass(const Path& p, Rng& r) {
  Path q = p;
  uint32_t i = r.range(1, (uint32_t)q.size() - 2);
  q[i].sid = r.range(2, 15);
  return q;
}
Path attack_reorder(const Path& p, Rng& r) {
  Path q = p;
  if (q.size() < 4) return q;
  uint32_t i = r.range(1, (uint32_t)q.size() - 3);
  std::swap(q[i], q[i + 1]);
  return q;
}
Path attack_delete(const Path& p, Rng& r) {
  Path q = p;
  if (q.size() < 4) return q;
  q.erase(q.begin() + r.range(1, (uint32_t)q.size() - 2));
  return q;
}
Path attack_insert(const Path& p, Rng& r) {
  Path q = p;
  uint32_t pos = r.range(1, (uint32_t)q.size() - 1);
  q.insert(q.begin() + pos, Hop{r.range(2, 15), 1, 3});
  return q;
}
Path attack_replace(const Path& p, Rng& r) {
  Path q;
  q.push_back(p.front());
  for (size_t i = 1; i + 1 < p.size(); ++i) q.push_back(Hop{r.range(2, 15), 1, 2});
  q.push_back(p.back());
  return q;
}
Path attack_truncate(const Path& p, Rng&) {
  Path q = p;
  if (q.size() > 2) q.pop_back();
  return q;
}

double now_us() {
  using namespace std::chrono;
  return duration_cast<nanoseconds>(steady_clock::now().time_since_epoch()).count() /
         1000.0;
}

double median(std::vector<double>& v) {
  std::sort(v.begin(), v.end());
  return v[v.size() / 2];
}

struct Row {
  const char* code;
  const char* name;
  int detected = 0;
  int total = 0;
};

}  // namespace

int main(int argc, char** argv) {
  int trials = 3000;
  uint64_t seed = 20260501;
  for (int i = 1; i < argc; ++i) {
    std::string a = argv[i];
    if (a == "--trials") trials = std::atoi(argv[++i]);
    else if (a == "--seed") seed = std::stoull(argv[++i]);
  }

  KeyRing kr = KeyRing::generate(16, 4, seed);
  Rng rng(seed);
  // 编译期确定条目顺序，避免与排序结果不一致
  std::vector<Row> rows = {
      {"S1", "改出端口", 0, 0},   {"S2", "改入端口", 0, 0},
      {"S3", "交换机旁路", 0, 0}, {"S4", "跳序交换", 0, 0},
      {"S5", "删除一跳", 0, 0},   {"S6", "插入一跳", 0, 0},
      {"S7", "整条替换", 0, 0},   {"S8", "截断路径", 0, 0},
  };

  int honest_ok = 0;

  for (int t = 0; t < trials; ++t) {
    uint32_t n = rng.range(3, 7);
    Path p = rand_path(rng, n);
    uint64_t nonce = rng.nonce();
    Header hdr = forward(kr, p, 0, nonce);

    std::vector<Path> one{p};
    ExpectationTable tb(kr, one);
    if (tb.verify_tag(hdr).ok) ++honest_ok;

    Path attacked[8];
    attacked[0] = attack_out_port(p, rng);
    attacked[1] = attack_in_port(p, rng);
    attacked[2] = attack_bypass(p, rng);
    attacked[3] = attack_reorder(p, rng);
    attacked[4] = attack_delete(p, rng);
    attacked[5] = attack_insert(p, rng);
    attacked[6] = attack_replace(p, rng);
    attacked[7] = attack_truncate(p, rng);

    for (int a = 0; a < 8; ++a) {
      if (attacked[a] == p) continue;  // 攻击退化为无操作，不计入分母
      ++rows[a].total;
      // 关键：用**合法路径**的表去验证被篡改的包，而不是用篡改后的表
      Header bad = forward(kr, attacked[a], 0, nonce);
      if (!tb.verify_tag(bad).ok) ++rows[a].detected;
    }
  }

  // 数据性攻击
  int flip_total = 0, flip_det = 0, forge_total = 0, forge_det = 0;
  for (int t = 0; t < trials; ++t) {
    Path p = rand_path(rng, rng.range(3, 7));
    uint64_t nonce = rng.nonce();
    Header hdr = forward(kr, p, 0, nonce);
    std::vector<Path> one{p};
    ExpectationTable tb(kr, one);

    Header flipped = hdr;
    flipped.acc ^= 1;
    ++flip_total;
    if (!tb.verify_tag(flipped).ok) ++flip_det;

    Path forged = rand_path(rng, rng.range(3, 7));
    if (!(forged == p)) {
      ++forge_total;
      Header fh = forward(kr, forged, 0, nonce);
      if (!tb.verify_tag(fh).ok) ++forge_det;
    }
  }

  std::printf("================================================================\n");
  std::printf("MPV-2 攻击矩阵（C++）  每组 %d 次\n", trials);
  std::printf("================================================================\n\n");
  std::printf("| 编号 | 攻击手法     | 检出 / 样本 | 检出率 |\n");
  std::printf("| ---- | ------------ | ----------- | ------ |\n");
  for (const Row& r : rows) {
    if (r.total == 0) continue;
    std::printf("| %-4s | %-12s | %5d/%-5d | %5.1f%% |\n", r.code, r.name,
                r.detected, r.total, 100.0 * r.detected / r.total);
  }
  std::printf("| S9   | 验证头比特翻转 | %5d/%-5d | %5.1f%% |\n", flip_det, flip_total,
              100.0 * flip_det / flip_total);
  std::printf("| S10  | 随机伪造验证头 | %5d/%-5d | %5.1f%% |\n", forge_det, forge_total,
              100.0 * forge_det / forge_total);
  std::printf("\n诚实样本接受率：%.2f%%（%d/%d）\n", 100.0 * honest_ok / trials,
              honest_ok, trials);
  std::printf("验证头长度：%d 字节（恒定）\n\n", HEADER_BYTES);

  // ---------------------------------------------------------------- 性能
  std::printf("控制器单次判定时延（7 跳，命中最末候选）\n");
  std::printf("| k  | tag (us) | scan (us) |\n");
  std::printf("| -- | -------- | --------- |\n");
  for (uint32_t k : {1u, 2u, 4u, 8u, 16u, 32u, 64u}) {
    std::vector<Path> cands;
    for (uint32_t i = 0; i < k; ++i) {
      Path p;
      p.push_back(Hop{1, 1, 2});
      p.push_back(Hop{2, 1, 2});
      p.push_back(Hop{3, 1, 2});
      uint32_t x = i;
      p.push_back(Hop{4 + (x % 11), 1, 2});
      x /= 11;
      p.push_back(Hop{4 + (x % 11), 1, 3});
      p.push_back(Hop{15, 1, 2});
      p.push_back(Hop{16, 1, 2});
      cands.push_back(p);
    }
    ExpectationTable tb(kr, cands);
    Header hdr = forward(kr, cands[k - 1], (uint8_t)((k - 1) & 0xff), rng.nonce());

    std::vector<double> tt, ts;
    for (int i = 0; i < 2000; ++i) {
      double t0 = now_us();
      tb.verify_tag(hdr);
      tt.push_back(now_us() - t0);
      t0 = now_us();
      tb.verify_scan(hdr);
      ts.push_back(now_us() - t0);
    }
    std::printf("| %-2u | %8.3f | %9.3f |\n", k, median(tt), median(ts));
  }

  // ------------------------------------------------- 多候选攻击矩阵（M3）
  std::printf("\n多候选集下的攻击检出（k 条合法路径共用一张期望表）\n");
  std::printf("| k  | 诚实接受          | 篡改检出          |\n");
  std::printf("| -- | ----------------- | ----------------- |\n");
  for (uint32_t k : {2u, 8u, 16u}) {
    // k 条互异候选路径（三元组周期 42 > 16，且 sid ≤ 15 不越界）
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
    int honest = 0, honest_total = 0, det = 0, det_total = 0;
    for (int t = 0; t < trials; ++t) {
      uint32_t pick = rng.range(0, k - 1);
      uint64_t nonce = rng.nonce();
      Header h = forward(kr, cands[pick], (uint8_t)pick, nonce);
      ++honest_total;
      if (tb.verify_tag(h).ok) ++honest;
      Path bad = cands[pick];
      uint32_t hi = rng.range(1, 3);
      bad[hi].out_port = (bad[hi].out_port % 3) + 1;
      if (!(bad == cands[pick])) {
        ++det_total;
        Header bh = forward(kr, bad, (uint8_t)pick, nonce);
        if (!tb.verify_tag(bh).ok && tb.verify_scan(bh).matched < 0) ++det;
      }
    }
    std::printf("| %-2u | %5.1f%% (%d/%d) | %5.1f%% (%d/%d) |\n", k,
                100.0 * honest / honest_total, honest, honest_total,
                100.0 * det / (det_total ? det_total : 1), det, det_total);
  }

  // ------------------------------------------------- 流级判定与 N 无关（CFMV）
  std::printf("\n流级（CFMV）判定时延与窗口大小 N 的关系（k=16）\n");
  std::printf("| N    | flow (us) |\n| ---- | --------- |\n");
  {
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
    for (uint64_t n : {1ull, 32ull, 512ull, 4096ull}) {
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
      std::printf("| %-4llu | %9.3f |\n", (unsigned long long)n, median(tv));
    }
  }

  // ------------------------------------------------- 与已有方案对比（解析口径）
  // 依据各方案公开设计推算，非复现实验；用于论文与演示的口径对齐。
  std::printf("\n与已有路径验证方案对比（解析口径，h=跳数，k=候选路径数，N=窗口包数）\n");
  std::printf("| 方案 | 验证头 | 控制器判定/包 | 多路径 | 交换机存储/流 | 覆盖率 |\n");
  std::printf("| ---- | ------ | -------------- | ------ | -------------- | ------ |\n");
  std::printf("| Icing | ≈4h B（随跳数线性） | O(h) 次逐跳校验 | 不支持 | O(h) | 逐包全采样 |\n");
  std::printf("| L-PVS | 定长 ≈16 B | O(k)（需逐候选） | 需枚举候选 | O(k) | 逐包全采样 |\n");
  std::printf("| Atlas | 小（概率标记） | O(1)（仅被采样包） | 支持 | O(1) | 采样 s，漏检 1-s |\n");
  std::printf("| BPMV（本文） | 16 B 恒定 | O(k) scan | 支持 | O(1) | 逐包全采样 |\n");
  std::printf("| CPMV（本文） | 16 B 恒定 | O(1) tag | 支持 | O(1) | 逐包全采样 |\n");
  std::printf("| CFMV（本文） | 16 B 恒定 | O(1)/窗口 | 支持 | O(1)/流 | 窗口全采样+nonce 去重 |\n");
  std::printf("\n注：CFMV 的流级判定必须配合 nonce 重放窗口（否则重放合法包可同时\n");
  std::printf("抬高三元组），工程实现见 vswitch --flow-window 与控制器 NonceWindow。\n");
  return 0;
}
