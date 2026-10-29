// 端到端上报验证器：读取交换机上报，按候选路径集合判定并定位。
//
// 输入：
//   --cand   候选路径描述（每方向一块）
//   --report 交换机上报（每行：sid tag nonce acc dst_mac）
//   --seed   密钥种子
//
// 候选描述格式：
//     DIR <dst_mac> <路径数>
//     PATH <sid:in:out> <sid:in:out> ...
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "mpv2.h"

using namespace mpv;

namespace {

struct Direction {
  std::string mac;
  std::vector<Path> paths;
};

std::vector<Direction> load_cand(const std::string& file) {
  std::vector<Direction> dirs;
  std::ifstream in(file);
  std::string line;
  while (std::getline(in, line)) {
    if (line.empty() || line[0] == '#') continue;
    std::istringstream ss(line);
    std::string kind;
    ss >> kind;
    if (kind == "DIR") {
      Direction d;
      int k = 0;
      ss >> d.mac >> k;
      dirs.push_back(d);
    } else if (kind == "PATH") {
      if (dirs.empty()) continue;
      Path p;
      std::string tok;
      while (ss >> tok) {
        int sid = 0, ip = 0, op = 0;
        std::sscanf(tok.c_str(), "%d:%d:%d", &sid, &ip, &op);
        p.push_back(Hop{(uint32_t)sid, (uint32_t)ip, (uint32_t)op});
      }
      dirs.back().paths.push_back(p);
    }
  }
  return dirs;
}

}  // namespace

int main(int argc, char** argv) {
  std::string cand, report;
  uint64_t seed = 0;
  for (int i = 1; i < argc; ++i) {
    std::string a = argv[i];
    if (a == "--cand") cand = argv[++i];
    else if (a == "--report") report = argv[++i];
    else if (a == "--seed") seed = std::stoull(argv[++i]);
  }
  if (cand.empty() || report.empty()) {
    std::fprintf(stderr, "用法: verify_reports --cand c.txt --report r.txt --seed S\n");
    return 2;
  }

  KeyRing kr = KeyRing::generate(16, 4, seed);
  std::vector<Direction> dirs = load_cand(cand);

  std::vector<ExpectationTable> tables;
  for (const Direction& d : dirs) tables.emplace_back(kr, d.paths);

  struct Stat {
    int total = 0, pass = 0, fail = 0, localized = 0;
    int matched_idx = -1;
    int claimed = -1;
    int diverge_sid = -1;
  };
  std::vector<Stat> stats(dirs.size());

  std::ifstream in(report);
  std::string line;
  while (std::getline(in, line)) {
    if (line.empty()) continue;
    unsigned sid, tag;
    unsigned long long nonce, acc;
    char mac[32];
    if (std::sscanf(line.c_str(), "%u %u %llu %llu %31s", &sid, &tag, &nonce,
                    &acc, mac) != 5)
      continue;
    Header h{nonce, acc, (uint8_t)tag};
    for (size_t i = 0; i < dirs.size(); ++i) {
      if (dirs[i].mac != mac) continue;
      Stat& s = stats[i];
      ++s.total;
      Verdict v = tables[i].verify_tag(h);
      if (v.ok) {
        ++s.pass;
      } else {
        ++s.fail;
        Verdict sc = tables[i].verify_scan(h);
        if (sc.matched >= 0) {
          ++s.localized;
          s.matched_idx = sc.matched;
          s.claimed = (int)tag;
          // 分歧点 = 声称路径与真实路径的最后一个共同交换机
          const Path& a = dirs[i].paths[(size_t)tag];
          const Path& b = dirs[i].paths[(size_t)sc.matched];
          size_t common = 0;
          while (common < a.size() && common < b.size() &&
                 a[common].sid == b[common].sid)
            ++common;
          s.diverge_sid = (int)a[common > 0 ? common - 1 : 0].sid;
        }
      }
      break;
    }
  }

  int rc = 0;
  for (size_t i = 0; i < dirs.size(); ++i) {
    const Stat& s = stats[i];
    if (s.total == 0) continue;
    std::printf("  %s: 通过 %d / 失败 %d / 共 %d\n", dirs[i].mac.c_str(), s.pass,
                s.fail, s.total);
    if (s.fail > 0 && s.localized > 0) {
      std::printf("      → 实际命中候选 #%d，标签声称 #%d：路径标签错配，分歧点 s%d\n",
                  s.matched_idx, s.claimed, s.diverge_sid);
    } else if (s.fail > 0) {
      std::printf("      → 未命中任何候选：路径偏离或验证头被篡改\n");
    }
    if (s.fail > 0) rc = 1;
  }
  return rc;
}
