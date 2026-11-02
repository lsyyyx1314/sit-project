// 端到端上报验证器：读取交换机上报，经共享控制器模块判定并定位。
//
// 输入：
//   --cand   候选路径描述（每方向一块）
//   --report 交换机上报文件（逐包行 / FLOW 行 / TRACE 行均可混排）
//   --seed   密钥种子
//
// 候选描述格式：
//     DIR <dst_mac> <路径数>
//     PATH <sid:in:out> <sid:in:out> ...
//
// 输出：每方向的逐包判定（CPMV tag 模式，失败回退 BPMV scan）、流级判定
// （CFMV）、重放计数与定位结论；退出码 1 表示存在验证失败。
#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "controller.h"

using namespace mpv;

namespace {

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

  std::vector<Direction> dirs = load_cand(cand);
  Controller ctl(seed, dirs);

  std::ifstream in(report);
  std::string line;
  while (std::getline(in, line)) ctl.feed(line);

  int rc = 0;
  for (size_t i = 0; i < dirs.size(); ++i) {
    const DirStat& s = ctl.stat(i);
    if (s.packets == 0 && s.flows == 0) continue;
    std::printf("  %s: 通过 %llu / 失败 %llu / 共 %llu",
                dirs[i].mac.c_str(), (unsigned long long)s.pass,
                (unsigned long long)s.fail, (unsigned long long)s.packets);
    if (s.replays)
      std::printf("，重放 %llu", (unsigned long long)s.replays);
    std::printf("\n");
    if (s.flows)
      std::printf("      流级(CFMV)：窗口 %llu，通过 %llu / 失败 %llu\n",
                  (unsigned long long)s.flows, (unsigned long long)s.flow_pass,
                  (unsigned long long)s.flow_fail);
    if (s.fail > 0) {
      if (s.localized > 0)
        std::printf("      → 已定位嫌疑交换机（逐跳取证 / 候选对比，见 dashboard 或 e2e 输出）\n");
      else
        std::printf("      → 未命中任何候选且无取证：路径偏离或验证头被篡改\n");
      rc = 1;
    }
    if (s.flow_fail > 0) rc = 1;
  }
  return rc;
}
