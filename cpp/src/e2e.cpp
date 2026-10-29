// MPV-2 端到端验证编排器（C++ 实现，工程内无脚本、无 Python）。
//
// 拓扑与场景定义见 topo.cpp。五轮：
//   R1 正常        转发表与候选路径一致 → 双向全部通过，流级窗口全过
//   R2 标签错配    s1 把 tag0 改走 P1 分支（数据面自洽）→ 正向全失败，
//                  定位到分歧点 s1；反向不受影响
//   R3 恶意改头    s2 为恶意交换机，转发时翻转验证头 1 比特 → 双向全失败，
//                  逐跳取证定位到 s2（首跳取证不匹配的交换机）
//   R4 恶意重放    s2 把带验证头的帧原样重发一份 → nonce 窗口全部判重放，
//                  诚实包不受影响（fail = 0）
//   R5 流级压缩    正常流量 + CFMV：出口按流聚合上报，控制器每窗口一次判定，
//                  判定次数相比逐包 CPMV 显著下降
//
// 用法： sudo ./build/e2e
#include <signal.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstdio>
#include <fstream>
#include <string>
#include <vector>

#include "controller.h"
#include "topo.h"

using namespace mpv;
using namespace topo;

namespace {

std::string g_vswitch;

std::string exe_dir() {
  char buf[4096];
  ssize_t n = ::readlink("/proc/self/exe", buf, sizeof(buf) - 1);
  if (n <= 0) return ".";
  buf[n] = 0;
  std::string s(buf);
  auto pos = s.find_last_of('/');
  return pos == std::string::npos ? "." : s.substr(0, pos);
}

// ------------------------------------------------------------------ 一轮
struct RoundResult {
  std::string name;
  bool ok = false;
  std::string detail;
};

std::vector<Event> run_round(const std::string& name, Scenario sc,
                             const std::string& evil_s2, int pings,
                             Controller& ctl) {
  std::printf("\n== %s ==\n", name.c_str());
  std::fflush(stdout);

  clear_logs();
  write_tables(sc);
  setup_links();

  auto mk = [&](int sid, std::vector<std::string> ports) {
    SwitchConf c;
    c.sid = sid;
    c.ports = ports;
    c.evil = (sid == 2) ? evil_s2 : "none";
    return c;
  };
  std::vector<pid_t> pids;
  pids.push_back(spawn_switch(g_vswitch, mk(1, {"1:s1p1", "2:s1p2", "3:s1p3"})));
  pids.push_back(spawn_switch(g_vswitch, mk(2, {"1:s2p1", "2:s2p2"})));
  pids.push_back(spawn_switch(g_vswitch, mk(3, {"1:s3p1", "2:s3p2"})));
  pids.push_back(spawn_switch(g_vswitch, mk(4, {"1:s4p1", "2:s4p2", "3:s4p3"})));
  ::sleep(1);

  run_traffic(pings);

  ::sleep(1);
  for (pid_t p : pids) stop_switch(p);  // SIGTERM 触发流级窗口冲刷
  cleanup();

  // 先取证后上报（与真实时序一致），都进控制器
  std::vector<Event> events;
  std::ifstream tin(trace_path());
  std::string line;
  while (std::getline(tin, line)) ctl.feed(line);
  std::ifstream in(report_path());
  while (std::getline(in, line)) {
    Event ev = ctl.feed(line);
    if (!ev.kind.empty()) events.push_back(ev);
  }
  return events;
}

void print_dir(const char* label, size_t d, const Controller& ctl) {
  const DirStat& s = ctl.stat(d);
  if (s.packets == 0 && s.flows == 0 && s.replays == 0) return;
  std::printf("  %s %s: 通过 %llu / 失败 %llu / 共 %llu", label,
              directions()[d].mac.c_str(), (unsigned long long)s.pass,
              (unsigned long long)s.fail, (unsigned long long)s.packets);
  if (s.replays)
    std::printf("，重放 %llu", (unsigned long long)s.replays);
  std::printf("\n");
  if (s.flows)
    std::printf("      流级(CFMV)：窗口 %llu，通过 %llu / 失败 %llu\n",
                (unsigned long long)s.flows, (unsigned long long)s.flow_pass,
                (unsigned long long)s.flow_fail);
}

int suspect_of(const std::vector<Event>& evs, size_t d) {
  for (const Event& e : evs)
    if (e.mac == directions()[d].mac && !e.ok && !e.replay &&
        e.suspect_sid >= 0)
      return e.suspect_sid;
  return -1;
}

RoundResult check(const std::string& name, bool cond, const std::string& why) {
  RoundResult r;
  r.name = name;
  r.ok = cond;
  if (!cond) r.detail = why;
  return r;
}

}  // namespace

int main() {
  if (::geteuid() != 0) {
    std::fprintf(stderr, "需要 root：sudo ./build/e2e\n");
    return 2;
  }
  g_vswitch = exe_dir() + "/vswitch";
  if (::access(g_vswitch.c_str(), X_OK) != 0) {
    std::fprintf(stderr, "找不到交换机程序: %s（先 make）\n", g_vswitch.c_str());
    return 2;
  }
  ::mkdir(WORK, 0755);

  std::printf("================================================================\n");
  std::printf("MPV-2 端到端验证 · C++ 软件交换机 4 台 · 五轮场景\n");
  std::printf("================================================================\n");

  const int PINGS = 20;
  std::vector<RoundResult> results;

  // ------------------------------------------------------------ R1 正常
  {
    Controller ctl(SEED, directions());
    auto evs = run_round("R1 正常转发", Scenario::kNormal, "none", PINGS, ctl);
    print_dir("正向", 0, ctl);
    print_dir("反向", 1, ctl);
    const DirStat& f = ctl.stat(0);
    const DirStat& r = ctl.stat(1);
    results.push_back(check("R1", f.fail == 0 && r.fail == 0 && f.pass > 0 &&
                                      r.pass > 0 && f.flow_fail == 0 &&
                                      r.flow_fail == 0 && f.flow_pass > 0,
                            "正常转发不应有失败，流级窗口应全过"));
    (void)evs;
  }

  // ------------------------------------------------------------ R2 标签错配
  {
    Controller ctl(SEED, directions());
    auto evs = run_round("R2 标签错配", Scenario::kTagflip, "none", PINGS, ctl);
    print_dir("正向", 0, ctl);
    print_dir("反向", 1, ctl);
    const DirStat& f = ctl.stat(0);
    const DirStat& r = ctl.stat(1);
    int suspect = suspect_of(evs, 0);
    std::printf("      → 定位：分歧点 s%d\n", suspect);
    results.push_back(check("R2", f.fail == f.packets && f.packets > 0 &&
                                      r.fail == 0 && suspect == 1,
                            "错配后正向应全失败并定位到 s1，反向不受影响"));
  }

  // ------------------------------------------------------------ R3 恶意改头
  {
    Controller ctl(SEED, directions());
    auto evs = run_round("R3 恶意交换机·比特翻转", Scenario::kNormal,
                         "bitflip", PINGS, ctl);
    print_dir("正向", 0, ctl);
    print_dir("反向", 1, ctl);
    const DirStat& f = ctl.stat(0);
    const DirStat& r = ctl.stat(1);
    int sf = suspect_of(evs, 0), sr = suspect_of(evs, 1);
    std::printf("      → 定位：正向嫌疑 s%d，反向嫌疑 s%d（逐跳取证）\n", sf, sr);
    results.push_back(check("R3", f.fail == f.packets && f.packets > 0 &&
                                      r.fail == r.packets && r.packets > 0 &&
                                      sf == 2 && sr == 2 && f.replays == 0,
                            "比特翻转应双向全失败且取证定位到 s2"));
  }

  // ------------------------------------------------------------ R4 恶意重放
  {
    Controller ctl(SEED, directions());
    auto evs = run_round("R4 恶意交换机·重放", Scenario::kNormal, "dup",
                         PINGS, ctl);
    print_dir("正向", 0, ctl);
    print_dir("反向", 1, ctl);
    const DirStat& f = ctl.stat(0);
    const DirStat& r = ctl.stat(1);
    results.push_back(check("R4", f.replays > 0 && r.replays > 0 &&
                                      f.fail == 0 && r.fail == 0 && f.pass > 0,
                            "重放应被 nonce 窗口拦截且不影响诚实包"));
  }

  // ------------------------------------------------------------ R5 流级压缩
  {
    Controller ctl(SEED, directions());
    run_round("R5 流级压缩（CFMV）", Scenario::kNormal, "none", PINGS, ctl);
    const DirStat& f = ctl.stat(0);
    const DirStat& r = ctl.stat(1);
    std::printf("  逐包判定（CPMV）%llu 次 vs 流级判定（CFMV）%llu 次\n",
                (unsigned long long)(f.cpmv_checks + r.cpmv_checks),
                (unsigned long long)(f.cfmv_checks + r.cfmv_checks));
    results.push_back(check("R5", f.flow_fail == 0 && r.flow_fail == 0 &&
                                      f.flow_pass > 0 && r.flow_pass > 0 &&
                                      f.cfmv_checks + r.cfmv_checks <
                                          f.cpmv_checks + r.cpmv_checks,
                            "流级判定应全过且判定次数显著少于逐包"));
  }

  // ------------------------------------------------------------ 汇总
  std::printf("\n----------------------------------------------------------------\n");
  int bad = 0;
  for (const RoundResult& r : results) {
    std::printf("%s  %s\n", r.ok ? "✅" : "❌", r.name.c_str());
    if (!r.ok) {
      std::printf("     %s\n", r.detail.c_str());
      ++bad;
    }
  }
  if (bad) {
    std::printf("结论：%d 轮未通过\n", bad);
    return 1;
  }
  std::printf("结论：R1–R5 全部通过 —— 端到端验证成立\n");
  return 0;
}
