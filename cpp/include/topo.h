// 拓扑与进程编排（Linux 专用，e2e 与 dashboard 共用）。
//
// 拓扑：
//     h1 --- s1 --- s2 --- s4 --- h2
//              \            /
//               +--- s3 ----+
// 候选路径（正向 h1→h2）：
//     P0: s1(1→2) s2(1→2) s4(1→3)
//     P1: s1(1→3) s3(1→2) s4(2→3)
// 反向对称。
#pragma once

#include <string>
#include <vector>

#include "controller.h"

namespace topo {

constexpr const char* H1MAC = "00:00:00:00:00:01";
constexpr const char* H2MAC = "00:00:00:00:00:02";
constexpr uint64_t SEED = 20260501;
constexpr const char* WORK = "/tmp/mpv_run";

// 场景：normal 正常；tagflip 标签错配（s1 把 tag0 改走 P1 分支且全网自洽）；
// blackhole 路径偏离（s1 把 tag0 改走 s3，s3 无 tag0 表项 → 丢包黑洞）。
enum class Scenario { kNormal, kTagflip, kBlackhole };

struct SwitchConf {
  int sid;
  std::vector<std::string> ports;  // {"1:s1p1", "2:s1p2", ...}
  std::string evil = "none";       // none | bitflip | dup
  bool trace = true;
  uint32_t flow_window = 32;
};

std::string table_path(int sid);
std::string report_path();
std::string trace_path();

void cleanup();      // 删除 netns 与残留 veth（幂等）
void setup_links();  // 建 netns h1/h2 + 6 条 veth + 地址/邻居表
void write_tables(Scenario sc);
void clear_logs();   // 清空上报与取证文件

pid_t spawn_switch(const std::string& vswitch_bin, const SwitchConf& conf);
void stop_switch(pid_t pid);

// ping 流量：h1 → h2，返回实际发送条数
void run_traffic(int count, const std::string& interval = "0.05");

// 候选路径与方向定义（控制器用）
std::vector<mpv::Path> cand_fwd();
std::vector<mpv::Path> cand_rev();
std::vector<mpv::Direction> directions();

}  // namespace topo