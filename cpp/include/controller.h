// 控制器侧验证模块：吃交换机上报（逐包 / 流级聚合 / 逐跳取证），
// 输出判定事件与定位结论。verify_reports、e2e、dashboard 共用。
//
// 三种上报行（与 vswitch.cpp 的输出格式一一对应）：
//     <sid> <tag> <nonce> <acc> <dst_mac>                        逐包上报
//     FLOW <dst_mac> <tag> <N> <sum_h> <sum_v>                   流级聚合（CFMV）
//     TRACE <dst_mac> <sid> <in> <out> <tag> <nonce> <pos> <V>   逐跳取证
#pragma once

#include <string>
#include <unordered_map>
#include <vector>

#include "mpv2.h"

namespace mpv {

struct Direction {
  std::string mac;
  std::vector<Path> paths;
};

// 一跳取证记录：包在 sid 上处理后的实际累加值
struct HopTrace {
  uint32_t sid = 0, in_port = 0, out_port = 0, pos = 0;
  uint64_t v_after = 0;
};

struct Event {
  std::string kind = "";  // "" | "packet" | "flow"
  std::string mac;
  uint64_t nonce = 0, acc = 0;
  uint32_t tag = 0;
  uint64_t n = 0;        // flow：窗口内包数
  bool ok = false;       // CPMV/CFMV 判定结果
  bool replay = false;   // nonce 窗口判定为重放
  int matched = -1;      // 实际命中的候选编号（scan 结果）
  int claimed = -1;      // 包声称的 tag（flow 为上报 tag）
  int suspect_sid = -1;  // 首个嫌疑交换机（= suspects 的第一个）
  std::vector<int> suspects;  // 多故障定位：全部嫌疑交换机
  double verify_us = 0;  // 本次判定耗时（微秒）
};

struct DirStat {
  uint64_t packets = 0, pass = 0, fail = 0, replays = 0;
  uint64_t flows = 0, flow_pass = 0, flow_fail = 0;
  uint64_t cpmv_checks = 0;  // tag 模式实测判定次数
  uint64_t bpmv_checks = 0;  // scan 模式实测判定次数
  uint64_t cfmv_checks = 0;  // 流级判定次数
  int localized = 0;
};

class Controller {
 public:
  Controller(uint64_t seed, const std::vector<Direction>& dirs);

  // 处理一行上报；不是已知格式时返回 kind == "" 的事件
  Event feed(const std::string& line);

  const DirStat& stat(size_t dir) const { return stats_[dir]; }
  const std::vector<Direction>& directions() const { return dirs_; }
  size_t dir_count() const { return dirs_.size(); }
  const KeyRing& keys() const { return kr_; }

  // 定位：优先逐跳取证（首个 V ≠ 期望前缀的交换机 / 最后取证点的下一跳），
  // 其次候选对比（声称路径与实际命中路径的首个分歧点）。返回嫌疑 sid 或 -1。
  int localize(size_t dir, uint8_t tag, uint64_t nonce, uint64_t acc);

  // 多故障定位：沿实际取证路由逐跳对照累计期望与声称路径位置，
  // 返回全部嫌疑交换机（改道跳 + 每个篡改跳）。无取证时退化为单点定位。
  std::vector<int> localize_all(size_t dir, uint8_t tag, uint64_t nonce,
                                uint64_t acc);

 private:
  int dir_of(const std::string& mac) const;
  Event feed_packet(std::istringstream& ss);
  Event feed_flow(std::istringstream& ss);
  Event feed_trace(std::istringstream& ss);

  KeyRing kr_;
  std::vector<Direction> dirs_;
  std::vector<ExpectationTable> tables_;
  std::vector<DirStat> stats_;
  std::vector<NonceWindow> windows_;
  std::unordered_map<std::string, std::vector<HopTrace>> traces_;
};

}  // namespace mpv