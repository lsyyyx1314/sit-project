#include "controller.h"

#include <chrono>
#include <cstdio>
#include <sstream>

namespace mpv {
namespace {

double now_us() {
  using namespace std::chrono;
  return duration_cast<nanoseconds>(steady_clock::now().time_since_epoch())
             .count() /
         1000.0;
}

}  // namespace

Controller::Controller(uint64_t seed, const std::vector<Direction>& dirs)
    : kr_(KeyRing::generate(16, 4, seed)), dirs_(dirs) {
  tables_.reserve(dirs.size());
  stats_.resize(dirs.size());
  windows_.resize(dirs.size());
  for (const Direction& d : dirs) tables_.emplace_back(kr_, d.paths);
}

int Controller::dir_of(const std::string& mac) const {
  for (size_t i = 0; i < dirs_.size(); ++i)
    if (dirs_[i].mac == mac) return (int)i;
  return -1;
}

Event Controller::feed(const std::string& line) {
  if (line.empty()) return Event{};
  std::istringstream ss(line);
  std::string head;
  ss >> head;
  if (head == "FLOW") return feed_flow(ss);
  if (head == "TRACE") return feed_trace(ss);
  // 逐包行以 sid 开头，把刚读走的字段放回去
  std::istringstream ss2(line);
  return feed_packet(ss2);
}

Event Controller::feed_packet(std::istringstream& ss) {
  Event ev;
  unsigned sid, tag;
  unsigned long long nonce, acc;
  char mac[32];
  if (std::sscanf((ss.str()).c_str(), "%u %u %llu %llu %31s", &sid, &tag,
                  &nonce, &acc, mac) != 5)
    return ev;
  ev.kind = "packet";
  ev.mac = mac;
  ev.nonce = nonce;
  ev.acc = acc;
  ev.tag = tag;

  int d = dir_of(mac);
  if (d < 0) return ev;
  DirStat& st = stats_[(size_t)d];
  ev.claimed = (int)tag;

  // 重放窗口：同方向最近见过的 nonce 直接判重放，不进入正常判定
  if (!windows_[(size_t)d].see(nonce)) {
    ev.replay = true;
    ++st.replays;
    // 重放是已验证包的复制品，不需要定位；重复的 acc 也不计入通过/失败
    return ev;
  }

  ++st.packets;
  const Header h{nonce, acc, (uint8_t)tag};

  double t0 = now_us();
  Verdict v = tables_[(size_t)d].verify_tag(h);
  double t1 = now_us();
  ev.verify_us = t1 - t0;
  ++st.cpmv_checks;
  // BPMV 对照口径：同样的包用 scan 模式再判定一次，记录真实检查次数
  Verdict sc = tables_[(size_t)d].verify_scan(h);
  st.bpmv_checks += (uint64_t)sc.checks;

  if (v.ok) {
    ++st.pass;
    ev.ok = true;
    ev.matched = v.matched;
    return ev;
  }
  ++st.fail;
  ev.matched = sc.matched;
  ev.suspect_sid = localize((size_t)d, (uint8_t)tag, nonce, acc);
  if (ev.suspect_sid >= 0) ++st.localized;
  return ev;
}

Event Controller::feed_flow(std::istringstream& ss) {
  Event ev;
  char mac[32];
  unsigned tag;
  unsigned long long n, sum_h, sum_v;
  if (std::sscanf(ss.str().c_str(), "FLOW %31s %u %llu %llu %llu", mac, &tag,
                  &n, &sum_h, &sum_v) != 5)
    return ev;
  ev.kind = "flow";
  ev.mac = mac;
  ev.tag = tag;
  ev.n = n;

  int d = dir_of(mac);
  if (d < 0) return ev;
  DirStat& st = stats_[(size_t)d];
  ev.claimed = (int)tag;

  ++st.flows;
  ++st.cfmv_checks;
  double t0 = now_us();
  Verdict v = tables_[(size_t)d].verify_flow((uint8_t)tag, n, sum_h, sum_v);
  double t1 = now_us();
  ev.verify_us = t1 - t0;
  if (v.ok) {
    ev.ok = true;
    ++st.flow_pass;
    return ev;
  }
  ++st.flow_fail;
  Verdict sc = tables_[(size_t)d].verify_flow_scan(n, sum_h, sum_v);
  st.cfmv_checks += (uint64_t)sc.checks;
  ev.matched = sc.matched;
  // 流级失败无法定位到具体交换机（聚合抹掉了单包信息），
  // 只能给出「该窗口内该 tag 的转发行为异常」——这正是包级与流级的分工。
  return ev;
}

Event Controller::feed_trace(std::istringstream& ss) {
  Event ev;
  char mac[32];
  unsigned sid, in_p, out_p, tag, pos;
  unsigned long long nonce, v_after;
  if (std::sscanf(ss.str().c_str(), "TRACE %31s %u %u %u %u %llu %u %llu", mac,
                  &sid, &in_p, &out_p, &tag, &nonce, &pos, &v_after) != 8)
    return ev;
  traces_[std::string(mac) + "|" + std::to_string(nonce)].push_back(
      HopTrace{sid, in_p, out_p, pos, v_after});
  return ev;  // kind == ""，trace 不产生判定事件
}

int Controller::localize(size_t dir, uint8_t tag, uint64_t nonce,
                         uint64_t acc) {
  if (dir >= dirs_.size()) return -1;
  const Path& claimed = dirs_[dir].paths[tag];
  const std::string key = dirs_[dir].mac + "|" + std::to_string(nonce);
  auto it = traces_.find(key);

  uint64_t hh = h_of(nonce);
  if (it != traces_.end() && !it->second.empty()) {
    // 逐跳对照：E_j = Σ_{i≤j} c_i·ρ^(i-1)，与各跳取证值比对
    uint64_t expect = 0;
    for (size_t j = 0; j < claimed.size(); ++j) {
      uint64_t c = contribution(kr_, claimed[j], hh);
      expect = addmod(expect, mulmod(c, powmod(RHO, (uint64_t)j)));
      const HopTrace* rec = nullptr;
      for (const HopTrace& r : it->second)
        if (r.sid == claimed[j].sid) rec = &r;  // 取该交换机的最后一条
      if (!rec) return (int)claimed[j].sid;     // 包没能到达该跳：嫌疑 = 该跳
      if (rec->v_after != expect) return (int)claimed[j].sid;  // 本跳起对不上
    }
    if (acc != expect) return (int)claimed.back().sid;  // 出口上报与取证不符
    return -1;
  }

  // 无取证时退化为候选对比：声称路径与实际命中路径的首个分歧交换机
  ExpectationTable tb(kr_, dirs_[dir].paths);
  Verdict sc = tb.verify_scan(Header{nonce, acc, tag});
  if (sc.matched < 0) return -1;
  const Path& actual = dirs_[dir].paths[(size_t)sc.matched];
  size_t common = 0;
  while (common < claimed.size() && common < actual.size() &&
         claimed[common].sid == actual[common].sid)
    ++common;
  return (int)claimed[common > 0 ? common - 1 : 0].sid;
}

}  // namespace mpv