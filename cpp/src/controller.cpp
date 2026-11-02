#include "controller.h"

#include <algorithm>
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
  ev.suspects = localize_all((size_t)d, (uint8_t)tag, nonce, acc);
  if (!ev.suspects.empty()) {
    ev.suspect_sid = ev.suspects.front();
    ++st.localized;
  }
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
  std::vector<int> s = localize_all(dir, tag, nonce, acc);
  return s.empty() ? -1 : s.front();
}

// 多故障定位：沿实际取证路由逐跳对照。
//   * 篡改检查：期望值用「上一跳的观测值」做基准（篡改偏移 δ 会随帧传播，
//     用纯净累计值会把下游诚实交换机也误标为嫌疑）；
//   * 位置检查：取证的实际 (sid,in,out) 与声称路径第 i 跳不一致 → 改道/改端口
//     嫌疑 = 声称路径的第 i 跳交换机；
//   * 取证覆盖全程但最终上报仍不符 → 出口上报篡改。
std::vector<int> Controller::localize_all(size_t dir, uint8_t tag,
                                          uint64_t nonce, uint64_t acc) {
  std::vector<int> out;
  if (dir >= dirs_.size()) return out;
  const Path& claimed = dirs_[dir].paths[tag];
  const std::string key = dirs_[dir].mac + "|" + std::to_string(nonce);
  auto it = traces_.find(key);

  uint64_t hh = h_of(nonce);
  if (it == traces_.end() || it->second.empty()) {
    // 无取证：候选对比，声称路径与实际命中路径的首个分歧交换机
    ExpectationTable tb(kr_, dirs_[dir].paths);
    Verdict sc = tb.verify_scan(Header{nonce, acc, tag});
    if (sc.matched < 0) return out;
    const Path& actual = dirs_[dir].paths[(size_t)sc.matched];
    size_t common = 0;
    while (common < claimed.size() && common < actual.size() &&
           claimed[common].sid == actual[common].sid)
      ++common;
    out.push_back((int)claimed[common > 0 ? common - 1 : 0].sid);
    return out;
  }

  std::vector<HopTrace> recs = it->second;
  std::stable_sort(recs.begin(), recs.end(),
                   [](const HopTrace& a, const HopTrace& b) {
                     return a.pos < b.pos;
                   });

  uint64_t carry = 0;      // 上一跳之后帧里的实际累加值
  bool on_claimed = true;  // 尚未偏离声称路径
  for (size_t i = 0; i < recs.size(); ++i) {
    const HopTrace& r = recs[i];
    Hop hop{r.sid, r.in_port, r.out_port};
    uint64_t expect = addmod(carry, mulmod(contribution(kr_, hop, hh),
                                           powmod(RHO, (uint64_t)i)));
    if (r.v_after != expect) out.push_back((int)r.sid);  // 本跳篡改嫌疑
    carry = r.v_after;  // 以观测值为准，让后续跳的期望建立在实际上

    if (on_claimed) {
      if (i < claimed.size() && r.sid == claimed[i].sid &&
          r.in_port == claimed[i].in_port && r.out_port == claimed[i].out_port)
        continue;
      // 与声称路径第 i 跳不一致：改道/改端口发生在该跳
      if (i < claimed.size()) out.push_back((int)claimed[i].sid);
      on_claimed = false;
    }
  }

  // 取证全程与声称路径吻合、无任何其他嫌疑，但出口上报仍不符：
  // 出口上报本身被篡改。路由已偏离或已有篡改嫌疑时，上报值不等属于正常
  // 推论，不得再把出口交换机标为嫌疑。
  if (out.empty() && on_claimed && recs.size() == claimed.size()) {
    uint64_t expect_total = 0;
    for (size_t j = 0; j < claimed.size(); ++j)
      expect_total =
          addmod(expect_total, mulmod(contribution(kr_, claimed[j], hh),
                                      powmod(RHO, (uint64_t)j)));
    if (acc != expect_total) out.push_back((int)claimed.back().sid);
  }

  // 去重保序
  std::vector<int> dedup;
  for (int sid : out)
    if (dedup.empty() || dedup.back() != sid) dedup.push_back(sid);
  return dedup;
}

}  // namespace mpv