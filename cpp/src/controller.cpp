#include "controller.h"

#include <algorithm>
#include <chrono>
#include <cstdio>

namespace mpv {
namespace {

double now_us() {
  using namespace std::chrono;
  return duration_cast<nanoseconds>(steady_clock::now().time_since_epoch())
             .count() /
         1000.0;
}

// 单 nonce 取证条目上界：合法取证每 nonce ≤ 路径最长跳数（exp[11] 上界 32，
// 取 64 有余量）。此前条目向量无界——同一 nonce 洪灌取证行可放大内存（P0-2）。
constexpr size_t kTraceHopsMax = 64;

}  // namespace

Controller::Controller(uint64_t seed, const std::vector<Direction>& dirs,
                       size_t trace_cap)
    : kr_(KeyRing::generate(kMaxSwitches, kMaxPorts, seed)),
      dirs_(dirs),
      trace_cap_(trace_cap ? trace_cap : 1) {
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
  // 快分发：前缀比较 + 手写解析（此前 FLOW/TRACE 行仍构造 istringstream）
  if (line.size() >= 5 && line.compare(0, 5, "FLOW ") == 0)
    return feed_flow(line.c_str());
  if (line.size() >= 6 && line.compare(0, 6, "TRACE ") == 0)
    return feed_trace(line.c_str());
  return feed_packet(line);
}

// 手写解析热路径 "<sid> <tag> <nonce> <acc> <mac>"（十进制、单空格分隔，
// 与 vswitch 输出严格一致；容忍前导空白，字段缺失即失败——与 sscanf 行为一致）。
// sscanf 全行解析实测 ~420ns/行，是上报吞吐的主要解析成本。
namespace {

const char* skip_ws(const char* p) {
  while (*p == ' ' || *p == '\t') ++p;
  return p;
}

bool parse_udec(const char*& p, uint64_t& out) {
  p = skip_ws(p);
  if (*p < '0' || *p > '9') return false;
  uint64_t v = 0;
  while (*p >= '0' && *p <= '9') {
    v = v * 10 + (uint64_t)(*p - '0');
    ++p;
  }
  out = v;
  return true;
}

bool parse_mac(const char*& p, char* out /*≥32*/) {
  p = skip_ws(p);
  size_t n = 0;
  while (*p && *p != ' ' && *p != '\t' && *p != '\n' && *p != '\r') {
    if (n >= 31) return false;
    out[n++] = *p++;
  }
  out[n] = 0;
  return n > 0;
}

}  // namespace

Event Controller::feed_packet(const std::string& line) {
  Event ev;
  const char* p = line.c_str();
  uint64_t sid, tag, nonce, acc;
  char mac[32];
  if (!parse_udec(p, sid) || !parse_udec(p, tag) || !parse_udec(p, nonce) ||
      !parse_udec(p, acc) || !parse_mac(p, mac))
    return ev;
  ev.kind = "packet";
  ev.mac = mac;
  ev.nonce = nonce;
  ev.acc = acc;
  ev.tag = (uint32_t)tag;

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

  // 公开哈希一次，tag/scan 双口径共用（h_of 占单次判定 ~99% 时间）
  uint64_t hh = h_of(nonce);
  double t0 = now_us();
  Verdict v = tables_[(size_t)d].verify_tag(h, hh);
  double t1 = now_us();
  ev.verify_us = t1 - t0;
  ++st.cpmv_checks;
  // BPMV 对照口径：同样的包用 scan 模式再判定一次，记录真实检查次数
  Verdict sc = tables_[(size_t)d].verify_scan(h, hh);
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

// 手写解析热路径 "FLOW <mac> <tag> <N> <sum_h> <sum_v>"（十进制、空白分隔，
// 与 vswitch 输出及旧 sscanf 行为一致：容忍制表符/多空格，字段缺失即失败）。
// 此前走 istringstream + ss.str()：每行流构造 + 整行拷贝，实测 ~1.6× 于逐包快路径。
Event Controller::feed_flow(const char* p) {
  Event ev;
  p += 5;  // 跳过 "FLOW " 前缀（dispatch 已匹配）
  char mac[32];
  uint64_t tag, n, sum_h, sum_v;
  if (!parse_mac(p, mac) || !parse_udec(p, tag) || !parse_udec(p, n) ||
      !parse_udec(p, sum_h) || !parse_udec(p, sum_v))
    return ev;
  ev.kind = "flow";
  ev.mac = mac;
  ev.tag = (uint32_t)tag;
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

// 手写解析 "TRACE <mac> <sid> <in> <out> <tag> <nonce> <pos> <V_after>"
// + 字段边界校验（M5.18 安全加固）：sid/端口超出部署边界（kMaxSwitches /
// kMaxPorts）的取证行不可能来自合法交换机——直接丢弃。此前越界 Hop 会进入
// 定位路径，在 KeyRing::port_key 的 unordered_map::at 处抛
// std::out_of_range 击穿控制器：恶意交换机一行伪造取证 + 一个失败包（或
// dashboard 黑洞路径）即可 DoS，且 dashboard 以 root 运行消费这些文件。
// 取证表单 nonce 条目数同步加上界（kTraceHopsMax）。
Event Controller::feed_trace(const char* p) {
  Event ev;
  p += 6;  // 跳过 "TRACE " 前缀（dispatch 已匹配）
  char mac[32];
  uint64_t sid, in_p, out_p, tag, nonce, pos, v_after;
  if (!parse_mac(p, mac) || !parse_udec(p, sid) || !parse_udec(p, in_p) ||
      !parse_udec(p, out_p) || !parse_udec(p, tag) || !parse_udec(p, nonce) ||
      !parse_udec(p, pos) || !parse_udec(p, v_after))
    return ev;
  int d = dir_of(mac);
  if (d < 0) return ev;  // 未知方向的取证无从对照，不入表
  if (sid < 1 || sid > kMaxSwitches || in_p < 1 || in_p > kMaxPorts ||
      out_p < 1 || out_p > kMaxPorts)
    return ev;  // 越界行丢弃：定位退化为候选对比，功能不中断
  // 键 = 方向(8b) | nonce(56b)：nonce 空间 56 bit，方向数 < 256，无碰撞
  uint64_t key = ((uint64_t)d << 56) | (uint64_t)nonce;
  auto& recs = traces_[key];
  if (recs.size() < kTraceHopsMax)
    recs.push_back(HopTrace{(uint32_t)sid, (uint32_t)in_p, (uint32_t)out_p,
                            (uint32_t)pos, v_after});
  // 内存上界：长期在线时取证按世代清空（旧取证的包退化为候选对比定位）
  if (traces_.size() > trace_cap_) traces_.clear();
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
  // tag 来自上报行（未信任输入，0~255）：越界 tag 无声称路径可对照，直接返回。
  // 此前 paths[tag] 越界读是 UB——恶意出口交换机声称 tag=200 即可触发。
  if (tag >= dirs_[dir].paths.size()) return out;
  const Path& claimed = dirs_[dir].paths[tag];
  // 键 = 方向(8b) | nonce(56b)，与 feed_trace 一致
  const uint64_t tkey = ((uint64_t)dir << 56) | (uint64_t)nonce;
  auto it = traces_.find(tkey);

  uint64_t hh = h_of(nonce);
  if (it == traces_.end() || it->second.empty()) {
    // 无取证：候选对比，声称路径与实际命中路径的首个分歧交换机
    // （复用已构建的期望表；此前此处每次重建 O(k·h)，纯浪费）
    Verdict sc = tables_[dir].verify_scan(Header{nonce, acc, tag});
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