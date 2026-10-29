// MPV-2 软件虚拟交换机（用户态数据平面，C++ 实现）。
//
// 为什么不用 OVS：OVS 动作集没有模运算，算不了 c_i = (a_i + b_i·H(nonce)) mod p。
// 为什么不用 BMv2：其 ALU 为 32 位，装不下 64 位模域。因此数据面自己实现。
//
// 帧格式（IPv4 场景）：
//     eth(14) | shim(16) | ip                 shim = nonce(7) V(8) tag(1)
//     ethertype = 0x88B5；出口交换机剥离并恢复 0x0800
//
// 转发表（纯文本，每行一条）：
//     <dst_mac> <tag> <out_port> <pos> <strip> <in_port>
// 以 # 开头为注释。文件 mtime 变化时自动重载。
//
// 上报（出口交换机，每包一行）：
//     <sid> <tag> <nonce> <acc> <dst_mac>
// 流级聚合上报（出口交换机，每凑满 --flow-window 包一行，CFMV）：
//     FLOW <dst_mac> <tag> <N> <sum_h> <sum_v>
//
// 逐跳取证（--trace 开启时，每跳一行，供控制器定位首分歧交换机）：
//     TRACE <dst_mac> <sid> <in> <out> <tag> <nonce> <pos> <V_after>
//
// 恶意交换机模拟（--evil）：
//     bitflip 转发时翻转验证头 acc 的 1 个比特（伪造/篡改）
//     dup     把带验证头的帧原样重发一份（重放攻击）
//
// 用法：
//     vswitch --sid 1 --seed 20260501 --table s1.tbl --report rep.txt
//             --paths 2 --force-tag 0 --port 1:s1p1 --port 2:s1p2
//             [--trace trace.txt] [--flow-window 32] [--evil bitflip]
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <csignal>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <unordered_map>
#include <vector>

#include "mpv2.h"

using namespace mpv;

namespace {

constexpr uint16_t kShimEther = 0x88B5;
constexpr uint16_t kIpEther = 0x0800;

struct Entry {
  int port = 0;
  int pos = 0;
  bool strip = false;
  int in_port = 0;
};

std::string mac_to_str(const uint8_t* m) {
  char buf[18];
  std::snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1],
                m[2], m[3], m[4], m[5]);
  return buf;
}

struct Port {
  int index = 0;
  std::string name;
  int fd = -1;
  int ifindex = 0;
};

struct PairHash {
  size_t operator()(const std::pair<std::string, std::string>& p) const {
    return std::hash<std::string>()(p.first) ^
           (std::hash<std::string>()(p.second) << 1);
  }
};

enum class Evil { kNone, kBitflip, kDup };

class VSwitch {
 public:
  VSwitch(uint32_t sid, uint64_t seed, std::string table, std::string report,
          std::vector<Port> ports, int paths, int force_tag, Evil evil,
          std::string trace_path, uint32_t flow_window)
      : kr_(KeyRing::generate(16, 4, seed)),
        sid_(sid),
        table_path_(std::move(table)),
        report_path_(std::move(report)),
        ports_(std::move(ports)),
        paths_(paths),
        force_tag_(force_tag),
        evil_(evil),
        flow_window_(flow_window) {
    for (const Port& p : ports_) {
      fd_by_port_[p.index] = p.fd;
      ifindex_by_port_[p.index] = p.ifindex;
    }
    report_ = std::fopen(report_path_.c_str(), "a");
    if (!trace_path.empty()) trace_ = std::fopen(trace_path.c_str(), "a");
    load_table(true);
  }

  void stats() const {
    if (!debug_) return;
    std::fprintf(stderr,
                 "[s%u] in=%llu out=%llu drop=%llu entries=%zu flows=%zu\n",
                 sid_, (unsigned long long)in_, (unsigned long long)out_,
                 (unsigned long long)drop_, entries_.size(), flows_.size());
  }

  // 把未凑满窗口的流级聚合冲进上报文件（退出前调用）
  void flush_flows() {
    for (auto& kv : flows_) {
      FlowAgg& a = kv.second;
      if (a.n == 0) continue;
      std::fprintf(report_, "FLOW %s %s %llu %llu %llu\n", kv.first.first.c_str(),
                   kv.first.second.c_str(), (unsigned long long)a.n,
                   (unsigned long long)a.sum_h, (unsigned long long)a.sum_v);
      a.reset();
    }
    std::fflush(report_);
  }

  void set_debug(bool v) { debug_ = v; }

  void run() {
    std::vector<pollfd> pfds;
    for (const Port& p : ports_) pfds.push_back(pollfd{p.fd, POLLIN, 0});
    uint32_t last_check = 0;
    while (true) {
      int n = ::poll(pfds.data(), pfds.size(), 200);
      if (n > 0) {
        for (size_t i = 0; i < pfds.size(); ++i) {
          if (!(pfds[i].revents & POLLIN)) continue;
          drain(ports_[i]);
        }
      }
      if (++last_check % 2 == 0) load_table(false);  // 约每 400ms 检查一次
    }
  }

 private:
  void load_table(bool force) {
    struct stat st{};
    if (::stat(table_path_.c_str(), &st) != 0) return;
    if (!force && st.st_mtime == mtime_) return;
    mtime_ = st.st_mtime;
    entries_.clear();
    std::FILE* f = std::fopen(table_path_.c_str(), "r");
    if (!f) return;
    char line[256];
    while (std::fgets(line, sizeof(line), f)) {
      if (line[0] == '#' || line[0] == '\n') continue;
      char mac[32];
      int tag, port, pos, strip, in_port;
      if (std::sscanf(line, "%31s %d %d %d %d %d", mac, &tag, &port, &pos, &strip,
                      &in_port) != 6)
        continue;
      entries_[std::string(mac) + "|" + std::to_string(tag)] =
          Entry{port, pos, strip != 0, in_port};
    }
    std::fclose(f);
  }

  const Entry* lookup(const std::string& mac, int tag) const {
    auto it = entries_.find(mac + "|" + std::to_string(tag));
    return it == entries_.end() ? nullptr : &it->second;
  }

  void drain(const Port& p) {
    uint8_t buf[65536];
    while (true) {
      struct sockaddr_ll sll{};
      socklen_t sl = sizeof(sll);
      ssize_t n = ::recvfrom(p.fd, buf, sizeof(buf), MSG_DONTWAIT,
                             reinterpret_cast<sockaddr*>(&sll), &sl);
      if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
        break;
      }
      if (sll.sll_pkttype == PACKET_OUTGOING) continue;  // 过滤本端口发出的帧
      ++in_;
      handle(buf, static_cast<size_t>(n), p.index);
    }
  }

  void handle(const uint8_t* frame, size_t len, int in_idx) {
    if (len < 14) return;
    uint16_t ether = (uint16_t)((frame[12] << 8) | frame[13]);
    std::string dst = mac_to_str(frame);
    std::string src = mac_to_str(frame + 6);

    uint8_t tag = 0;
    uint64_t nonce = 0, acc = 0;
    const uint8_t* payload = nullptr;
    size_t payload_len = 0;
    bool shimmed = false;

    if (ether == kShimEther) {
      if (len < 14 + HEADER_BYTES) return;
      Header h = decode_header(frame + 14);
      nonce = h.nonce;
      acc = h.acc;
      tag = h.tag;
      payload = frame + 14 + HEADER_BYTES;
      payload_len = len - 14 - HEADER_BYTES;
      shimmed = true;
    } else if (ether == kIpEther) {
      payload = frame + 14;
      payload_len = len - 14;
    } else {
      ++drop_;
      return;
    }

    const Entry* e = nullptr;
    if (!shimmed) {
      if (force_tag_ >= 0) {
        tag = (uint8_t)force_tag_;
      } else {
        uint64_t mix = 1469598103934665603ULL;
        for (int i = 0; i < 6; ++i) mix = (mix ^ frame[6 + i]) * 1099511628211ULL;
        for (int i = 0; i < 6; ++i) mix = (mix ^ frame[i]) * 1099511628211ULL;
        tag = (uint8_t)(mix % (uint64_t)(paths_ > 0 ? paths_ : 1));
      }
    }
    e = lookup(dst, tag);
    if (!e) {
      ++drop_;
      return;
    }

    Hop hop{sid_, (uint32_t)(e->in_port > 0 ? e->in_port : in_idx),
            (uint32_t)e->port};
    // 入端口以实际到达端口为准（与控制器侧一致时表里的 in_port 应等于它）
    hop.in_port = (uint32_t)in_idx;

    if (!shimmed) {
      nonce = 0;
      for (int i = 0; i < 7; ++i) nonce = (nonce << 8) | (uint8_t)(rand() & 0xff);
      Header h = ingress(kr_, hop, tag, nonce);
      acc = h.acc;
    } else {
      uint64_t c = contribution(kr_, hop, h_of(nonce));
      acc = addmod(acc, mulmod(c, powmod(RHO, (uint64_t)e->pos - 1)));
    }

    // 恶意交换机：篡改验证头（在本跳的合法贡献之后叠加比特翻转）
    if (evil_ == Evil::kBitflip && shimmed) acc ^= 1;

    int out_fd = fd_by_port_[e->port];
    if (out_fd < 0) return;

    uint8_t out[65536];
    std::memcpy(out, frame, 12);
    uint16_t et = e->strip ? kIpEther : kShimEther;
    out[12] = (uint8_t)(et >> 8);
    out[13] = (uint8_t)(et & 0xff);
    size_t off = 14;
    if (!e->strip) {
      Header h{nonce, acc, tag};
      encode_header(h, out + 14);
      off += HEADER_BYTES;
    }
    std::memcpy(out + off, payload, payload_len);
    struct sockaddr_ll dst_addr{};
    dst_addr.sll_family = AF_PACKET;
    dst_addr.sll_ifindex = ifindex_by_port_[e->port];
    dst_addr.sll_halen = 6;
    std::memcpy(dst_addr.sll_addr, out, 6);
    ssize_t sent = ::sendto(out_fd, out, off + payload_len, 0,
                            reinterpret_cast<sockaddr*>(&dst_addr),
                            sizeof(dst_addr));
    if (sent > 0)
      ++out_;
    else
      std::fprintf(stderr, "[s%u] sendto 失败: %s\n", sid_, std::strerror(errno));

    // 恶意交换机：重放（把带验证头的帧原样再发一份）
    if (evil_ == Evil::kDup && shimmed && sent > 0)
      ::sendto(out_fd, out, off + payload_len, 0,
               reinterpret_cast<sockaddr*>(&dst_addr), sizeof(dst_addr));

    // 逐跳取证：记录本跳之后实际写进帧里的累加值
    if (trace_) {
      std::fprintf(trace_, "TRACE %s %u %u %u %u %llu %u %llu\n", dst.c_str(),
                   sid_, hop.in_port, e->port, tag,
                   (unsigned long long)nonce, e->pos,
                   (unsigned long long)acc);
      std::fflush(trace_);
    }

    if (e->strip) {
      std::fprintf(report_, "%u %u %llu %llu %s\n", sid_, tag,
                   (unsigned long long)nonce, (unsigned long long)acc,
                   dst.c_str());
      std::fflush(report_);
      // CFMV：按 (流, tag) 聚合，凑满一个窗口上报一行
      FlowAgg& a = flows_[{dst, std::to_string(tag)}];
      a.add(nonce, acc);
      if (a.n >= flow_window_) {
        std::fprintf(report_, "FLOW %s %u %llu %llu %llu\n", dst.c_str(), tag,
                     (unsigned long long)a.n, (unsigned long long)a.sum_h,
                     (unsigned long long)a.sum_v);
        a.reset();
      }
    }
    (void)src;
  }

  KeyRing kr_;
  uint32_t sid_;
  std::string table_path_;
  std::string report_path_;
  std::vector<Port> ports_;
  int paths_;
  int force_tag_;
  Evil evil_ = Evil::kNone;
  uint32_t flow_window_ = 32;
  std::unordered_map<std::pair<std::string, std::string>, FlowAgg, PairHash>
      flows_;
  std::unordered_map<std::string, Entry> entries_;
  std::unordered_map<int, int> fd_by_port_;
  std::unordered_map<int, int> ifindex_by_port_;
  time_t mtime_ = 0;
  std::FILE* report_ = nullptr;
  std::FILE* trace_ = nullptr;
  uint64_t in_ = 0, out_ = 0, drop_ = 0;
  bool debug_ = false;
};

int open_port(const std::string& name) {
  int fd = ::socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (fd < 0) {
    std::perror("socket");
    return -1;
  }
  struct sockaddr_ll sll{};
  sll.sll_family = AF_PACKET;
  sll.sll_protocol = htons(ETH_P_ALL);
  sll.sll_ifindex = (int)::if_nametoindex(name.c_str());
  if (sll.sll_ifindex == 0) {
    std::fprintf(stderr, "找不到接口 %s\n", name.c_str());
    ::close(fd);
    return -1;
  }
  if (::bind(fd, reinterpret_cast<sockaddr*>(&sll), sizeof(sll)) < 0) {
    std::perror("bind");
    ::close(fd);
    return -1;
  }
  return fd;
}

VSwitch* g_sw = nullptr;

void on_term(int) {
  if (g_sw) {
    g_sw->flush_flows();
    g_sw->stats();
  }
  std::_Exit(0);
}

}  // namespace

int main(int argc, char** argv) {
  uint32_t sid = 0;
  uint64_t seed = 0;
  bool debug = false;
  std::string table, report, trace, evil = "none";
  int paths = 1, force_tag = -1;
  uint32_t flow_window = 32;
  std::vector<Port> ports;

  for (int i = 1; i < argc; ++i) {
    std::string a = argv[i];
    auto next = [&]() { return std::string(argv[++i]); };
    if (a == "--sid") sid = (uint32_t)std::stoul(next());
    else if (a == "--seed") seed = std::stoull(next());
    else if (a == "--table") table = next();
    else if (a == "--report") report = next();
    else if (a == "--trace") trace = next();
    else if (a == "--paths") paths = std::stoi(next());
    else if (a == "--force-tag") force_tag = std::stoi(next());
    else if (a == "--flow-window") flow_window = (uint32_t)std::stoul(next());
    else if (a == "--evil") evil = next();
    else if (a == "--debug") debug = true;
    else if (a == "--port") {
      std::string spec = next();
      auto pos = spec.find(':');
      Port p;
      p.index = std::stoi(spec.substr(0, pos));
      p.name = spec.substr(pos + 1);
      p.ifindex = (int)::if_nametoindex(p.name.c_str());
      p.fd = open_port(p.name);
      if (p.fd < 0) return 1;
      ports.push_back(p);
    }
  }
  if (ports.empty()) {
    std::fprintf(stderr, "至少需要一个 --port\n");
    return 1;
  }
  Evil emode = Evil::kNone;
  if (evil == "bitflip") emode = Evil::kBitflip;
  else if (evil == "dup") emode = Evil::kDup;
  else if (evil != "none") {
    std::fprintf(stderr, "未知 --evil：%s（none|bitflip|dup）\n", evil.c_str());
    return 2;
  }

  std::srand((unsigned)(seed ^ (sid * 2654435761u)));
  VSwitch sw(sid, seed, table, report, std::move(ports), paths, force_tag,
             emode, trace, flow_window);
  sw.set_debug(debug);
  g_sw = &sw;
  std::signal(SIGTERM, on_term);
  std::signal(SIGINT, on_term);
  sw.run();
  return 0;
}
