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
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <atomic>
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

// ---------------------------------------------------------------- 内核加速（M5.17）
// 1) TPACKET_V3 RX ring：内核把收到的帧直接写进 mmap 共享环，用户态处理完
//    把块状态置回 KERNEL——彻底消除逐包 recvfrom/recvmmsg 系统调用；
//    retire_blk_tov=20ms 保证低速率下块也及时归还（tailer 语义不变）。
// 2) PACKET_QDISC_BYPASS：发包旁路 qdisc 排队，sendto 直达驱动。
// 3) SO_BUSY_POLL：套接字忙轮询，缩短每跳唤醒延迟（配合 topo 的 sysctl）。
//    环建立失败时自动回退 recvmmsg 路径（旧路径保留）。

struct Entry {
  int port = 0;
  int pos = 0;
  bool strip = false;
  int in_port = 0;
};

// MAC 全部以 48-bit 整数参与查表与流聚合键——每包路径上零堆分配。
// （此前 dst/src 每包构造 std::string、查表键再拼两次 string，是热路径
//  最大的非 syscall 开销；src 甚至从未被使用。）
uint64_t mac_key(const uint8_t* m) {
  uint64_t v = 0;
  for (int i = 0; i < 6; ++i) v = (v << 8) | m[i];
  return v;
}

bool mac_from_str(const char* s, uint64_t& out) {
  unsigned b[6];
  if (std::sscanf(s, "%2x:%2x:%2x:%2x:%2x:%2x", &b[0], &b[1], &b[2], &b[3],
                  &b[4], &b[5]) != 6)
    return false;
  out = 0;
  for (int i = 0; i < 6; ++i) out = (out << 8) | (b[i] & 0xff);
  return true;
}

// 查表/流聚合键 = mac48 << 8 | tag（tag 8 bit）
uint64_t entry_key(uint64_t mac48, uint8_t tag) { return (mac48 << 8) | tag; }

void mac_str(uint64_t m, char* buf /*≥18*/) {
  std::snprintf(buf, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
                (unsigned)((m >> 40) & 0xff), (unsigned)((m >> 32) & 0xff),
                (unsigned)((m >> 24) & 0xff), (unsigned)((m >> 16) & 0xff),
                (unsigned)((m >> 8) & 0xff), (unsigned)(m & 0xff));
}

struct Port {
  int index = 0;
  std::string name;
  int fd = -1;
  int ifindex = 0;
  uint8_t mac[6] = {0};  // 本接口 MAC（V3 头无 pkttype，出向帧用它过滤）
  // TPACKET_V3 RX ring（建立失败时 rx_map == nullptr → recvmmsg 兜底）
  uint8_t* rx_map = nullptr;
  size_t rx_map_len = 0;
  uint32_t rx_block_nr = 0, rx_block_size = 0, rx_frame_size = 0;
};

bool setup_rx_ring(Port& p) {
  int ver = TPACKET_V3;
  if (::setsockopt(p.fd, SOL_PACKET, PACKET_VERSION, &ver, sizeof(ver)) != 0)
    return false;
  struct tpacket_req3 req {};
  req.tp_block_size = 131072;  // 4 块 × 128KB，每块 32 帧 × 4KB
  req.tp_frame_size = 4096;
  req.tp_block_nr = 4;
  req.tp_sizeof_priv = 0;
  req.tp_retire_blk_tov = 20;  // 低速率下 20ms 也归还块（tailer 语义不变）
  req.tp_feature_req_word = 0;
  if (::setsockopt(p.fd, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req)) != 0)
    return false;
  size_t len = (size_t)req.tp_block_nr * req.tp_block_size;
  void* m = ::mmap(nullptr, len, PROT_READ | PROT_WRITE, MAP_SHARED, p.fd, 0);
  if (m == MAP_FAILED) return false;
  p.rx_map = static_cast<uint8_t*>(m);
  p.rx_map_len = len;
  p.rx_block_nr = req.tp_block_nr;
  p.rx_block_size = req.tp_block_size;
  p.rx_frame_size = req.tp_frame_size;
  return true;
}

// nonce 来源：内核 CSPRNG（getrandom）。
// 此前用 srand(seed^sid)+rand()：同 seed 每次启动产生完全相同的 nonce 序列，
// 而验证头只依赖 (nonce, 路径, 密钥) —— 上一轮运行录制的帧在控制器重启
// （重放窗口清空）之后可以永久重放且必然通过判定。CSPRNG 保证跨启动不重复。
uint64_t fresh_nonce() {
  uint64_t v = 0;
  while (::getrandom(&v, sizeof(v), 0) != (ssize_t)sizeof(v)) {
    if (errno != EINTR) {
      std::perror("getrandom");
      std::_Exit(2);
    }
  }
  return v & ((1ULL << 56) - 1);  // nonce 空间 56 bit
}

enum class Evil { kNone, kBitflip, kDup };

std::atomic<bool> g_stop{false};  // SIGTERM/SIGINT 置位，run() 主循环退出

// MPV_RX_RING=1 时启用 TPACKET_V3 收包环（默认关——对串行转发链实测净伤害，§19）
const bool g_qdisc_bypass = [] {
  const char* e = ::getenv("MPV_QDISC_BYPASS");
  return e && e[0] == '1';  // veth 为 noqueue：实测 bypass 反增 CPU，默认关（§19）
}();

const bool g_rx_ring = [] {
  const char* e = ::getenv("MPV_RX_RING");
  return e && e[0] == '1';
}();

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
    // ρ 的幂只与位置有关：预计算查表，替掉转发热路径上的模幂
    for (int i = 0; i < RHO_POW_N; ++i) rho_[i] = powmod(RHO, (uint64_t)i);
    // M5.17 内核加速：MPV_RX_RING=1 时为每个端口建立 TPACKET_V3 RX ring
    //（默认关闭——实测对串行转发链是净伤害，见 §19；失败回退 recvmmsg）
    if (g_rx_ring) {
      int rings = 0;
      for (Port& p : ports_)
        if (setup_rx_ring(p)) ++rings;
      if (debug_)
        std::fprintf(stderr, "[s%u] rx_ring=%d/%zu\n", sid_, rings,
                     ports_.size());
    }
    report_ = std::fopen(report_path_.c_str(), "a");
    if (!trace_path.empty()) trace_ = std::fopen(trace_path.c_str(), "a");
    load_table(true);
  }

  static constexpr int RHO_POW_N = 80;

  uint64_t rho_pow(uint32_t pos_1based) const {
    return pos_1based >= 1 && pos_1based <= (uint32_t)RHO_POW_N
               ? rho_[pos_1based - 1]
               : powmod(RHO, pos_1based - 1);
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
      char db[18];
      mac_str(kv.first >> 8, db);
      std::fprintf(report_, "FLOW %s %u %llu %llu %llu\n", db,
                   (unsigned)(kv.first & 0xff), (unsigned long long)a.n,
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
    while (!g_stop.load(std::memory_order_relaxed)) {
      int n = ::poll(pfds.data(), pfds.size(), 200);
      if (n > 0) {
        for (size_t i = 0; i < pfds.size(); ++i) {
          if (!(pfds[i].revents & POLLIN)) continue;
          drain(ports_[i]);
        }
      }
      // 每个轮次末统一冲刷上报/取证文件：每包 fflush 是热路径上最密集的
      // syscall（每包 1~2 次），批量冲刷把 N 次收成 1 次，且帧到达至可见
      // 的延迟不超过一个 poll 轮次（tailer 轮询 120ms，语义不变）
      if (dirty_) {
        if (report_) std::fflush(report_);
        if (trace_) std::fflush(trace_);
        dirty_ = false;
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
      uint64_t mk;
      if (!mac_from_str(mac, mk)) continue;
      if (tag < 0 || tag > 255) continue;
      entries_[entry_key(mk, (uint8_t)tag)] = Entry{port, pos, strip != 0, in_port};
    }
    std::fclose(f);
  }

  const Entry* lookup(uint64_t mac48, uint8_t tag) const {
    auto it = entries_.find(entry_key(mac48, tag));
    return it == entries_.end() ? nullptr : &it->second;
  }

  // recvmmsg 兜底（RX ring 建立失败时使用）
  void drain_fallback(const Port& p) {
    constexpr int kBatch = 32;
    constexpr size_t kFrame = 2048;  // netns mtu 1500，留足余量
    uint8_t bufs[kBatch][kFrame];
    struct mmsghdr msgs[kBatch];
    struct iovec iovecs[kBatch];
    struct sockaddr_ll addrs[kBatch];
    while (true) {
      std::memset(msgs, 0, sizeof(msgs));
      for (int i = 0; i < kBatch; ++i) {
        iovecs[i].iov_base = bufs[i];
        iovecs[i].iov_len = kFrame;
        msgs[i].msg_hdr.msg_iov = &iovecs[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
        msgs[i].msg_hdr.msg_name = &addrs[i];
        msgs[i].msg_hdr.msg_namelen = sizeof(addrs[i]);
      }
      int n = ::recvmmsg(p.fd, msgs, kBatch, MSG_DONTWAIT, nullptr);
      if (n <= 0) break;  // EAGAIN / 异常：回到 poll
      for (int i = 0; i < n; ++i) {
        if (addrs[i].sll_pkttype == PACKET_OUTGOING) continue;  // 本端口发出的帧
        ++in_;
        handle(bufs[i], (size_t)msgs[i].msg_len, p.index);
      }
      if (n < kBatch) break;
    }
  }

  // TPACKET_V3：消费环内所有 USER 块。syscall 只发生在 poll 唤醒与状态
  // 置位，逐包收发零系统调用。
  void drain(const Port& p) {
    if (!p.rx_map) {
      drain_fallback(p);
      return;
    }
    uint32_t fper = p.rx_block_size / p.rx_frame_size;
    for (uint32_t bi = 0; bi < p.rx_block_nr; ++bi) {
      auto* bdesc = reinterpret_cast<struct tpacket_block_desc*>(
          p.rx_map + (size_t)bi * p.rx_block_size);
      if ((bdesc->hdr.bh1.block_status & TP_STATUS_USER) == 0) continue;
      uint8_t* base =
          reinterpret_cast<uint8_t*>(bdesc) + bdesc->hdr.bh1.offset_to_first_pkt;
      for (uint32_t fi = 0; fi < fper; ++fi) {
        auto* th = reinterpret_cast<struct tpacket3_hdr*>(
            base + (size_t)fi * p.rx_frame_size);
        if ((th->tp_status & TP_STATUS_USER) == 0) continue;
        uint8_t* fp = base + (size_t)fi * p.rx_frame_size + th->tp_mac;
        // V3 头无 pkttype：源 MAC == 本接口 MAC 的帧是本端口发出的回环帧
        if (th->tp_snaplen >= 12 &&
            std::memcmp(fp + 6, p.mac, 6) != 0) {
          ++in_;
          handle(fp, (size_t)th->tp_snaplen, p.index);
        }
        th->tp_status = TP_STATUS_KERNEL;
      }
      // 块内帧全部处理完毕，归还内核
      bdesc->hdr.bh1.block_status = TP_STATUS_KERNEL;
    }
  }

  void handle(const uint8_t* frame, size_t len, int in_idx) {
    if (len < 14) return;
    uint16_t ether = (uint16_t)((frame[12] << 8) | frame[13]);
    uint64_t dk = mac_key(frame);  // 目的 MAC（48-bit 键，全程无堆分配）

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
    e = lookup(dk, tag);
    if (!e) {
      ++drop_;
      return;
    }

    Hop hop{sid_, (uint32_t)(e->in_port > 0 ? e->in_port : in_idx),
            (uint32_t)e->port};
    // 入端口以实际到达端口为准（与控制器侧一致时表里的 in_port 应等于它）
    hop.in_port = (uint32_t)in_idx;

    if (!shimmed) {
      nonce = fresh_nonce();
      Header h = ingress(kr_, hop, tag, nonce);
      acc = h.acc;
    } else {
      uint64_t c = contribution(kr_, hop, h_of(nonce));
      acc = addmod(acc, mulmod(c, rho_pow(e->pos)));
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

    // 逐跳取证：记录本跳之后实际写进帧里的累加值（flush 由 run() 轮次末统一做）
    if (trace_) {
      char db[18];
      mac_str(dk, db);
      std::fprintf(trace_, "TRACE %s %u %u %u %u %llu %u %llu\n", db,
                   sid_, hop.in_port, e->port, tag,
                   (unsigned long long)nonce, e->pos,
                   (unsigned long long)acc);
      dirty_ = true;
    }

    if (e->strip) {
      char db[18];
      mac_str(dk, db);
      std::fprintf(report_, "%u %u %llu %llu %s\n", sid_, tag,
                   (unsigned long long)nonce, (unsigned long long)acc, db);
      dirty_ = true;
      // CFMV：按 (流, tag) 聚合，凑满一个窗口上报一行
      FlowAgg& a = flows_[entry_key(dk, tag)];
      a.add(nonce, acc);
      if (a.n >= flow_window_) {
        std::fprintf(report_, "FLOW %s %u %llu %llu %llu\n", db, tag,
                     (unsigned long long)a.n, (unsigned long long)a.sum_h,
                     (unsigned long long)a.sum_v);
        a.reset();
      }
    }
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
  std::unordered_map<uint64_t, FlowAgg> flows_;
  std::unordered_map<uint64_t, Entry> entries_;
  std::unordered_map<int, int> fd_by_port_;
  std::unordered_map<int, int> ifindex_by_port_;
  uint64_t rho_[RHO_POW_N];
  time_t mtime_ = 0;
  std::FILE* report_ = nullptr;
  std::FILE* trace_ = nullptr;
  bool dirty_ = false;  // 本轮次有未冲刷的输出（run() 轮次末统一 fflush）
  uint64_t in_ = 0, out_ = 0, drop_ = 0;
  bool debug_ = false;
};

int open_port(Port& p) {
  int fd = ::socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (fd < 0) {
    std::perror("socket");
    return -1;
  }
  struct sockaddr_ll sll{};
  sll.sll_family = AF_PACKET;
  sll.sll_protocol = htons(ETH_P_ALL);
  sll.sll_ifindex = (int)::if_nametoindex(p.name.c_str());
  if (sll.sll_ifindex == 0) {
    std::fprintf(stderr, "找不到接口 %s\n", p.name.c_str());
    ::close(fd);
    return -1;
  }
  if (::bind(fd, reinterpret_cast<sockaddr*>(&sll), sizeof(sll)) < 0) {
    std::perror("bind");
    ::close(fd);
    return -1;
  }
  p.fd = fd;
  p.ifindex = (int)sll.sll_ifindex;
  // 本接口 MAC：V3 头不带 pkttype，环内出向帧以"源 MAC == 本接口 MAC"过滤
  struct ifreq ifr{};
  std::memset(&ifr, 0, sizeof(ifr));
  std::strncpy(ifr.ifr_name, p.name.c_str(), IFNAMSIZ - 1);
  if (::ioctl(fd, SIOCGIFHWADDR, &ifr) == 0)
    std::memcpy(p.mac, ifr.ifr_hwaddr.sa_data, 6);
  // 内核加速（尽力而为，失败不致命）：
  //   发包旁路 qdisc（默认开——纯 TX 路径旁路，无负效应）；
  //   TPACKET_V3 RX ring 与 SO_BUSY_POLL 仅在 MPV_RX_RING=1 时启用——
  //   实测对低时延串行转发链是净伤害（批等待 + 忙等烧 CPU），
  //   见设计报告 §19 的对照数据；默认走 recvmmsg 批收路径
  int one = 1;
  if (g_qdisc_bypass)
    (void)::setsockopt(fd, SOL_PACKET, PACKET_QDISC_BYPASS, &one, sizeof(one));
  if (g_rx_ring)
    (void)::setsockopt(fd, SOL_SOCKET, SO_BUSY_POLL, &one, sizeof(one));
  return fd;
}

VSwitch* g_sw = nullptr;

// 信号处理函数只做原子写（异步信号安全）；
// 未决窗口的冲刷与统计打印由主循环退出后在主线程完成——
// 此前在 handler 里直接 fprintf/std::fopen，与主线程的 stdio 并发是未定义行为。
void on_term(int) { g_stop = true; }

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
      if (open_port(p) < 0) return 1;
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

  VSwitch sw(sid, seed, table, report, std::move(ports), paths, force_tag,
             emode, trace, flow_window);
  sw.set_debug(debug);
  g_sw = &sw;
  std::signal(SIGTERM, on_term);
  std::signal(SIGINT, on_term);
  sw.run();
  // 主线程里完成收尾：未满窗口的流级聚合冲进上报文件 + 统计
  g_sw->flush_flows();
  g_sw->stats();
  return 0;
}
