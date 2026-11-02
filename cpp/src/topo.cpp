#include "topo.h"

#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <thread>

namespace topo {
namespace {

void sh(const std::string& cmd) { (void)std::system((cmd + " 2>/dev/null").c_str()); }

void must(const std::string& cmd) {
  if (std::system((cmd + " 2>/dev/null").c_str()) != 0)
    std::fprintf(stderr, "[topo] 命令失败: %s\n", cmd.c_str());
}

void write_file(const std::string& path, const std::string& content) {
  std::ofstream f(path, std::ios::trunc);
  f << content;
}

void veth(const std::string& host, const std::string& sw, const std::string& ns) {
  must("ip link add " + host + " type veth peer name " + sw);
  must("ip link set " + sw + " up");
  if (!ns.empty()) {
    must("ip link set " + host + " netns " + ns);
    must("ip netns exec " + ns + " ip link set " + host + " up");
  } else {
    must("ip link set " + host + " up");
  }
}

}  // namespace

std::string table_path(int sid) {
  return std::string(WORK) + "/s" + std::to_string(sid) + ".tbl";
}
std::string report_path() { return std::string(WORK) + "/report.txt"; }
std::string trace_path() { return std::string(WORK) + "/trace.txt"; }

void cleanup() {
  for (const char* ns : {"h1", "h2"}) sh(std::string("ip netns del ") + ns);
  for (const char* i : {"s1p1", "s1p2", "s1p3", "s2p1", "s2p2", "s3p1", "s3p2",
                        "s4p1", "s4p2", "s4p3", "h1e", "h2e"})
    sh(std::string("ip link del ") + i);
}

void setup_links() {
  cleanup();
  must("ip netns add h1");
  must("ip netns add h2");
  for (const char* ns : {"h1", "h2"})
    sh(std::string("ip netns exec ") + ns +
       " sysctl -qw net.ipv6.conf.all.disable_ipv6=1");

  veth("h1e", "s1p1", "h1");
  veth("s1p2", "s2p1", "");
  veth("s1p3", "s3p1", "");
  veth("s2p2", "s4p1", "");
  veth("s3p2", "s4p2", "");
  veth("h2e", "s4p3", "h2");

  must(std::string("ip netns exec h1 ip link set h1e address ") + H1MAC);
  must(std::string("ip netns exec h2 ip link set h2e address ") + H2MAC);
  must("ip netns exec h1 ip addr add 10.0.0.1/24 dev h1e");
  must("ip netns exec h2 ip addr add 10.0.0.2/24 dev h2e");
  must("ip netns exec h1 ip link set lo up");
  must("ip netns exec h2 ip link set lo up");
  must(std::string("ip netns exec h1 ip neigh replace 10.0.0.2 lladdr ") +
       H2MAC + " dev h1e");
  must(std::string("ip netns exec h2 ip neigh replace 10.0.0.1 lladdr ") +
       H1MAC + " dev h2e");
}

void write_tables(Scenario sc) {
  std::ostringstream s1, s2, s3, s4;
  if (sc == Scenario::kTagflip) {
    // s1 把 tag0 改走 P1 分支，s3/s4 的 tag0 表项同步补齐 → 数据面自洽，
    // 但声称的 tag=0 对应的合法路径是 P0 → 控制器侧判定失败并可定位分歧点
    s1 << H2MAC << " 0 3 1 0 1\n" << H2MAC << " 1 3 1 0 1\n"
       << H1MAC << " 0 1 3 1 2\n" << H1MAC << " 1 1 3 1 3\n";
    s2 << H2MAC << " 0 2 2 0 1\n" << H1MAC << " 0 1 2 0 2\n";
    s3 << H2MAC << " 0 2 2 0 1\n" << H2MAC << " 1 2 2 0 1\n"
       << H1MAC << " 1 1 2 0 2\n";
    s4 << H2MAC << " 0 3 3 1 2\n" << H2MAC << " 1 3 3 1 2\n"
       << H1MAC << " 0 1 1 0 3\n" << H1MAC << " 1 2 1 0 3\n";
  } else if (sc == Scenario::kBlackhole) {
    // s1 把 tag0 改走 s3，但 s3 没有 tag0 表项 → 丢包（黑洞）。
    // 控制器侧通过「取证里出现过但出口未上报」的 nonce 发现失联，
    // 并用首个取证不匹配的跳定位 s1 的改道行为。
    s1 << H2MAC << " 0 3 1 0 1\n" << H2MAC << " 1 3 1 0 1\n"
       << H1MAC << " 0 1 3 1 2\n" << H1MAC << " 1 1 3 1 3\n";
    s2 << H2MAC << " 0 2 2 0 1\n" << H1MAC << " 0 1 2 0 2\n";
    s3 << H2MAC << " 1 2 2 0 1\n" << H1MAC << " 1 1 2 0 2\n";  // 无 tag0 → 丢弃
    s4 << H2MAC << " 0 3 3 1 1\n" << H2MAC << " 1 3 3 1 2\n"
       << H1MAC << " 0 1 1 0 3\n" << H1MAC << " 1 2 1 0 3\n";
  } else if (sc == Scenario::kFailover) {
    // 链路故障切换：s1–s2 断开（apply_link_state 置 down），tag0 全网改走 P1
    // 分支，控制器候选集同步收敛为 {P1} → 切换后验证继续全通过（零误报）。
    s1 << H2MAC << " 0 3 1 0 1\n" << H2MAC << " 1 3 1 0 1\n"
       << H1MAC << " 0 1 3 1 2\n" << H1MAC << " 1 1 3 1 3\n";
    s2 << H2MAC << " 0 2 2 0 1\n" << H1MAC << " 0 1 2 0 2\n";  // 不可达，保留原表
    s3 << H2MAC << " 0 2 2 0 1\n" << H2MAC << " 1 2 2 0 1\n"
       << H1MAC << " 0 1 2 0 2\n" << H1MAC << " 1 1 2 0 2\n";
    s4 << H2MAC << " 0 3 3 1 2\n" << H2MAC << " 1 3 3 1 2\n"
       << H1MAC << " 0 2 1 0 3\n" << H1MAC << " 1 2 1 0 3\n";
  } else {  // kNormal
    s1 << H2MAC << " 0 2 1 0 1\n" << H2MAC << " 1 3 1 0 1\n"
       << H1MAC << " 0 1 3 1 2\n" << H1MAC << " 1 1 3 1 3\n";
    s2 << H2MAC << " 0 2 2 0 1\n" << H1MAC << " 0 1 2 0 2\n";
    s3 << H2MAC << " 1 2 2 0 1\n" << H1MAC << " 1 1 2 0 2\n";
    s4 << H2MAC << " 0 3 3 1 1\n" << H2MAC << " 1 3 3 1 2\n"
       << H1MAC << " 0 1 1 0 3\n" << H1MAC << " 1 2 1 0 3\n";
  }
  write_file(table_path(1), s1.str());
  write_file(table_path(2), s2.str());
  write_file(table_path(3), s3.str());
  write_file(table_path(4), s4.str());
}

void apply_link_state(Scenario sc) {
  // failover：物理断开 s1–s2 互联链路（两端都 down，帧级不可达）
  if (sc == Scenario::kFailover) {
    must("ip link set s1p2 down");
    must("ip link set s2p1 down");
  } else {
    must("ip link set s1p2 up");
    must("ip link set s2p1 up");
  }
}

void clear_logs() {
  write_file(report_path(), "");
  write_file(trace_path(), "");
}

pid_t spawn_switch(const std::string& vswitch_bin, const SwitchConf& conf) {
  std::vector<std::string> a;
  a.push_back(vswitch_bin);
  a.push_back("--sid");
  a.push_back(std::to_string(conf.sid));
  a.push_back("--seed");
  a.push_back(std::to_string(SEED));
  a.push_back("--table");
  a.push_back(table_path(conf.sid));
  a.push_back("--report");
  a.push_back(report_path());
  a.push_back("--paths");
  a.push_back("2");
  a.push_back("--force-tag");
  a.push_back("0");
  a.push_back("--flow-window");
  a.push_back(std::to_string(conf.flow_window));
  if (conf.trace) {
    a.push_back("--trace");
    a.push_back(trace_path());
  }
  if (conf.evil != "none") {
    a.push_back("--evil");
    a.push_back(conf.evil);
  }
  for (const std::string& p : conf.ports) {
    a.push_back("--port");
    a.push_back(p);
  }
  std::vector<char*> argv;
  for (std::string& s : a) argv.push_back(const_cast<char*>(s.c_str()));
  argv.push_back(nullptr);

  pid_t pid = ::fork();
  if (pid == 0) {
    ::execv(vswitch_bin.c_str(), argv.data());
    std::perror("execv");
    ::_exit(127);
  }
  return pid;
}

void stop_switch(pid_t pid) {
  ::kill(pid, SIGTERM);
  ::waitpid(pid, nullptr, 0);
}

void run_traffic(int count, const std::string& interval) {
  sh("ip netns exec h1 ping -c " + std::to_string(count) + " -i " + interval +
     " -W 1 10.0.0.2 >/dev/null");
}

std::vector<mpv::Path> cand_fwd() {
  return {
      {mpv::Hop{1, 1, 2}, mpv::Hop{2, 1, 2}, mpv::Hop{4, 1, 3}},
      {mpv::Hop{1, 1, 3}, mpv::Hop{3, 1, 2}, mpv::Hop{4, 2, 3}},
  };
}

std::vector<mpv::Path> cand_rev() {
  return {
      {mpv::Hop{4, 3, 1}, mpv::Hop{2, 2, 1}, mpv::Hop{1, 2, 1}},
      {mpv::Hop{4, 3, 2}, mpv::Hop{3, 2, 1}, mpv::Hop{1, 3, 1}},
  };
}

std::vector<mpv::Direction> directions() {
  return {{H2MAC, cand_fwd()}, {H1MAC, cand_rev()}};
}

std::vector<mpv::Direction> directions_for(Scenario sc) {
  if (sc == Scenario::kFailover) {
    // P0 不可达：候选收敛为 {P1}，tag0 即 P1
    std::vector<mpv::Path> fwd{cand_fwd()[1]}, rev{cand_rev()[1]};
    return {{H2MAC, fwd}, {H1MAC, rev}};
  }
  return directions();
}

}  // namespace topo