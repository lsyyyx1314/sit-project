// MPV-2 端到端验证编排器（C++ 实现，工程内无脚本、无 Python）。
//
// 拓扑：
//     h1 --- s1 --- s2 --- s4 --- h2
//              \            /
//               +--- s3 ----+
//
// 两轮：
//   R1 正常     转发表与候选路径一致 → 双向全部通过
//   R2 标签错配 s1 的 tag=0 改走 P1 分支，s3/s4 的 tag=0 同步改，
//               使错标路径在数据面自洽 → 正向全部失败且可定位到 s1
//
// 实现说明：拓扑用 iproute2 的 ip 命令搭建（系统工具），交换机与验证器
// 都是本工程编译出的 C++ 可执行文件。工程本身不含任何脚本语言代码。
//
// 用法： sudo ./build/e2e
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "mpv2.h"

using namespace mpv;

namespace {

constexpr const char* H1MAC = "00:00:00:00:00:01";
constexpr const char* H2MAC = "00:00:00:00:00:02";
constexpr uint64_t SEED = 20260501;
constexpr const char* WORK = "/tmp/mpv_cpp_e2e";

std::string g_vswitch;

// ----------------------------------------------------------------- 工具
int sh(const std::string& cmd) {
  return std::system((cmd + " 2>/dev/null").c_str());
}

void must(const std::string& cmd) {
  if (std::system((cmd + " 2>/dev/null").c_str()) != 0)
    std::fprintf(stderr, "[WARN] 命令失败: %s\n", cmd.c_str());
}

void sleep_ms(int ms) {
  std::this_thread::sleep_for(std::chrono::milliseconds(ms));
}

std::string exe_dir() {
  char buf[4096];
  ssize_t n = ::readlink("/proc/self/exe", buf, sizeof(buf) - 1);
  if (n <= 0) return ".";
  buf[n] = 0;
  std::string s(buf);
  auto pos = s.find_last_of('/');
  return pos == std::string::npos ? "." : s.substr(0, pos);
}

void write_file(const std::string& path, const std::string& content) {
  std::ofstream f(path, std::ios::trunc);
  f << content;
}

// ----------------------------------------------------------------- 拓扑
void teardown() {
  for (const char* ns : {"h1", "h2"}) sh(std::string("ip netns del ") + ns);
  for (const char* i : {"s1p1", "s1p2", "s1p3", "s2p1", "s2p2", "s3p1", "s3p2",
                        "s4p1", "s4p2", "s4p3", "h1e", "h2e"})
    sh(std::string("ip link del ") + i);
}

void veth(const std::string& host, const std::string& sw, const std::string& ns) {
  must("ip link add " + host + " type veth peer name " + sw);
  must("ip link set " + sw + " up");
  if (!ns.empty()) {
    must("ip link set " + host + " netns " + ns);
    must("ip netns exec " + ns + " ip link set " + host + " up");
  } else {
    must("ip link set " + host + " up"); // 交换机互联：两端都要 up
  }
}

void setup_topo() {
  teardown();
  must("ip netns add h1");
  must("ip netns add h2");
  for (const char* ns : {"h1", "h2"})
    sh(std::string("ip netns exec ") + ns + " sysctl -qw net.ipv6.conf.all.disable_ipv6=1");

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
  must(std::string("ip netns exec h1 ip neigh replace 10.0.0.2 lladdr ") + H2MAC + " dev h1e");
  must(std::string("ip netns exec h2 ip neigh replace 10.0.0.1 lladdr ") + H1MAC + " dev h2e");
}

// ----------------------------------------------------------------- 转发表
void write_tables(bool tamper) {
  std::ostringstream s1, s2, s3, s4;
  s1 << H2MAC << " 0 " << (tamper ? 3 : 2) << " 1 0 1\n"
     << H2MAC << " 1 3 1 0 1\n"
     << H1MAC << " 0 1 3 1 2\n"
     << H1MAC << " 1 1 3 1 3\n";
  s2 << H2MAC << " 0 2 2 0 1\n" << H1MAC << " 0 1 2 0 2\n";
  if (tamper) {
    s3 << H2MAC << " 0 2 2 0 1\n" << H2MAC << " 1 2 2 0 1\n" << H1MAC << " 1 1 2 0 2\n";
    s4 << H2MAC << " 0 3 3 1 2\n" << H2MAC << " 1 3 3 1 2\n"
       << H1MAC << " 0 1 1 0 3\n" << H1MAC << " 1 2 1 0 3\n";
  } else {
    s3 << H2MAC << " 1 2 2 0 1\n" << H1MAC << " 1 1 2 0 2\n";
    s4 << H2MAC << " 0 3 3 1 1\n" << H2MAC << " 1 3 3 1 2\n"
       << H1MAC << " 0 1 1 0 3\n" << H1MAC << " 1 2 1 0 3\n";
  }
  write_file(std::string(WORK) + "/s1.tbl", s1.str());
  write_file(std::string(WORK) + "/s2.tbl", s2.str());
  write_file(std::string(WORK) + "/s3.tbl", s3.str());
  write_file(std::string(WORK) + "/s4.tbl", s4.str());
}

// ----------------------------------------------------------------- 交换机进程
pid_t spawn_switch(int sid, const std::string& table,
                   const std::vector<std::string>& ports) {
  std::vector<std::string> store;
  store.push_back(g_vswitch);
  store.push_back("--sid");
  store.push_back(std::to_string(sid));
  store.push_back("--seed");
  store.push_back(std::to_string(SEED));
  store.push_back("--table");
  store.push_back(table);
  store.push_back("--report");
  store.push_back(std::string(WORK) + "/report.txt");
  store.push_back("--paths");
  store.push_back("2");
  store.push_back("--force-tag");
  store.push_back("0");
  for (const std::string& p : ports) {
    store.push_back("--port");
    store.push_back(p);
  }
  std::vector<char*> argv;
  for (std::string& s : store) argv.push_back(const_cast<char*>(s.c_str()));
  argv.push_back(nullptr);

  pid_t pid = ::fork();
  if (pid == 0) {
    ::execv(g_vswitch.c_str(), argv.data());
    std::perror("execv");
    ::_exit(127);
  }
  return pid;
}

// ----------------------------------------------------------------- 验证
struct Stat {
  std::string mac;
  int total = 0, pass = 0, fail = 0;
  int matched = -1, claimed = -1, diverge = -1;
};

std::vector<Path> cand_fwd() {
  return {
      {Hop{1, 1, 2}, Hop{2, 1, 2}, Hop{4, 1, 3}},
      {Hop{1, 1, 3}, Hop{3, 1, 2}, Hop{4, 2, 3}},
  };
}
std::vector<Path> cand_rev() {
  return {
      {Hop{4, 3, 1}, Hop{2, 2, 1}, Hop{1, 2, 1}},
      {Hop{4, 3, 2}, Hop{3, 2, 1}, Hop{1, 3, 1}},
  };
}

Stat verify_dir(const KeyRing& kr, const std::string& mac,
                const std::vector<Path>& paths) {
  Stat st;
  st.mac = mac;
  ExpectationTable tb(kr, paths);

  std::ifstream in(std::string(WORK) + "/report.txt");
  std::string line;
  while (std::getline(in, line)) {
    if (line.empty()) continue;
    unsigned sid, tag;
    unsigned long long nonce, acc;
    char m[32];
    if (std::sscanf(line.c_str(), "%u %u %llu %llu %31s", &sid, &tag, &nonce,
                    &acc, m) != 5)
      continue;
    if (mac != m) continue;
    ++st.total;
    Header h{nonce, acc, (uint8_t)tag};
    if (tb.verify_tag(h).ok) {
      ++st.pass;
      continue;
    }
    ++st.fail;
    Verdict sc = tb.verify_scan(h);
    if (sc.matched >= 0) {
      st.matched = sc.matched;
      st.claimed = (int)tag;
      const Path& a = paths[(size_t)tag];
      const Path& b = paths[(size_t)sc.matched];
      size_t common = 0;
      while (common < a.size() && common < b.size() && a[common].sid == b[common].sid)
        ++common;
      st.diverge = (int)a[common > 0 ? common - 1 : 0].sid;
    }
  }
  return st;
}

// ----------------------------------------------------------------- 一轮
struct Round {
  std::string name;
  Stat fwd, rev;
  int reports = 0;
};

Round run_round(const std::string& name, bool tamper) {
  std::printf("\n== %s ==\n", name.c_str());
  std::fflush(stdout);

  write_file(std::string(WORK) + "/report.txt", "");
  write_tables(tamper);
  setup_topo();

  std::vector<pid_t> pids;
  pids.push_back(spawn_switch(1, std::string(WORK) + "/s1.tbl", {"1:s1p1", "2:s1p2", "3:s1p3"}));
  pids.push_back(spawn_switch(2, std::string(WORK) + "/s2.tbl", {"1:s2p1", "2:s2p2"}));
  pids.push_back(spawn_switch(3, std::string(WORK) + "/s3.tbl", {"1:s3p1", "2:s3p2"}));
  pids.push_back(spawn_switch(4, std::string(WORK) + "/s4.tbl", {"1:s4p1", "2:s4p2", "3:s4p3"}));
  sleep_ms(800);

  sh("ip netns exec h1 ping -c 20 -i 0.05 -W 1 10.0.0.2 >/dev/null");
  sleep_ms(500);

  for (pid_t p : pids) ::kill(p, SIGTERM);
  for (pid_t p : pids) ::waitpid(p, nullptr, 0);

  KeyRing kr = KeyRing::generate(16, 4, SEED);
  Round r;
  r.name = name;
  r.fwd = verify_dir(kr, H2MAC, cand_fwd());
  r.rev = verify_dir(kr, H1MAC, cand_rev());

  std::ifstream cnt(std::string(WORK) + "/report.txt");
  std::string l;
  while (std::getline(cnt, l))
    if (!l.empty()) ++r.reports;
  return r;
}

void report_dir(const Stat& s) {
  if (s.total == 0) return;
  std::printf("  %s: 通过 %d / 失败 %d / 共 %d\n", s.mac.c_str(), s.pass, s.fail,
              s.total);
  if (s.fail > 0 && s.matched >= 0)
    std::printf("      → 实际命中候选 #%d，标签声称 #%d：路径标签错配，分歧点 s%d\n",
                s.matched, s.claimed, s.diverge);
  else if (s.fail > 0)
    std::printf("      → 未命中任何候选：路径偏离或验证头被篡改\n");
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
  std::printf("MPV-2 端到端验证 · C++ 软件虚拟交换机 4 台 · 双向双路径\n");
  std::printf("================================================================\n");

  Round r1 = run_round("R1 正常转发", false);
  report_dir(r1.fwd);
  report_dir(r1.rev);
  std::printf("    (上报 %d 条)\n", r1.reports);

  Round r2 = run_round("R2 标签错配", true);
  report_dir(r2.fwd);
  report_dir(r2.rev);
  std::printf("    (上报 %d 条)\n", r2.reports);

  teardown();

  bool ok1 = r1.fwd.fail == 0 && r1.rev.fail == 0 && r1.fwd.total > 0;
  bool ok2 = r2.fwd.fail == r2.fwd.total && r2.fwd.total > 0 && r2.rev.fail == 0;

  std::printf("\n");
  if (!ok1) {
    std::printf("结论：R1 未通过（正常转发不应有失败）\n");
    return 1;
  }
  if (!ok2) {
    std::printf("结论：R2 未检出（故障注入后应全部失败且反向不受影响）\n");
    return 1;
  }
  std::printf("结论：R1 全通、R2 全检出并定位 —— 端到端验证成立\n");
  return 0;
}
