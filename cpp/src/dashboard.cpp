// MPV-2 演示控制台：纯 C++17 HTTP 服务 + 内嵌 Web UI。
//
// 功能：
//   * 在 VM 上拉起 netns + veth 拓扑与 4 台软件交换机（复用 topo 模块）
//   * 浏览器实时看到每个包的验证结论（通过 / 失败 / 重放）与拓扑动画
//   * 一键切换场景：正常 / 标签错配 / 黑洞偏离 / 恶意改头 / 恶意重放
//   * 失败包自动定位嫌疑交换机并在拓扑上标红（逐跳取证）
//   * 黑洞场景：出口未上报但取证里出现过的包 = 半路失联，定位改道交换机
//   * 流级压缩（CFMV）实时窗口判定 + BPMV/CPMV/CFMV 判定次数对比
//
// 用法： sudo ./build/dashboard [--port 8080] [--flow-window 10]
// 浏览器打开 http://<VM地址>:8080
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <csignal>

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <mutex>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "controller.h"
#include "topo.h"

using namespace mpv;
using namespace topo;

namespace {

// ---------------------------------------------------------------- 状态
struct EventView {
  double t;
  std::string mac;
  std::string nonce_hex;
  int tag, matched, suspect;
  bool ok, replay, lost;
  std::string kind;  // packet | flow
  uint64_t n;
  double us;
};

struct State {
  std::mutex mu;
  std::string scenario = "normal";
  std::vector<EventView> events;              // 环形，最新在后
  std::vector<DirStat> stats;                 // 每方向
  std::vector<double> us_sum{0.0, 0.0};       // 判定时延累计
  std::vector<uint64_t> us_cnt{0, 0};
  int suspect = -1;                           // 最近一次定位
  int lost_count = 0;
  std::vector<int> lost_suspects;
  uint64_t traffic_packets = 0;               // 已触发 ping 数
  std::set<uint64_t> traced_h2, reported_h2;  // 黑洞检测用
  double started = 0;                         // 单调秒
};

State g_state;
Controller* g_ctl = nullptr;  // 受 g_state.mu 保护
uint32_t g_flow_window = 10;
std::atomic<bool> g_traffic_running{false};
void blackhole_check();  // 定义在交换机管理之后

// 后台跑一轮流量：ping 完成后视场景做黑洞定位
void traffic_worker(int count) {
  run_traffic(count, "0.04");
  std::this_thread::sleep_for(std::chrono::milliseconds(600));
  bool bh = false;
  {
    std::lock_guard<std::mutex> lk(g_state.mu);
    bh = (g_state.scenario == "blackhole");
  }
  if (bh) blackhole_check();
  g_traffic_running = false;
}

double mono_s() {
  using namespace std::chrono;
  return duration_cast<duration<double>>(steady_clock::now().time_since_epoch())
      .count();
}

double g_started = 0;

std::vector<pid_t> g_pids;  // s1..s4
std::string g_vswitch;

const char* kScenarios[] = {"normal", "tagflip", "blackhole", "bitflip", "dup"};

Scenario scenario_tables(const std::string& s) {
  if (s == "tagflip") return Scenario::kTagflip;
  if (s == "blackhole") return Scenario::kBlackhole;
  return Scenario::kNormal;
}

const char* scenario_evil(const std::string& s) {
  if (s == "bitflip") return "bitflip";
  if (s == "dup") return "dup";
  return "none";
}

// ---------------------------------------------------------------- 尾随读
struct Tailer {
  std::string path;
  FILE* f = nullptr;
  long off = 0;
  std::string rest;

  void close() {
    if (f) std::fclose(f);
    f = nullptr;
    off = 0;
    rest.clear();
  }

  // 把新增的完整行交给 fn；文件被截断时自动重开
  void pump(const std::function<void(const std::string&)>& fn) {
    struct stat st {};
    if (::stat(path.c_str(), &st) != 0) return;
    if (!f) {
      f = std::fopen(path.c_str(), "r");
      if (!f) return;
      off = 0;
      rest.clear();
    }
    if ((long)st.st_size < off) {  // 被清空重写
      std::fclose(f);
      f = std::fopen(path.c_str(), "r");
      if (!f) return;
      off = 0;
      rest.clear();
    }
    std::fseek(f, off, SEEK_SET);
    char buf[65536];
    size_t n = std::fread(buf, 1, sizeof(buf), f);
    if (n == 0) return;
    off += (long)n;
    std::string data = rest + std::string(buf, n);
    size_t start = 0;
    while (true) {
      size_t nl = data.find('\n', start);
      if (nl == std::string::npos) break;
      std::string line = data.substr(start, nl - start);
      start = nl + 1;
      if (!line.empty() && line.back() == '\r') line.pop_back();
      if (!line.empty()) fn(line);
    }
    rest = data.substr(start);
    if (rest.size() > (1 << 20)) rest.clear();  // 防御：异常长行丢弃
  }
};

Tailer g_tail_report, g_tail_trace;

void push_event(const EventView& ev) {
  constexpr size_t kCap = 300;
  g_state.events.push_back(ev);
  if (g_state.events.size() > kCap)
    g_state.events.erase(g_state.events.begin(),
                         g_state.events.begin() + (g_state.events.size() - kCap));
}

int dir_index(const std::string& mac) {
  for (size_t i = 0; i < 2; ++i)
    if (g_ctl->directions()[i].mac == mac) return (int)i;
  return -1;
}

void handle_line(const std::string& line) {
  // 黑洞检测的 nonce 集合（正向 h1→h2）：TRACE mac sid in out tag nonce pos v
  {
    unsigned a, b, c, d;
    unsigned long long nonce;
    char mac[32];
    if (std::sscanf(line.c_str(), "TRACE %31s %u %u %u %u %llu", mac, &a, &b, &c,
                    &d, &nonce) == 6 &&
        std::strcmp(mac, H2MAC) == 0)
      g_state.traced_h2.insert(nonce);
  }
  Event ev = g_ctl->feed(line);
  if (ev.kind.empty()) return;

  if (ev.kind == "packet" && ev.mac == H2MAC)
    g_state.reported_h2.insert(ev.nonce);

  int d = dir_index(ev.mac);
  if (d < 0) return;
  DirStat& st = g_state.stats[(size_t)d];
  DirStat now = g_ctl->stat((size_t)d);
  st = now;

  EventView v;
  v.t = mono_s() - g_started;
  v.mac = ev.mac;
  char nh[20];
  std::snprintf(nh, sizeof(nh), "0x%014llx", (unsigned long long)ev.nonce);
  v.nonce_hex = nh;
  v.tag = (int)ev.tag;
  v.ok = ev.ok;
  v.replay = ev.replay;
  v.matched = ev.matched;
  v.suspect = ev.suspect_sid;
  v.lost = false;
  v.kind = ev.kind;
  v.n = ev.n;
  v.us = ev.verify_us;
  g_state.us_sum[(size_t)d] += ev.verify_us;
  g_state.us_cnt[(size_t)d] += 1;
  if (ev.suspect_sid >= 0) g_state.suspect = ev.suspect_sid;
  push_event(v);
}

void tailer_loop() {
  g_tail_report.path = report_path();
  g_tail_trace.path = trace_path();
  while (true) {
    std::this_thread::sleep_for(std::chrono::milliseconds(120));
    std::lock_guard<std::mutex> lk(g_state.mu);
    g_tail_trace.pump(handle_line);  // 取证先行（与控制器 localize 依赖一致）
    g_tail_report.pump(handle_line);
  }
}

// ---------------------------------------------------------------- 交换机管理
void start_switches(const std::string& evil_s2) {
  auto mk = [&](int sid, std::vector<std::string> ports,
                const std::string& evil) {
    SwitchConf c;
    c.sid = sid;
    c.ports = ports;
    c.evil = evil;
    c.flow_window = g_flow_window;
    return c;
  };
  g_pids.clear();
  g_pids.push_back(
      spawn_switch(g_vswitch, mk(1, {"1:s1p1", "2:s1p2", "3:s1p3"}, "none")));
  g_pids.push_back(
      spawn_switch(g_vswitch, mk(2, {"1:s2p1", "2:s2p2"}, evil_s2)));
  g_pids.push_back(
      spawn_switch(g_vswitch, mk(3, {"1:s3p1", "2:s3p2"}, "none")));
  g_pids.push_back(spawn_switch(
      g_vswitch, mk(4, {"1:s4p1", "2:s4p2", "3:s4p3"}, "none")));
}

void stop_switches() {
  for (pid_t p : g_pids) ::kill(p, SIGTERM);
  for (pid_t p : g_pids) ::waitpid(p, nullptr, 0);
  g_pids.clear();
}

void reset_run(const std::string& scenario) {
  std::lock_guard<std::mutex> lk(g_state.mu);
  g_tail_report.close();
  g_tail_trace.close();
  clear_logs();
  delete g_ctl;
  g_ctl = new Controller(SEED, directions());
  g_state.stats.assign(2, DirStat{});
  g_state.us_sum.assign(2, 0.0);
  g_state.us_cnt.assign(2, 0);
  g_state.events.clear();
  g_state.suspect = -1;
  g_state.lost_count = 0;
  g_state.lost_suspects.clear();
  g_state.traced_h2.clear();
  g_state.reported_h2.clear();
  g_state.scenario = scenario;
}

// 黑洞定位：取证里出现过、出口却没有上报的正向 nonce = 半路失联
void blackhole_check() {
  std::lock_guard<std::mutex> lk(g_state.mu);
  std::vector<uint64_t> lost;
  for (uint64_t n : g_state.traced_h2)
    if (!g_state.reported_h2.count(n)) lost.push_back(n);
  g_state.lost_count = (int)lost.size();
  g_state.lost_suspects.clear();
  for (uint64_t n : lost) {
    int s = g_ctl->localize(0, 0, n, 0);  // 走取证前缀对照，acc 不参与
    if (s >= 0) g_state.lost_suspects.push_back(s);
    EventView v;
    v.t = mono_s() - g_started;
    v.mac = H2MAC;
    char nh[20];
    std::snprintf(nh, sizeof(nh), "0x%014llx", (unsigned long long)n);
    v.nonce_hex = nh;
    v.tag = 0;
    v.ok = false;
    v.replay = false;
    v.matched = -1;
    v.suspect = s;
    v.lost = true;
    v.kind = "packet";
    v.n = 0;
    v.us = 0;
    push_event(v);
    if (s >= 0) g_state.suspect = s;
  }
}

// ---------------------------------------------------------------- HTTP
std::string http_get(int fd, const std::string& path);
std::string http_post(int fd, const std::string& path,
                      const std::string& body);

void serve(int fd) {
  // 连接级防护：读 2s / 写 5s 超时，防止空闲预连接泄漏线程
  struct timeval rv{2, 0}, sv{5, 0};
  ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &rv, sizeof(rv));
  ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &sv, sizeof(sv));
  int one = 1;
  ::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

  std::string req;
  char buf[4096];
  // 读完整个头部（\r\n\r\n），再按 Content-Length 收完 body
  while (req.find("\r\n\r\n") == std::string::npos && req.size() < 65536) {
    ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
    if (n <= 0) break;
    req.append(buf, (size_t)n);
  }
  if (req.find("\r\n\r\n") == std::string::npos) {
    ::close(fd);
    return;
  }
  size_t content_len = 0;
  auto cl = req.find("Content-Length: ");
  if (cl == std::string::npos) cl = req.find("Content-length: ");
  if (cl != std::string::npos)
    content_len = (size_t)std::atoi(req.c_str() + cl + 15);
  auto body_start = req.find("\r\n\r\n");
  while (content_len > 0 && req.size() - body_start - 4 < content_len &&
         req.size() < 1 << 20) {
    ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
    if (n <= 0) break;
    req.append(buf, (size_t)n);
  }
  std::string body =
      content_len ? req.substr(body_start + 4, content_len) : "";

  std::istringstream ss(req.substr(0, req.find("\r\n")));
  std::string method, path, ver;
  ss >> method >> path >> ver;

  std::string resp;
  if (method == "GET" && (path == "/" || path == "/index.html"))
    resp = http_get(fd, "/");
  else if (method == "GET" && path == "/api/state")
    resp = http_get(fd, path);
  else if (method == "POST" && path == "/api/scenario")
    resp = http_post(fd, path, body);
  else if (method == "POST" && path == "/api/traffic")
    resp = http_post(fd, path, body);
  else if (method == "POST" && path == "/api/reset")
    resp = http_post(fd, path, body);
  else {
    resp = "HTTP/1.1 404 Not Found\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
  }
  // 显式声明短连接：避免浏览器复用已被服务端关闭的陈旧连接（NAT 下会挂 20s）
  auto cpos = resp.find("\r\n\r\n");
  resp.insert(cpos, "\r\nConnection: close");
  size_t sent = 0;
  while (sent < resp.size()) {
    ssize_t w = ::send(fd, resp.data() + sent, resp.size() - sent, 0);
    if (w <= 0) break;
    sent += (size_t)w;
  }
  ::shutdown(fd, SHUT_WR);
  // 收掉残余字节让对端干净关闭
  while (::recv(fd, buf, sizeof(buf), 0) > 0) {
  }
  ::close(fd);
}

std::string esc(const std::string& s) {
  std::string o;
  for (char c : s) {
    switch (c) {
      case '"': o += "\\\""; break;
      case '\\': o += "\\\\"; break;
      case '\n': o += "\\n"; break;
      default:
        if ((unsigned char)c < 0x20) o += ' ';
        else o += c;
    }
  }
  return o;
}

std::string json_state() {
  std::lock_guard<std::mutex> lk(g_state.mu);
  std::ostringstream o;
  o << "{\"scenario\":\"" << esc(g_state.scenario) << "\"";
  o << ",\"uptime\":" << (mono_s() - g_started);
  o << ",\"suspect\":" << g_state.suspect;
  o << ",\"lost\":{\"count\":" << g_state.lost_count << ",\"suspects\":[";
  for (size_t i = 0; i < g_state.lost_suspects.size(); ++i) {
    if (i) o << ",";
    o << g_state.lost_suspects[i];
  }
  o << "]}";
  o << ",\"traffic\":" << g_state.traffic_packets;
  o << ",\"dirs\":[";
  for (size_t i = 0; i < g_state.stats.size(); ++i) {
    const DirStat& s = g_state.stats[i];
    double avg = g_state.us_cnt[i] ? g_state.us_sum[i] / (double)g_state.us_cnt[i]
                                   : 0.0;
    if (i) o << ",";
    o << "{\"mac\":\"" << esc(g_ctl->directions()[i].mac) << "\""
      << ",\"packets\":" << s.packets << ",\"pass\":" << s.pass
      << ",\"fail\":" << s.fail << ",\"replays\":" << s.replays
      << ",\"flows\":" << s.flows << ",\"flow_pass\":" << s.flow_pass
      << ",\"flow_fail\":" << s.flow_fail
      << ",\"cpmv\":" << s.cpmv_checks << ",\"bpmv\":" << s.bpmv_checks
      << ",\"cfmv\":" << s.cfmv_checks << ",\"avg_us\":" << avg << "}";
  }
  o << "],\"events\":[";
  size_t from = g_state.events.size() > 40 ? g_state.events.size() - 40 : 0;
  for (size_t i = from; i < g_state.events.size(); ++i) {
    const EventView& e = g_state.events[i];
    if (i > from) o << ",";
    o << "{\"t\":" << e.t << ",\"mac\":\"" << esc(e.mac) << "\""
      << ",\"nonce\":\"" << esc(e.nonce_hex) << "\",\"tag\":" << e.tag
      << ",\"ok\":" << (e.ok ? "true" : "false")
      << ",\"replay\":" << (e.replay ? "true" : "false")
      << ",\"lost\":" << (e.lost ? "true" : "false")
      << ",\"matched\":" << e.matched << ",\"suspect\":" << e.suspect
      << ",\"us\":" << e.us << ",\"kind\":\"" << esc(e.kind) << "\""
      << ",\"n\":" << e.n << "}";
  }
  o << "]}";
  return o.str();
}

std::string find_in_body(const std::string& body, const std::string& key) {
  auto k = body.find("\"" + key + "\"");
  if (k == std::string::npos) return "";
  auto colon = body.find(':', k);
  if (colon == std::string::npos) return "";
  auto q1 = body.find('"', colon);
  if (q1 == std::string::npos) return "";
  auto q2 = body.find('"', q1 + 1);
  if (q2 == std::string::npos) return "";
  return body.substr(q1 + 1, q2 - q1 - 1);
}

std::string http_post(int, const std::string& path, const std::string& body) {
  if (path == "/api/scenario") {
    std::string name = find_in_body(body, "name");
    bool known = false;
    for (const char* s : kScenarios)
      if (name == s) known = true;
    if (!known)
      return "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";
    stop_switches();
    reset_run(name);
    write_tables(scenario_tables(name));
    start_switches(scenario_evil(name));
    std::this_thread::sleep_for(std::chrono::milliseconds(700));  // 等表热加载
    return "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
  }
  if (path == "/api/traffic") {
    int count = 20;
    {
      std::lock_guard<std::mutex> lk(g_state.mu);
      auto k = body.find("\"count\"");
      if (k != std::string::npos) {
        auto colon = body.find(':', k);
        if (colon != std::string::npos) {
          int v = std::atoi(body.c_str() + colon + 1);
          if (v > 0 && v <= 500) count = v;
        }
      }
      g_state.traffic_packets += (uint64_t)count;
    }
    // 异步执行：POST 立即返回，避免占用连接线程（ping 最多几秒）
    bool expect = false;
    if (g_traffic_running.compare_exchange_strong(expect, true))
      std::thread(traffic_worker, count).detach();
    return "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
  }
  if (path == "/api/reset") {
    std::string sc;
    {
      std::lock_guard<std::mutex> lk(g_state.mu);
      sc = g_state.scenario;
    }
    reset_run(sc);
    return "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
  }
  return "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
}

// ---------------------------------------------------------------- 内嵌页面
const char* kPage = R"HTML(<!DOCTYPE html>
<html lang="zh"><head><meta charset="utf-8">
<title>MPV-2 · SDN 多路径验证演示台</title>
<style>
:root{--bg:#0b1020;--panel:#121a30;--line:#23304f;--tx:#dbe4ff;--dim:#7f8db1;
--ok:#4ade80;--bad:#f87171;--replay:#fbbf24;--acc:#60a5fa}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--tx);font:14px/1.6 "Segoe UI","Microsoft YaHei",sans-serif;padding:18px}
h1{font-size:20px;margin-bottom:2px}
.sub{color:var(--dim);font-size:12px;margin-bottom:14px}
.grid{display:grid;grid-template-columns:1.25fr 1fr;gap:14px;max-width:1280px;margin:auto}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px}
.panel h2{font-size:14px;color:var(--acc);margin-bottom:10px;font-weight:600}
svg text{fill:var(--tx);font-size:12px}
.btn{background:#1c2a4f;border:1px solid var(--line);color:var(--tx);border-radius:7px;
padding:7px 12px;cursor:pointer;font-size:13px;margin:0 6px 6px 0}
.btn:hover{background:#27407a}
.btn.on{background:var(--acc);color:#04122e;border-color:var(--acc);font-weight:600}
.btn.warn:hover{background:#7a2740}
.cards{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-bottom:10px}
.card{background:#0e1530;border:1px solid var(--line);border-radius:8px;padding:8px 10px}
.card .v{font-size:19px;font-weight:700}
.card .k{font-size:11px;color:var(--dim)}
.ok{color:var(--ok)} .bad{color:var(--bad)} .rp{color:var(--replay)}
table{width:100%;border-collapse:collapse;font-size:12px}
th{color:var(--dim);text-align:left;font-weight:500;border-bottom:1px solid var(--line);padding:4px 6px}
td{padding:4px 6px;border-bottom:1px solid #1a2440;font-family:Consolas,monospace}
.barwrap{display:flex;align-items:flex-end;gap:18px;height:130px;padding:6px 4px}
.bar{width:52px;background:linear-gradient(#3b82f6,#1d4ed8);border-radius:4px 4px 0 0;position:relative}
.bar .lb{position:absolute;bottom:-20px;left:50%;transform:translateX(-50%);font-size:11px;color:var(--dim);white-space:nowrap}
.bar .vv{position:absolute;top:-18px;left:50%;transform:translateX(-50%);font-size:11px}
.dot{animation:none}
@keyframes pulse{0%{opacity:.9;r:10}70%{opacity:0;r:26}100%{opacity:0;r:26}}
.suspect{animation:pulse 1.4s infinite;fill:none;stroke:var(--bad);stroke-width:3}
.legend{font-size:12px;color:var(--dim);margin-top:6px}
.legend i{display:inline-block;width:10px;height:10px;border-radius:50%;margin:0 4px 0 10px}
.note{font-size:12px;color:var(--dim);margin-top:8px}
#flowbox .v,.stat-inline b{color:var(--acc)}
</style></head><body>
<div style="max-width:1280px;margin:auto">
<h1>MPV-2 · SDN 多路径验证演示台</h1>
<div class="sub">湖南大学大创项目 · 固定 16B 验证头 · 合法路径集合判定 · 逐跳取证定位 · 流级压缩（CFMV）</div>
<div class="grid">
<div>
  <div class="panel">
    <h2>拓扑与实时验证</h2>
    <svg id="topo" width="100%" viewBox="0 0 560 330" style="background:#0e1530;border-radius:8px"></svg>
    <div class="legend">判定 <i style="background:var(--ok)"></i>通过 <i style="background:var(--bad)"></i>失败 <i style="background:var(--replay)"></i>重放/失联
    <span id="scenlabel" style="margin-left:14px"></span></div>
    <div id="lostnote" class="note"></div>
  </div>
  <div class="panel" style="margin-top:14px">
    <h2>场景注入</h2>
    <button class="btn" data-sc="normal">正常转发</button>
    <button class="btn" data-sc="tagflip">标签错配</button>
    <button class="btn" data-sc="blackhole">路径偏离(黑洞)</button>
    <button class="btn" data-sc="bitflip">恶意改头(s2)</button>
    <button class="btn" data-sc="dup">恶意重放(s2)</button>
    <button class="btn warn" id="reset">清零统计</button>
    <div class="note">场景切换会重写转发表（交换机热加载）并重建控制器；恶意场景会把 s2 换成带恶意行为的交换机进程。</div>
  </div>
  <div class="panel" style="margin-top:14px">
    <h2>验证事件流</h2>
    <table><thead><tr><th>时间</th><th>方向</th><th>nonce</th><th>tag</th><th>结论</th><th>定位</th><th>判定耗时</th></tr></thead>
    <tbody id="evt"></tbody></table>
  </div>
</div>
<div>
  <div class="panel">
    <h2>实时指标</h2>
    <div class="cards">
      <div class="card"><div class="v" id="vpass">0</div><div class="k">通过</div></div>
      <div class="card"><div class="v" id="vfail">0</div><div class="k">失败</div></div>
      <div class="card"><div class="v" id="vreplay">0</div><div class="k">重放拦截</div></div>
      <div class="card"><div class="v" id="vcpmv">0</div><div class="k">CPMV 判定次数</div></div>
      <div class="card"><div class="v" id="vbpmv">0</div><div class="k">BPMV 判定次数</div></div>
      <div class="card"><div class="v" id="vcfmv">0</div><div class="k">CFMV 窗口判定</div></div>
      <div class="card"><div class="v" id="vflows">0/0</div><div class="k">流级窗口 通过/总</div></div>
      <div class="card"><div class="v" id="vlat">–</div><div class="k">平均判定耗时 µs</div></div>
      <div class="card"><div class="v" id="vuptime">0</div><div class="k">运行秒数</div></div>
    </div>
    <button class="btn" id="send20">▶ 发送 20 包</button>
    <button class="btn" id="send100">▶▶ 发送 100 包</button>
    <span class="note">每 (流,tag) 凑满 10 包输出一个流级窗口（CFMV）。</span>
  </div>
  <div class="panel" style="margin-top:14px">
    <h2>控制器判定开销：BPMV vs CPMV vs CFMV（累计，实测）</h2>
    <div class="barwrap" id="bars"></div>
    <div class="note">同一批包的两种口径：BPMV=不信任 tag 逐候选扫描；CPMV=tag+期望值一次判定；CFMV=整窗聚合一次判定。</div>
  </div>
  <div class="panel" style="margin-top:14px">
    <h2>单次判定时延 vs 候选路径数 k（bench 实测，7 跳）</h2>
    <svg id="chart" width="100%" height="150" viewBox="0 0 460 150"></svg>
    <div class="legend"><i style="background:var(--acc)"></i>tag（CPMV）<i style="background:var(--replay)"></i>scan（BPMV）—— tag 模式与 k 无关</div>
  </div>
  <div class="panel" style="margin-top:14px" id="flowbox">
    <h2>流级窗口（CFMV）判定</h2>
    <table><thead><tr><th>时间</th><th>方向</th><th>tag</th><th>窗口包数 N</th><th>结论</th><th>判定耗时</th></tr></thead>
    <tbody id="flowevt"></tbody></table>
    <div class="note">ΣV = N·A + B·Σh：出口按流聚合，控制器每窗口一次判定；N=4096 时仍为 0.04µs（与 N 无关）。</div>
  </div>
</div>
</div></div>
<script>
const KS=[1,2,4,8,16,32,64],TAG=[0.271,0.350,0.310,0.310,0.310,0.271,0.211],SCAN=[0.271,0.351,0.321,0.351,0.391,0.440,0.471];
const NODES={h1:[36,165],s1:[136,165],s2:[268,85],s3:[268,245],s4:[400,165],h2:[508,165]};
const EDGES=[["h1","s1"],["s1","s2"],["s1","s3"],["s2","s4"],["s3","s4"],["s4","h2"]];
const PATHS={
 fwd0:["h1","s1","s2","s4","h2"],fwd1:["h1","s1","s3","s4","h2"],
 rev0:["h2","s4","s2","s1","h1"],rev1:["h2","s4","s3","s1","h1"]};
const topo=document.getElementById("topo");
function el(t,a){const e=document.createElementNS("http://www.w3.org/2000/svg",t);for(const k in a)e.setAttribute(k,a[k]);return e}
function drawTopo(){
 topo.innerHTML="";
 EDGES.forEach(([a,b])=>{const A=NODES[a],B=NODES[b];
  topo.appendChild(el("line",{x1:A[0],y1:A[1],x2:B[0],y2:B[1],stroke:"#23304f","stroke-width":3}))});
 for(const id in NODES){const[x,y]=NODES[id];const g=el("g",{id:"g_"+id});
  const sw=id[0]==="s";
  g.appendChild(el("rect",{x:x-24,y:y-17,width:48,height:34,rx:sw?7:17,
   fill:sw?"#1c2a4f":"#14301f",stroke:sw?"#3b5aa0":"#2f7d4a","stroke-width":2}));
  const t=el("text",{x:x,y:y+5,"text-anchor":"middle"});t.textContent=id;g.appendChild(t);
  topo.appendChild(g)}
}
drawTopo();
function poly(ids){return ids.map(id=>NODES[id].join(",")).join(" ")}
function dot(ids,color,fadeAt){
 const p=el("polyline",{points:poly(ids),fill:"none",stroke:"none"});
 let pl="M "+poly(ids).replace(/ /g," L ");
 if(fadeAt!==undefined){const i=ids.indexOf(fadeAt);if(i<0)return;
  pl="M "+ids.slice(0,i+1).map(id=>NODES[id].join(",")).join(" L ")}
 const c=el("circle",{r:5.5,fill:color});
 const a=el("animateMotion",{dur:"1.15s",path:pl,fill:"freeze"});
 c.appendChild(a);topo.appendChild(c);
 setTimeout(()=>c.remove(),1250);
}
const suspectRing=id=>{const g=document.getElementById("g_"+id);if(!g)return;
 const[x,y]=NODES[id];const r=el("circle",{cx:x,cy:y,r:10,class:"suspect"});
 r.setAttribute("style","animation:pulse 1.4s infinite");
 g.appendChild(r);setTimeout(()=>r.remove(),6000)};
const S={last:0,shownSuspect:-1,scen:""};
function fmt(n){return n.toLocaleString("en-US")}
async function refresh(){
 try{const r=await fetch("/api/state");const j=await r.json();
 document.getElementById("scenlabel").textContent="当前场景："+({normal:"正常转发",tagflip:"标签错配",blackhole:"路径偏离(黑洞)",bitflip:"恶意改头(s2)",dup:"恶意重放(s2)"})[j.scenario];
 const f=j.dirs[0],rv=j.dirs[1];
 const pass=f.pass+rv.pass,fail=f.fail+rv.fail,rp=f.replays+rv.replays;
 document.getElementById("vpass").textContent=fmt(pass);
 document.getElementById("vpass").className="v ok";
 document.getElementById("vfail").textContent=fmt(fail);
 document.getElementById("vfail").className="v"+(fail?" bad":"");
 document.getElementById("vreplay").textContent=fmt(rp);
 document.getElementById("vreplay").className="v"+(rp?" rp":"");
 const cp=f.cpmv+rv.cpmv,bp=f.bpmv+rv.bpmv,cf=f.cfmv+rv.cfmv;
 document.getElementById("vcpmv").textContent=fmt(cp);
 document.getElementById("vbpmv").textContent=fmt(bp);
 document.getElementById("vcfmv").textContent=fmt(cf);
 const fp=f.flow_pass+rv.flow_pass,ff=f.flows+rv.flows;
 document.getElementById("vflows").textContent=fp+"/"+ff;
 const us_cnt=f.avg_us&&rv.avg_us?(f.avg_us+rv.avg_us)/2:(f.avg_us||rv.avg_us||0);
 document.getElementById("vlat").textContent=us_cnt?us_cnt.toFixed(2):"–";
 document.getElementById("vuptime").textContent=j.uptime.toFixed(0);
 // 柱状图
 const bars=document.getElementById("bars");bars.innerHTML="";
 const mx=Math.max(bp,cp,cf,1);
 [[bp,"BPMV","#f87171"],[cp,"CPMV","#60a5fa"],[cf,"CFMV","#4ade80"]].forEach(([v,l,c])=>{
  const d=document.createElement("div");d.className="bar";
  d.style.height=Math.max(4,v/mx*100)+"px";d.style.background="linear-gradient("+c+",#123)";
  d.innerHTML='<div class="vv">'+fmt(v)+'</div><div class="lb">'+l+'</div>';bars.appendChild(d)});
 // 事件
 const tb=document.getElementById("evt");tb.innerHTML="";
 const mac2d=m=>m==="00:00:00:00:00:02"?"h1→h2":"h2→h1";
 for(let i=Math.max(0,j.events.length-12);i<j.events.length;i++){const e=j.events[i];
  const tr=document.createElement("tr");
  let verdict=e.lost?'<span class="rp">失联</span>':e.replay?'<span class="rp">重放</span>':(e.ok?'<span class="ok">通过</span>':'<span class="bad">失败</span>');
  if(e.kind==="flow")verdict=(e.ok?'<span class="ok">流级通过</span>':'<span class="bad">流级失败</span>')+" N="+e.n;
  const loc=e.suspect>=0?'<span class="bad">s'+e.suspect+'</span>':"–";
  tr.innerHTML="<td>"+e.t.toFixed(1)+"</td><td>"+(e.kind==="flow"?"流级·":"")+mac2d(e.mac)+"</td><td>"+e.nonce+"</td><td>"+e.tag+"</td><td>"+verdict+"</td><td>"+loc+"</td><td>"+e.us.toFixed(2)+"µs</td>";
  tb.appendChild(tr)}
 // 流级窗口表
 const ft=document.getElementById("flowevt");ft.innerHTML="";
 for(let i=j.events.length-1;i>=0&&ft.children.length<6;i--){const e=j.events[i];
  if(e.kind!=="flow")continue;const tr=document.createElement("tr");
  tr.innerHTML="<td>"+e.t.toFixed(1)+"</td><td>"+mac2d(e.mac)+"</td><td>"+e.tag+"</td><td>"+e.n+"</td><td>"+(e.ok?'<span class="ok">通过</span>':'<span class="bad">失败</span>')+"</td><td>"+e.us.toFixed(2)+"µs</td>";
  ft.appendChild(tr)}
 // 拓扑动画：新事件
 for(let i=S.last;i<j.events.length;i++){const e=j.events[i];
  if(e.kind!=="packet")continue;
  const fwd=e.mac==="00:00:00:00:00:02";
  const pi=e.lost?"fwd1":(e.matched>=0&&e.matched<=1?(fwd?(e.matched?"fwd1":"fwd0"):(e.matched?"rev1":"rev0")):(fwd?"fwd0":"rev0"));
  const col=e.lost?"#fbbf24":e.replay?"#fbbf24":e.ok?"#4ade80":"#f87171";
  dot(PATHS[pi],col,e.lost?"s3":undefined)}
 S.last=j.events.length;
 // 嫌疑交换机
 if(j.suspect>=0&&j.suspect!==S.shownSuspect){S.shownSuspect=j.suspect;suspectRing("s"+j.suspect)}
 if(j.suspect<0)S.shownSuspect=-1;
 // 黑洞提示
 const ln=document.getElementById("lostnote");
 if(j.lost.count>0){ln.innerHTML='<span class="rp">检测到 '+j.lost.count+" 个包半路失联（出口未上报）。取证定位：改道嫌疑 s"+(j.lost.suspects[0]!==undefined?j.lost.suspects[0]:"?")+'</span>'}
 else ln.innerHTML="";
 // 场景按钮态
 document.querySelectorAll("[data-sc]").forEach(b=>b.classList.toggle("on",b.dataset.sc===j.scenario));
 S.scen=j.scenario;
 }catch(e){}
}
setInterval(refresh,700);refresh();
document.querySelectorAll("[data-sc]").forEach(b=>b.onclick=async()=>{
 await fetch("/api/scenario",{method:"POST",body:JSON.stringify({name:b.dataset.sc})});
 S.last=0;S.shownSuspect=-1;refresh()});
document.getElementById("reset").onclick=()=>fetch("/api/reset",{method:"POST"});
const send=async n=>{await fetch("/api/traffic",{method:"POST",body:JSON.stringify({count:n})});refresh()};
document.getElementById("send20").onclick=()=>send(20);
document.getElementById("send100").onclick=()=>send(100);
// 时延-k 折线
(()=>{const c=document.getElementById("chart");const W=460,H=150,px=40,py=18;
 const mx=0.55,mn=0.18;const X=i=>px+i*(W-px-14)/(KS.length-1);
 const Y=v=>H-py-(v-mn)/(mx-mn)*(H-2*py);
 c.appendChild(el("line",{x1:px,y1:H-py,x2:W-14,y2:H-py,stroke:"#23304f"}));
 c.appendChild(el("line",{x1:px,y1:py,x2:px,y2:H-py,stroke:"#23304f"}));
 [[0.2,"0.2"],[0.35,"0.35"],[0.5,"0.5"]].forEach(([v,l])=>{const t=el("text",{x:px-6,y:Y(v)+4,"text-anchor":"end","font-size":"10"});t.textContent=l;c.appendChild(t)});
 KS.forEach((k,i)=>{const t=el("text",{x:X(i),y:H-py+14,"text-anchor":"middle","font-size":"10"});t.textContent="k="+k;c.appendChild(t)});
 const line=(arr,color)=>{c.appendChild(el("polyline",{points:arr.map((v,i)=>X(i)+","+Y(v)).join(" "),fill:"none",stroke:color,"stroke-width":2.5}));
  arr.forEach((v,i)=>c.appendChild(el("circle",{cx:X(i),cy:Y(v),r:3,fill:color})))};
 line(TAG,"#60a5fa");line(SCAN,"#fbbf24");
 const t1=el("text",{x:px+8,y:py+8,"font-size":"11",fill:"#60a5fa"});t1.textContent="tag（CPMV）≈0.3µs，与 k 无关";c.appendChild(t1)})();
</script></body></html>)HTML";

std::string http_get(int, const std::string& path) {
  if (path == "/api/state")
    return "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" +
           json_state();
  std::string page = kPage;
  return "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n"
         "Content-Length: " +
         std::to_string(page.size()) + "\r\n\r\n" + page;
}

// ---------------------------------------------------------------- main
void on_term(int) {
  for (pid_t p : g_pids) ::kill(p, SIGTERM);
  topo::cleanup();
  std::_Exit(0);
}

}  // namespace

int main(int argc, char** argv) {
  if (::geteuid() != 0) {
    std::fprintf(stderr, "需要 root：sudo ./build/dashboard\n");
    return 2;
  }
  int port = 8080;
  for (int i = 1; i < argc; ++i) {
    std::string a = argv[i];
    if (a == "--port") port = std::atoi(argv[++i]);
    else if (a == "--flow-window") g_flow_window = (uint32_t)std::atoi(argv[++i]);
  }

  g_vswitch = [] {
    char buf[4096];
    ssize_t n = ::readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (n <= 0) return std::string("./vswitch");
    buf[n] = 0;
    std::string s(buf);
    auto pos = s.find_last_of('/');
    return (pos == std::string::npos ? std::string(".") : s.substr(0, pos)) +
           "/vswitch";
  }();
  if (::access(g_vswitch.c_str(), X_OK) != 0) {
    std::fprintf(stderr, "找不到交换机程序: %s（先 make）\n", g_vswitch.c_str());
    return 2;
  }
  ::mkdir(WORK, 0755);

  g_started = mono_s();
  setup_links();
  write_tables(Scenario::kNormal);
  clear_logs();
  g_ctl = new Controller(SEED, directions());
  g_state.stats.assign(2, DirStat{});
  start_switches("none");

  int srv = ::socket(AF_INET, SOCK_STREAM, 0);
  int one = 1;
  ::setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  addr.sin_port = htons((uint16_t)port);
  if (::bind(srv, (sockaddr*)&addr, sizeof(addr)) != 0) {
    std::fprintf(stderr, "bind 失败（端口 %d 被占？）\n", port);
    return 1;
  }
  ::listen(srv, 16);

  std::thread t_tail(tailer_loop);
  t_tail.detach();

  std::signal(SIGTERM, on_term);
  std::signal(SIGINT, on_term);

  std::printf("MPV-2 演示控制台已启动：http://0.0.0.0:%d  （Ctrl-C 退出并清理拓扑）\n",
              port);
  std::fflush(stdout);
  while (true) {
    int fd = ::accept(srv, nullptr, nullptr);
    if (fd < 0) continue;
    std::thread(serve, fd).detach();
  }
  return 0;
}
