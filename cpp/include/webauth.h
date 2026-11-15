// Web 管理接口的授权原语（M5.19 部署加固，header-only，零依赖）。
//
// 行业范式（Jupyter / Minikube / Grafana 的通用组合）：
//   * 服务默认绑定回环地址，暴露到非回环必须显式 --bind；
//   * 每次启动生成 CSPRNG 管理令牌，状态变更接口（POST）必须携带——
//     浏览器经 HttpOnly + SameSite=Strict Cookie 自动携带（SameSite=Strict
//     使跨站请求不携带 Cookie，天然免疫 CSRF，页面 JS 无需任何改动）；
//     命令行脚本用 X-MPV-Token 头；
//   * 令牌比较用常数时间实现，防时序侧信道；
//   * 只读接口（GET /api/state）不设门禁——绑定回环时本就只有本机可达。
#pragma once

#include <cctype>
#include <cstdint>
#include <string>

namespace mpv {

// 常数时间比较：长度差与逐字节异或累积进 volatile 变量，编译器无法短路。
inline bool secure_equal(const std::string& a, const std::string& b) {
  volatile uint8_t diff = 0;
  const size_t n = a.size() > b.size() ? a.size() : b.size();
  for (size_t i = 0; i < n; ++i) {
    uint8_t x = i < a.size() ? static_cast<uint8_t>(a[i]) : 0;
    uint8_t y = i < b.size() ? static_cast<uint8_t>(b[i]) : 0;
    diff = static_cast<uint8_t>(diff | (x ^ y));
  }
  diff = static_cast<uint8_t>(diff | (a.size() ^ b.size()));
  return diff == 0;
}

inline char ascii_lower(char c) {
  return static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
}

// 从请求头块中取指定头的第一个值（头名大小写不敏感，头块按 \n 分行、容忍 \r）。
inline bool header_value(const std::string& head, const std::string& name,
                         std::string* out) {
  size_t pos = 0;
  while (pos < head.size()) {
    size_t eol = head.find('\n', pos);
    if (eol == std::string::npos) eol = head.size();
    std::string line = head.substr(pos, eol - pos);
    pos = eol + 1;
    if (!line.empty() && line.back() == '\r') line.pop_back();
    if (line.size() <= name.size() + 1) continue;
    bool match = true;
    for (size_t i = 0; i < name.size(); ++i)
      if (ascii_lower(line[i]) != ascii_lower(name[i])) {
        match = false;
        break;
      }
    if (!match || line[name.size()] != ':') continue;
    size_t v = name.size() + 1;
    while (v < line.size() && (line[v] == ' ' || line[v] == '\t')) ++v;
    size_t end = line.size();
    while (end > v && (line[end - 1] == ' ' || line[end - 1] == '\t')) --end;
    *out = line.substr(v, end - v);
    return true;
  }
  return false;
}

// X-MPV-Token 头（命令行脚本入口）。
inline bool header_token(const std::string& head, std::string* out) {
  return header_value(head, "x-mpv-token", out) && !out->empty();
}

// Cookie: ... mpv_token=<t> ...（浏览器入口；HttpOnly 由服务端 Set-Cookie 下发）。
// 按分号切分参数并在参数边界匹配名字——裸子串搜索会把 "Xmpv_token=" 误认。
inline bool cookie_token(const std::string& head, std::string* out) {
  std::string cookie;
  if (!header_value(head, "cookie", &cookie)) return false;
  const std::string k = "mpv_token=";
  size_t pos = 0;
  while (pos <= cookie.size()) {
    size_t semi = cookie.find(';', pos);
    if (semi == std::string::npos) semi = cookie.size();
    std::string pair = cookie.substr(pos, semi - pos);
    size_t b = pair.find_first_not_of(" \t");
    if (b != std::string::npos) {
      size_t e = pair.find_last_not_of(" \t");
      pair = pair.substr(b, e - b + 1);
      if (pair.size() > k.size() && pair.compare(0, k.size(), k) == 0) {
        *out = pair.substr(k.size());
        return true;
      }
    }
    if (semi == cookie.size()) break;
    pos = semi + 1;
  }
  return false;
}

// 状态变更请求（POST）的授权判定：头或 Cookie 任一匹配即通过。
// 对不存在/不匹配统一返回 false，不泄露"哪个字段错了"。
inline bool write_authorized(const std::string& request_head,
                             const std::string& token) {
  std::string v;
  if (header_token(request_head, &v)) return secure_equal(v, token);
  if (cookie_token(request_head, &v)) return secure_equal(v, token);
  return false;
}

}  // namespace mpv
