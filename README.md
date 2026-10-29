# SIT — 面向软件定义网络的高效多路径验证研究

大学生创新创业训练计划（创新训练项目）原型。

**实现语言：C++17，工程内没有任何脚本语言代码**（无 Python、无 Shell）。
依赖只有一个 C++ 编译器与 make；拓扑用 iproute2 的 `ip` 命令搭建，交换机、验证器与
演示 APP 全部是本工程编译出的可执行文件。

把「验证一条固定路径」扩展为「验证一个合法路径集合」：数据包逐跳维护 16 字节定长
验证头，出口上报控制器，控制器据此判定路径合法性，失败时逐跳取证定位嫌疑交换机，
并支持流级压缩判定（CFMV）。

- 计划书：`docs/项目实施与开发计划书.md`
- 算法与验证报告：`docs/算法设计与验证报告.md`
- 项目总说明：`PROJECT.md`
- 实测结果：`results/`

## 快速开始

```bash
make deps       # 安装 g++ / make / iproute2（已装则跳过）
make            # 编译 7 个可执行文件
make test       # 黄金向量交叉校验 + 功能/对抗/CFMV/定位断言
make bench      # 攻击矩阵、多候选矩阵、性能与基线对比
sudo make e2e   # 五轮端到端：正常/标签错配/恶意改头/恶意重放/流级压缩
sudo make demo  # 演示 APP：浏览器打开 http://<VM地址>:8080
sudo make exp   # 结题实验：7 组实验一键运行，生成报告与 SVG 图表
```

> 注意：`e2e` 与 `dashboard` 共用 `/tmp/mpv_run` 与 h1/h2 netns 名，不要同时运行；
> e2e 结束时会清理共享拓扑。演示服务异常时重启即可（`sudo make demo`）。

## 目录

| 路径 | 内容 |
|---|---|
| `cpp/include/` | `blake2b.h`（RFC 7693）、`mpv2.h`（算法接口）、`controller.h`（判定与定位）、`topo.h`（拓扑编排） |
| `cpp/src/` | 对应实现 + `vswitch.cpp`、`verify_reports.cpp`、`bench.cpp`、`e2e.cpp`、`dashboard.cpp`（演示 APP） |
| `cpp/tests/` | `test_mpv2.cpp`、`golden_vectors.txt`（冻结的交叉校验夹具） |
| `docs/` | 计划书、算法设计与验证报告 |
| `results/` | VM 实测报告与演示截图 |

## 可执行文件

| 程序 | 作用 |
|---|---|
| `tests` | 黄金向量比对 + 功能/对抗/CFMV/重放/定位断言 |
| `vswitch` | 软件虚拟交换机（AF_PACKET，逐跳更新验证头；`--trace` 逐跳取证、`--flow-window` 流级聚合、`--evil bitflip\|dup` 恶意模式） |
| `verify_reports` | 离线验证器：读上报文件，判定并定位 |
| `bench` | 10 类攻击矩阵 + 多候选(k=2/8/16)矩阵 + 判定时延 + 解析基线对比 |
| `e2e` | 五轮端到端编排：建拓扑、跑场景、断言、出结论 |
| `dashboard` | **演示 APP**：纯 C++ HTTP 服务 + 内嵌 Web UI（实时拓扑、场景注入、嫌疑定位、BPMV/CPMV/CFMV 对比） |
| `exp` | **结题实验套件**：攻击矩阵/多候选/时延/流级/通信开销/头长/端到端统计 7 组实验一键运行，自动生成 `results/exp_report.md` 与 SVG 图表 |

## 核心设计

随机性放在**线性项**而非指数上，因此不需要「消去随机数」：

```
h    = H(nonce)                  公开哈希
c_i  = (a_i + b_i·h) mod p       单跳贡献
V    = Σ c_i·ρ^(i-1) mod p       逐跳累积，ρ 位置加权绑定顺序
E(P) = A_P + B_P·h               控制器期望值（与 nonce 无关，可预计算）
```

- 头部恒定 16 字节：nonce 56 + V 64 + tag 8
- 判定 O(1)：按 tag 直接比对（CPMV）；tag 不可信时退化为 O(k) 扫描（BPMV）
- **流级压缩（CFMV）**：E(h) 线性于 h ⇒ `ΣV = N·A + B·Σh`，出口按 (流,tag) 聚合
  三元组 `(N, Σh, ΣV)`，控制器每窗口一次判定，与 N 无关（N=4096 实测 0.04 µs）
- 重放防御：流级聚合可加、可被重放抬高，控制器以 nonce 窗口去重（`NonceWindow`）
- 异常定位：交换机 `--trace` 逐跳记录取证值，控制器对照声称路径前缀期望，
  首个不匹配的交换机即嫌疑节点；黑洞场景用「取证出现但出口未上报」发现失联

## 已验证结论（VM 实测，Ubuntu 24.04 / g++ 13）

| 项 | 结果 |
|---|---|
| 黄金向量交叉校验 | 612 项逐位一致，0 失败 |
| 断言总数（功能/对抗/CFMV/重放/定位） | 695 项，0 失败 |
| 10 类攻击检出率（各 3000 次） | 100%（申报书原式为 0%） |
| 多候选集 k=2/8/16 攻击检出 / 诚实接受 | 100% / 100% |
| 控制器判定 k=64 | 0.21 µs（tag）/ 0.47 µs（scan），tag 与 k 无关 |
| CFMV 流级判定 | 0.04 µs，与窗口大小 N 无关 |
| 端到端 R1–R5 | 全部通过（含 s1/s2 精确定位、60 条重放拦截） |
| 演示 APP 五场景 | 标签错配→s1、恶意改头→s2、黑洞→改道交换机、重放→全拦截 |

## 演示 APP 截图

| 场景 | 截图 |
|---|---|
| 正常转发（40/40 通过，CFMV 窗口判定） | `results/dashboard_normal.png` |
| 标签错配（20 失败全检出，定位 s1） | `results/dashboard_tagflip.png` |
| 恶意改头（40 失败全检出，取证定位 s2） | `results/dashboard_bitflip.png` |
