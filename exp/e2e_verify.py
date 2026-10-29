"""端到端验证：在真实转发路径上跑 MPV-2。

拓扑（双向双路径）：

        h1 --- s1 --- s2 --- s4 --- h2
                 \\            /
                  +--- s3 ----+

    正向 P0 = [s1, s2, s4]    P1 = [s1, s3, s4]
    反向同理。

两轮：
    R1 正常   —— 转发表与路径一致，出口上报应全部通过
    R2 故障   —— s1 的 tag=0 条目被改成走 P1 分支，且下游表同步改，
                 使"错标"路径在数据面上自洽。出口上报的 V 会命中 P1，
                 而 tag 声称 P0；控制器扫描候选集即可定位到分歧点 s1。

运行
----
    sudo .venv/bin/python -m exp.e2e_verify
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Tuple

PROJ = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJ))

from mpv.core import KeyRing  # noqa: E402
from mpv.core.keys import Hop, Path as NetPath  # noqa: E402
from mpv.core.scheme import (  # noqa: E402
    ExpectationTable,
    Header2,
    verify_scan,
    verify_tag,
)

SEED = 20260501
WORK = Path("/tmp/mpv_e2e")
FORCE_TAG = 0

FWD = [["s1", "s2", "s4"], ["s1", "s3", "s4"]]
REV = [["s4", "s2", "s1"], ["s4", "s3", "s1"]]


# ---------------------------------------------------------------------------
# 拓扑与交换机
# ---------------------------------------------------------------------------


def build_net():
    from mininet.net import Mininet
    from mininet.node import Switch
    from mininet.topo import Topo

    class Topo2(Topo):
        def build(self):
            h1 = self.addHost("h1", ip="10.0.0.1/24")
            h2 = self.addHost("h2", ip="10.0.0.2/24")
            s1 = self.addSwitch("s1")
            s2 = self.addSwitch("s2")
            s3 = self.addSwitch("s3")
            s4 = self.addSwitch("s4")
            self.addLink(h1, s1)
            self.addLink(s1, s2)
            self.addLink(s1, s3)
            self.addLink(s2, s4)
            self.addLink(s3, s4)
            self.addLink(s4, h2)

    class MPVSwitch(Switch):
        """每台交换机拉一个独立的 vswitch 进程。"""

        def __init__(self, name, **params):
            Switch.__init__(self, name, **params)
            self.sid = int(name[1:])
            self.proc = None
            self.table = WORK / f"{name}.json"

        def start(self, controllers):
            args = [
                sys.executable,
                "-m",
                "mpv.dp.vswitch",
                "--sid",
                str(self.sid),
                "--seed",
                str(SEED),
                "--table",
                str(self.table),
                "--report",
                str(WORK / "reports.jsonl"),
                "--paths",
                str(len(FWD)),
                "--force-tag",
                str(FORCE_TAG),
            ]
            for port, intf in sorted(self.intfs.items()):
                args += ["--port", f"{port}:{intf.name}"]
            self.proc = subprocess.Popen(
                args,
                cwd=str(PROJ),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

        def stop(self, deleteIntfs=True):
            if self.proc and self.proc.poll() is None:
                self.proc.terminate()
                try:
                    self.proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    self.proc.kill()
            Switch.stop(self, deleteIntfs)

    return Mininet(topo=Topo2(), switch=MPVSwitch, controller=None, ipBase="10.0.0.0/24")


# ---------------------------------------------------------------------------
# 转发表
# ---------------------------------------------------------------------------


def build_adj(net) -> Dict[Tuple[str, int], str]:
    adj: Dict[Tuple[str, int], str] = {}
    for link in net.links:
        n1, n2 = link.intf1.node, link.intf2.node
        adj[(n1.name, n1.ports[link.intf1])] = n2.name
        adj[(n2.name, n2.ports[link.intf2])] = n1.name
    return adj


def port_between(adj, a: str, b: str) -> int:
    for (node, port), peer in adj.items():
        if node == a and peer == b:
            return port
    raise KeyError(f"{a} 与 {b} 之间无链路")


def netpath(adj, path: List[str], host_from: str, host_to: str) -> NetPath:
    hops = []
    n = len(path)
    for i, sw in enumerate(path):
        prev = host_from if i == 0 else path[i - 1]
        nxt = host_to if i == n - 1 else path[i + 1]
        hops.append(
            Hop(
                sid=int(sw[1:]),
                in_port=port_between(adj, sw, prev),
                out_port=port_between(adj, sw, nxt),
            )
        )
    return tuple(hops)


def make_tables(net, adj, h1_mac: str, h2_mac: str, tamper: bool):
    tables = {sw.name: {"sid": sw.sid, "entries": {}} for sw in net.switches}

    def fill(paths: List[List[str]], dst_mac: str, src_host: str, dst_host: str):
        for tag, path in enumerate(paths):
            for i, sw in enumerate(path):
                prev = src_host if i == 0 else path[i - 1]
                nxt = dst_host if i == len(path) - 1 else path[i + 1]
                tables[sw]["entries"][f"{dst_mac}|{tag}"] = {
                    "port": port_between(adj, sw, nxt),
                    "pos": i + 1,
                    "strip": i == len(path) - 1,
                    "in_port": port_between(adj, sw, prev),
                }

    fill(FWD, h2_mac, "h1", "h2")
    fill(REV, h1_mac, "h2", "h1")

    if tamper:
        # s1 把 tag=0 引到 P1 分支；P1 上各跳的 tag=0 条目同步复制，
        # 使错标路径在数据面上自洽 —— 这类异常最难靠单点检查发现。
        tables["s1"]["entries"][f"{h2_mac}|0"] = dict(
            tables["s1"]["entries"][f"{h2_mac}|1"]
        )
        for sw in ("s3", "s4"):
            key1 = f"{h2_mac}|1"
            if key1 in tables[sw]["entries"]:
                tables[sw]["entries"][f"{h2_mac}|0"] = dict(tables[sw]["entries"][key1])
    return tables


def write_tables(tables) -> None:
    WORK.mkdir(parents=True, exist_ok=True)
    for name, t in tables.items():
        (WORK / f"{name}.json").write_text(json.dumps(t, ensure_ascii=False))


# ---------------------------------------------------------------------------
# 验证
# ---------------------------------------------------------------------------


def read_reports() -> List[dict]:
    p = WORK / "reports.jsonl"
    if not p.exists():
        return []
    out = []
    for line in p.read_text().splitlines():
        line = line.strip()
        if line:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return out


def _diverge(paths: List[List[str]], claimed: int, matched: int):
    """两条路径的分歧点：最后一个共同交换机（亦即错误下发发生的位置）。"""
    if matched is None or claimed >= len(paths) or matched >= len(paths):
        return None
    a, b = paths[claimed], paths[matched]
    common = 0
    for x, y in zip(a, b):
        if x != y:
            break
        common += 1
    return a[common - 1] if common else a[0]


def judge(
    reports: List[dict], table: ExpectationTable, paths: List[List[str]]
) -> dict:
    res = {"total": 0, "pass": 0, "fail": 0, "localized": []}
    for r in reports:
        hdr = Header2(nonce=r["nonce"], acc=r["acc"], tag=r["tag"])
        res["total"] += 1
        if verify_tag(table, hdr).ok:
            res["pass"] += 1
        else:
            res["fail"] += 1
            scan = verify_scan(table, hdr)
            res["localized"].append(
                {
                    "tag": r["tag"],
                    "matched": scan.matched_index,
                    "at": _diverge(paths, r["tag"], scan.matched_index),
                }
            )
    return res


# ---------------------------------------------------------------------------
# 一轮
# ---------------------------------------------------------------------------


def run_round(name: str, tamper: bool, packets: int = 20) -> dict:
    WORK.mkdir(parents=True, exist_ok=True)
    for f in WORK.glob("*.jsonl"):
        f.unlink()
    for f in WORK.glob("s*.json"):
        f.unlink()

    net = build_net()
    net.start()
    try:
        h1, h2 = net.get("h1"), net.get("h2")
        h1.setARP(h2.IP(), h2.MAC())
        h2.setARP(h1.IP(), h1.MAC())

        adj = build_adj(net)
        write_tables(make_tables(net, adj, h1.MAC(), h2.MAC(), tamper))
        time.sleep(1.2)  # 等交换机轮询加载转发表

        h1.cmd(f"ping -c {packets} -i 0.05 -W 1 {h2.IP()} > /dev/null 2>&1")
        time.sleep(0.8)

        kr = KeyRing.generate(n_switches=16, ports_per_switch=4, seed=SEED)
        reports = read_reports()
        fwd_reports = [r for r in reports if r.get("dst") == h2.MAC()]
        rev_reports = [r for r in reports if r.get("dst") == h1.MAC()]

        t_fwd = ExpectationTable(kr, [netpath(adj, p, "h1", "h2") for p in FWD])
        t_rev = ExpectationTable(kr, [netpath(adj, p, "h2", "h1") for p in REV])

        return {
            "round": name,
            "tamper": tamper,
            "reports": len(reports),
            "fwd": judge(fwd_reports, t_fwd, FWD),
            "rev": judge(rev_reports, t_rev, REV),
        }
    finally:
        net.stop()


def main() -> None:
    if os.geteuid() != 0:
        print("需要 root：sudo .venv/bin/python -m exp.e2e_verify")
        sys.exit(1)

    Path("/tmp/.mpv_stop").unlink(missing_ok=True)
    print("=" * 72)
    print("MPV-2 端到端验证 · 软件虚拟交换机 4 台 · 双路径")
    print("=" * 72)

    r1 = run_round("R1 正常转发", tamper=False)
    r2 = run_round("R2 标签错配", tamper=True)

    for r in (r1, r2):
        print()
        print(f"[{r['round']}]  出口上报 {r['reports']} 条")
        for key, label in (("fwd", "正向 h1→h2"), ("rev", "反向 h2→h1")):
            d = r[key]
            if not d["total"]:
                continue
            print(
                f"  {label}: 通过 {d['pass']} / 失败 {d['fail']} / 共 {d['total']}"
            )
            loc = d["localized"][0] if d["localized"] else None
            if loc:
                if loc["matched"] is not None:
                    print(
                        f"      → 实际命中候选 #{loc['matched']}，标签声称 #{loc['tag']}"
                        f"：路径标签错配，分歧点 {loc['at']}"
                        f"（{d['fail']} 条上报全部一致）"
                    )
                else:
                    print(
                        f"      → 未命中任何候选（{d['fail']} 条）：路径偏离或验证头被篡改"
                    )

    out = WORK / "result.json"
    out.write_text(json.dumps([r1, r2], ensure_ascii=False, indent=2))
    print(f"\n结果写入 {out}")


if __name__ == "__main__":
    main()
