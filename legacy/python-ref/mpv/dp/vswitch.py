"""MPV-2 软件虚拟交换机（用户态数据平面）。

为什么自己写交换机
------------------
Open vSwitch 的动作集只有 set_field / add / group 等，**无法执行模运算**，
因此无法在数据面计算 c_i = (a_i + b_i·H(nonce)) mod p。而 MPV-2 的逐跳更新
本质就是一次模乘加。所以要"在真实转发中跑验证"，只有两条路：

  1. P4/BMv2 —— 保真度高，但 BMv2 的 ALU 是 32 位，跑不了 64 位模域；
  2. 用户态软件交换机 —— 自己收发以太帧，模运算随便做。

本文件走第 2 条：一个基于 AF_PACKET 的多端口二层交换机，每个端口一个收发
循环，按预置转发表转发，并在每一跳执行 MPV-2 累加。

帧格式
------
    +--------+--------+--------+  普通帧
    | eth 14 |  ip    |
    +--------+--------+
    +--------+--------------------+--------+  带验证头的帧
    | eth 14 | shim 16 字节       |  ip    |
    | ethertype = 0x88B5          |
    +--------+--------------------+--------+
    shim = nonce(7) | V(8) | tag(1)

    只在 IPv4 场景使用；出口交换机把 shim 剥掉并恢复 ethertype = 0x0800。

转发表
------
每个交换机一份 JSON：

    {
      "sid": 2,
      "entries": {
        "aa:bb:cc:dd:ee:ff|0": {"port": 3, "pos": 2, "strip": false},
        ...
      }
    }

键是 "<目的 MAC>|<tag>"。pos 是该跳在路径中的位置（1-based），strip 表示
这是最后一跳、需要剥掉 shim 并投递给主机。

用法
----
    python -m mpv.dp.vswitch --sid 1 --seed 12345 \
        --table /tmp/s1.json --report /tmp/report.jsonl \
        --port 1:s1-eth1 --port 2:s1-eth2
"""

from __future__ import annotations

import argparse
import json
import os
import selectors
import socket
import struct
import sys
import time
from hashlib import blake2b
from pathlib import Path
from typing import Dict, List, Tuple

from mpv.core.keys import KeyRing
from mpv.core.scheme import P, RHO, _h, hop_key

ETH_P_ALL = 0x0003
SHIM_ETHERTYPE = 0x88B5
SHIM_LEN = 16  # nonce7 + V8 + tag1

MAC_BROADCAST = b"\xff" * 6


def _mac(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


class Port:
    __slots__ = ("index", "name", "sock")

    def __init__(self, index: int, name: str):
        self.index = index
        self.name = name
        self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        self.sock.bind((name, 0))
        self.sock.setblocking(False)

    def send(self, frame: bytes) -> None:
        try:
            self.sock.send(frame)
        except OSError:
            pass


class VSwitch:
    def __init__(
        self,
        sid: int,
        kr: KeyRing,
        table_path: Path,
        report_path: Path,
        ports: Dict[int, str],
        paths: int = 1,
        force_tag: int = -1,
    ):
        self.sid = sid
        self.kr = kr
        self.table_path = table_path
        self.report_path = report_path
        self.ports: Dict[int, Port] = {i: Port(i, n) for i, n in ports.items()}
        self.by_name = {p.name: p for p in self.ports.values()}
        self.paths = paths
        self.force_tag = force_tag
        self.entries: Dict[str, dict] = {}
        self._mtime = 0.0
        self._load_table()
        self._report_fp = open(report_path, "a", buffering=1)
        self.frames_in = 0
        self.frames_out = 0
        self.dropped = 0

    # ------------------------------------------------------------------
    def _load_table(self) -> None:
        try:
            st = self.table_path.stat()
        except OSError:
            self.entries = {}
            return
        if st.st_mtime == self._mtime:
            return
        self._mtime = st.st_mtime
        data = json.loads(self.table_path.read_text())
        self.entries = data.get("entries", {})

    def _lookup(self, dst_mac: str, tag: int):
        return self.entries.get(f"{dst_mac}|{tag}")

    # ------------------------------------------------------------------
    def _parse(self, frame: bytes):
        if len(frame) < 14:
            return None
        dst = _mac(frame[0:6])
        etype = struct.unpack("!H", frame[12:14])[0]
        if etype == SHIM_ETHERTYPE:
            if len(frame) < 14 + SHIM_LEN:
                return None
            shim = frame[14 : 14 + SHIM_LEN]
            nonce = int.from_bytes(shim[0:7], "big")
            acc = int.from_bytes(shim[7:15], "big")
            tag = shim[15]
            payload = frame[14 + SHIM_LEN :]
            return dst, True, nonce, acc, tag, payload
        if etype == 0x0800:
            return dst, False, 0, 0, 0, frame[14:]
        return None

    def _emit(self, port: Port, dst: bytes, src: bytes, payload: bytes, shim: bytes | None, strip: bool):
        if strip:
            frame = dst + src + struct.pack("!H", 0x0800) + payload
        else:
            frame = dst + src + struct.pack("!H", SHIM_ETHERTYPE) + shim + payload
        port.send(frame)
        self.frames_out += 1

    # ------------------------------------------------------------------
    def handle(self, frame: bytes, in_port: Port) -> None:
        parsed = self._parse(frame)
        if parsed is None:
            self.dropped += 1
            return
        dst_mac, shimmed, nonce, acc, tag, payload = parsed
        src_mac = _mac(frame[6:12])

        if not shimmed:
            # 入口交换机：按流哈希选路径（等价 ECMP），并对验证头初始化
            if self.force_tag >= 0:
                tag = self.force_tag
            else:
                d = blake2b(frame[6:12] + frame[0:6], digest_size=4).digest()
                tag = int.from_bytes(d, "big") % max(1, self.paths)
            entry0 = self._lookup(dst_mac, tag)
            if entry0 is None:
                self.dropped += 1
                return
            pos = entry0["pos"]
            out_idx = entry0["port"]
            nonce = int.from_bytes(os.urandom(7), "big")
            hop = self._hop(in_port.index, out_idx)
            acc = self._contrib(hop, _h(nonce)) % P
        else:
            entry = self._lookup(dst_mac, tag)
            if entry is None:
                self.dropped += 1
                return
            pos = entry["pos"]
            out_idx = entry["port"]
            hop = self._hop(in_port.index, out_idx)
            c = self._contrib(hop, _h(nonce))
            acc = (acc + c * pow(RHO, pos - 1, P)) % P

        out_port = self.ports.get(out_idx)
        if out_port is None:
            self.dropped += 1
            return

        strip = bool(entry.get("strip")) if shimmed else bool(entry0.get("strip"))
        shim = (
            nonce.to_bytes(7, "big") + acc.to_bytes(8, "big") + bytes([tag])
        )
        self._emit(
            out_port,
            frame[0:6],
            frame[6:12],
            payload,
            shim,
            strip,
        )
        if strip:
            self._report(tag, nonce, acc, pos, dst_mac)

    def _hop(self, in_idx: int, out_idx: int):
        from mpv.core.keys import Hop

        return Hop(sid=self.sid, in_port=in_idx, out_port=out_idx)

    def _contrib(self, hop, h: int) -> int:
        k = hop_key(self.kr, hop)
        return (k.a + k.b * h) % P

    def _report(self, tag: int, nonce: int, acc: int, pos: int, dst: str) -> None:
        rec = {
            "sid": self.sid,
            "dst": dst,
            "tag": tag,
            "nonce": nonce,
            "acc": acc,
            "pos": pos,
            "ts": time.time(),
        }
        self._report_fp.write(json.dumps(rec) + "\n")

    # ------------------------------------------------------------------
    def run(self) -> None:
        sel = selectors.DefaultSelector()
        for p in self.ports.values():
            sel.register(p.sock, selectors.EVENT_READ, p)
        last_reload = time.time()
        while True:
            for key, _ in sel.select(timeout=0.2):
                port: Port = key.data
                while True:
                    try:
                        frame, addr = port.sock.recvfrom(65535)
                    except BlockingIOError:
                        break
                    except OSError:
                        break
                    # 关键：AF_PACKET 同时能看到本端口发出的帧，必须过滤，否则自环
                    if addr[2] == socket.PACKET_OUTGOING:
                        continue
                    self.frames_in += 1
                    self.handle(frame, port)
            now = time.time()
            if now - last_reload > 0.3:
                self._load_table()
                last_reload = now
            if os.path.exists("/tmp/.mpv_stop"):
                break


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sid", type=int, required=True)
    ap.add_argument("--seed", type=int, required=True)
    ap.add_argument("--table", required=True)
    ap.add_argument("--report", required=True)
    ap.add_argument("--port", action="append", default=[], help="idx:name")
    ap.add_argument("--paths", type=int, default=1)
    ap.add_argument("--force-tag", type=int, default=-1)
    args = ap.parse_args()

    ports: Dict[int, str] = {}
    for spec in args.port:
        idx, name = spec.split(":", 1)
        ports[int(idx)] = name

    kr = KeyRing.generate(n_switches=16, ports_per_switch=4, seed=args.seed)
    sw = VSwitch(
        sid=args.sid,
        kr=kr,
        table_path=Path(args.table),
        report_path=Path(args.report),
        ports=ports,
        paths=args.paths,
        force_tag=args.force_tag,
    )
    try:
        sw.run()
    except KeyboardInterrupt:
        pass
    finally:
        print(
            f"[s{args.sid}] in={sw.frames_in} out={sw.frames_out} drop={sw.dropped}",
            file=sys.stderr,
            flush=True,
        )


if __name__ == "__main__":
    main()
