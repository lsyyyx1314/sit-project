"""SIT —— 面向 SDN 的高效多路径验证研究 原型代码（包名 mpv）。

包结构：
    mpv.core    验证算法内核（不依赖真实网络）
    mpv.ctrl    控制器应用（os-ken / Ryu）
    mpv.dp      数据平面验证代理
"""

__version__ = "0.1.0"
