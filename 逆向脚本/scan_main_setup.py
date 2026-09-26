# -*- coding: utf-8 -*-
import os
_BASE = os.environ.get("PE_BASE") or os.getcwd()
"""在主安装器和 SetSys.exe 中搜索 Defender 关闭相关字符串"""
import re

files = {
    "主安装器 DaBaiCai_d30": os.path.join(_BASE, "baicai", "某白菜PE装机工具+取证工具留档", "DaBaiCai_d30_v6.0_2606_Online.exe"),
    "SetSys.exe": os.path.join(_BASE, "baicai", "submit_samples", "SetSys.exe"),
}
pats = [
    b"WinDefend", b"Defender", b"DisableAntiSpyware", b"DisableAntiVirus", b"DisableRealtimeMonitoring",
    b"MpPreference", b"Set-MpPreference", b"mpssvc", b"WindowsSecurityCenter", b"wscsvc",
    b"SecurityHealthService", b"sc.exe", b"powershell", b"reg.exe", b"net.exe",
    b"DisableAntiSpyware\\", b"Set-ItemProperty", b"New-ItemProperty",
    b"ControlService", b"DeleteService", b"ChangeServiceConfig", b"StartService",
    b"qccutil", b"CDelSecuritySoft", b"DelSecuritySoft",
]
for fname, fpath in files.items():
    data = open(fpath, "rb").read()
    print("=" * 60)
    print("== %s (%d KB) ==" % (fname, len(data) // 1024))
    for p in pats:
        n = data.count(p)
        if n:
            offs = []
            st = 0
            while len(offs) < 5:
                i = data.find(p, st)
                if i == -1: break
                offs.append(i); st = i + 1
            print("  %-26s x%d  @ %s" % (p.decode(), n, ", ".join("0x%X" % o for o in offs)))
    # Windows Defender 的变体（大写/小写混合）
    for m in re.finditer(rb"(?i)defender", data):
        ctx = data[max(0, m.start()-20):m.start()+30]
        print("  [ctx] ...%r..." % ctx)
