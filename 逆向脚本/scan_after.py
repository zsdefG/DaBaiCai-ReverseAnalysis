# -*- coding: utf-8 -*-
"""在 AFTER (NSIS) 中搜索 Defender/关闭安全软件相关字符串"""
import re

path = r"D:\文档\workbuddy\Safe\my\baicai\setsys_unpack\.rsrc\2052\RCDATA\AFTER"
data = open(path, "rb").read()

# NSIS 脚本中的 Unicode/ASCII 字符串
pats = [
    b"Defender", b"WinDefend", b"DisableAntiSpyware", b"DisableAntiVirus",
    b"MpPreference", b"Set-MpPreference", b"mpssvc", b"Windows Defender",
    b"sc.exe", b"net stop", b"net start", b"reg add", b"reg delete",
    b"powershell", b"cmd.exe", b"/c ", b"taskkill", b"360", b"huorong",
    b"QQPCMgr", b"killer", b"kill", b"StopService", b"Set-DefenderPreference",
    b"DisableRealtimeMonitoring", b"Remove-MpPreference", b"AttackSurfaceReduction",
    b"Sample file", b"samples", b"disable", b"del ", b"delete",
]
print("搜索 AFTER 中的关键字符串:")
for p in pats:
    offs = []
    start = 0
    while True:
        i = data.find(p, start)
        if i == -1: break
        offs.append(i)
        start = i + 1
    if offs:
        print("  %-28s -> %d 处: %s" % (p.decode(), len(offs), ", ".join("0x%X" % o for o in offs[:12])))

# 提取所有 ASCII 可打印字符串供人工审查
print("\nAFTER 中的 ASCII 字符串 (>=6 字符):")
strs = re.findall(rb"[\x20-\x7e]{6,}", data)
seen = set()
for s in strs:
    d = s.decode('ascii', 'replace')
    if d not in seen and any(k in d.lower() for k in ["defend", "secur", "firewall", "360", "uac", "reg", "service", "kill", "del", "soft", "install", "run", "exec", "cmd", "script"]):
        seen.add(d)
        print("  %r" % d)
