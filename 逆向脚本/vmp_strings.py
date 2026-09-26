# -*- coding: utf-8 -*-
import os
_BASE = os.environ.get("PE_BASE") or os.getcwd()
"""列出 .vmp0/.vmp1 中所有可读字符串 (揭示 VMP 保护的 API/DLL/路径)"""
import pefile, re

path = os.path.join(_BASE, "baicai", "setsys_unpack", ".rsrc", "2052", "RCDATA", "DEPLOY")
pe = pefile.PE(path, fast_load=False)
img = pe.OPTIONAL_HEADER.ImageBase

for s in pe.sections:
    nm = s.Name.rstrip(b'\x00').decode('latin1')
    if nm not in ('.vmp0', '.vmp1'):
        continue
    d = s.get_data()
    va = img + s.VirtualAddress
    strs = []
    for m in re.finditer(rb"[\x20-\x7e]{5,}", d):
        t = m.group().decode('ascii', 'replace')
        if t.startswith(("HH", "hH")):  # 跳过 VMP 随机标记
            continue
        strs.append((m.start(), t))
    print("== %s: %d 个字符串 ==" % (nm, len(strs)))
    # 只打印看起来像 API/DLL/路径/URL 的
    interesting = []
    for off, t in strs:
        low = t.lower()
        if any(k in low for k in [".dll", "!getprocaddress", "controlservice", "deleteservice", "regset", "regopen",
                                  "regcreate", "regdelete", "startservice", "createservice", "changeservice",
                                  "queryservice", "enum", "scmanager", "winhttp", "http", "urlmon", "loadlibrary",
                                  "getprocaddress", "virtua", "write", "readprocess", "createthread", "shellexecute",
                                  "cmd", "\\", "exec", "delet", "file"]):
            interesting.append((off, t))
    for off, t in interesting[:80]:
        print("  0x%X: %r" % (va + off, t))
    if len(interesting) > 80:
        print("  ... 共 %d 个" % len(interesting))
