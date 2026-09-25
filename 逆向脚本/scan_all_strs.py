# -*- coding: utf-8 -*-
"""全面扫描 DEPLOY 所有段中的字符串 + 分析 0x100159F0"""
import pefile, re
from capstone import *

path = r"D:\文档\workbuddy\Safe\my\baicai\setsys_unpack\.rsrc\2052\RCDATA\DEPLOY"
pe = pefile.PE(path, fast_load=False)
img = pe.OPTIONAL_HEADER.ImageBase
data = open(path, "rb").read()

print("== DEPLOY 全段字符串扫描 (敏感词) ==")
sensitive = [b"defen", b"win", b"wsc", b"secur", b"360", b"huorong", b"qqpc", b"soft", b"kill", b"stop",
             b"serv", b"reg ", b"set", b"uac", b"fire", b"policy", b"auto", b"start", b"type", b"image",
             b"sysprep", b"driv", b"pack", b"install", b"unin", b"pesafe"]
sections = {}
for s in pe.sections:
    nm = s.Name.rstrip(b'\x00').decode('latin1')
    sections[nm] = (img + s.VirtualAddress, s.get_data())

for nm, (va, d) in sections.items():
    if nm in ('.text', '.vmp0', '.vmp1', '.data', '.rdata'):
        found = []
        for m in re.finditer(rb"[\x20-\x7e]{4,}", d):
            t = m.group()
            low = t.lower()
            if any(k in low for k in [b"defen", b"wscsvc", b"win", b"mpssvc", b"sc.exe", b"powershell", b"DisableAntiSpyware"]):
                found.append((va + m.start(), t))
        for a, t in found[:25]:
            print("  %s+0x%X: %r" % (nm, a - va, t))

# 分析 0x100159F0
for s in pe.sections:
    if s.Name.rstrip(b'\x00') == b'.text':
        text_va = img + s.VirtualAddress
        text_data = s.get_data()
        break

import_map = {}
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    for imp in entry.imports:
        if imp.name:
            import_map[imp.address] = imp.name.decode()

md = Cs(CS_ARCH_X86, CS_MODE_32)
ins_list = list(md.disasm(text_data, text_va))
idx = next((k for k, i in enumerate(ins_list) if i.address == 0x100159F0), None)
print("\n== 0x100159F0 ==")
if idx:
    for i in ins_list[idx:idx+80]:
        m = re.search(r"0x[0-9a-fA-F]+", i.op_str)
        annot = ""
        if m:
            v = int(m.group(0), 16)
            if v in import_map: annot = "  ; -> %s" % import_map[v]
        print("  0x%08X: %-26s %s%s" % (i.address, i.mnemonic, i.op_str, annot))
        if i.mnemonic == "ret" and i.address > 0x100159F0:
            break
