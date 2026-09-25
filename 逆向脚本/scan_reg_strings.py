# -*- coding: utf-8 -*-
"""扫描 .text 中引用 EnableFirewall/EnableLUA/ConsentPrompt 字符串区域的指令 + dump 上下文"""
import pefile, re
from capstone import *

path = r"D:\文档\workbuddy\Safe\my\baicai\setsys_unpack\.rsrc\2052\RCDATA\DEPLOY"
pe = pefile.PE(path, fast_load=False)
img = pe.OPTIONAL_HEADER.ImageBase

for s in pe.sections:
    if s.Name.rstrip(b'\x00') == b'.text':
        text_va = img + s.VirtualAddress
        text_data = s.get_data()
        break

md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = True

targets = {
    0x100675D8: "EnableFirewall",
    0x10067560: "EnableLUA",
    0x10067544: "ConsentPromptBehaviorAdmin",
    0x10067564: "FirewallPolicy(SharedAccess)",
}
# 也包含路径字符串: \Microsoft\Windows\CurrentVersion\Policies\System
path_str = br"\Microsoft\Windows\CurrentVersion\Policies\System"
d_all = open(path, "rb").read()
idx = 0
while True:
    i = d_all.find(path_str, idx)
    if i == -1: break
    # 转 VA
    for s2 in pe.sections:
        if s2.PointerToRawData <= i < s2.PointerToRawData + max(s2.SizeOfRawData, s2.Misc_VirtualSize):
            va = img + s2.VirtualAddress + (i - s2.PointerToRawData)
            targets.setdefault(va, "Policies\\System path")
            break
    idx = i + 1

print("目标字符串 VA:")
for va, nm in sorted(targets.items()):
    print("  0x%08X %s" % (va, nm))

print("\n.text 引用:")
hits = []
for i in md.disasm(text_data, text_va):
    if i.mnemonic in ("mov", "lea", "push"):
        for op in i.operands:
            if op.type in (2, 3):
                if op.type == 2:
                    val = op.imm
                else:
                    m = re.search(r"0x[0-9a-fA-F]+", i.op_str)
                    val = int(m.group(0), 16) if m else None
                if val is None: continue
                for tva, tname in targets.items():
                    if tva - 0x10 <= val <= tva + 0x10:
                        hits.append((i.address, i.mnemonic, i.op_str, tname, val))
                        break

for a, mn, ops, tn, val in sorted(hits):
    print("  0x%08X %s %-40s -> %s" % (a, mn, ops, tn))
print("共 %d 处" % len(hits))
