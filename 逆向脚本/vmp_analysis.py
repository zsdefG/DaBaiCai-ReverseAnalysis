# -*- coding: utf-8 -*-
import os
_BASE = os.environ.get("PE_BASE") or os.getcwd()
"""1) 检查 .vmp1/.vmp0 中是否有指向 .text 的指针数组(虚拟 vftable) 2) dump .text->.vmp 调用点上下文"""
import pefile, re, struct
from capstone import *

path = os.path.join(_BASE, "baicai", "setsys_unpack", ".rsrc", "2052", "RCDATA", "DEPLOY")
pe = pefile.PE(path, fast_load=False)
img = pe.OPTIONAL_HEADER.ImageBase

text_va = text_data = None
vmp0_va = vmp0_data = None
vmp1_va = vmp1_data = None
secs = {}
for s in pe.sections:
    nm = s.Name.rstrip(b'\x00').decode('latin1')
    va = img + s.VirtualAddress
    secs[nm] = (va, s.get_data())
    if nm == '.text':
        text_va, text_data = va, s.get_data()
    if nm == '.vmp0':
        vmp0_va, vmp0_data = va, s.get_data()
    if nm == '.vmp1':
        vmp1_va, vmp1_data = va, s.get_data()

def which_sec(va):
    for nm, (lo, d) in secs.items():
        if lo <= va < lo + len(d):
            return nm
    return "OUT"

# 1. 在 .vmp0/.vmp1 中找指向 .text 的 4 字节指针 (虚拟 vftable 候选)
print("== .vmp0/.vmp1 中指向 .text 的指针 ==")
for nm in (".vmp0", ".vmp1"):
    va, d = secs[nm]
    count = 0
    for off in range(0, len(d) - 3, 4):
        v = struct.unpack("<I", d[off:off+4])[0]
        if text_va <= v < text_va + len(text_data):
            if count < 12:
                print("  %s+0x%X = 0x%08X (-> .text)" % (nm, off, v))
            count += 1
    print("  %s: %d 个指向 .text 的指针" % (nm, count))

# 2. dump .text->.vmp 调用点上下文
print("\n== .text -> .vmp0 调用点上下文 ==")
md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = True
calls = []
for i in md.disasm(text_data, text_va):
    if i.mnemonic == "call" and i.operands[0].type == 2 and which_sec(i.operands[0].imm) == ".vmp0":
        calls.append((i.address, i.operands[0].imm))

# 按调用点地址排序，看分组
calls.sort()
print("调用点地址: ", " ".join("0x%X" % a for a, t in calls[:65]))

# 反汇编后找函数边界难; 改为对每个调用点 dump 前 25 条指令
for call_addr, target in calls[:10]:
    print("\n--- call @ 0x%08X -> 0x%08X ---" % (call_addr, target))
    # 找到包含该地址的函数起点: 回溯找 push ebp / 连续 ret
    # 简单: dump call 前 30 条
    ins_list = list(md.disasm(text_data, text_va))
    # 找指令索引
    idx = next((k for k, i in enumerate(ins_list) if i.address == call_addr), None)
    if idx is None:
        continue
    for i in ins_list[max(0, idx-25):idx+1]:
        print("  0x%08X %s %s" % (i.address, i.mnemonic, i.op_str))
