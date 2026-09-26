# -*- coding: utf-8 -*-
import os
_BASE = os.environ.get("PE_BASE") or os.getcwd()
"""统计 .text 中 call 指令的目标分布 + 完整列出调用 0x102xxxxx 范围(导入/动态)的调用点"""
import pefile, re
from capstone import *

path = os.path.join(_BASE, "baicai", "setsys_unpack", ".rsrc", "2052", "RCDATA", "DEPLOY")
pe = pefile.PE(path, fast_load=False)
img = pe.OPTIONAL_HEADER.ImageBase

import_map = {}
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    dll = entry.dll.decode()
    for imp in entry.imports:
        if imp.name:
            import_map[imp.address] = "%s!%s" % (dll, imp.name.decode())

for s in pe.sections:
    if s.Name.rstrip(b'\x00') == b'.text':
        text_va = img + s.VirtualAddress
        text_data = s.get_data()
        break

md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = True

# section 范围
secs = []
for s in pe.sections:
    nm = s.Name.rstrip(b'\x00').decode('latin1')
    secs.append((nm, img + s.VirtualAddress, img + s.VirtualAddress + max(s.SizeOfRawData, s.Misc_VirtualSize)))

def which_sec(va):
    for nm, lo, hi in secs:
        if lo <= va < hi:
            return nm
    return "OUT"

call_targets = {}
direct_calls_to_iat = []
for i in md.disasm(text_data, text_va):
    if i.mnemonic == "call":
        t = i.operands[0]
        if t.type == 2:  # IMM
            target = t.imm
            key = which_sec(target)
            call_targets[key] = call_targets.get(key, 0) + 1
            if target in import_map:
                direct_calls_to_iat.append((i.address, import_map[target]))
        elif t.type == 3:  # MEM (call dword ptr [...])
            # 提取地址
            m = re.search(r"0x[0-9a-fA-F]+", i.op_str)
            if m:
                addr = int(m.group(0), 16)
                if addr in import_map:
                    direct_calls_to_iat.append((i.address, "MEM:" + import_map[addr]))

print("call 目标按段分布 (直接 imm call):")
for k, v in sorted(call_targets.items(), key=lambda x: -x[1]):
    print("  %-8s %d" % (k, v))

print("\n直接调用导入 API 的点 (%d):" % len(direct_calls_to_iat))
for a, n in sorted(direct_calls_to_iat):
    print("  0x%08X call %s" % (a, n))

# 列出 .text 中调用 .vmp0/.vmp1 的点（样本）
vmp_calls = []
for i in md.disasm(text_data, text_va):
    if i.mnemonic == "call" and i.operands[0].type == 2:
        t = i.operands[0].imm
        if which_sec(t) in (".vmp0", ".vmp1"):
            vmp_calls.append((i.address, t))
print("\n.text -> .vmp 段调用点数量: %d" % len(vmp_calls))
for a, t in vmp_calls[:30]:
    print("  0x%08X call 0x%08X (%s)" % (a, t, which_sec(t)))
