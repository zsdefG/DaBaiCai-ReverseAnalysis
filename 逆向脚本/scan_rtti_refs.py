# -*- coding: utf-8 -*-
"""在 .text 中搜索引用 CDelSecuritySoft RTTI 相关地址的指令"""
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

# 目标地址
targets = {
    0x1007436C: "RTTI_CDelSecuritySoft(str)",
    0x100742EC: "RTTI_CDelSecuritySoft_Nop(str)",
    0x10074364: "TD_CDelSecuritySoft",
    0x100742E4: "TD_CDelSecuritySoft_Nop",
    0x1006A7FC: "COL_CDelSecuritySoft",
    0x1006A78C: "COL_Nop#1",
    0x1006A898: "COL_Nop#2",
    0x1005F62C: "type_info vftable",
}

print("扫描 .text 中引用 RTTI 区域的指令:")
hits = []
for i in md.disasm(text_data, text_va):
    if i.mnemonic in ("mov", "lea", "push") :
        for op in i.operands:
            if op.type in (2, 3):  # IMM / MEM
                # 提取立即数
                if op.type == 2:
                    val = op.imm
                else:
                    m = re.search(r"0x[0-9a-fA-F]+", i.op_str)
                    val = int(m.group(0), 16) if m else None
                if val is None:
                    continue
                for tva, tname in targets.items():
                    if tva - 0x40 <= val <= tva + 0x40:
                        hits.append((i.address, i.mnemonic, i.op_str, tname, val))
                        break

for a, mn, ops, tn, val in sorted(hits):
    print("  0x%08X %s %-30s -> %s (val=0x%X)" % (a, mn, ops, tn, val))
print("共 %d 处" % len(hits))
