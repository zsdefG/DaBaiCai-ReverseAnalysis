# -*- coding: utf-8 -*-
"""1) 找 0x10007E80 的调用者 2) dump ClassDescriptor 0x1006A874 3) 找引用 CDelSecuritySoft vftable/类的构造函数"""
import pefile, re, struct
from capstone import *

path = r"D:\文档\workbuddy\Safe\my\baicai\setsys_unpack\.rsrc\2052\RCDATA\DEPLOY"
pe = pefile.PE(path, fast_load=False)
img = pe.OPTIONAL_HEADER.ImageBase
data = open(path, "rb").read()

for s in pe.sections:
    if s.Name.rstrip(b'\x00') == b'.text':
        text_va = img + s.VirtualAddress
        text_data = s.get_data()
        break

md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = True

# 1. 找所有 call 0x10007E80
print("== 调用 0x10007E80 的位置 ==")
callers = []
for i in md.disasm(text_data, text_va):
    if i.mnemonic == "call" and i.operands[0].type == 2 and i.operands[0].imm == 0x10007E80:
        callers.append(i.address)
        print("  0x%08X call 0x10007E80" % i.address)

# 2. dump 0x1006A874 ClassDescriptor
def rva_to_off(rva):
    for s in pe.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + max(s.SizeOfRawData, s.Misc_VirtualSize):
            return s.PointerToRawData + (rva - s.VirtualAddress)
    return None

def read_dwords(va, n):
    off = rva_to_off(va - img)
    if off is None: return None
    return [struct.unpack("<I", data[off+i*4:off+i*4+4])[0] for i in range(n)]

print("\n== ClassDescriptor 0x1006A874 (CDelSecuritySoft) ==")
cd = read_dwords(0x1006A874, 6)
print("  值:", ["0x%08X" % v for v in cd])
if cd:
    # 32位 ClassDescriptor: [pClassDescriptorOfMostBaseClass][pContainingClassHierarchy][pContainingClassVMShape][pVBaseClassArray][attributes][pBaseClassArray?]
    pass

# 3. 在 .text 中找引用 0x1006A7FC (COL Del) 或 0x1006A874 (ClassDesc) 的指令
print("\n== .text 引用 CDelSecuritySoft COL/ClassDesc ==")
for i in md.disasm(text_data, text_va):
    if i.mnemonic in ("mov", "lea", "push"):
        for op in i.operands:
            if op.type in (2, 3):
                val = op.imm if op.type == 2 else int(re.search(r"0x[0-9a-fA-F]+", i.op_str).group(0), 16) if re.search(r"0x[0-9a-fA-F]+", i.op_str) else None
                if val in (0x1006A7FC, 0x1006A874, 0x1006A78C, 0x1006A898, 0x10074364, 0x100742E4):
                    print("  0x%08X %s %s -> 0x%X" % (i.address, i.mnemonic, i.op_str, val))

# 4. dump 0x10007570 的调用者（设置 vftable 0x1006750C 的构造函数）
print("\n== 调用 0x10007570 (CWinRegKey 构造) 的位置 ==")
for i in md.disasm(text_data, text_va):
    if i.mnemonic == "call" and i.operands[0].type == 2 and i.operands[0].imm == 0x10007570:
        print("  0x%08X call 0x10007570" % i.address)
