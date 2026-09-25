# -*- coding: utf-8 -*-
"""1) dump 0x1000E62E-0x1000E6C0 (函数尾部) 2) 找调用 0x1000E570 的位置并 dump 参数"""
import pefile, re
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

def read_cstr(va, maxlen=128):
    off = None
    for s in pe.sections:
        if s.VirtualAddress <= va - img < s.VirtualAddress + max(s.SizeOfRawData, s.Misc_VirtualSize):
            off = s.PointerToRawData + (va - img - s.VirtualAddress)
            break
    if off is None: return None
    end = data.find(b"\x00", off, off + maxlen)
    return data[off:end].decode('latin1', 'replace')

md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = True
ins_list = list(md.disasm(text_data, text_va))

print("== 0x1000E570 函数尾部 (0x1000E62E-0x1000E6D0) ==")
for i in md.disasm(text_data[0x1000E62E-text_va:0x1000E6D0-text_va], 0x1000E62E):
    print("  0x%08X: %-26s %s" % (i.address, i.mnemonic, i.op_str))

print("\n== 调用 0x1000E570 的位置 ==")
for i in ins_list:
    if i.mnemonic == "call" and i.operands[0].type == 2 and i.operands[0].imm == 0x1000E570:
        idx = next((k for k, j in enumerate(ins_list) if j.address == i.address), None)
        print("--- call @ 0x%08X, 前 14 条 ---" % i.address)
        for j in ins_list[max(0, idx-14):idx+1]:
            m = re.search(r"0x[0-9a-fA-F]+", j.op_str)
            annot = ""
            if m:
                v = int(m.group(0), 16)
                s = read_cstr(v)
                if s and s.isprintable() and 2 <= len(s) <= 80:
                    annot = '  ; "%s"' % s
            print("   0x%08X: %-26s %s%s" % (j.address, j.mnemonic, j.op_str, annot))
