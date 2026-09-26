# -*- coding: utf-8 -*-
import os
_BASE = os.environ.get("PE_BASE") or os.getcwd()
"""1) dump 关键字符串内容 2) 反汇编 0x10015970 和 0x100082B0 的实现"""
import pefile, re
from capstone import *

path = os.path.join(_BASE, "baicai", "setsys_unpack", ".rsrc", "2052", "RCDATA", "DEPLOY")
pe = pefile.PE(path, fast_load=False)
img = pe.OPTIONAL_HEADER.ImageBase
data = open(path, "rb").read()

def read_cstr(va, maxlen=128):
    off = None
    for s in pe.sections:
        if s.VirtualAddress <= va - img < s.VirtualAddress + max(s.SizeOfRawData, s.Misc_VirtualSize):
            off = s.PointerToRawData + (va - img - s.VirtualAddress)
            break
    if off is None: return None
    end = data.find(b"\x00", off, off + maxlen)
    return data[off:end].decode('latin1', 'replace')

print("== 关键字符串 ==")
for va, nm in [(0x1006750C,"path?0"),(0x10067510,"Policies\\System"),(0x10067544,"ConsentPromptBehaviorAdmin"),
               (0x10067560,"EnableLUA"),(0x1006756C,"?3"),(0x10067588,"fwpath1"),(0x100675E8,"fwpath2"),
               (0x1006763C,"data0"),(0x10067334,"data1")]:
    s = read_cstr(va)
    print("  0x%08X %-24s = %r" % (va, nm, s))

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
def dump_func(addr, label, max_instr=120):
    print("\n== %s @ 0x%08X ==" % (label, addr))
    # 找函数起点: 从 addr 往回找 push ebp 或 int3 前的边界
    ins_list = list(md.disasm(text_data, text_va))
    idx = next((k for k,i in enumerate(ins_list) if i.address == addr), None)
    if idx is None:
        print("  (无法定位)"); return
    start = addr
    # 反汇编直到 ret
    count = 0
    for i in ins_list[idx:]:
        m = re.search(r"0x[0-9a-fA-F]+", i.op_str)
        annot = ""
        if m:
            v = int(m.group(0), 16)
            if v in import_map: annot = "  ; -> %s" % import_map[v]
        print("  0x%08X: %-26s %s%s" % (i.address, i.mnemonic, i.op_str, annot))
        count += 1
        if count > max_instr: 
            print("  ...(截断)"); break
        if i.mnemonic == "ret" and count > 5:
            break

dump_func(0x10015970, "RegSetValueExW 包装?")
