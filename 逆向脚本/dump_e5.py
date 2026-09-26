# -*- coding: utf-8 -*-
import os
_BASE = os.environ.get("PE_BASE") or os.getcwd()
"""反汇编 0x1000E500-0x1000E9D0, 重点看 0x1000E617 调用点所在函数的完整逻辑"""
import pefile, re
from capstone import *

path = os.path.join(_BASE, "baicai", "setsys_unpack", ".rsrc", "2052", "RCDATA", "DEPLOY")
pe = pefile.PE(path, fast_load=False)
img = pe.OPTIONAL_HEADER.ImageBase
data = open(path, "rb").read()

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

lo, hi = 0x1000E500, 0x1000E9D0
for i in md.disasm(text_data[lo-text_va:hi-text_va], lo):
    m = re.search(r"0x[0-9a-fA-F]+", i.op_str)
    annot = ""
    if m:
        v = int(m.group(0), 16)
        if v in import_map:
            annot = "  ; -> %s" % import_map[v]
        else:
            s = read_cstr(v)
            if s and s.isprintable() and 4 <= len(s) <= 60:
                annot = "  ; \"%s\"" % s
    print("  0x%08X: %-26s %s%s" % (i.address, i.mnemonic, i.op_str, annot))
