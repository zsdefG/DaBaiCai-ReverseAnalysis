# -*- coding: utf-8 -*-
import os
_BASE = os.environ.get("PE_BASE") or os.getcwd()
"""dump 0x10006C00-0x10006F20, 确认驱动服务注册逻辑"""
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

def va_to_off(va):
    for s in pe.sections:
        if s.VirtualAddress <= va - img < s.VirtualAddress + max(s.SizeOfRawData, s.Misc_VirtualSize):
            return s.PointerToRawData + (va - img - s.VirtualAddress)
    return None

def read_str(va):
    off = va_to_off(va)
    if off is None: return None
    end = data.find(b"\x00", off, off + 64)
    return data[off:end].decode('latin1', 'replace')

import_map = {}
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    for imp in entry.imports:
        if imp.name:
            import_map[imp.address] = imp.name.decode()

md = Cs(CS_ARCH_X86, CS_MODE_32)
lo, hi = 0x10006C00, 0x10006F20
for i in md.disasm(text_data[lo-text_va:hi-text_va], lo):
    m = re.search(r"0x[0-9a-fA-F]+", i.op_str)
    annot = ""
    if m:
        v = int(m.group(0), 16)
        if v in import_map:
            annot = "  ; -> %s" % import_map[v]
        else:
            s = read_str(v)
            if s and s.isprintable() and 2 <= len(s) <= 60:
                annot = '  ; "%s"' % s
    print("  0x%08X: %-26s %s%s" % (i.address, i.mnemonic, i.op_str, annot))
