# -*- coding: utf-8 -*-
import os
_BASE = os.environ.get("PE_BASE") or os.getcwd()
"""反汇编 0x10007F00-0x10008180 (注册表写入核心区) 和 0x10001500-0x10001600 附近"""
import pefile, re
from capstone import *

path = os.path.join(_BASE, "baicai", "setsys_unpack", ".rsrc", "2052", "RCDATA", "DEPLOY")
pe = pefile.PE(path, fast_load=False)
img = pe.OPTIONAL_HEADER.ImageBase

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

data = open(path, "rb").read()
def va_of_str(b):
    off = 0
    while True:
        i = data.find(b, off)
        if i == -1: return None
        for s in pe.sections:
            if s.PointerToRawData <= i < s.PointerToRawData + max(s.SizeOfRawData, s.Misc_VirtualSize):
                return img + s.VirtualAddress + (i - s.PointerToRawData)
        off = i + 1
str_map = {}
for name, pat in [("Policies\\System", r"\Microsoft\Windows\CurrentVersion\Policies\System"),
                  ("ConsentPromptBehaviorAdmin", "ConsentPromptBehaviorAdmin"),
                  ("EnableLUA", "EnableLUA"),
                  ("EnableFirewall", "EnableFirewall"),
                  ("FirewallPolicy", "FirewallPolicy"),
                  ("SharedAccess", "SharedAccess"),
                  ("ControlSet001", "ControlSet001"),
                  ("Services", "Services"),
                  ("SharedAccess\\Parameters", "SharedAccess\\Parameters")]:
    va = va_of_str(pat.encode())
    if va: str_map[va] = name

md = Cs(CS_ARCH_X86, CS_MODE_32)

def dump_range(lo, hi, label):
    print("\n" + "=" * 70)
    print("== %s ==" % label)
    for i in md.disasm(text_data[lo-text_va:hi-text_va], lo):
        m = re.search(r"0x[0-9a-fA-F]+", i.op_str)
        annot = ""
        if m:
            v = int(m.group(0), 16)
            if v in import_map: annot = "  ; -> %s" % import_map[v]
            elif v in str_map: annot = "  ; \"%s\"" % str_map[v]
        print("  0x%08X: %-26s %s%s" % (i.address, i.mnemonic, i.op_str, annot))

dump_range(0x10007E80, 0x10008180, "注册表写入核心区 0x10007E80")
