# -*- coding: utf-8 -*-
import os
_BASE = os.environ.get("PE_BASE") or os.getcwd()
"""完整反汇编 0x10007500-0x10007600 (路径构造) 和 0x10007E00-0x10008200 (注册表写入)"""
import pefile
from capstone import *

path = os.path.join(_BASE, "baicai", "setsys_unpack", ".rsrc", "2052", "RCDATA", "DEPLOY")
pe = pefile.PE(path, fast_load=False)
img = pe.OPTIONAL_HEADER.ImageBase

for s in pe.sections:
    if s.Name.rstrip(b'\x00') == b'.text':
        text_va = img + s.VirtualAddress
        text_data = s.get_data()
        break

# IAT 表
import_map = {}
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    dll = entry.dll.decode()
    for imp in entry.imports:
        if imp.name:
            import_map[imp.address] = imp.name.decode()

# 字符串表（从文件搜索）
def va_of_str(b, sec=None):
    off = 0
    while True:
        i = data.find(b, off)
        if i == -1: return None
        for s in pe.sections:
            if s.PointerToRawData <= i < s.PointerToRawData + max(s.SizeOfRawData, s.Misc_VirtualSize):
                return img + s.VirtualAddress + (i - s.PointerToRawData)
        off = i + 1
data = open(path, "rb").read()
str_map = {}
for name, pat in [("Policies\\System", r"\Microsoft\Windows\CurrentVersion\Policies\System"),
                  ("ConsentPromptBehaviorAdmin", "ConsentPromptBehaviorAdmin"),
                  ("EnableLUA", "EnableLUA"),
                  ("EnableFirewall", "EnableFirewall"),
                  ("PublicProfile", "PublicProfile"),
                  ("StandardProfile", "StandardProfile"),
                  ("SharedAccess", "SharedAccess"),
                  ("FirewallPolicy", "FirewallPolicy")]:
    va = va_of_str(pat.encode())
    if va: str_map[va] = name

md = Cs(CS_ARCH_X86, CS_MODE_32)

def dump_range(lo, hi, label):
    print("\n" + "=" * 70)
    print("== %s  (0x%X - 0x%X) ==" % (label, lo, hi))
    for i in md.disasm(text_data[lo-text_va:hi-text_va], lo):
        # 解析操作数中的地址
        ops = i.op_str
        import re
        m = re.search(r"0x[0-9a-fA-F]+", ops)
        annot = ""
        if m:
            v = int(m.group(0), 16)
            if v in import_map:
                annot = "  ; -> %s" % import_map[v]
            elif v in str_map:
                annot = "  ; \"%s\"" % str_map[v]
            elif 0x10067000 <= v <= 0x10068000:
                annot = "  ; (data)"
        print("  0x%08X: %-28s %s%s" % (i.address, i.mnemonic, i.op_str, annot))

dump_range(0x10007500, 0x10007620, "Policies\\System 路径构造")
dump_range(0x10007E00, 0x10008200, "注册表写入 (UAC/防火墙)")
