# -*- coding: utf-8 -*-
import os
_BASE = os.environ.get("PE_BASE") or os.getcwd()
"""定位 DEPLOY 中 RTTI/Defender 相关字符串的文件偏移与 VA"""
import pefile, sys

path = os.path.join(_BASE, "baicai", "setsys_unpack", ".rsrc", "2052", "RCDATA", "DEPLOY")
pe = pefile.PE(path, fast_load=False)
image_base = pe.OPTIONAL_HEADER.ImageBase

def rva_to_va(rva):
    return image_base + rva

def file_off_to_rva(off):
    for s in pe.sections:
        if s.PointerToRawData <= off < s.PointerToRawData + max(s.SizeOfRawData, s.Misc_VirtualSize):
            return s.VirtualAddress + (off - s.PointerToRawData)
    return None

data = open(path, "rb").read()
targets = [
    b".?AVIDelSecuritySoft@@",
    b".?AVCDelSecuritySoft_Nop@@",
    b"DisableAntiSpyware",
    b"DisableAntiVirus",
    b"DisableRealtimeMonitoring",
    b"WinDefend",
    b"mpssvc",
    b"MpPreference",
    b"Set-MpPreference",
    b"EnableFirewall",
    b"EnableLUA",
    b"ConsentPromptBehaviorAdmin",
    b"DisableDefender",
    b"Defender",
    b"SecurityCenter",
    b"wscsvc",
]

print("ImageBase: 0x%X" % image_base)
for t in targets:
    hits = []
    start = 0
    while True:
        i = data.find(t, start)
        if i == -1:
            break
        rva = file_off_to_rva(i)
        va = rva_to_va(rva) if rva is not None else None
        hits.append((i, va))
        start = i + 1
    if hits:
        for off, va in hits[:8]:
            va_s = ("0x%X" % va) if va else "?"
            print("%-28s fileoff=0x%-7X va=%s" % (t.decode('ascii', 'replace'), off, va_s))
    else:
        print("%-28s NOT FOUND" % t.decode('ascii', 'replace'))

# 打印 section 布局，用于手动换算
print("\nSections:")
for s in pe.sections:
    name = s.Name.rstrip(b'\x00').decode('latin1')
    print("  %-8s VA=0x%-8X RAW=0x%-8X size=0x%X" % (name, s.VirtualAddress, s.PointerToRawData, max(s.SizeOfRawData, s.Misc_VirtualSize)))
