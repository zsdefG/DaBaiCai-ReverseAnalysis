# -*- coding: utf-8 -*-
import os
_BASE = os.environ.get("PE_BASE") or os.getcwd()
"""在 DEPLOY 中定位 TypeDescriptor -> COL -> vftable (32位 RTTI)"""
import struct, pefile

path = os.path.join(_BASE, "baicai", "setsys_unpack", ".rsrc", "2052", "RCDATA", "DEPLOY")
pe = pefile.PE(path)
img = pe.OPTIONAL_HEADER.ImageBase

def rva_to_off(rva):
    for s in pe.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + max(s.SizeOfRawData, s.Misc_VirtualSize):
            return s.PointerToRawData + (rva - s.VirtualAddress)
    return None

def off_to_rva(off):
    for s in pe.sections:
        if s.PointerToRawData <= off < s.PointerToRawData + max(s.SizeOfRawData, s.Misc_VirtualSize):
            return s.VirtualAddress + (off - s.PointerToRawData)
    return None

def va_to_off(va):
    return rva_to_off(va - img)

data = open(path, "rb").read()

# TypeDescriptor 地址
tds = {
    "CDelSecuritySoft":    0x10074364,  # 0x1007436C - 0x8
    "CDelSecuritySoft_Nop": 0x100742E4,  # 0x100742EC - 0x8
}
td_bytes = {k: struct.pack("<I", v) for k, v in tds.items()}

print("搜索指向 TypeDescriptor 的指针 (COL 内的 pTypeDescriptor 字段):")
for cls, b in td_bytes.items():
    offs = []
    start = 0
    while True:
        i = data.find(b, start)
        if i == -1: break
        rva = off_to_rva(i)
        va = img + rva if rva else 0
        offs.append((i, va))
        start = i + 1
    print("  %-22s -> %d hits" % (cls, len(offs)))
    for off, va in offs[:20]:
        print("      fileoff=0x%X va=0x%X" % (off, va))

# 对每个可能的 COL，回溯找 vftable: vftable 的第一个槽指向 COL
# COL 通常紧跟在 vftable 后面（4字节对齐）。vftable = COL - n*4
# 验证: vftable[i] 指向 .text 中的代码
def in_text(va):
    for s in pe.sections:
        nm = s.Name.rstrip(b'\x00').decode('latin1')
        if nm == ".text":
            return s.VirtualAddress <= va - img < s.VirtualAddress + s.Misc_VirtualSize
    return False

print("\n验证 COL 前邻接的 vftable 槽:")
for cls, td_va in tds.items():
    # 找到 COL 地址
    b = struct.pack("<I", td_va)
    start = 0
    while True:
        i = data.find(b, start)
        if i == -1: break
        col_va = img + (off_to_rva(i) or 0)
        # COL 签名应为 0 / 1 (32位: 0)
        sig_off = i - 4 - 0  # 已找到的是 pTypeDescriptor @ COL+0xC(32位), 所以 COL 在 i-0xC
        # 简单起见: 检查 COL 前 4*n 字节是 vftable
        cand = []
        for n in range(1, 32):
            slot_off = i - 0xC - n*4
            if slot_off < 0: break
            slot_val = struct.unpack("<I", data[slot_off:slot_off+4])[0]
            if slot_val > img and slot_val < img + 0x500000 and in_text(slot_val):
                cand.append((slot_val, n))
        if cand:
            print("  [%s] COL candidate @ 0x%X (found via pTypeDescriptor)" % (cls, col_va))
            for slot_val, n in cand[:12]:
                print("      vftable[-%d] = 0x%X (code in .text)" % (n, slot_val))
        start = i + 1
