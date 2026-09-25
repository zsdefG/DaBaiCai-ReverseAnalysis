# -*- coding: utf-8 -*-
"""dump DEPLOY 中 RTTI COL/vftable 区域"""
import struct, pefile

path = r"D:\文档\workbuddy\Safe\my\baicai\setsys_unpack\.rsrc\2052\RCDATA\DEPLOY"
pe = pefile.PE(path)
img = pe.OPTIONAL_HEADER.ImageBase

def rva_to_off(rva):
    for s in pe.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + max(s.SizeOfRawData, s.Misc_VirtualSize):
            return s.PointerToRawData + (rva - s.VirtualAddress)
    return None

def va_to_off(va):
    return rva_to_off(va - img)

def off_to_va(off):
    for s in pe.sections:
        if s.PointerToRawData <= off < s.PointerToRawData + max(s.SizeOfRawData, s.Misc_VirtualSize):
            return img + s.VirtualAddress + (off - s.PointerToRawData)
    return None

data = open(path, "rb").read()

def dump_region(va, length, label):
    off = va_to_off(va)
    if off is None:
        print("  [%s] 0x%X -> no file backing" % (label, va)); return
    print("== %s @ VA 0x%X (fileoff 0x%X) ==" % (label, va, off))
    for row in range(0, length, 16):
        chunk = data[off+row:off+row+16]
        vals = []
        for i in range(0, len(chunk)-3, 4):
            vals.append("0x%08X" % struct.unpack("<I", chunk[i:i+4])[0])
        print("  +0x%03X: %s" % (row, " ".join(vals)))

# CDelSecuritySoft
td_del = 0x10074364
col_del = 0x1006A7FC   # pTypeDescriptor 指针位置 - 0xC
# CDelSecuritySoft_Nop
td_nop = 0x100742E4
col_nop1 = 0x1006A78C
col_nop2 = 0x1006A898

dump_region(col_nop1 - 0x40, 0x40, "vftable? before Nop COL#1")
dump_region(col_nop1, 0x30, "COL Nop #1")
dump_region(col_del - 0x40, 0x40, "vftable? before Del COL")
dump_region(col_del, 0x30, "COL Del")
dump_region(col_nop2 - 0x20, 0x30, "COL Nop #2 area")

# 打印 TD 内容
dump_region(td_nop, 0x20, "TypeDescriptor Nop")
dump_region(td_del, 0x20, "TypeDescriptor Del")
