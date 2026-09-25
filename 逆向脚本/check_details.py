# -*- coding: utf-8 -*-
"""核查 0x1005d110 动态函数指针、0x10067AC4 消息、中文/提示字符串"""
import pefile, re, struct

path = r"D:\文档\workbuddy\Safe\my\baicai\setsys_unpack\.rsrc\2052\RCDATA\DEPLOY"
pe = pefile.PE(path, fast_load=False)
img = pe.OPTIONAL_HEADER.ImageBase
data = open(path, "rb").read()

def va_to_off(va):
    for s in pe.sections:
        if s.VirtualAddress <= va - img < s.VirtualAddress + max(s.SizeOfRawData, s.Misc_VirtualSize):
            return s.PointerToRawData + (va - img - s.VirtualAddress)
    return None

def read_cstr(va, maxlen=200):
    off = va_to_off(va)
    if off is None: return None
    end = data.find(b"\x00", off, off + maxlen)
    return data[off:end].decode('latin1', 'replace')

# 0x1005d110 内容 (动态 API 指针)
off = va_to_off(0x1005D110)
if off:
    v = struct.unpack("<I", data[off:off+4])[0]
    print("0x1005D110 指针值 = 0x%08X" % v)
    # 若指向文件内, 读取
    if img <= v < img + 0x300000:
        s = read_cstr(v)
        print("  指向字符串: %r" % s)

print("\n0x10067AC4 消息: %r" % read_cstr(0x10067AC4))

# 全部 UTF-16LE 中文字符串
print("\nUTF-16LE 中文/提示字符串:")
for m in re.finditer(rb"(?:[\x20-\x7e]|[\x80-\xff]){2}\x00", data):
    pass
# 用简单方式: 搜 UTF-16 中文
utf16_strs = []
i = 0
while i < len(data) - 3:
    if data[i+1] == 0 and data[i+3] == 0 and data[i] > 0x20 and data[i] < 0x80 or (data[i] > 0x80):
        # 尝试 UTF-16LE 解码
        j = i
        while j < len(data) - 1 and data[j+1] == 0 and data[j] != 0:
            j += 2
        if j - i >= 10:
            s = data[i:j].decode('utf-16-le', 'replace')
            if any(ord(c) > 0x2000 for c in s):
                utf16_strs.append((i, s))
        i = j + 2
    else:
        i += 2
for off, s in utf16_strs[:30]:
    print("  0x%X: %r" % (off, s))
