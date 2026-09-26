# -*- coding: utf-8 -*-
import os
_BASE = os.environ.get("PE_BASE") or os.getcwd()
"""在 DEPLOY .text 中定位服务/注册表 API 的调用点"""
import pefile
import re
from capstone import *

path = os.path.join(_BASE, "baicai", "setsys_unpack", ".rsrc", "2052", "RCDATA", "DEPLOY")
pe = pefile.PE(path, fast_load=False)
img = pe.OPTIONAL_HEADER.ImageBase

# 收集导入 API -> IAT 地址
import_map = {}  # iat_va -> api_name
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    dll = entry.dll.decode()
    for imp in entry.imports:
        if imp.name:
            iat_va = imp.address  # pefile 的 imp.address 已是绝对 VA
            import_map[iat_va] = "%s!%s" % (dll, imp.name.decode())

# .text 段
for s in pe.sections:
    if s.Name.rstrip(b'\x00') == b'.text':
        text_va = img + s.VirtualAddress
        text_data = s.get_data()
        break

md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = True

# 目标 API（服务枚举 + 注册表 + 其他关键）
targets = ["OpenSCManagerW","EnumServicesStatusExW","OpenServiceW","QueryServiceConfigW",
           "CloseServiceHandle","RegQueryValueExW","RegCloseKey","LoadLibraryA","GetProcAddress",
           "WTSSendMessageW","PathFileExistsW","CryptDecodeObject"]
target_iat = {va: name for va, name in import_map.items() if any(t in name for t in targets)}

print("目标 IAT:")
for va, name in sorted(target_iat.items()):
    print("  0x%08X %s" % (va, name))

print("\n调用点:")
calls = []
for i in md.disasm(text_data, text_va):
    if i.mnemonic == "call":
        # 直接 call [iat]
        if i.op_str.startswith("dword ptr [") and "]" in i.op_str:
            inner = i.op_str.split("[")[1].split("]")[0]
            # 解析地址，如 0x1006a000 或 0x1006a000*1 等
            import re
            m = re.search(r"0x[0-9a-fA-F]+", inner)
            if m:
                addr = int(m.group(0), 16)
                if addr in import_map:
                    calls.append((i.address, import_map[addr]))
        # 间接 call eax (GetProcAddress 结果)
    # 也找引用目标 IAT 地址的 mov/lea (thunk)
    if i.mnemonic in ("mov","lea") and "0x" in i.op_str:
        m = re.search(r"0x[0-9a-fA-F]+", i.op_str)
        if m:
            addr = int(m.group(0), 16)
            if addr in target_iat:
                print("  0x%08X %s %s  <-- 引用 %s" % (i.address, i.mnemonic, i.op_str, target_iat[addr]))

for addr, name in sorted(calls):
    print("  0x%08X call %s" % (addr, name))
