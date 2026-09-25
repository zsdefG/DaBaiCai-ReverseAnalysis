# -*- coding: utf-8 -*-
"""扫描所有调用 0x10015970 / 0x100159F0 / 0x10007E80 的位置及其参数上下文"""
import pefile, re
from capstone import *

path = r"D:\文档\workbuddy\Safe\my\baicai\setsys_unpack\.rsrc\2052\RCDATA\DEPLOY"
pe = pefile.PE(path, fast_load=False)
img = pe.OPTIONAL_HEADER.ImageBase
data = open(path, "rb").read()

for s in pe.sections:
    if s.Name.rstrip(b'\x00') == b'.text':
        text_va = img + s.VirtualAddress
        text_data = s.get_data()
        break

md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = True
ins_list = list(md.disasm(text_data, text_va))

# 找调用点
def find_calls_to(target):
    return [(i.address, i.operands[0].imm) for i in ins_list
            if i.mnemonic == "call" and i.operands[0].type == 2 and i.operands[0].imm == target]

for target, label in [(0x10015970, "写注册表包装A"), (0x100159F0, "写注册表包装B"), (0x10007E80, "关UAC/防火墙")]:
    calls = find_calls_to(target)
    print("== call 0x%X (%s): %d 处 ==" % (target, label, len(calls)))
    for ca, _ in calls:
        idx = next((k for k, i in enumerate(ins_list) if i.address == ca), None)
        # 打印调用前 12 条指令, 标注 push 的字符串地址
        print("--- @ 0x%08X ---" % ca)
        for i in ins_list[max(0, idx-12):idx+1]:
            m = re.search(r"0x[0-9a-fA-F]+", i.op_str)
            annot = ""
            if m:
                v = int(m.group(0), 16)
                if v in (0x10067510, 0x10067544, 0x10067560, 0x1006756C, 0x10067588, 0x100675E8, 0x100675D8, 0x1006750C, 0x1006763C):
                    annot = "  ; KNOWN-STR"
            print("   0x%08X: %-26s %s%s" % (i.address, i.mnemonic, i.op_str, annot))
