# CDelSecuritySoft 分析脚本 (Ghidra 12.x, Jython)
# 流程: 定位 RTTI TypeDescriptor 字符串 -> 找引用它的 RTTI CompleteObjectLocator -> 找引用 COL 的 vftable -> 反汇编所有方法
import sys

from ghidra.program.model.mem import Memory
from ghidra.program.model.address import AddressSet
from ghidra.program.model.symbol import SourceType, RefType
from ghidra.app.decompiler import DecompInterface, DecompileOptions

OUT = open(r"d:\文档\workbuddy\Safe\my\baicai\ghidra\cdel_security_soft_dump.txt", "w", encoding="utf-8")

def log(*a):
    msg = " ".join(str(x) for x in a)
    print(msg)
    OUT.write(msg + "\n")
    OUT.flush()

def find_bytes_pattern(pattern, start=None):
    mem = currentProgram.getMemory()
    addr = start if start else currentProgram.getMinAddress()
    found = mem.findBytes(addr, pattern, None, True, monitor)
    return found

def get_string_at(addr):
    d = getDataAt(addr)
    if d and d.hasValue() and str(d.getDataType().getName()) in ("string", "unicode"):
        return d.getValue()
    # fallback: raw read
    try:
        return getBytes(addr, 0x60)
    except:
        return None

def xrefs_to(addr):
    res = []
    it = currentProgram.getReferenceManager().getReferencesTo(addr)
    while it.hasNext():
        ref = it.next()
        res.append(ref.getFromAddress())
    return res

# ---- 1. 定位 RTTI 字符串 ----
rtti_names = [b".?AVIDelSecuritySoft@@", b".?AVCDelSecuritySoft_Nop@@"]
str_addrs = {}
for pat in rtti_names:
    a = find_bytes_pattern(pat)
    log("[+] RTTI string %s @ %s" % (pat, a))
    if a:
        str_addrs[pat] = a

# ---- 2. 通过字符串找 TypeDescriptor -> COL -> vftable ----
vftables = set()
for pat, str_addr in str_addrs.items():
    # TypeDescriptor 是: [vftable_ptr][spare][name...]
    td_addr = str_addr.subtract(0x10)
    log("[*] TypeDescriptor candidate @ %s" % td_addr)
    # COL 结构: [signature][offset][cdOffset][pTypeDescriptor][pClassDescriptor][pBaseClassArray]
    # vftable[0] 指向 COL。COL 的 +0xC 偏移处存放 TypeDescriptor 指针 (x64) / +0x8 (x86)
    # DEPLOY 是 32 位 PE (imagebase 0x10000000, 通常 32 位)。
    col_candidates = []
    for ref_from in xrefs_to(td_addr):
        log("    TypeDescriptor referenced from %s" % ref_from)
        col_candidates.append(ref_from)
        # 引用 TypeDescriptor 的结构通常是 COL，位于 vftable 之后不远处
    # 找到引用这些地址(vftable槽)的结构 -> vftable 本身在 COL 前面
    for col in col_candidates:
        # COL 通常紧跟在 vftable 数组之后: vftable[0..n-1], 然后 4字节对齐后是 COL
        for vft in xrefs_to(col):
            log("    COL referenced from %s  (vftable slot)" % vft)
            vftables.add(vft)

log("=" * 60)
log("[+] vftables: %s" % list(vftables))

# ---- 3. 对每个 vftable，dump 方法 ----
func_mgr = currentProgram.getFunctionManager()
listing = currentProgram.getListing()

decomp = DecompInterface()
decomp.openProgram(currentProgram)

seen = set()
for vft in sorted(vftables):
    log("")
    log("#" * 70)
    log("[vftable] @ %s" % vft)
    # 读取槽位直到空/无效
    i = 0
    while True:
        slot = vft.add(i * 4)
        try:
            val = getInt(slot)
        except:
            break
        if val == 0 or val <= 0x1000:
            break
        target = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(val)
        # 检查是否指向 .text
        if not currentProgram.getMemory().getBlock(target).getName() in (".text",):
            # 可能指向 thunk/导入表；继续收集但标注
            pass
        f = func_mgr.getFunctionContaining(target)
        if f is None:
            log("  slot %d -> 0x%X (no function)" % (i, val))
        else:
            log("  slot %d -> %s @ %s (body %s)" % (i, f.getName(), f.getEntryPoint(), f.getBody()))
            # 反汇编指令列表
            instr_iter = listing.getInstructions(f.getBody(), True)
            n = 0
            while instr_iter.hasNext() and n < 400:
                ins = instr_iter.next()
                log("      %s" % ins)
                n += 1
            if n >= 400:
                log("      ... (truncated)")
        i += 1
        if i > 24:
            break

OUT.close()
print("DONE")
