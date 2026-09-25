# CDelSecuritySoft 定位脚本 v2 (Ghidra 12.x Jython)
# 目标: 找到 .text 中引用 RTTI 字符串/TypeDescriptor 的指令, 反汇编上下文
import re

OUT = open(r"d:\文档\workbuddy\Safe\my\baicai\ghidra\cdel_refs.txt", "w", encoding="utf-8")

def log(*a):
    msg = " ".join(str(x) for x in a)
    print(msg)
    OUT.write(msg + "\n")
    OUT.flush()

mem = currentProgram.getMemory()
listing = currentProgram.getListing()
func_mgr = currentProgram.getFunctionManager()

# 1. 定位字符串
strs = {}
for pat, start in [(b".?AVIDelSecuritySoft@@", 0x10074000), (b".?AVCDelSecuritySoft_Nop@@", 0x10074000)]:
    a = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(start)
    found = mem.findBytes(a, pat, None, True, monitor)
    log("[+] %s @ %s" % (pat, found))
    if found:
        strs[pat] = found

# 2. 找所有引用这些地址的指令 (xrefs)
def refs_to(addr):
    it = currentProgram.getReferenceManager().getReferencesTo(addr)
    return [r.getFromAddress() for r in it]

for pat, addr in strs.items():
    for ref in refs_to(addr):
        f = func_mgr.getFunctionContaining(ref)
        log("[*] %s referenced from %s (func=%s)" % (pat, ref, f.getName() if f else "?"))
        # 打印引用点周围指令
        it = listing.getInstructions(ref.subtract(0x40), True)
        while it.hasNext():
            ins = it.next()
            if ins.getMinAddress().getOffset() > ref.add(0x40).getOffset():
                break
            mark = "  <<<" if ins.getMinAddress() == ref else ""
            log("      %s%s" % (ins, mark))

OUT.close()
print("DONE")
