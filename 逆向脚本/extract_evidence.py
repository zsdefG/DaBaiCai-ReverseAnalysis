# -*- coding: utf-8 -*-
import os
_BASE = os.environ.get("PE_BASE") or os.getcwd()
"""提取非可执行证据: RES1/SECURCONF 字符串转储 + 360SAFE 包文件清单 + DEPLOY 资源结构"""
import re, os

base = os.path.join(_BASE, "baicai")
out = os.path.join(base, "打包发布包", "提取证据")
os.makedirs(out, exist_ok=True)

def dump_strings(src, dst, label, minlen=4):
    data = open(src, "rb").read()
    strs = re.findall(rb"[\x20-\x7e]{%d,}" % minlen, data)
    with open(dst, "w", encoding="utf-8") as f:
        f.write("# %s\n# 来源: %s\n# 提取时间: 2026-09-25\n\n" % (label, src))
        for s in strs:
            f.write(s.decode('ascii', 'replace') + "\n")
    print("  %s -> %s (%d 字符串)" % (label, dst, len(strs)))

# RES1 驱动伪装配置
dump_strings(os.path.join(base, "setsys_unpack", ".rsrc", "2052", "RCDATA", "RES1"),
             os.path.join(out, "RES1_驱动伪装配置_字符串.txt"), "RES1 (随机驱动服务/伪装属性/白名单签名配置)")
# SECURCONF 异或配置
dump_strings(os.path.join(base, "setsys_unpack", ".rsrc", "2052", "RCDATA", "SECURCONF"),
             os.path.join(out, "SECURCONF_异或编码配置_字符串.txt"), "SECURCONF (异或编码配置)", minlen=3)

# 360SAFE 包文件清单 (7z 列目录)
import subprocess
r = subprocess.run([r"D:\7-Zip\7z.exe", "l", os.path.join(base, "setsys_unpack", ".rsrc", "2052", "RCDATA", "360SAFE")],
                   capture_output=True, text=True, errors="replace")
with open(os.path.join(out, "360SAFE_白名单包_文件清单.txt"), "w", encoding="utf-8") as f:
    f.write("# 360SAFE 包 = 360 安全数据库文件(白名单篡改用)\n\n")
    f.write(r.stdout)
print("  360SAFE 清单已生成")

# 资源结构清单
r2 = subprocess.run([r"D:\7-Zip\7z.exe", "l", os.path.join(base, "setsys_unpack", ".rsrc", "2052", "RCDATA", "DEPLOY")],
                    capture_output=True, text=True, errors="replace")
with open(os.path.join(out, "DEPLOY_结构说明.txt"), "w", encoding="utf-8") as f:
    f.write("# DEPLOY = SetSys.exe 内嵌的安装完成阶段处理模块 (VMProtect 保护)\n")
    f.write("# 关键类: CDelSecuritySoft (删除安全软件) / qcutil::CWinRegKey (注册表写入)\n")
    f.write("# 已还原: 关闭 UAC(3键)+防火墙(2键) 写注册表函数 0x10007E80\n\n")
    f.write(r2.stdout)
print("  DEPLOY 结构说明已生成")
print("完成, 输出目录:", out)
