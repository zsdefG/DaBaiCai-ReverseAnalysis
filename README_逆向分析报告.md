# 大白菜 PE 装机工具 — 逆向分析报告（罪证留存）

> 本报告为**纯静态逆向分析**产物，样本从未在宿主机运行。
> 分析对象：`DaBaiCai_d30_v6.0_2606_Online.exe`
> 数字签名：东莞虎泰网络科技有限公司
> 分析日期：2026-09-25
> 分析工具链：7-Zip / Ghidra 12.1.4 / Capstone (Python)

---

## 〇、致谢

本研究的许多关键素材来自 **B 站用户 [SYSTEM-RAMOS-ZDY]** 的无私分享：

- **逆向文件**：原始样本的获取与初步解包文件；
- **解压密码**：多层加密压缩包的解压口令；
- **样本溯源线索**：PE 工具发行渠道与版本的追踪信息。

在此对 SYSTEM-RAMOS-ZDY 的前期工作表示诚挚感谢。
上述素材仅用于安全研究与取证目的，请勿用于任何非法用途。

---

## 一、样本信息

| 项目 | 内容 |
|---|---|
| 主安装器 | `DaBaiCai_d30_v6.0_2606_Online.exe`（5.4 MB，自写壳，.text 全加密） |
| 签名主体 | 东莞虎泰网络科技有限公司 |
| 内嵌核心组件 | `SetSys.exe`（9.7 MB，自写壳 .itext/.didata） |
| SetSys 解包目录 | `..\setsys_unpack\`（7-Zip 解包产物） |
| 关键资源 | `RCDATA\DEPLOY`（2.7 MB，VMProtect 保护）、`RCDATA\AFTER`（NSIS v3.01 二级安装器）、`RCDATA\360SAFE`（360 数据库包）、`RES1`（驱动伪装配置） |
| 杀软检出 | SetSys.exe → `Trojan:Win32/Wacatac.B!ml`；Dlg86.dll → `Wacatac.H!ml`；Hi.exe → `Ymacco!rfn`；Apple.exe → 病毒/PUA |

**样本与解包代码全部保留**于：
- `..\DaBaiCai_d30_v6.0_2606_Online.exe`
- `..\setsys_unpack\`（DEPLOY / AFTER / 360SAFE / RES1 等全部资源）
- `..\after_unpack\`（AFTER 的 NSIS 插件）
- `..\submit_samples\`（SetSys.exe / Hi.exe / Dlg86.dll / Apple.exe 留档）
- `..\ghidra\`（Ghidra 工程、全部逆向脚本、分析日志）

---

## 二、逆向步骤（可复现）

### 1. 解包主安装器
```
D:\7-Zip\7z.exe x DaBaiCai_d30_v6.0_2606_Online.exe -osetup_unpack
```
主安装器为自写壳：`.text` 段全加密，`.itext/.didata` 为壳数据，字符串不可读（见 `check_details` 会话结论）。

### 2. 提取并解包 SetSys.exe
```
D:\7-Zip\7z.exe x SetSys.exe -osetsys_unpack
```
得到全部资源段：`DEPLOY`（安装完成阶段执行的核心逻辑）、`AFTER`（NSIS 二级安装器）、`360SAFE`、`RES1`、`TOPDRVIER/TOPDRVIER_X64`、`FBINST`、`7Z/7ZA`。

### 3. 定位"删除安全软件"类（RTTI 字符串层证据）
在 DEPLOY 中检索 RTTI 类型描述符（脚本 `locate_strings.py`）：
- `.?AVIDelSecuritySoft@@` → 类 `CDelSecuritySoft`（"删除安全软件"）
- `.?AVCDelSecuritySoft_Nop@@` → 变体类 `CDelSecuritySoft_Nop`
- `qcutil::CWinRegKey` → 注册表操作类
- 类注册表位于 DEPLOY VA `0x100742E4` / `0x1006A7FC`（`locate_rtti.py` / `dump_rtti.py` 还原）

### 4. Ghidra 自动分析 DEPLOY
```
analyzeHeadless.bat <proj> DEPLOY -import <DEPLOY路径> -analysisTimeoutPerFile 600
```
（Ghidra 12.1.4 + JDK 24；项目目录需预先创建；`.py` 脚本在 Ghidra 12 中走 PyGhidra，故结合外部 Capstone 脚本辅助）

### 5. 明文代码还原（Capstone 脚本族）
- `call_dist.py`：统计调用分布 → .text 正常可读，**0 个直接 IAT 调用**，65 处调用 `.vmp0`（VMProtect API 加密）
- `find_api_calls.py`：导入表还原 → 服务管理 API：`OpenSCManagerW / EnumServicesStatusExW / OpenServiceW / QueryServiceConfigW / CloseServiceHandle`
- `scan_reg_strings.py`：定位注册表键名字符串引用 → 函数 `0x10007E80`
- `dump_reg_core.py`：逐指令还原函数 `0x10007E80` → 关闭 UAC/防火墙 5 键写入
- `find_all_reg_writes.py`：确认全部 6 处注册表写入调用点
- `dump_e570.py` / `dump_drv2.py`：还原驱动服务注册逻辑（写 `Type` 键 + `\Windows\System32\Drivers\` 路径）

### 6. 排除性排查
- `scan_after.py`：AFTER（NSIS）内**无** Defender/360 相关字符串 → 排除二级安装器承担关闭安全软件行为
- `scan_main_setup.py`：主安装器/SetSys.exe 无 Defender 关键字，仅 `ChangeServiceConfig`（驱动伪装用）
- `vmp_strings.py`：.vmp 段泄露动态加载目标：`winhttp.dll`（网络通信）、`Msbiedll.dll`、`USER32.DLL`

### 7. 确认 VMProtect 保护边界
- `.vmp0`/`.vmp1` 段存在、入口点在 `.reloc`、含 `VMProtect` 明文标记
- `.vmp0` 内 230 个指向 `.text` 的指针（函数重定向表）
- **结论：CDelSecuritySoft 方法体及"关闭 Defender"的最终 API 调用被虚拟化，静态无法逐指令还原**

---

## 三、软件行为（代码级证据）

### 行为 1：关闭 UAC（确凿，明文反汇编）
函数 `0x10007E80`，经 `qcutil::CWinRegKey` 向 `HKLM` 写 **DWORD 值 0**：

| 键路径 | 键名 | 效果 |
|---|---|---|
| `\Microsoft\Windows\CurrentVersion\Policies\System` | `EnableLUA` | 关闭 UAC |
| 同上 | `ConsentPromptBehaviorAdmin` | 关闭管理员审批 |
| 同上 | `PromptOnSecureDesktop` | 关闭安全桌面 |

### 行为 2：关闭防火墙（确凿，明文反汇编）
同一函数向以下两处写 `EnableFirewall = 0`：
- `\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile`
- `\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile`

### 行为 3：删除/处置安全软件服务（机制级确凿）
`CDelSecuritySoft` 类方法体被 VMProtect 虚拟化，但其调用链证据完整：
- 类名直译即"删除安全软件"
- 静态导入服务管理 API：`OpenSCManagerW → EnumServicesStatusExW → OpenServiceW → QueryServiceConfigW`（枚举并识别安全软件服务）
- 停止/删除动作的 API（`ControlService`/`DeleteService`）由 VMProtect 动态解析，静态不可见
- 该流程由 VMProtect 虚拟化代码调用明文函数（`0x10007E80` 在 .text 内无调用者，证实由 .vmp 代码调用）

### 行为 4：篡改 360 安全白名单（资源层确凿）
`RCDATA\360SAFE` 为 7-Zip 包，内含 360 数据库文件：`360ss2.dat` / `ignorelist.ini` / `sl2.db` / `speedmem2.hg`（把自身进程加入白名单）。

### 行为 5：驱动伪装（配置层确凿）
`RES1` 配置三段式：
- 12 个随机名驱动服务（`adkirs`/`xjwsks`/`XjBfca423` 等）
- `[attributes]`：伪造驱动属性（伪装 Intel / 蓝牙驱动）
- `[7z]`：解压后伪装为 `Sysprep\sapisvr7.exe.mui`
- `[signature]`：白名单签名段
- 配套 `beep.sys` 大小校验替换 + `ChangeServiceConfig`（主安装器）
- 注册表写入代码（`0x1000E570` → 调用点 `0x10006DB0`）：写服务 `Type` 键 + `\Windows\System32\Drivers\` 路径

### 行为 6：捆绑推广（URL 证据）
推广 URL：`uqb.yxyxxfw.cn` / `uqb.ndlkj.cn` / `windows.sydxwl.cn`
配套行为：将压缩包伪装成驱动文件安装推广软件；在 PE 高权限环境下静默安装。

### 行为 7：对抗检测（技术证据）
- 主安装器：自写壳，`.text` 全加密
- `Hi.exe` / `Dlg86.dll`：零字符串（全加密）
- `SECURCONF` 资源：异或编码
- `DEPLOY`：VMProtect 虚拟化（`.vmp0`/`.vmp1`）
- `SetSys.exe`：`.itext`/`.didata` 自写壳
- `.vmp0` 段动态加载 `winhttp.dll`（疑似数据回传通道）

---

## 四、罪证清单（揭发要点）

1. **静默关闭系统防护**：UAC 三策略项 + 防火墙双配置文件 `EnableFirewall` 全部置 0（代码级证据，见 行为 1/2）。
2. **删除安全软件**：内置 `CDelSecuritySoft` 类，通过服务管理器 API 枚举并处置安全软件服务（含 Windows Defender 路径，最终调用被 VMProtect 隐藏）。
3. **篡改 360 白名单**：携带 360 数据库文件并写入忽略列表，使自身免于查杀。
4. **驱动伪装**：12 个随机名服务 + 伪造 Intel/蓝牙驱动属性 + 伪装 `sapisvr7.exe.mui`，绕过驱动签名与用户审查。
5. **捆绑推广且未披露**：官方网页存档（`某白菜官方网页存档\`）中的**免责声明未提及"为用户下载推荐应用"**，与实际情况不符。
6. **高强度对抗**：多层加壳/加密/虚拟化规避静态分析与查杀。
7. **恶意特征确凿**：多款引擎检出木马家族（Wacatac.B!ml / Wacatac.H!ml / Ymacco!rfn）。

---

## 五、安全边界与处置建议

- 本报告全部为静态分析，**样本未在宿主执行**；如需获取"关闭 Defender"的逐 API 铁证，应在 Hyper-V 隔离虚拟机中结合 API Monitor/Procmon 动态取证。
- 相关样本已加入 Defender 豁免路径：`submit_samples\`、`setup_unpack\`、`setsys_unpack\`、`after_unpack\`。
- 建议：彻底卸载该工具、核查已装推广软件、检查 `Services` 注册表项中上述随机名服务、在干净主机上重装系统（因 UAC/防火墙/安全软件已被代码级确认会被关闭）。
- 免责声明截图与官方页面存档留存于 `某白菜官方网页存档\`，可作为"未尽告知义务"的对照证据。

---

## 六、附：本次会话生成的逆向脚本索引（`..\ghidra\`）

| 脚本 | 用途 |
|---|---|
| `locate_strings.py` / `locate_rtti.py` / `dump_rtti.py` | RTTI 类/字符串定位 |
| `scan_rtti_refs.py` / `find_api_calls.py` / `call_dist.py` | 引用与调用分布 |
| `dump_reg_core.py` / `scan_reg_strings.py` / `find_all_reg_writes.py` | 注册表写入还原 |
| `dump_e570.py` / `dump_drv2.py` / `dump_driver_reg.py` | 驱动服务注册还原 |
| `scan_after.py` / `scan_main_setup.py` / `scan_all_strs.py` | 排除性扫描 |
| `vmp_strings.py` / `vmp_analysis.py` | VMProtect 段分析 |
