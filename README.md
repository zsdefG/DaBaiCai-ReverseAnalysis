# 大白菜 PE 装机工具 · 恶意行为逆向分析

> **取证性质的安全研究报告** —— 针对"某白菜PE装机工具"（DaBaiCai）的静态逆向分析，
> 还原其安装过程中关闭系统防护、篡改安全软件白名单、伪装驱动、捆绑推广等恶意行为。
>
> ⚠️ **本仓库不含任何可执行样本**（exe / dll / 加壳模块）。分析对象为受恶意代码感染的软件，
> 请勿下载、传播或运行原始样本。详见 [安全与法律声明](#安全与法律声明)。

---

## 目录

1. [项目背景](#一项目背景)
2. [致谢](#二致谢)
3. [核心结论（摘要）](#三核心结论摘要)
4. [样本信息](#四样本信息)
5. [详细逆向发现](#五详细逆向发现)
6. [逆向方法](#六逆向方法)
7. [仓库结构](#七仓库结构)
8. [复现指南](#八复现指南)
9. [分析局限性](#九分析局限性)
10. [安全与法律声明](#十安全与法律声明)

---

## 一、项目背景

"某白菜PE装机工具"是一个面向普通用户的 PE 启动盘 / 系统安装工具。安装完成后，它：

- 静默关闭 Windows 安全防护（UAC、防火墙、安全软件服务）；
- 篡改 360 安全软件白名单数据库，使自身免于查杀；
- 将恶意载荷伪装成系统驱动/系统文件安装；
- 捆绑安装推广软件，且官方免责声明未对此作出披露。

本仓库通过对安装包内嵌组件（`SetSys.exe` 及其资源模块 `DEPLOY`）的**纯静态逆向**，
将这些行为落实到了代码级 / 配置级证据。

**分析声明**：全部分析在隔离环境下完成，**从未在宿主系统运行样本**；
使用 Ghidra 12.1.4、Capstone 等工具进行反汇编与结构还原。

---

## 二、致谢

本研究的许多关键素材直接来自 **B 站用户 [SYSTEM-RAMOS-ZDY]**，包括但不限于：

- **逆向文件**：原始样本的获取与初步解包文件；
- **解压密码**：多层加密压缩包的解压口令；
- **样本溯源线索**：PE 工具发行渠道与版本的追踪信息。

在此对 SYSTEM-RAMOS-ZDY 的前期工作与无私分享表示诚挚感谢。
没有这些基础素材，本报告的代码级与配置级还原将无法完成。

> 说明：上述素材仅用于安全研究与取证目的，请勿用于任何非法用途。

---

## 三、核心结论（摘要）

| # | 恶意行为 | 证据强度 | 证据位置 |
|---|---|---|---|
| 1 | **关闭 UAC**（`EnableLUA`/`ConsentPromptBehaviorAdmin`/`PromptOnSecureDesktop` 写 0） | 代码级（明文反汇编） | DEPLOY 函数 `0x10007E80` |
| 2 | **关闭防火墙**（`PublicProfile`/`StandardProfile` 的 `EnableFirewall` 写 0） | 代码级（明文反汇编） | 同上 |
| 3 | **删除/处置安全软件**（`CDelSecuritySoft` 类 + 服务管理器 API） | 机制级（RTTI + 导入表） | DEPLOY `CDelSecuritySoft` |
| 4 | **篡改 360 白名单**（携带 360 数据库文件写入忽略列表） | 配置级 | `RCDATA\360SAFE` |
| 5 | **驱动伪装**（12 个随机名服务 + 伪造 Intel/蓝牙驱动属性 + 伪装 `sapisvr7.exe.mui`） | 配置级 | `RCDATA\RES1` |
| 6 | **捆绑推广**（推广 URL + 压缩包伪装驱动安装） | 配置级 | `RES1` / 资源 `7Z` |
| 7 | **对抗检测**（多层加壳 / VMProtect 虚拟化 / 异或编码） | 技术级 | 全部核心模块 |
| 8 | **免责声明未披露**推广行为 | 文档级 | 官方网页存档 PDF |

---

## 四、样本信息

| 项目 | 内容 |
|---|---|
| 主安装器 | `DaBaiCai_d30_v6.0_2606_Online.exe`（5.4 MB） |
| 数字签名 | 东莞虎泰网络科技有限公司 |
| 内嵌核心组件 | `SetSys.exe`（9.7 MB） |
| 关键资源模块 | `DEPLOY`（2.7 MB，VMProtect 保护） / `AFTER`（NSIS v3.01） / `360SAFE` / `RES1` / `SECURCONF` |
| 杀软检出 | `Trojan:Win32/Wacatac.B!ml`、`Wacatac.H!ml`、`Ymacco!rfn` 等 |

### 模块结构

```
DaBaiCai_d30_v6.0_2606_Online.exe（自写壳，.text 全加密）
└── 解包 → SetSys.exe（自写壳 .itext/.didata）
    ├── DEPLOY       安装完成阶段处理模块（VMProtect 虚拟化）★ 核心
    ├── AFTER        NSIS 二级安装器（未发现 Defender 行为，已排除）
    ├── 360SAFE      360 安全数据库包（白名单篡改）
    ├── RES1         驱动伪装三段配置（驱动/签名/属性/7z 载荷）
    ├── SECURCONF    异或编码配置
    ├── TOPDRVIER / TOPDRVIER_X64   驱动载荷
    └── 7Z / 7ZA     压缩载荷（伪装驱动安装推广软件）
```

---

## 五、详细逆向发现

### 5.1 关闭 UAC（代码级证据）

`DEPLOY` 函数 `0x10007E80`，经 `qcutil::CWinRegKey` 类向注册表写入 **DWORD 值 0**：

```text
HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System
    EnableLUA                 = 0   ; 关闭 UAC
    ConsentPromptBehaviorAdmin = 0  ; 关闭管理员审批
    PromptOnSecureDesktop     = 0   ; 关闭安全桌面
```

关键反汇编（`0x10007FB5` / `0x10007FD3` / `0x10007FF1`）：

```asm
push 0                          ; 数据 = 0
push 0x10067544                 ; "ConsentPromptBehaviorAdmin"
mov  ecx, 0x80000002            ; HKLM
call 0x10015970                 ; RegSetValueExW 包装（经 VMProtect API 层）
```

### 5.2 关闭防火墙（代码级证据）

同一函数写入：

```text
HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy
    PublicProfile\EnableFirewall   = 0
    StandardProfile\EnableFirewall = 0
```

### 5.3 删除安全软件（机制级证据）

- RTTI 类名：`.?AVIDelSecuritySoft@@` → **CDelSecuritySoft**（"删除安全软件"）
- 静态导入服务管理 API：
  `OpenSCManagerW → EnumServicesStatusExW → OpenServiceW → QueryServiceConfigW`
- 调用链：VMProtect 虚拟化代码调用明文注册表写入函数（`0x10007E80` 在 `.text` 内无调用者，证实由 `.vmp` 段代码调用）
- ⚠️ 停止/删除安全软件服务的最终 API（`ControlService`/`DeleteService`）被 VMProtect 动态解析，静态不可见 —— 见 [分析局限性](#八分析局限性)

### 5.4 篡改 360 白名单（配置级证据）

`RCDATA\360SAFE` 为 7-Zip 包，内含 360 安全软件数据库文件：

```
360ss2.dat / ignorelist.ini / sl2.db / speedmem2.hg
```

作用：将自身写入 360 忽略/白名单，规避查杀。

### 5.5 驱动伪装（配置级证据）

`RCDATA\RES1` 配置三段式（节选）：

```ini
[drivers]
1=SYSTEM\ControlSet001\Services\adkirs
2=SYSTEM\ControlSet001\Services\xjwsks
3=SYSTEM\ControlSet001\services\XjBfasa123
...（共 12 个随机名驱动服务）

[signature]
Xtreaming Technology Inc.=1
Beijing JoinHope Image Technology Ltd.=1
...

[attributes]
Advaned ICP Controller Driver=ProductName|1572864|3145728
Runtime Monitor Agent Driver=FileDescription|1048576|1572864
Bluetooth Bus Driver=FileDescription|1048576|1572864
...

[7z]
Windows\Speech\Common\zh-CN\sapisvr7.exe.mui|CUc_sndf23dne=
;https://windows.sydxwl.cn/
```

作用：注册随机名驱动服务、伪造签名白名单与驱动描述（伪装 Intel/蓝牙驱动）、
将载荷解压伪装为 `Sysprep\sapisvr7.exe.mui`。

### 5.6 捆绑推广（配置级证据）

- 推广 URL：`uqb.yxyxxfw.cn` / `uqb.ndlkj.cn` / `windows.sydxwl.cn`
- 手法：压缩包（资源 `7Z`）伪装成驱动文件，在 PE 高权限环境下静默安装推广软件

### 5.7 对抗检测（技术级证据）

| 组件 | 保护手段 |
|---|---|
| 主安装器 | 自写壳，`.text` 全加密 |
| `Hi.exe` / `Dlg86.dll` | 零字符串（全加密） |
| `SECURCONF` | 异或编码 |
| `DEPLOY` | VMProtect 虚拟化（`.vmp0`/`.vmp1` 段） |
| `SetSys.exe` | 自写壳（`.itext`/`.didata`） |

`.vmp0` 段还泄露动态加载目标：`winhttp.dll`（疑似数据回传）、`Msbiedll.dll`、`USER32.DLL`。

### 5.8 免责声明未披露（文档级证据）

`官方网页存档\` 中的免责声明与用户协议 PDF，**未提及"为用户下载推荐应用"**，
与实际捆绑推广行为不符，构成未尽告知义务的证据。

---

## 六、逆向方法

```
样本解包（7-Zip）
  → 资源提取（RCDATA: DEPLOY/AFTER/360SAFE/RES1...）
  → RTTI 类定位（CDelSecuritySoft / qcutil::CWinRegKey）
  → Ghidra 12.1.4 headless 自动分析
  → Capstone 脚本族反汇编（注册表写入 / 服务注册 / 调用分布）
  → 排除性排查（AFTER / 主安装器 / SetSys 全样本字符串扫描）
  → VMProtect 保护边界确认
```

完整可复现步骤见 `逆向脚本\` 与 `README_逆向分析报告.md` 第二节。

---

## 七、仓库结构

```
.
├── README.md                     ← 本文件
├── README_逆向分析报告.md         ← 完整分析报告（罪证清单 / 处置建议）
├── 样本说明.txt                   ← 为何不含样本本体
├── 官方网页存档/                  ← 免责声明/用户协议/主页 PDF 存档
├── 提取证据/                      ← 配置级证据（RES1/SECURCONF/360SAFE 清单）
└── 逆向脚本/                      ← 25 个可复现分析的 Python 脚本
```

---

## 八、复现指南

依赖：`7-Zip`、`Python 3.12+`（`pefile`、`capstone`）、`JDK 21+`、`Ghidra 12.1.4`

```bash
# 1. 解包主安装器
7z x DaBaiCai_d30_v6.0_2606_Online.exe -osetup_unpack

# 2. 解包 SetSys.exe
7z x SetSys.exe -osetsys_unpack

# 3. 定位 RTTI 类（字符串层证据）
python 逆向脚本/locate_strings.py
python 逆向脚本/locate_rtti.py

# 4. Ghidra 自动分析 DEPLOY
analyzeHeadless.bat proj DEPLOY -import <DEPLOY路径> -analysisTimeoutPerFile 600

# 5. 还原注册表写入逻辑
python 逆向脚本/scan_reg_strings.py
python 逆向脚本/dump_reg_core.py
python 逆向脚本/find_all_reg_writes.py

# 6. 提取配置级证据
python 逆向脚本/extract_evidence.py
```

> 脚本输入路径为分析时的绝对路径，复现时请按需修改为本地路径。

---

## 九、分析局限性

- **VMProtect 虚拟化边界**：`CDelSecuritySoft` 方法体及"关闭 Windows Defender"的最终 API
  调用（停止/删除服务、或写 `DisableAntiSpyware`）被虚拟化，**纯静态无法还原逐条指令**。
  已通过类名、导入表、调用链三种证据锁定其功能。
- **获取逐 API 铁证**需在 Hyper-V 隔离虚拟机中动态运行（API Monitor / Procmon），
  本仓库基于"不运行样本"原则未包含该部分。
- 全样本字符串层均无 `WinDefend`/`DisableAntiSpyware` 关键字，常量被 VMProtect 加密或动态构建。

---

## 十、安全与法律声明

1. **本仓库不含恶意样本**，仅包含分析报告、逆向脚本与配置级证据。
2. 原始样本保留在分析者的隔离环境（已配置杀软豁免），**请勿索取、传播或运行**。
3. 本报告基于静态分析结论，证据强度已在各章节标注；如需法律用途，
   建议在司法鉴定机构监督下补充动态取证与哈希链完整性校验。
4. 分析对象"某白菜PE装机工具"的官方页面/免责声明存档，仅用于对照其未尽披露义务。

---

*分析日期：2026-09-25　|　方法：纯静态逆向　|　状态：取证留档*
