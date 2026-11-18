# 两份固件的组件识别改进与实施计划复核

日期：2026-11-18。基线提交：`89f28c8a90f6a4c65c3f5a96381b8d1688454f24`。本轮已按用户授权完成代码修改、扩库和前后实扫；研究与独立文件核验使用 Luna，主 agent 核验集成结果。改动尚未提交或推送。

**结论：识别覆盖和定向核验结果有提升，但原计划的“全部交付、零误报、100% 版本匹配、实时情报”不能作为已验收结论。** 本轮修正了组件版本的证据语义并扩展原生库覆盖。漏洞情报与许可证的可复现问题另列待修。

## 实际扫描结果

| 指标 | Allwinner 原版 → 修改后 | system.img 原版 → 修改后 |
|---|---:|---:|
| 去重后的组件记录 | 559 → **581** | 1053 → **1122** |
| native 候选记录 | 294 → **316** | 703 → **767** |
| 带版本候选证据的 native 记录 | 14 → **23** | 17 → **21** |
| 全部组件中的版本候选记录 | 110 → 111 | 140 → 142 |
| 将 Android 系统版本回填为组件版本 | 413 → **0** | 700 → **0** |
| 将接口、ABI 或 API 下界作为版本 | 6 → **0** | 176 → **0** |
| 非空版本字段，包含旧版错误填充 | 535 → 117 | 1024 → 149 |
| SBOM 组件数 / 唯一 bom-ref 数 | 559 / 557 → **581 / 581** | 1053 / 1048 → **1122 / 1122** |

组件记录包含 Android 平台文件、应用及内嵌第三方库，不等于独立第三方项目数。native 统计依据原生库描述或 `.so` 文件名。版本候选表示存在扫描器认可的版本证据，仍需验证来源和厂商修改；不能将上述数量直接解释为准确率。非空版本字段减少主要来自删除 1113 条系统版本回填，以及纠正接口、ABI、API 下界和不可靠的字符串推断。

32 个主动选择的证据检查点：**16/32 → 31/32**。其中，23 个有明确版本证据的点从 **15 → 22** 个正确；9 个没有足够精确版本证据、应保留未知的点从 **1 → 9** 个正确。这是针对已发现风险和覆盖缺口的检查集，不能报告为总体精确率或召回率，也不能证明新增的全部候选都正确。

### 有价值的具体结果

- `/system/lib64/liblz4.so`：补出 **1.10.0**；`libharfbuzz_ng.so`：补出 **10.2.0**。通过已定义版本 getter 的有限静态指令路径取到字符串，未执行目标代码。
- `/system/lib64/libjpeg.so`：保留完整 **2.1.5.1**；`/system/bin/curl`：保留 **8.12.0-DEV**；libxml2 保留 **21400-GITv2.13.0-1904-g4d38e2fe**，避免把开发快照改写为正式发布版本。
- 同一镜像的 SQLite 保留 **3.44.5** 与 ARM 兼容目录中的 **3.44.3**，分别关联位置；不再按文件名合并成一个版本。
- Katniss APK 的 `libassistant_android.so` 补出 **FLAC 1.3.2、Opus 1.1、libcurl 8.4.0-DEV**，归属到 APK 内的实际文件，而非把依赖版本赋给宿主应用。
- `/system/lib64/libbpf.so` 中识别到 **zstd 1.5.7** 的版本证据；libbpf 自身版本保持未知，避免把内嵌依赖的版本当作宿主版本。
- Allwinner 的 OpenSSL **1.0.1e**、libpng **1.2.46**、Expat **2.1.0**、SQLite **3.7.11**、zlib **1.2.8** 保留。旧版从 JFIF 协议、ICU 数据 ABI 或 API 门槛推断出的精确版本被清除。
- 实扫中还发现并修正了否定句 `This is not GNU sed version 4.0` 误识别 sed、`glibc 2.11.1` 被误识别为 bc，以及 `libcurl` 被误识别为 curl 程序的问题。

**尚未补出的检查点：Protobuf。** `/system/lib64/libprotobuf-cpp-full.so` 原版报告 **3.21.13**，新版为未知。独立反汇编发现 `cmp esi,0x2e18d5; jl ...` 使用了当前版本加一的边界；错误消息路径传给 `VersionString` 的实际常量是 `0x2e18d4`，按上游编码为 **3.21.12**。只扫描附近整数会读错。当前未实现足够严格的参数与分支数据流验证，因此未将该人工结论自动填回产品。[上游实现](https://raw.githubusercontent.com/protocolbuffers/protobuf/v21.12/src/google/protobuf/stubs/common.cc)、[版本编码](https://raw.githubusercontent.com/protocolbuffers/protobuf/v21.12/src/google/protobuf/stubs/common.h)

## 已落地的修改

1. 新增带上游来源的二进制规则库：**78 条规则、72 个归一化组件家族**，含 60 条版本 banner 规则和 18 条仅身份规则；与既有 EMBA 规则互补。符号组合必须来自 ELF 中实际定义的符号，导入符号或普通 API 字符串不能证明文件包含该库的实现。
2. 新增共享 `BinaryInventory`，Android 原生文件、APK 内嵌原生库与普通 ELF 使用一致的身份、宿主和版本归属方式。版本、身份、接口、ABI、运行时与 Android 构建背景分开保存；冲突不静默取第一项。
3. 新增白名单版本 getter 静态解析器，支持 x86-64、AArch64 的有限直接返回指针路径；未知指令、调用、分支、越界或不支持的间接访问拒绝解析。共配置 8 个已知 getter，ARM32/Thumb 尚不支持。
4. 扩展目录深度和 ARM 兼容目录扫描；原生文件读取上限统一为 32 MiB，APK 上限 128 MiB，内嵌库有单文件、个数和总解压量上限。达到限制时输出覆盖告警，CLI 继续传递该告警。
5. CLI 去重保留不同版本并合并文件位置与证据属性；两份最终 SBOM 的组件引用均唯一，引用目标检查通过。
6. 删除 11 个无已核验构建来源的默认哈希条目；默认真实构建哈希库目前为空。保留用户提供的完整文件哈希匹配；单独 `.text`/`.rodata` 相同不再自动确定精确发布版本。已用“相同只读数据、不同代码”的实际编译样本验证反例。

本轮添加/更新了行为回归，并运行完整单元测试：**121 passed，3 个既有 Pydantic 弃用警告**。重点覆盖误归属、系统版本回填、导入符号、开发后缀、四段版本、APK 内嵌库、跨架构多版本、哈希反例及覆盖告警。最终实扫使用的冻结源码与当前 `src` 的 **130 个文件哈希完全一致**。测试通过不替代真实固件证据核验。

## 扫描入口、耗时与覆盖边界

| 输入 | 基线方式 | 修改后方式 | 同入口基线 → 修改后耗时 | 峰值 RSS 基线 → 修改后 |
|---|---|---|---:|---:|
| `sun8iw6p1_android_perf3_v1_0_uart0.img`，653,989,888 字节 | 完整 CLI；另对容器内真实 system 分区扫描 | 同一真实 system 分区，经产品核心扫描入口 | 65.500 → 216.092 秒 | 662032 → 662032 KiB |
| `system.img`，2,309,611,520 字节，ext4 | 产品核心扫描入口 | 相同入口 | 410.049 → 519.767 秒 | 1253216 → 1394776 KiB |

产品核心入口为 `Ext4Reader` + `AndroidSystemScanner` + CLI `_deduplicate_components` + `CycloneDXGenerator`，通过只读 mmap 避免将 2.2 GiB 镜像反复复制进内存。Allwinner 的 system 分区由原版容器解析器抽取，偏移 18,891,776，展开长度 805,306,368 字节。原版完整 CLI 的 559 个组件与该分区扫描的 `(name, version, type)` 逐项一致；完整 CLI 基线耗时 749.709 秒，不能与分区入口耗时直接比较。

**本轮未完成修改后整镜像完整 CLI 的两次端到端复测，也未启动固件或在设备上运行验证。** 最终数据证明上述核心扫描路径的行为，不等同于所有容器、分区、HTML/VEX 或其他 CLI 分支均已验收。

新增分析带来耗时成本；上述运行存在并行扫描、系统缓存与宿主负载差异，不能作为受控性能基准，更不能宣称扫描提速。下一步应先分析热点，再做按内容缓存和分段读取。

`system.img` 最终输出 3 条覆盖告警：

- `/product/app/webview/webview.apk` 超过 128 MiB。
- `/product/priv-app/AndroidMediaShell/AndroidMediaShell.apk` 超过 128 MiB。
- GoogleTTS 的 `lib/x86/libgoogle_speech_sbg_tts_jni.so` 达到内嵌原生库扫描限制。

APEX payload 尚未深入展开，ARM32/Thumb getter、复杂返回函数、部分大文件和厂商定制版本仍有漏检。该镜像的 Android release/SDK 与旧 fingerprint 还有不一致；这些仅作为构建背景保存，不能据此替所有组件定版本，也不能从 SPL 推断漏洞已修补。两份固件不构成完整真值集。

## 对原实施计划的可行动反馈

原文件：`/home/kali/.gemini/antigravity-cli/brain/d7895371-9a97-464b-8402-f5edf918f0ec/implementation_plan.md`。其“已全部交付”状态应拆成源码实现、单元测试、真实文件扫描、人工证据核验和发布验收；84 个测试不能证明其余层次。本轮不修改该历史文件，也未验证其“已推送远程”声明。

| 优先级 / 状态 | 证据位置 | 可复现问题及修正方向 |
|---|---|---|
| P1，待修 | `src/firmware_scanner/vuln/threat_intel.py:125` | 未知 `CVE-2099-0001` 被拼成 `CNVD-2099-0001`、`CNNVD-209999-0001`。编号必须来自真实映射并带来源，缺失时为空；不能算法造号。原计划 4.3 不能据此视为完成。 |
| P1，待修 | `src/firmware_scanner/vuln/threat_intel.py:96` | 同一未知 CVE 搭配 CVSS 9.8 返回所谓 EPSS `(0.35,0.88)`，实际是严重度启发式。应接入 FIRST 数据并记录评分日期；内部优先级估算另设字段。FIRST 的 EPSS 是预测未来 30 天利用概率的模型输出。[FIRST](https://www.first.org/epss/) |
| P1，待修 | `src/firmware_scanner/vuln/threat_intel.py:172` | 未知漏洞仅凭 `high`、7.5 就输出 `exploitable`。没有本产品受影响组件、代码可达性或利用前提证据时，应保留待研判并独立给出处置优先级。 |
| P1，待修 | `src/firmware_scanner/sbom/license_compliance.py:150` | `MIT OR GPL-2.0-only` 被简化为 GPL；`WITH Classpath-exception-2.0` 丢失例外；`Apache-2.0 AND MIT` 丢失 MIT；`BSD-4-Clause` 变为 BSD-3-Clause。先解析并保留完整 SPDX 表达式，再分别评估选择、组合和例外，不能按首个子串归一化。[SPDX 表达式规范](https://spdx.github.io/spdx-spec/v2.3.1/SPDX-license-expressions/) |
| P2，待修 | `src/firmware_scanner/vuln/threat_intel.py:1` | KEV/EPSS/CNVD 当前为少量本地硬编码条目，缺少可验证的实时同步、数据日期及缺失策略，原计划 4.1 的“实时”尚不成立。建议做可追溯缓存和离线状态，不把缺失等同于无风险。 |
| P1，已在本轮修正 | 原计划 3.1；`src/firmware_scanner/extraction/hash_matcher.py` | 未核验的预置摘要和节哈希不能证明精确版本。已删除默认示例库、禁用节哈希作为版本定论；真实、有来源的多架构构建库仍需另建。 |
| P2，未在本轮验收 | 原计划 1.x、2.1–2.5 | 两份 Android 镜像不能证明 super/FIT/UBIFS/JFFS2/CramFS、全部 Go/Rust/JAR 路由和恶意输入边界正确；为每项补真实格式样本、负例和端到端验收，再勾选完成。不能把“零误报、全部依赖”当已证实能力。 |

上述待修模块没有被本轮组件识别改动顺带改写；原始复现结果保存在 `reports/accuracy-20261118/evidence/remaining-plan-issues.json`。它们是已观察到的问题，而非假设风险。

## 行业方法与值得继续投入的方向

本轮选择“包元数据 → 明确 banner → 已定义符号组合 → 有限版本 getter → 未知”的分层策略，并保留位置与冲突。EMBA 的公开方案同样组合多层信息；普通 build-id 或单个节摘要不是通用的精确版本标识。[EMBA 方法](https://github.com/e-m-b-a/emba/wiki/Increase-component-identification-rate)、[GNU ld](https://sourceware.org/binutils/docs/ld/Options.html)

函数级检索和版本差分已有 LibAM、LibvDiff、BinCoFer 等工作，不能直接宣称为本项目创新。更有价值的工程方向是“可审计的库身份与版本证据链 + 多版本冲突 + 厂商补丁状态”，并使用真实构建语料验证。论文结果也不能直接转换成本项目的准确率。[LibAM](https://github.com/Siyuan-Li201/LibAM)、[LibvDiff](https://gentlecp.github.io/pdfs/LibvDiff_ICSE_2024.pdf)、[BinCoFer](https://wu-yueming.github.io/Files/JSS2025_BinCoFer.pdf)

建议下一轮按以下顺序验收：

1. 先修上述 CNVD、EPSS、VEX、许可证表达式问题，确保报告输出具有真实来源与正确语义。
2. 补分段读取、大 APK/APEX、ARM/Thumb、Protobuf 参数数据流，直接针对这两份固件暴露的覆盖缺口；再重扫本次固定检查集。
3. 以 OpenSSL/BoringSSL、SQLite、zlib、curl、BusyBox 等高频家族建立有版本来源、编译器、架构、优化与配置标签的构建集；使用公共负特征和留出厂商固件测误报，库身份与精确版本分别评估。
4. 在构建集上验证函数级候选检索与版本敏感差异特征，继而单独验证补丁证据。保持厂商分支、观测版本、补丁状态三者独立，不用版本号推断补丁已存在。

已用 Syft 1.57.1 对 15 个选定的真实二进制交叉扫描，仅识别到 curl 8.12.0，且丢失原始 `-DEV` 后缀。这是有限样本上的工具分歧，不能宣称对 Syft 的全面性能或准确率优势。更多方法调查见 [研究记录](binary-identification-research.md)。

## 证据、结果和复现

所有原始产物位于项目下 `reports/accuracy-20261118/`，该目录按现有 Git 规则忽略，包含真实固件分区及二进制，不随代码提交。主要入口：

- [汇总验证 JSON](../reports/accuracy-20261118/verification.json)：计数、耗时、SBOM 引用检查、源码快照一致性和人工检查点分组。
- [32 个检查点详情](../reports/accuracy-20261118/evidence-checkpoints.json)、[单元测试日志](../reports/accuracy-20261118/unit-tests.txt)。
- [Allwinner 最终结果](../reports/accuracy-20261118/after/allwinner/system_analysis.json)、[最终 SBOM](../reports/accuracy-20261118/after/allwinner/system_sbom.json)。
- [system.img 最终结果](../reports/accuracy-20261118/after/system/system_analysis.json)、[最终 SBOM](../reports/accuracy-20261118/after/system/system_sbom.json)。
- [独立系统镜像核验](../reports/accuracy-20261118/evidence/system-independent-inventory.json)、[Allwinner 原始文件证据](../reports/accuracy-20261118/evidence/allwinner-binary-evidence.json)、[APK 内嵌库字节证据](../reports/accuracy-20261118/evidence/embedded-library-verification.json)、[SQLite/Protobuf 人工核验](../reports/accuracy-20261118/evidence/manual-sqlite-protobuf-verification.json)。独立核验中的初始未知项不代表最终产品仍未知，最终状态以重扫与检查点为准。
- 冻结原版和最终源码：`baseline-src/`、`final-src/`；`intermediate-first-pass/` 保留修正过程中的诊断结果，不计作最终结果。

复现最终核心扫描（在项目根目录运行；保留既有产物时改用新的输出目录）：

```bash
SCAN_PY=/home/kali/Desktop/Code/cra/vuln/firmware_scanner/.venv/bin/python
"$SCAN_PY" reports/accuracy-20261118/scan_filesystem.py \
  reports/accuracy-20261118/evidence/allwinner-system.img \
  reports/accuracy-20261118/reproduction/allwinner \
  --source reports/accuracy-20261118/final-src
"$SCAN_PY" reports/accuracy-20261118/scan_filesystem.py \
  /home/kali/Desktop/work/project/vulnscan/system.img \
  reports/accuracy-20261118/reproduction/system \
  --source reports/accuracy-20261118/final-src
PYTHONPATH=src "$SCAN_PY" -m pytest tests/unit -q -p no:cacheprovider
"$SCAN_PY" reports/accuracy-20261118/audit_cases.py
```

本轮结论边界：真实文件与产品核心扫描已验证；总体精确率/召回率、所有解包格式、修改后完整 CLI、设备运行和发布状态未作通过声明。
