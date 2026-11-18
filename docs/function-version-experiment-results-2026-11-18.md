# 函数语义版本识别：两份固件的实测结果

日期：2026-11-18。产品基线为已提交的 `a4a93cca2f4661213833b39d3a5d590c57e5740e`；实验分支为 `codex/function-version-experiment`。子任务使用 GPT-6 Luna，主 agent 核查实际字节、反例和重扫产物。

**结论：有限函数语义能补足这两份固件的一部分版本识别缺口，值得继续验证。** 实验新增 9 条文件/组件版本观测，带版本的 native 记录净增 8 条（44 → 52）；同时发现一个厂商后缀冲突。它依赖已定义的已知 API 和受限指令路径，尚不能替代多版本参考库，也没有建立总体精确率/召回率或任意 stripped 二进制的识别能力。

原型只在独立进程中附加到产品扫描器，不改默认 `src`。未执行、加载目标 ELF，也未推送 Git 或发布产品。

## 相同产品核心入口的对比

| 指标 | Allwinner：已提交基线 → 实验 | system.img：已提交基线 → 实验 |
|---|---:|---:|
| 去重组件记录 | 581 → 582 | 1122 → 1129 |
| native 候选记录 | 316 → 317 | 767 → 774 |
| 带版本候选证据的 native 记录 | **23 → 25** | **21 → 27** |
| 全部非空版本字段 | 117 → 119 | 149 → 155 |
| 冲突记录 | 0 → 0 | 1 → 2 |
| 覆盖告警 | 0 → 0 | 3 → 3 |
| SBOM 组件 / 唯一引用 | 581/581 → 582/582 | 1122/1122 → 1129/1129 |
| 本次耗时 | 118.916 秒 | 426.784 秒 |
| 本次峰值 RSS | 662032 KiB | 1321492 KiB |

native 统计沿用首次报告的描述/文件名口径，包含 Android 平台库及内嵌依赖；同一组件可有多个位置/版本。新增身份、版本拆分、冲突导致的拆分都会影响去重总数，不能用总数衡量组件准确率。两镜像合计版本候选数增加 18.2%，仅表示该口径的输出覆盖变化。

基线前次耗时分别为 216.092、519.767 秒。本次扫描存在缓存、并行和宿主负载差异，未作受控性能实验，不能据此宣称加速。

两阶段均使用 `Ext4Reader` + `AndroidSystemScanner` + CLI 去重 + `CycloneDXGenerator`。Allwinner 使用从原始容器抽出的真实 system 分区；其来源偏移、解包方式与完整 CLI 基线对应关系见[首次报告](firmware-accuracy-review-2026-11-18.md)。本轮不是修改后两份整镜像完整 CLI 的端到端验收。

## 新增版本的逐项证据

以下均为文件中库实现所声明的版本，不能证明未修改的上游源码或漏洞补丁状态。

| 镜像 / 文件 | 新版本证据 | 核查依据 |
|---|---|---|
| Allwinner `/lib/libharfbuzz_ng.so` | HarfBuzz **0.9.5** | ARM `hb_version_string` 的 PC 相对加载、加法、`bx lr` 指向完整字符串。 |
| Allwinner `/lib/libskia.so` | 内嵌 libwebp **0.3.1** | Thumb getter 返回 `0x301`，按 8 位三段编码为 0.3.1。Encoder/Decoder 别名指向同一函数体，不计作两条独立证明。 |
| system `/system/lib64/liblz4.so` | 内嵌 xxHash **0.6.5** | `XXH_versionNumber` 为 `mov eax,605; ret`，十进制编码与 xxHash 官方定义一致。LZ4 自身仍为 1.10.0。 |
| system `/system/lib64/libprotobuf-cpp-full.so` | Protobuf **3.21.12** | 定义的 `VerifyVersion` 中第一比较、失败边、消息与两次 `VersionString` 参数关联；版本常量 3021012 与比较上界 3021013 交叉一致。 |
| system `/system/lib64/libprotobuf-cpp-lite.so` | Protobuf **3.21.12** | 同样核查失败边及库内常量，保留独立文件哈希/地址。 |
| system `/system/lib64/service.incremental.so` | 内嵌 Protobuf **3.21.12** | 相同源码语义与机器码数据流证据，宿主自身版本保持未知。 |
| system `/system/lib64/libsnapshot.so` | 内嵌 Brotli **1.0.9** | `BrotliDecoderVersion` 返回 `0x1000009`；使用语义版本编码，未将不同的 ABI 编码当作版本。 |
| system `/system/lib64/arm64/libicuuc.so` | ICU **76.1** | `u_getVersion_76` 的字符串参数指向 `76.1`，尾调用经 PLT/GOT 指向同后缀且实际定义的 `u_versionFromString_76`。 |
| system `/system/lib64/arm64/libsqlite.so` | SQLite **3.44.3** | AArch64 `mov w0,#0x72a3; movk w0,#0x2e,lsl#16; ret` 构造 3044003；没有把其他架构的 3.44.5 移植到这里。 |

编码与 API 语义核对一手来源：[libwebp getter](https://github.com/webmproject/libwebp/blob/v0.3.1/src/dec/vp8.c) 与[版本宏](https://github.com/webmproject/libwebp/blob/v0.3.1/src/dec/vp8i.h)、[xxHash 0.6.5](https://github.com/Cyan4973/xxHash/blob/v0.6.5/xxhash.h)、[Brotli 1.0.9 版本/ABI 区别](https://github.com/google/brotli/blob/v1.0.9/c/common/version.h)、[ICU getter 实现](https://github.com/unicode-org/icu/blob/release-76-1/icu4c/source/common/putil.cpp)、[Protobuf v21.12](https://github.com/protocolbuffers/protobuf/blob/v21.12/src/google/protobuf/stubs/common.cc)。完整文件哈希、地址与指令保存在原始观测 JSON。

另有 **14 条**文件/组件观测印证已有版本，并不计作新增版本。

### 厂商后缀与冲突

`/system/lib/arm/libz.so` 的旧 banner 是 `deflate 1.3.0.1`；实际定义的 `zlibVersion` 指向 **`1.3.0.1-motley`**。后者是更完整的厂商自报字符串，但当前实验未建立通用的来源优先/后缀兼容规则，因此保留两个声明、输出冲突，撤回单一 resolved version。9 条新增观测因此对应净增 8 个带版本记录。这个保守行为避免静默覆盖，也提示后续需要明确定义“数字基底、开发后缀、厂商分支”的兼容关系。

原有 `/product/lib64/libssh.so` 的 OpenSSH 多版本字符串冲突仍然存在；兼容性字符串不能作为该文件内真实 OpenSSH 发布版本的真值。候选组件总数仍需进一步人工分层核验。

## 检查点、反例与拒判

**统一修订后的 32 个定向检查点：基线 29/32 → 实验 31/32。** 25 个已知版本点为 22 → 24 个通过；7 个应保持未知的点两阶段均通过。剩余未通过点是 Allwinner ICU：独立人工追踪 `u_getVersion_51` 的复杂内联解析路径确认 **51.1.0.1**，原型仍不支持，保持未知。

首次报告曾为基线记录 31/32。当时把 Allwinner HarfBuzz 和 ICU 的“尚未证明”作为期望未知。获得独立 getter/字符串证据后，这两个标签分别修订为 0.9.5、51.1.0.1，并对两阶段统一重算。这里不将标签变化伪装成算法退步或 100% 提升；检查集也是主动选择的诊断样本，不是未见固件上的独立精度评测。

| 验证 | 实际结果 | 限制 |
|---|---|---|
| 真实文件与语义反例 | 16/16 控制通过 | 含 Protobuf 边界/消息不一致、互斥分支、方向反转、缺定义、头文件调用方、运行时 getter 与 ARM 条件/循环。 |
| ICU | 1 个真实命中；5/5 变异负例拒判；2/2 不支持路径拒判 | 错误重定位、错误 GOT 槽、移位 ADD、Unicode-only、uint8 溢出；ARM32 和复杂内联解析不支持。 |
| GCC/Clang API 形态夹具 | 24 个 ELF、72 个期望值：48 正确、24 拒判、0 错误版本 | 两个 SQLite 数值、LZ4/Brotli API，`-O0/-O2/-Os`，strip 前后；不是完整上游库构建集。`-O0` prologue 不支持；strip 后仍有动态导出符号。 |
| 既有产品单元测试 | 提交基线前 121 passed | 实验未改 `src/tests/pyproject.toml`；本轮运行新增实验控制，不将产品单测当作实验识别效果。 |
| 冻结与 SBOM | 130 个产品文件及 3 个原型文件哈希一致；引用唯一、无悬空 dependency ref | 只证明本次所用代码和产物一致，未证明所有格式/CLI/设备运行。 |

Luna 审查曾发现第一版 Protobuf 原型跨互斥块累计格式化调用，两个专门构造的 ELF 都会误报。本轮先复现，再改为失败边内参数数据流、调用后的 caller-saved 清理及消息约束；两个反例均拒判，真实 full/lite 与嵌入样本保留。该修复在代码冻结和正式重扫之前完成。

## 方法价值与继续投入的边界

本轮验证了三个可用的工程方向：从版本 API 恢复真实返回语义；由版本校验失败路径恢复库内版本而非调用方头文件；为静态嵌入依赖保留可审计的宿主/文件/地址证据。与仅扫字符串或附近整数相比，它能补出部分无明显 banner 的版本，并暴露更完整的厂商版本字符串。

这不能直接声称为研究原创。[LibvDiff](https://github.com/GentleCP/LibvDiff-public/) 已研究版本差分识别，[LibAM](https://github.com/Siyuan-Li201/LibAM) 和 [BinCoFer](https://wu-yueming.github.io/Files/JSS2025_BinCoFer.pdf) 已研究函数/区域匹配与候选降噪。相关证据和适用边界见[方法调查](function-version-experiment-research.md)。本轮没有复现这些完整系统，也没有实现多版本函数指纹检索或补丁验证。

建议先将经验证的有限路径作为显式可选证据层，再建设版本参考库。后续优先级：

1. 明确 zlib 厂商后缀兼容规则、ICU 宿主名称归一化及冲突处理；补齐真实 getter 与相似错误路径负例后再集成产品。
2. 扩展有限 ARM/Thumb、AArch64 形态，针对 Allwinner ICU 内联解析与 FreeType 运行时字段追溯。没有证明初始化数据流时继续拒判。
3. 解决大 APK/APEX 覆盖，再评估增量扫描/按内容缓存。当前 system 的三条覆盖告警完全保留，APEX payload 仍未展开。
4. 为高频库采集有源码 tag、编译器、优化、架构和配置来源的真实构建；以相邻版本差分和多个独立函数确认，整组留出厂商/版本/架构测错误率。不要将本轮 API 形态夹具冒充该语料库。

## 产物与复现

本地目录：`reports/function-version-experiment-20261118/`。真实固件、抽取对象和大扫描产物按原 Git 规则忽略，不提交。ICU 子任务已提交的两个小型 scout 报告只含文本/JSON；最终汇总以本报告和下面的最终结果为准。

- [比较结果与修订检查点](../reports/function-version-experiment-20261118/comparison.json)、[文件级版本证据](../reports/function-version-experiment-20261118/file-version-observations.json)、[最终一致性与控制汇总](../reports/function-version-experiment-20261118/verification.json)。
- [Allwinner analysis](../reports/function-version-experiment-20261118/after/allwinner/system_analysis.json)、[SBOM](../reports/function-version-experiment-20261118/after/allwinner/system_sbom.json)；[system analysis](../reports/function-version-experiment-20261118/after/system/system_analysis.json)、[SBOM](../reports/function-version-experiment-20261118/after/system/system_sbom.json)。
- [输入哈希](../reports/function-version-experiment-20261118/input-manifest.json)、[冻结代码哈希](../reports/function-version-experiment-20261118/source-manifest.json)、[Luna 路由核对](../reports/function-version-experiment-20261118/agent-routing.json)。
- [语义控制](../reports/function-version-experiment-20261118/controls/results.json)、[ICU 控制](../reports/function-version-experiment-20261118/controls/icu-results.json)、[独立审查与修复复核](../reports/function-version-experiment-20261118/probe-review.md)、[ARM 独立核验](../reports/function-version-experiment-20261118/scout/REPORT.md)。

复现命令与依赖见[实验 README](../experiments/function_versions/README.md)。本轮已取得真实扫描的正向收益；总体精确率、全组件真值覆盖、任意无符号代码、完整 CLI 及设备执行仍未验收。
