# 固件组件版本覆盖：行业方法与本项目的投入方向

日期：2026-11-18。项目核查基点：`e890f0c`，分支 `codex/function-version-experiment`。本轮是公开资料研究和现状核查，未实现下面的新识别管线，未产生新的固件扫描结果。两项并行调查均使用 GPT-6 Luna；主 agent 复核关键来源、项目代码和结果口径。

## 结论

当前版本覆盖不满足用户的产品可用目标。此前扩充 banner/符号规则和少数版本函数路径，覆盖了少量可见线索；主投入应转向**完整展开、带来源的多版本参考库、代码候选检索、版本差异确认**。有构建资料时，再用构建 SBOM 与二进制观察交叉核对。

这不是一个公开证据支持的“换上某个模型就能达到某识别率”的问题。下面区分已核查的源码机制、论文方法和厂商声明；都还没有成为本项目的新增实测效果。

## 业界如何处理不同情形

### 有构建过程：从生产环节取得组件来源

AOSP 在 Android CI 中生成 SBOM，也提供 `m sbom` 构建入口；Yocto 提供 `create-spdx` 构建产物与依赖信息。这一路直接利用构建时已知的组件来源、版本和依赖，比在最终镜像中重新猜测信息更直接。[AOSP 官方流程](https://source.android.com/docs/setup/create/create-sbom)、[Yocto 官方流程](https://docs.yoctoproject.org/dev/dev-manual/sbom.html)

本项目可增加可选的构建 SBOM、供应商清单和源码版本元数据输入，并用文件证据核对其是否对应当前固件。只有固件时，仍需下面的二进制识别路线；不能把提供源码或 SBOM 变成扫描的前提。Android 系统版本、APEX versionCode、APK versionName 均不能替代其中每个第三方库的发布版本。

### 只有固件且保留线索：元数据与逐组件规则

EMBA 使用包数据库、包归档和语言生态元数据，也维护组件字符串规则；cve-bin-tool 的 checker 使用组件身份模式与版本提取规则。Syft 的 Go binary cataloger 能读取 Go build info 中的模块与依赖版本。这些方法适合仍有包信息、banner 或构建信息的文件。[EMBA](https://github.com/e-m-b-a/emba/wiki/Increase-component-identification-rate)、[cve-bin-tool](https://github.com/ossf/cve-bin-tool/blob/main/doc/README.md)、[Syft Go cataloger](https://github.com/anchore/syft/blob/main/syft/pkg/cataloger/golang/parse_go_binary.go)

我们的规则层应继续维护并接收格式化元数据，但大量无标记的 C/C++ 代码还需要参考样本和代码特征。详细源码调查见[开源工具报告](industry-open-source-binary-sca-2026-11-18.md)。

### 无版本字符串或静态链接：参考样本与代码匹配

Black Duck Binary Analysis 官方文档明确列出文件 checksum、组件指纹库和包管理器数据库等匹配方法。其 Vendor Components 功能允许用已知组件样本建立指纹，并说明链接裁剪会影响指纹命中比例、降低阈值会增加误报。这提供了公开的产品机制例子：识别能力需要参考数据及匹配策略共同支撑。[官方匹配方法](https://docs.blackduck.com/r/bdba/latest/black-duck-binary-analysis-user-guide/understanding-results-the-vulnerability-analysis-tab.html)、[官方自定义组件指纹说明](https://docs.blackduck.com/r/bdba/latest/black-duck-binary-analysis-user-guide/vendor-components.html)

可复用的开源能力是 Ghidra BSim：由反编译器的数据流、控制流生成函数特征，在参考数据库中检索近似函数。它能帮助定位同源代码，适合验证静态链接或符号缺失文件的组件身份；实际效果需要在目标编译配置上测量。[BSim 官方原理](https://github.com/NationalSecurityAgency/ghidra/blob/master/GhidraDocs/GhidraClass/BSim/BSimTutorial_Intro.md)

Finite State 宣称能识别静态链接和修改后的组件；Binarly 公开材料介绍二进制相似度、依赖与 SBOM 分析。但厂商没有公开足以复现其完整版本算法和参考库的资料，本轮也没有实测其产品，不能给出它们在这两份镜像上的识别率。[Finite State 产品页](https://finitestate.io/platform/binary-analysis)、[Binarly 平台公告](https://www.binarly.io/news/binarly-unveils-nextgen-firmware-protection-transparency-platform-revolutionizing-device-supply-chain-security)。更多边界和对照方法见[商用调查](industry-commercial-binary-sca-2026-11-18.md)。

### 已知库身份，但相邻版本很相似：做版本差异确认

BSim 为适应编译差异会有意忽略常量值、寄存器名等信息。因此，相似函数候选不能单独确认补丁级版本；一个只改变版本常量的 getter 就可能无法靠这一特征区分。我们需要另保留版本敏感的常量、分支、表格、函数变化和引用关系。

LibvDiff（ICSE 2024）提供了相关研究路线：用版本间差异缩小候选，再结合函数代码与调用路径进行版本判断。其公开实现包含多版本、多架构和优化配置的参考构建；论文中的准确率只对应其数据与实验，未在本项目复现。[论文](https://gentlecp.github.io/pdfs/LibvDiff_ICSE_2024.pdf)、[作者实现与数据说明](https://github.com/GentleCP/LibvDiff-public/)

因此，本项目应分别建设“库身份检索”和“版本确认”。前者允许对编译变化归一化，后者必须保留能区分候选版本的差异。缺失函数可能源于编译裁剪，不能把未观察到某函数直接当作该版本不存在。

### APK 中的 Java/DEX 库：建立独立的字节码参考库

LibScout 的方法以原始 JAR/AAR 建立库 profile，再与 Android 应用中的字节码结构匹配。它说明 APK 内的第三方 Java 库需要自己的参考资料和特征路径，而不只是扫描 `lib/*.so`；公开项目也允许多个候选版本结果。[LibScout 官方仓库](https://github.com/reddr/LibScout)

这是值得评估的方法，不代表旧项目的现有 profile 已覆盖本项目的应用或最新 Android 构建。APK 自身版本不能移植给内嵌 SDK。

## 当前代码中确认的缺口

| 缺口 | 当前证据 | 对下一步的影响 |
|---|---|---|
| 规则层没有替代多版本参考库 | `binary_reference.py` 接受 `banner` / `identity_only` 两类规则；当前扩库为 78 条规则、72 个归一化家族 | 应把“规则条数”和“可比较的真实版本构建数”分别管理 |
| 缺少通用函数参考检索管线 | `BinaryInventory.extract` 组合 ELF 线索、规则、有限 getter 和 EMBA 补充；没有多版本函数索引 | 需要新的语料生产与检索模块，扩大现有正则表不足以覆盖这部分 |
| 默认已验证整文件哈希数据为空 | `hash_matcher.py:17` 的 `KNOWN_BINARY_HASHES = {}`；当前 Android `BinaryInventory` 没有直接调用它 | 既要有真实参考数据，也要接入实际入口；仅填充这个字典不等于完整方案 |
| APEX 内容未深入 | `system_scanner.py:320` 起只解析 ZIP 顶层 manifest，并从 protobuf 查 `.so` 名；没有分析 `apex_payload.img` | 先补容器内部文件的获取，再谈其库识别效果 |
| 大文件存在分析范围缺口 | APK 128 MiB、ELF 32 MiB、内嵌库数量和总字节限制；system 实扫仍有三条覆盖告警 | 改为有预算的随机读取/按条目处理，记录跳过范围；不能只无界提高内存上限 |
| 函数实验依赖少数已知 API 形态 | 当前实验支持有限的 x86-64、AArch64、ARM/Thumb 路径 | 保留为版本证据插件，不能视作通用 stripped 库匹配器 |

源码位置：[规则匹配器](../src/firmware_scanner/extraction/binary_reference.py)、[当前识别入口](../src/firmware_scanner/extraction/binary_inventory.py)、[哈希匹配器](../src/firmware_scanner/extraction/hash_matcher.py)、[Android 扫描器](../src/firmware_scanner/android/system_scanner.py)。

AOSP 官方格式说明明确将 APEX 内部文件放在 `apex_payload.img`，所以顶层模块版本解析不能覆盖其内容。[APEX 格式](https://source.android.com/docs/core/ota/apex)。本项目的两镜像数据、修订统计和已知边界见[实测报告](function-version-experiment-results-2026-11-18.md)。

## 建议实施路线

以下是基于调查提出的方案，尚未实现或测出收益。

1. **补齐输入覆盖，并生成漏扫清单。** 对 APEX payload、APK/归档内条目和文件系统逐层读取；将实际分析文件与超限、损坏、未支持对象逐项关联。内容哈希缓存可避免多路径、多架构重复文件反复分析。每个内部组件保留容器与文件位置。
2. **把参考库建成可持续生产的数据资产。** 按两镜像实际未知样本选择首批组件，收集上游 tag/commit、AOSP 对应来源、公开已知二进制或可追溯的供应商源码。每次构建记录来源、源码摘要、架构、编译器、优化、配置、链接方式、产物摘要与调试符号。保留源码版本和厂商构建标识，不能混成一个字段。整文件哈希负责同字节产物，函数/代码特征负责变体检索。
3. **建立两阶段识别。** 首先利用元数据、身份规则和函数/代码区域匹配召回组件及候选版本；对公共工具函数降权，用多个独立函数及其调用关系确认归属。然后仅检查候选版本间有区分力的代码位置，并结合已有 getter/banner 证据确认版本。冲突、候选集合及可支持的范围应保留，禁止自动把最高分变成精确版本。
4. **为 Java/DEX 增加专门路径。** 评估 JAR/AAR profile 到 DEX 的结构匹配，分别验证混淆、裁剪与版本区分能力；与 native 组件证据汇合，避免把宿主 APK 版本赋给依赖。
5. **单独验证厂商补丁状态。** 在上游版本、厂商分支、构建标识之外存放补丁证据。具体安全修复可以用源码/二进制差异核验；不能用旧版本号推导必然未修，也不能用 Android SPL 推导某库已修。

可优先用 Ghidra BSim 的本地数据库验证函数候选检索，再决定生产索引方案。官方提供命令行生成签名和入库流程，本轮尚未安装、建库或运行此验证。[BSim 命令行](https://github.com/NationalSecurityAgency/ghidra/blob/master/GhidraDocs/GhidraClass/BSim/BSimTutorial_BSim_Command_Line.md)

## 下一轮怎样验证有效

采用固定的两镜像及独立参考构建，不再只围绕此前的少数 getter 命中点验证：

| 对照 | 要回答的问题 |
|---|---|
| 已提交产品基线 / 有限函数原型 / 新参考检索 / 再加版本差异确认 | 每一层实际补回多少正确身份和正确版本？引入哪些错报？ |
| 已有成功样本 / 当前未知样本 / 完全未进入分析的容器内容 | 收益来自更好识别、补充输入，还是重复枚举？ |
| 同版本不同编译器、优化、架构、链接与 strip 构建 | 匹配能否跨构建配置，而不是只记住样本字节？ |
| 整组留出的供应商分支与参考库中不存在的版本 | 是否误报最接近的已知版本？是否能给出有依据的候选范围？ |
| 相邻版本、仅改版本常量、只回补丁、通用代码复用的反例 | 是否把代码相似误当作精确版本或补丁状态？ |

真值由可信源码/构建资料或独立文件证据建立，被测扫描器和商用工具的输出都不能直接作为真值。保留当前未知样本和未分析范围，不通过缩小统计范围制造提升。按镜像分别报告：正确组件身份、正确精确版本、版本范围、错误版本、仍未知、未分析，以及运行成本。定向核验集的通过率不代表所有组件的准确率。

该路线中的“版本差异驱动核验”已有研究先例，不能宣称首创。值得本项目验证的工程提升是：针对真实候选只分析有区分力的代码，把结果关联到具体文件与地址，并以同一证据链区分上游版本、厂商分支和补丁状态。是否优于当前扫描器，以新增实测为准。

## 研究核验记录

- 已独立核查 AOSP SBOM/APEX 文档、Ghidra BSim 原理、LibvDiff 论文/作者实现及关键项目源码；两份 Luna 分工报告链接如上。
- Black Duck 部分页面直接打开失败，关键匹配方法与 Vendor Components 内容通过该厂商官方文档的搜索索引核查；没有据此验证其算法或实际准确率。
- Finite State 官方更新日志提供组件版本识别与修正规则的具体记录，但未提供本项目可套用的准确率。商用产品机制披露和实际效果仍须分开。[官方更新日志](https://docs.finitestate.io/changelog/)
- 本轮仅新增/修订研究文档；未改产品识别代码，未产生新的识别增益数据。
