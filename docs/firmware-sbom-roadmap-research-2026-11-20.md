# 固件 SBOM 路线图一手资料研究

日期：2026-11-20
范围：只读研究。本文依据用户提供的路线图、当前仓库已有报告快照和下列一手资料编写；没有修改扫描器代码，没有重新扫描固件，也没有验证路线图中的实验数字。

## 结论先行

路线图的方向大体正确：从单一字符串规则转向多证据融合；把版本值、版本来源和可信等级分开；先做包管理器/构建元数据等强证据；对弱证据保留 unknown 或版本等价类；建立 held-out 真值集；把关系、许可证、漏洞与证据链纳入产品闭环。

路线图中的量化承诺尚不能接受为计划基线。现代 Android 的“usable coverage 69.53%”把 560 个 estimated 版本与 225 个 exact 版本相加；同一快照中 `independently_verified=0`、`correct=0`，因此它证明的是版本字段覆盖而非真实召回或准确率。Allwinner 的对应数字为 32.65%；其中只有 5 条 AOSP 来源校准真值且 5/5 正确，远不足以验证全镜像准确率。路线图承诺的 50%、65%、70% 召回率、95% 精确率、DEX/扫描耗时目标、Rust 求解率、依赖边与 License 覆盖率均需按明确分母、held-out 数据和实测重跑后才能接受。

对两份当前固件，最高优先级应是先把已知的真实组件身份转成可验证版本证据：平台/厂商构建溯源与组件来源映射、可读的包/模块/语言元数据、每个候选对应的官方发布制品和二进制内生版本点。随后再做有封闭候选集的原生库差异识别。BLintDB 的 callgraph/function fingerprints 应被当作身份候选生成器；NSRL 应被当作精确文件身份和分发 provenance 的辅助来源。两者都不能单独证明任意重编译固件中的组件版本。

## 研究范围与本仓库事实

路线图提出通用固件路由、统一 ELF/PE/Mach-O 中间表示、多层版本识别、Rust 源码行号差分、C/C++ Version-Delta、DEX 指纹、门控 Ghidra BSim、依赖关系、License 与独立真值集等方案。以下区分：

- **路线图事实**：文档内记载的历史测量与主张，尚未由本轮重新实验验证。
- **仓库快照事实**：读取当前 `reports/version-coverage-getters-20261120/final-summary.json` 的记录。
- **来源支持的事实**：标准或项目官方资料明确支持的能力。
- **推断/建议**：结合来源能力与本项目当前缺口给出的优先级判断，仍需实验验证收益。

当前快照显示：

| 目标固件 | 固定组件队列 | exact | estimated | usable 字段覆盖 | independently verified |
|---|---:|---:|---:|---:|---:|
| Android 16 `system.img` | 1,129 | 225 | 560 | 785/1,129 = 69.53% | 0 |
| Allwinner Android 4.4.4 | 582 | 119 | 71 | 190/582 = 32.65% | 5（开发校准） |

同一报告记载的数据库实测中，BLint 在现代固件确认 9 个组件身份、Allwinner 确认 4 个并复核 5 个组件；NSRL 分别 0/1,789 和 0/430 文件命中。BLint 参考版本一致数为 0、mismatch 为 8（现代）与 3（Allwinner），另有 1 个 Allwinner 目标版本不可比较。这意味着 BLint 这轮提供了有限身份佐证，没有带来直接版本确认；NSRL 对这两个镜像的精确哈希未命中。该结论仅适用于这次报告使用的数据版本、查询口径和两份样本。

路线图记录 Android NOTICE 唯一源码仓候选覆盖 332 个未知原生库，以及 Rust 上下文记录覆盖 62 个库中的 39 个、共 2,256 个代码引用点；这些是值得优先利用的现有资产，但候选身份数、源码位置数不等于版本真值命中数。路线图还记载了“多 DEX 只读首个 DEX”“32 MiB ELF 上限”等代码问题；本研究未检查代码，也未确认这些问题在当前分支仍存在，需以现行实现和回归复现为准。

## 1. 建议采纳、调整后采纳与暂缓项

| 路线图建议 | 结论 | 理由与落地边界 |
|---|---|---|
| exact / estimated / unknown、版本等价类和证据范围显式分层 | **采纳** | 版本字段存在不代表可用于漏洞判定。CycloneDX 支持 component identity evidence；OSV 数据质量规范要求版本/提交范围精确并能映射到生态系统。输出必须保留方法、来源、观测值、候选范围与置信依据。 |
| 包数据库、JAR/Maven 元数据、APEX 清单、Rust 嵌入依赖清单等强证据优先 | **采纳，严格限定语义** | 这些元数据可直接携带包标识和版本，但只有当它确实与目标文件/组件形成可证明的关联时才可归属。外围同名 `METADATA`、源码 tag 或父包版本不可自动当成二进制版本。APEX manifest 的 versionCode 是 APEX 模块版本，不是其中每个 ELF/JAR 的上游版本。 |
| Android Repo manifest、构建属性、NOTICE 与源码仓用于组件溯源 | **采纳，拆成身份与版本两步** | Repo manifest 将 Android 多 Git 项目聚合到指定 revision；Android build 可记录平台构建 ID。NOTICE 更适合许可证/项目候选线索，不等价于“该库二进制来自某个仓库某个 tag”。需要 path/module/target/product/构建 commit 的连接证据。 |
| 官方 distro 包与语言包仓的参考样本 | **采纳，作为候选数据库/真值切片** | 哈希精确匹配、包版本与文件归属可形成强证据。对重新编译、厂商 patch、不同架构/编译选项的样本，完整哈希通常失效；官方发布制品与目标不同时只能作为候选参照。Maven Central 的 GAV/POM/制品哈希对 Java 很有用。 |
| BLintDB 作为符号、函数特征与 callgraph 数据库 | **采纳，作为召回候选和排序证据** | BLintDB v2 记录 project/build/binary、符号、动态依赖、函数指纹和 source/binary callgraph。官方项目说明其调用图匹配可为剥离二进制生成候选；这不构成单独的版本判决，须验证目标候选在当前 corpus 是否有对应架构、构建形态与跨版本区分特征。 |
| NSRL 哈希比对 | **采纳为精确文件指纹旁证** | NIST RDS 是已收集软件文件的哈希与元信息集合，适合确认原样文件及来源记录。它不是针对任意 OEM 编译变体的代码相似度/组件版本数据库；零命中不表示固件无该组件。当前 NSRL 发布已转向 SQLite RDSv3，应固定数据版本、校验下载签名/哈希并保留查询记录。 |
| C/C++ Version-Delta：先定项目，再以跨版本差异点裁版本 | **作为研究原型采纳** | 方法设计比“字符串出现就猜版本”可靠，特别是负证据和不可区分版本组。但 2 个 delta、矛盾率 <10% 等阈值是路线图作者提出的启发式，不是行业标准；须做版本留出、编译器/架构留出和相邻版本挑战集，测校准后的精确率/召回率。 |
| Rust panic/unwrap/expect 源码行位置差分 | **低成本实验，禁止提前写成 +39~62 版本命中** | 当前数据资产使它值得先做离线可行性实验。行号会随 patch、宏展开、内联、LTO、路径重写和编译器变化；精确列号/行号命中可能说明源码近似关联，却不保证唯一定版。需多版本、多个 target 和实际固件回放比较，并和源码提交/发布包证据独立交叉验证。 |
| 依赖图、双轨 License、CycloneDX 证据输出 | **采纳为产品成熟化主线** | CycloneDX 有 components、dependencies、evidence、licenses 和 vulnerabilities；SPDX 也有规范化 license 与包/文件关系表达。ELF DT_NEEDED 是运行依赖边，不等同于源码依赖或静态包含关系；NOTICE/上游 License 只能按关联证据标明来源，冲突要保留而非自动覆盖。 |
| 门控 Ghidra BSim | **暂缓到轻量候选引擎评估后** | 成本和维护面明显高于哈希、包元数据、符号、版本对象和候选项目差分。用户目标首先是改善两份样本真实版本召回。先证明其在 held-out 样本有额外净增量，再决定部署、资源预算和长期升级成本。文中对 H2/PG、插件耗时、准确率的具体断言需另行复核 Ghidra 官方资料和本机复现实验。 |
| 通用 FirmwareRouter、统一 IR、UEFI/RTOS/全形态扩展、QEMU `--version` | **分阶段，不作为当前版本率主线** | 对未来固件品类有产品价值，但现有 Android 样本上尚未证明其提升。QEMU 执行可能依赖架构、动态库、环境和参数，输出可被包装脚本/版本兼容性误导；只能作为隔离后的低权重运行证据。先做最小接入和分类型评测，避免摊薄 Android 准确率工作。 |

## 2. 夸大、不可直接承诺或待验证的说法

1. **“现代固件版本覆盖已经达 69.53% / 目标 50% 已达成”**：这是固定队列上 exact+estimated 的字段覆盖。报告的 `independently_verified=0`，因此不代表 69.53% 版本召回，更不代表正确率。建议仪表板同时报告 identity precision、exact-version precision、estimated-version precision、version recall、unknown rate、组件召回和组件精确率；未标注真值的数据只能标为 coverage proxy。
2. **“版本准确率 ≥95%、50/70% 版本召回”**：没有 held-out 真值和抽样策略时不可承诺。160 个样本的计划规模可做第一轮 smoke/探索集，但总体精确率置信区间可能很宽，且按 Android/原生/JAR/Rust/架构分层后每格更小。需要按样本独立性估算置信区间、固定开发/验证/盲测拆分并防止同一项目相邻版本跨集合泄漏。
3. **Rust Top-500、+39～62 命中、≥60%/85% 命中率**：路线图把“具备源码位置记录的 Rust 二进制/目标”与“能唯一识别版本的目标”混在一起。可先以已有 39 个有记录的对象做回放，但测量单位要是 unique binary/component，答案需由独立版本清单确认，不能把源行命中率替代版本准确率。
4. **Android NOTICE 的 332 个唯一候选可直接投入差分定版**：NOTICE 条目通常陈述许可证/项目和文件，不能单独证明打包 ELF 与特定 upstream release、patch set 或构建配置的关系。它有助于缩小候选项目集；版本仍要靠可归属的构建溯源、二进制内生版本对象/差异或版本化参考样本。
5. **跨版本二进制差分以“两处 Delta + <10% 矛盾”就达到高精度**：属于待训练、待校准的 heuristic。编译器/架构/优化选项会改变字符串和函数边界；LTO、条件编译、厂商补丁会漏掉特征。必须按 component family 做独立测试，报告 coverage-risk 曲线与 abstain/等价类比例。
6. **Rust `Δline`、字符串附近行号、静态版本对象可普遍抗 patch/混淆**：只能在被测项目和构建模式上验证。版本字符串可能沿用、被厂商改动或来自兼容层；源码行号也可能被重排。任何单个弱特征都不应让 estimated 自动升级为 exact。
7. **BSim 作为通用版本识别终局**：函数相似通常有利于项目/家族归属；相邻发布版本的代码主体可以相同，匹配本身不能保证小版本。只有在训练样本包含目标项目的对应发布版本，且特征能分开相邻版本时，才可能裁版本。
8. **Android 16 <200s、RSS <1.2GiB、差分扫描收益、版本覆盖 KPI**：当前仓库快照中的 0.13 Modern 单次为 452.7s、峰值 RSS 约 2.42GiB；此前不同运行有 337.6s。硬件负载和扫描选项不同，不能据此断言算法退化，但路线图的 <200s 也未实证。性能 KPI 应先固定主机、并发、冷热缓存、扫描选项和重复次数，报告中位数/p95 与内存峰值。
9. **依赖边 95%、License 覆盖 90%**：DT_NEEDED 能覆盖部分动态 ELF 关系，无法直接推出完整依赖图（静态链接、插件/dlopen、APK/Java、服务调用等）；License 命中率也不能替代文本级许可证识别 precision、未知/冲突处理、NOTICE 与组件映射正确性。
10. **通用“已扫描 BOM 中漏洞数量”代表漏洞已证实存在**：OSV/CVE 查询是已知公告与组件版本匹配。若版本只是 estimated、PURL/生态归属错误、downstream backport 未建模，结果只能是候选；VEX 的 `affected/unaffected/unknown` 与理由需要有针对性的分析证据。CycloneDX 官方也明确推荐让随时间变化的 VEX 与相对静态 BOM 解耦。
11. **“全文件 SHA256 参考库可大幅提升二进制版本召回”**：对原样官方包很强，对 OEM 重链、strip、patch 和不同 target 常低召回。NSRL 当前两份镜像为 0 命中，BLintDB 尚未显示版本一致命中。哈希数据库仍有价值，但预期增量应在当前固件留出样本上量化，不宜以数据库体量推断收益。
12. **“构建源码发行版即能给出固件组件版本”**：源码 tag/manifest 与目标二进制之间缺少构建映射时，只能形成参考库。Android 平台 build ID 是整机/平台构建标识，APEX versionCode 是模块包版本，都不能无条件赋给其内的第三方库。

## 3. 下一优先级：按证据强度、成本和可测净增量排序

下表的“预期增量”是**实验对象与测量方式**，不是收益预测。先对当前两份固件重新计算基线和固定分母，再逐项做 ablation。

| 顺位 | 工作项 | 证据强度 | 成本 | 当前可测净增量 | 为什么排此位 / 退出条件 |
|---:|---|---|---|---|---|
| 1 | **建立冻结的组件级真值切片和口径门禁**：对可核验样本维护固件 SHA256、路径、组件/PURL、版本真值、真值来源、验证人/日期；把组件身份精确率、版本 exact/adjacent/unknown 分开 | 高（方法学基础） | 中 | 当前报告已显示可立即发现“字段覆盖≠准确率”；数量增量未知 | 不先做它，后续收益无法分辨。用 held-out 样本；至少抽样复核每种推断方法。每次扫描固定去重/全路径两个分母与 taxonomy 分层。 |
| 2 | **先对可读元数据做组件级归属和读取闭环**：APEX manifest、JAR `pom.properties`/manifest、Maven POM/哈希、Rust auditable section、系统包数据库、Build ID/增量版本、文件路径/签名/安装包关系 | 高（标准/工具直接定义元数据字段） | 低到中 | 按固件内可存在的元数据文件/二进制逐类统计命中；预计 Modern 的 JAR/APEX 有较好验证面，未承诺具体数量 | 元数据只能绑定其声明对象；把父包/AOSP 平台/普通文件名版本与第三方二进制版本隔离。输出每个对象原始来源与归属规则。 |
| 3 | **对 Android 构建溯源建立 `path → module/target → repo project/revision → output` 映射**，联用 manifest、build properties、APEX、NOTICE/许可记录、可获得的官方 build/source manifests | 中高（AOSP Repo 架构/平台构建资料是官方；当前固件映射需本地验证） | 中 | NOTICE 的 332 个单候选可作种子集，能带来多少“可验证版本”尚未知 | 这是可能同时改善身份与版本的高 ROI 途径。只有当源码 revision/构建目标能与成品关联时才升级版本结论；AOSP manifest revision 可记录为 source/build provenance，不能冒充 upstream package release。 |
| 4 | **从 BLintDB 取版本感知候选，但评估数据库命中可迁移性**：候选记录需带 PURL、具体 build/arch/optimization/strip 信息；利用符号、import 集、函数 fingerprint、source/binary graph 召回多个候选；与内生版本证据交叉确认 | 中（数据库 schema/功能公开；跨编译匹配性能需实测） | 中 | 已有实测身份确认 9 和 4；当前参考版本一致 0；下一轮要测额外候选数、版本排名、错误项目数、exact 版本数 | 先选 20–50 个明确上游项目做 query-level ablation，避免全库拉取/重建。只按未见固件评估。没有对应 build variability 的匹配应停留在身份候选层。 |
| 5 | **版本 getter/object/字符串 + 官方发布样本的候选范围测试**：优先已有可确认的只读对象/成对函数；按架构与编译方式收集离线官方发行样本 | 中高（目标内生版本对象若语义与归属无冲突是强证据） | 中 | 可按“新增 exact / 等价类 / 错误版本”逐组件报告，未有全量量化 | 防止仅凭宏、文档串、依赖路径或 compat string 误定版。至少覆盖相邻版本和同名不同分支挑战样本。 |
| 6 | **C/C++ Version-Delta 小规模原型**：选 Android NOTICE 已唯一收敛、且官方 tag/构建样本好获取的 10–20 个项目；每个至少多版本、多架构/编译配置；冻结阈值 | 中低（想法合理，目标数据上的可用性未证） | 中高 | 直接测同项目候选排序 top-1/top-k、精确版本/等价类、coverage-risk；增量未知 | 若无法跨编译设置保持校准的版本区分率，则只保留项目识别信号，不接 VEX/CVE 的精确版本路径。 |
| 7 | **Rust 行号/代码位置求解器作为限域实验**：从已有 39 个上下文库中选出可取官方历史 crate、已知实际版本的样本，检验不同 release 的判别性及 patch/编译器稳健性 | 低到中（已具目标端观测点；版本判别性未证明） | 低到中 | 以“已独立验证的版本覆盖净新增”衡量，不报告行号命中率当作版本召回 | 如果相邻版本经常并列或跨 target 不稳定，作为候选家族识别或 abstain 证据。Top-500 扩库须等小实验有正收益再做。 |
| 8 | **DEX/JAR 版本参考语料和结构 fingerprint** | 中（Maven 元数据/制品路径可获取；混淆环境分辨率不确定） | 中高 | 测 Maven 哈希、pom、类/方法结构三种证据分别新增的组件和版本 | 先对未混淆 JAR 与已知 R8 版本做独立 split；对混淆样本可能只给候选/家族。不要先把 Top-300 当作覆盖承诺。 |
| 9 | **门控 BSim、RTOS/UEFI/QEMU 与全通用路由** | 低（相对当前 Android 版本目标） | 高 | 当前两固件上的额外 verified version 是否大于维护/运行成本 | 只有轻量层饱和且回放显示有明显净增量时，才投资源做 benchmark。 |

**实验汇报最小字段**：每项新增 exact / estimated / equivalence / unknown 数；组件身份新增/错误数；对每个候选的匹配分与矛盾特征；版本是否由独立真值命中；按 unique content 与路径两种口径；处理耗时、峰值内存；开发集与盲测集哈希。这样可以判断提升来自真版本识别，还是只提高了非空率或重复路径数量。

## 4. 将 BLintDB 和 NSRL 做成产品中有用的证据

### BLintDB：候选和相似度证据库

BLintDB v2 不只是符号表：上游项目文档列出了 Projects/Builds/Binaries、文件哈希、符号、动态依赖、函数级 fingerprints，以及 source/binary callgraph。合理的产品集成方式是将其作为可版本化、可审计的离线 reference corpus，而不是“黑盒命中即版本”：

1. **语料供应链**：固定 DB schema、源仓库 commit、输入项目和版本清单、下载/构建成功失败、架构/编译器/优化/strip 配置、各表计数、数据库 SHA256；更新时保留旧版本可回放。
2. **先做 identity candidate ranker**：目标二进制抽取 ABI、导入/导出符号、SONAME/NEEDED、callgraph/function fingerprints；按多项独立信号返回 top-k 项目/PURL 和可解释命中项。符号名称相同、单函数 hash 命中、架构不匹配都要有不同权重。
3. **version stage 独立判定**：候选 project 下面必须有多个真实发布版本，且匹配特征能分辨版本。若数据库仅存一个 release 或分数相近，报告“组件候选已确认/版本未决”或版本等价类；不得把候选库的版本继承成目标版本。
4. **把查询过程序列化为 provenance**：reference DB digest、query binary SHA256、提取器版本和选项、匹配算法版本、top-k 分数、正证据/反证据、门槛、弃权原因写入扫描记录，并映射到 CycloneDX component `evidence.identity` 或外部 JSON sidecar。数据库参考组件与固件 observed component 分开保存。
5. **按当前数据做现实评估**：当前摘要中的 9/4 个身份确认是有用 seed。因 reference-version agreements=0 且 mismatch 多，下一轮应将 mismatch 样本逐一审查：这是同一组件不同编译/分支、旧候选数据库错误，还是版本证据不可比？以独立真值定原因，不可以靠调低阈值把 mismatch 变成 match。

### NSRL：原样文件精确确认和 provenance 线索

NIST 说明 RDS 是软件文件收集的公开子集，记录文件哈希与描述元信息；当前发布页说明 RDSv3 SQLite 已成为后续发行格式，并提供发布版本/下载及 README。对产品而言：

1. 记录 hash algorithm、digest、NSRL publication ID、DB hash、关联 File/Prod/OS 表、匹配行、查询状态和唯一匹配/多义匹配情况。
2. Exact hash 命中可以证明目标文件与 RDS 中某条记录内容相同；若 RDS 元数据还关联到可信产品/发行版，可增强文件来源推断。要明确这里识别的是**文件内容**，未必等于该文件自身声明的开源库上游版本。
3. 多个软件产品共用同一文件、安装文件与运行文件不同、RDS 只覆盖样本集合、厂商重编译导致 hash 变化，都会降低组件级版本解释力。查无结果是 no-match，不是 negative proof。
4. 以查询和增量构建做本地 benchmark：已知 exact 文件正例、近似但不同文件负例、同哈希多产品样例；将数据库版本升级前后差异报告纳入 CI。两份目标固件当前 0 命中，优先保留能力但不能把其当本固件版本召回主引擎。

### 统一的证据数据模型

每条证据应至少有：`subject_sha256`、固件分区/路径、分析对象（容器/二进制/包）、claim（组件身份、版本、license、关系）、observed value、source URI/DB release+digest、method/tool version、支持/反对/上下文角色、置信/校准版本、适用范围、时间戳。推导 claim 还要保存输入证据 ID 与规则版本。CycloneDX 可承载 component identity evidence、hashes、licenses、dependencies、pedigree 和 vulnerabilities；对超出标准字段或需保留多个候选/打分的内部细节，应提供稳定外部 evidence report 并从 BOM 引用，而不是滥用自由文本字段。

## 5. 商业化成熟度缺口与验收设计

### 真值集和精度门禁

- **版本真值**：优先采用发布包元数据/签名清单、确切系统构建 manifest、可重建 build manifest、APEX 自身 manifest、JAR GAV 和原始制品哈希、cargo-auditable embedded dependency data 等独立材料。固件自身待评的同一字符串规则不能再当真值。
- **分层与泄漏控制**：按固件家族、组件生态、CPU 架构、编译配置、strip/LTO、厂商 patch 分层；同一项目相邻 release 和同一构建模板不可同时落入开发和最终盲测集。以固件镜像/构建为独立抽样单位，避免把复制的文件当独立样本。
- **至少报告**：组件 identity precision/recall；exact version precision/recall；equivalence-class truth containment；estimated version accuracy（exact/adjacent/wrong 分开）；unknown/abstention；coverage-risk 曲线；bootstrap/二项置信区间；按语言、架构、taxonomy 及方法分层。对安全用途，低证据结论可以弃权。
- **门禁**：每个信号/规则变更做 held-out regression；每个“可用于 OSV exact query”的版本来源设高阈值和零越权语义测试；precision 下置信界而非点估计作为发布门槛。小样本集只作为早期质量闸，不得宣称代表全市场。

### 证据链与关系图

- 所有提取结果必须能从组件 claim 反查到镜像 digest、文件 digest/path、分析工具版本、数据库版本、匹配证据和决策阈值。
- CycloneDX components 数组表达层级/组件组装，不应被误当完整依赖树；`dependencies` 关系要表达有证据的边。ELF DT_NEEDED、DEX/JAR 静态调用依赖、APEX contains、APK package、固件分区包含边必须区分关系类型和来源。
- 静态链接/复制代码、插件动态加载、运行时网络依赖不能被 ELF NEEDED 图覆盖；未知边要留空/unknown，不能伪造“完整”。报告 BOM completeness/composition 声明和发现限制。

### License

- 组件识别与 license 识别是两个 claim；上游仓库 SPDX 文件、二进制旁 NOTICE、安装目录 license 文本、代码片段匹配各自需要自己的关联证据。
- 以 SPDX License List 的 identifier/exception 规范化输出；识别不确定、多个文本、厂商修改或源/二进制冲突时保留原文、表达式和冲突，必要时列为 `NOASSERTION`/未知并交法律审查，而非以组件目录推测 license。
- 需测试 license text 识别的 precision/recall、异常 license、NOTICE 映射、组件覆盖和多 license 表达。SPDX 标识规范化不是法律结论。

### CVE / OSV / VEX 语义

- OSV 的 affected package、ecosystem、version ranges/commit ranges 是机器可判定的范围，不是任意版本字符串的模糊比较。版本不 exact、PURL ecosystem/name 不确定、版本格式不兼容时，应保留 `unknown`/候选，不自动报告“受影响”。
- AOSP/downstream backport、发行版补丁和 OEM patch 可能让版本号相同但漏洞状态不同；需发行版公告/补丁状态或代码级影响分析。OSV 官方资料指出 C/C++ 覆盖依赖 commit-level 数据，且数据完整性仍在持续建设。
- VEX 是产品上下文中的影响分析陈述，应对接精确的 BOM component ref、公告、状态、justification、分析依据和签发时间。`not_affected` 不能由“版本范围没匹配”自动推出；版本未知应保持 unknown。
- CycloneDX 指南建议 VEX 与相对静态 BOM 分开演进，使漏洞状态更新无需重建整个 BOM。产品应提供单独的 VEX 生命周期、签名/来源和回溯。

### 可复现、供应链和版本管理

- 固件扫描记录须固定 scanner commit/version、规则锁/规则仓 commit、参考数据库版本与 digest、OSV snapshot/time、schema version、选项、平台与输出 hash；同输入同配置应产生可解释的稳定结果。
- 每个 reference DB 的 ingest/build 要有 provenance sidecar、失败清单、许可证审核、更新时间和回滚机制；外部数据库下载要校验签名/校验和。没有可重建数据时至少保留来源 manifest 与 artifact digest。
- 规则应有测试样本、命中证据、适用目标、known false positives、review owner 和变更历史。生产规则与大型二进制数据库分开版本，防止 repo 被几十 GB 数据库和构建缓存污染；数据库 artifact 可独立托管但由仓库锁定 digest 与兼容 schema。
- Git 每次提交需能指向生成报告的确切 commit；扫描报告里的“uncommitted changes=false”须与 Git 实际 tree hash 对上。不要修改已发布旧报告来覆盖历史基线；新版本报告以新目录和 manifest 保存。

## 推荐的 90 天起步序列

1. **第 1–2 周：评测底座。** 冻结两份固件 digest、扫描器和数据库版本；建立可独立核验的组件/版本标注清单；定义 exact/estimated/unknown/等价类与固定分母。抽样覆盖 Android platform、third-party native、JAR、APEX、Rust、vendor binary。
2. **第 2–4 周：元数据与来源映射。** 用一条记录串起 `partition/path → module/package/container → source/project → release/build revision → file digest`；先处理 APEX/JAR/系统包数据库和可唯一收敛 NOTICE 项目。把无法建立 link 的 NOTICE 项目保留为 identity prior。
3. **第 3–6 周：reference DB 实用性评估。** 对 BLintDB 选定项目及现有 13 个身份确认样本做特征层 ablation；分析 mismatch 根因；NSRL 记录 RDSv3 发行版本并针对 exact hit 设计 smoke test。量化新增可验证 exact versions 和 false positives。
4. **第 5–9 周：二进制内生版本证据。** 针对高频项目用已知官方版本和多 target 样本评估 strings/version getters、成对函数、只读常量和 delta 特征。采用版本留出挑战，不在训练 corpus 上报告准确率。
5. **第 8–12 周：仅对已证实缺口试 Rust/DEX/C++ 原型。** Rust 行号、JAR 结构、C++ Delta 分别在自己的 held-out 子集上做消融。任何原型若只增加候选、没有 verified version 增量，继续作为 identity evidence，不升格为 exact。
6. **并行推进合规输出。** 实现 CycloneDX identity evidence、固定 provenance sidecar、依赖边证据、SPDX license 表达、OSV exact-version gating 和 VEX unknown 语义。schema validation 与语义测试分别报告。

## 一手来源

### 标准与漏洞数据

- [CycloneDX Specification Overview](https://cyclonedx.org/specification/overview/) — 组件、依赖、License、pedigree、evidence 与声明/证明能力。
- [CycloneDX v1.7 JSON Reference](https://cyclonedx.org/docs/1.7/json/) — component evidence/identity 的字段定义；v1.7 当前版本信息应结合项目目标的 schema 兼容性验证。
- [CycloneDX evidence guide](https://cyclonedx.org/guides/sbom/evidence) — identity claims 的 evidence 语义。
- [CycloneDX lifecycle phases / VEX](https://cyclonedx.org/guides/sbom/lifecycle_phases) — VEX 与 BOM 解耦更新建议及示例。
- [SPDX 3.0 specification information (OMG)](https://www.omg.org/spec/SPDX/3.0/About-SPDX) 与 [SPDX 3.0 user guide](https://spdx.github.io/using/) — SPDX 3.0 标准文档和使用资料。
- [SPDX License List](https://spdx.org/licenses/) — 标准化 license identifiers、文本和永久 URL。
- [OSV data quality](https://google.github.io/osv.dev/data_quality.html) — ecosystem/version/commit range 的数据质量要求。
- [OSV introduction](https://google.github.io/osv.dev/) 和 [OSV-Scanner C/C++ usage](https://google.github.io/osv-scanner-v1/usage/) — OSV 数据、commit 范围及 C/C++ 限制。

### NIST 与二进制参考库/商业基准

- [NIST NSRL current RDS releases](https://www.nist.gov/itl/csd/secure-systems-and-applications/national-software-reference-library-nsrl/nsrl-download-0) — RDSv3 SQLite 当前发行、README 与发布历史。
- [NIST NSRL introduction](https://www.nist.gov/itl/csd/secure-systems-and-applications/national-software-reference-library-nsrl/about-nsrl/nsrl) — RDS 文件哈希和元数据用途。
- [AppThreat BLintDB](https://github.com/AppThreat/blint-db) — BLintDB v2 schema、binary/source graphs、function fingerprints、项目和构建元数据；项目可快速变化，部署前锁 commit/schema。
- [Black Duck Binary Analysis documentation](https://docs.blackduck.com/r/blackduck/2026.7/black-duck-documentation/black-duck-binary-analysis.html) — 官方公开的 signature、hashsum、package-manager 与 Java 元数据多种识别方法。
- [Black Duck BDBA capabilities and limitations](https://docs.blackduck.com/r/bdba/latest/black-duck-binary-analysis-user-guide/capabilities-and-limitations.html) — 厂商对静态二进制识别和版本能力的说明；属供应商能力描述，不作为独立准确率证明。
- [Black Duck BDBA supported software and applications](https://docs.blackduck.com/r/bdba/latest/black-duck-binary-analysis-user-guide/appendix-supported-software-and-applications.html) — 官方列出其固件/嵌入式支持范围（包括多种 CPU 架构及若干 RTOS）；这说明产品覆盖方向，不构成本项目或竞品在任意样本上的准确率证据。
- [Black Duck Polaris binary analysis limitations](https://docs.blackduck.com/r/polaris/black-duck-polaris-platform/binary-analysis.html) — 官方明确部分二进制扫描可能只能给组件名、不能识别准确版本/来源。
- [Black Duck SCA official datasheet](https://assets.blackduck.com/image/upload/blackduck-sca-ds-ul.pdf) — 官方描述源码/包管理器、二进制、snippet、container 等互补分析方式；其产品级覆盖宣传不等同于逐样本版本精度实测。

### Android、Java、Rust 与 Linux 包生态

- [AOSP Repo command reference](https://source.android.com/docs/setup/reference/repo) 与 [AOSP source control tools](https://source.android.com/docs/setup/download/source-control-tools) — 多仓库 manifest 聚合及 revision 获取。
- [AOSP source download](https://source.android.com/docs/setup/download) — Android source 与 device-specific proprietary binary 的边界。
- [Android APEX file format](https://source.android.com/docs/core/ota/apex) — APEX manifest 的 package name/version 和 payload 内文件类型。
- [AOSP build environment example](https://source.android.com/docs/setup/start) — Build ID、平台版本、target product/arch 等构建属性。
- [Maven repository layout](https://maven.apache.org/repository/layout.html) 和 [Maven metadata](https://maven.apache.org/repositories/metadata.html) — GAV 目录、POM、制品、checksum 与元数据模型。
- [cargo-auditable](https://github.com/rust-secure-code/cargo-auditable) — 通过二进制专用 linker section 嵌入 Rust dependency tree；未使用该构建方式的固件二进制无法假设具有该数据。
- [Debian package management FAQ](https://www.debian.org/doc/manuals/debian-faq/pkgtools.en.html) — 已安装包状态/版本和 `.deb` 组成信息。
- [OpenWrt apk package manager](https://openwrt.org/docs/guide-user/additional-software/apk) — OpenWrt 新版本包管理器为 apk；不能把旧版 opkg 路径硬套到所有固件。

## 来源解释边界

本研究使用一手规范/官方说明确认“数据字段能表达什么、工具数据库包含什么、生态包记录提供什么”。标准本身不能证明某个固件确实含有该证据，也不能证明扫描器的解释正确。所有目标固件的真实增量必须来自可回放扫描、held-out 真值和独立复核。Black Duck 的材料用于理解成熟商业方案的多层匹配方向与已公开限制，不将其供应商宣传当作对比实验结果。
