# 黑盒固件组件身份与具体版本识别：可落地方法补充研究

日期：2026-11-20
范围：只讨论 Android/Linux 固件中，除全文件哈希、符号/字符串及版本 getter 之外，如何提高组件身份和具体版本的真实召回，同时控制 exact 版本误报。本文是行业方法研究，不代表这些方法已在当前两份固件上取得增量。

## 结论

建议按以下顺序投入：

1. **优先建立构建归属链**：Android 侧把固件 build fingerprint/build ID、可获得的 source manifest、Repo project revision、ELF 源码路径、模块/安装目标连接起来。源码路径主要解决“哪个项目”，manifest revision 主要证明“源代码快照”；只有目标 ELF 与该 revision 的构建产物存在可验证连接时，才能据此给它一个精确版本。
2. **优先做官方发行制品的文件级精确匹配**：在目标固件与官方 APK/OTA/factory image/发行包之间解包到同一文件粒度，比较目标 ELF 的 SHA-256，并沿着签名元数据、官方索引和包文件把结论追溯到发行版本。这是少量直接命中的高精度通道；整镜像 hash、包名相似或同路径本身都不能替代文件级匹配。
3. **把 NOTICE HTML/XML 限定为 identity/license evidence**：它适合产生组件候选、版权和许可证证据，以及帮助缩小项目搜索范围；不携带足够的构建绑定信息时，不足以证明某个二进制来自某一上游 release。
4. **C/C++ 跨版本 binary delta 先做封闭小试验**：先验证少数已确认项目在真实编译差异下是否能形成稳定、版本有区分力的特征。它可能带来其他方法没有的版本召回，但构建选项变化会产生大量非版本差异，必须允许 abstain 和等价版本组。
5. **把非空字段覆盖与准确性分开**：报告身份 precision/recall、exact-version precision/recall、覆盖率、unknown/abstain、邻近版本错误和独立真值比例。无真值的数据只能给出“字段覆盖”或“候选覆盖”，不能称为准确版本召回率。

下文中的“exact”采用严格口径：输出版本与被测二进制实际对应版本一致，并有指向该二进制或其构建输入的直接证据；若数据只足以定位到 manifest revision、Android 平台 build、父包版本或等价版本集合，应保留为独立 provenance/estimate/range，不升级为上游组件 exact release。

## 1. AOSP manifest 与 ELF 源码路径：先身份，后版本

Repo manifest 描述多仓源码树的项目布局。官方格式定义了 project 的仓库名、checkout path、remote 和 revision；revision 可以是分支、tag 或 commit hash。由此可构造 `source path → Repo project → pinned revision` 映射。[Repo manifest format](https://android.googlesource.com/tools/repo/+/HEAD/docs/manifest-format.md)

AOSP build ID 的官方语义是平台构建标识，可包含平台 release、分支和分支/同步日期信息；它不是其中每个第三方 ELF 的版本号。[AOSP build IDs and tags](https://source.android.com/docs/setup/reference/build-numbers) Soong 的 `Android.bp` 把模块定义为构建系统的基本单位，这提示真正有用的归属链应继续走到 module/target/install output，而不能止于路径前缀。[AOSP Soong](https://android.googlesource.com/platform/build/soong)

### 能可靠回答什么

- ELF 中出现多个独立、项目特有的 `external/<project>/...` 或其他源码路径，可作为项目身份候选；最好结合模块名、SONAME、导出符号集合和镜像分区路径共同判定。
- 与该镜像准确匹配的 Repo manifest 若包含 40 位 commit，可精确记录“该源码项目在该 manifest 中的 revision”。需保留 manifest 文件 hash、获取来源和 revision 原文。
- 若有构建图或官方 build manifest 将 `project/revision → module/target → 输出文件` 关联起来，并确认输出 ELF 与目标文件一致，revision 才能成为强的二进制 provenance。若项目在该 revision 上有可证明的版本声明，也可映射 release；必须保留版本声明到源码 revision 的证据链。

### 不能直接推出什么

- 源码路径是编译时残留，路径可能来自调试信息、宏字符串、代码生成、供应商复制或多项目合并；单个通用路径不能唯一识别项目。
- 设备 `ro.build.*`、Android 版本、security patch level、AOSP tag 或 Repo revision 都不是自动等价的第三方上游 release。
- manifest 固定一个源码快照，不证明该二进制没有本地修改、厂商 cherry-pick、构建时 patch、不同编译开关或来自另一个预编译库。
- Linux 的 ELF build-id/debuglink 可用于关联调试文件和发行构建记录，但在没有签名索引或发布制品关联时不能单独证明组件版本。

### 最小落地验证

对固定固件中的 20–30 个身份较可信但版本 unknown 的 ELF，先构造归因表：固件 hash/build id、ELF path/hash/SONAME、源码路径候选、候选 Repo project、manifest revision、候选模块/target、官方版本声明、供应商补丁可能性、证据等级。只用已知对应镜像的 manifest；不以最新版 manifest 回填旧固件。由独立人员抽查至少 10 个路径归因，并将误归因率和可走完整链路的比例单独报告。

## 2. NOTICE HTML/XML：license/identity 证据，不是 release 证据

AOSP 构建代码把 NOTICE 文档作为与目标安装模块相关的 notice/license 产物，并按 system、vendor、product、system_ext 等镜像分区生成或安装 NOTICE 文件。[AOSP build NOTICE generation](https://android.googlesource.com/platform/build/+/refs/heads/master/core/Makefile) Android Settings 的 `LicenseHtmlLoader` 则从各分区的 `NOTICE.xml.gz` 读取许可证信息，再生成显示用 HTML。[AOSP LicenseHtmlLoader](https://android.googlesource.com/platform/packages/apps/Settings/+/e9060a3/src/com/android/settings/LicenseHtmlLoader.java)

因此，固件中发现 NOTICE HTML/XML 是有价值的**观察证据**：它可含项目名、版权方、许可证文本和可能的文件清单/锚点。其最稳妥用途是：

- 生成组件身份候选和 license/copyright 证据；
- 若内容明确列出文件名或安装路径，将这个关联作为 NOTICE 声称的 file/project 关系记录；
- 与 ELF 中的项目路径、SONAME、导出 API、官方包内容交叉验证；
- 区分 NOTICE 声明的许可证和对目标文件实际 license 的结论；保留来源、解析置信度、冲突与未映射状态。

NOTICE 条目可能来自参与整机构建的模块集合，或者只描述 attribution/license；它并不必然是当前分区文件的逐个清单，也不声明项目 revision、上游 release、构建 tag 或厂商 patch 集。AOSP 甚至会在生成阶段按构建配置筛选随目标安装的模块，说明不同镜像构建可以包含不同 notice 集。[AOSP build NOTICE generation](https://android.googlesource.com/platform/build/+/refs/heads/master/core/Makefile)

### 解析 HTML/XML 的建议

按格式解析而不是把 HTML 当 XML：保留原始文件 SHA-256、压缩前后 hash/大小、原始路径、parser 版本、DOM section/anchor、原始文本摘录和规范化字段。以 TOC anchor、标题层级、文件路径字符串、License 文本区域作为结构特征；对同名项目、多个版本重复 notice、多个 ELF 同属一个 notice section 的情况保留一对多候选。解析成功只证明“读到了记录”，不证明记录绑定到目标 ELF。

## 3. 官方发行制品与包库：文件级 hash + provenance

NIST NSRL 的数据模型说明了这类方法的核心价值：文件 hash 可关联已知文件及其来源软件包、制造商、文件名和大小；但它是已收录文件参考库，覆盖缺口不代表目标文件未知或组件不存在。[NIST NSRL overview](https://www.nist.gov/itl/csd/secure-systems-and-applications/national-software-reference-library-nsrl/about-nsrl/nsrl) 当前 NSRL 发布已转向 RDSv3 SQLite，且不同子集面向 Android、PC 等类别；因此要固定数据库版本和 hash，不能把一次无命中解释为无版本。[NIST current RDS downloads](https://www.nist.gov/itl/csd/secure-systems-and-applications/national-software-reference-library-nsrl/nsrl-download-0)

Linux 发行版包库提供了可复现的追溯链。以 Debian 为例，签名的 `InRelease/Release` 将索引文件 hash 纳入信任链；`Packages` 条目再列出包的版本、架构和包文件校验信息。官方文档描述了对索引签名和归档来源的验证边界。[Debian package authenticity](https://www.debian.org/doc/manuals/debian-handbook/sect.package-authentication.el.html) `.buildinfo` 可补充构建环境和输入信息，适用于从二进制包回到源包/构建记录的调查，但它本身并不能证明固件文件与包内文件相同。[Debian buildinfo files](https://wiki.debian.org/ReproducibleBuilds/BuildinfoFiles)

### 建议的文件级闭环

1. 从上游官方站点获取受签名索引、发布清单或官方镜像；记录签名验证结果、官方 URL、时间、索引/镜像 hash。
2. 获取候选版本的二进制发行包，提取包元数据：包名、source package、版本、架构、文件路径、包 hash；Linux 包同时保留发行版 epoch/revision 等版本语义。
3. 从官方制品中提取与固件 ELF 对应的单文件，计算 SHA-256；只有目标文件 hash 完全一致时，才将其记录为“与官方制品中的该文件字节完全相同”。
4. 将官方制品 hash 链到签名元数据/发布记录/版本，再把这个 provenance 与固件文件的 hash、路径、ELF build-id、架构绑定。所有中间候选和不匹配的近似结果只作为诊断。
5. 若目标固件文件与所有官方制品 hash 不同，可继续做符号剥离归一化、可重现构建或 binary similarity 研究；这些方法不能继承精确 hash 的证明强度。

### 边界与收益预期

精确 hash 的收益通常是**高 precision、低覆盖**：原样复制、未修改且同构建的文件可以直接精确匹配；供应商重编译、strip、链接器变化、补丁、重定位或构建路径变化都可能使 hash 不同。NSRL 或发行版包库提供的是参考来源，不是所有厂商固件的完整真值库。整张 OTA 的签名/hash 只认证整个制品，不能单独把里面某个 ELF 定版。官方 image manifest、包签名与单文件 hash 要分别记录，避免把整机来源推断当作文件级证明。

CycloneDX 支持组件 identity evidence、method、confidence、hash 和 occurrence/location；SPDX 能表示 package/file checksum 与 package-file relationship。可以把匹配证据表达出来，保留“哪个证据支撑 name/version/hash”而非只输出一个裸版本字段。[CycloneDX identity evidence](https://cyclonedx.org/guides/sbom/evidence) [CycloneDX JSON reference](https://cyclonedx.org/docs/1.7/json/) [SPDX file/package relationships](https://spdx.github.io/spdx-spec/v2.3/relationships-between-SPDX-elements/) [SPDX package checksum guidance](https://spdx.github.io/spdx-spec/v2.3.1/how-to-use/)

## 4. C/C++ 跨版本 binary delta：最小可行试验

成熟的二进制比较工具把函数的控制流/调用结构、指令或特征用于匹配；例如 BinDiff 文档描述了基于函数结构签名、唯一匹配及调用图传播的过程，同时也指出歧义函数会保留为 unmatched，而不是强行匹配。[BinDiff matching concepts](https://github.com/google/bindiff/blob/main/docs/concepts.md) 相关研究持续测试 compiler optimization 对二进制差异的影响，说明同一源码版本不同构建与相邻源码版本同构建必须作为两种不同变量处理。[Compiler optimization empirical study](https://arxiv.org/abs/2103.12357)

这类工具更适合先做“候选 release 排序”和“版本间可区分性”实验，不能因为相似度最高就输出 exact。最小试验应使用封闭候选集并确保没有用 held-out 结果调规则：

### 数据集设计

- 选择 8–12 个在目标固件中真实出现的 C/C++ 项目，优先项目身份已确认、上游 release/tag 可取、至少有 3 个候选版本的样本。
- 每个项目选 3–5 个相邻/非相邻 release，构建同一固定 ABI/架构、编译器、链接器、优化级别、LTO、strip 配置的 binary；记录 source commit、编译 recipe 和 artifact hash。
- 再对其中至少 2 个版本做编译器版本、`-O`、LTO、strip、链接器等变化，作为“同版本跨构建”负对照；采集厂商补丁构建或实际固件样本时单独标记，不混作上游原版。
- 训练/调参按项目或版本隔离；至少留出一整个 release 或项目作 blind test。不要随机拆分同一构建的函数，否则测试泄漏会夸大效果。

### 识别单位和试验流程

1. 先用其他证据确定项目族和候选版本集合；binary delta 不负责从全宇宙猜项目名。
2. 对每个版本生成函数集合/CFG/调用图或函数 embedding。去掉非稳定地址、重定位常量和明确的构建噪声；保留工具、参数及特征版本。
3. 计算版本间差异特征：函数存在/缺失、函数体/基本块结构变化、跨版本稳定的函数簇、版本特有 API/行为变化。每个特征要有可审查的函数位置和候选版本来源。
4. 以版本为单位做候选评分和拒判：同版本不同构建之间的分数分布要能与相邻版本区分；若多个 release 对目标二进制不可分，应输出版本等价组/range 或 unknown。
5. 固定阈值后对 held-out 样本评测；所有候选参考制品和脚本需能由样本 manifest 重建。

### 通过门槛和停止条件

门槛不是行业标准，以下是本项目建议的 go/no-go 起点：

- Exact precision：blind cohort 至少 30 个可判定目标，点估计 ≥98%，且零错误时报告 95% 单侧置信下界；若样本太少，不宣称达到高精度，只报告计数和区间。
- 与现行方法相比，exact recall/coverage 的绝对提升至少 5 个百分点，或新增 ≥10 个经独立真值确认的 exact 版本；同时报告新增错误数和 abstain 数。
- 同版本不同构建负对照不得大量被错判成相邻 release；相邻版本挑战集必须单列，且错误输出必须能追溯到导致误判的特征。
- 发现候选版本不可区分、目标二进制被大量厂商 patch、参考版本构建缺失，或成本/耗时超过业务允许值时，停止扩库，保留 identity-only 或 unknown。不要通过降低阈值来“填满”版本字段。

若样本量不足以验证上述 precision，仍可继续做研究原型，但标记为 exploratory，不进入 exact 生产通道。

## 5. 评测：版本非空不等于准确

业界的安全漏洞数据质量也要求版本/提交范围可被具体生态系统解释并可自动回答受影响状态。OSV 高质量记录要求版本范围有效，且版本属于特定 package ecosystem；这说明 SBOM 的版本输出需要有精确语义和 package identity，不能把任意字符串当版本。[OSV data quality](https://google.github.io/osv.dev/data_quality.html)

建议每轮报告至少拆开如下指标：

| 指标 | 分子 / 分母 | 解释 |
|---|---|---|
| Identity precision | 正确组件身份数 / 所有已声明身份数 | 回答输出的组件名是否正确 |
| Identity recall | 找到的真值组件数 / 真值组件总数 | 回答组件是否漏扫；需有独立 ground truth |
| Exact-version precision | 完全正确的 exact 版本数 / 输出 exact 数 | exact 输出是否可信；这是漏洞匹配最关键的质量门 |
| Exact-version recall | 正确 exact 版本数 / 有精确真值的组件总数 | 真正找回多少可核验具体版本 |
| Version field coverage | 任意非空版本字段数 / 固定组件分母 | 仅表示填充率，不能称作准确率或真实召回 |
| Estimated/range coverage | 有估计或候选范围的组件数 / 固定分母 | 与 exact 分开，不与 exact precision 混加 |
| Adjacent-version error | 输出相邻版本但不相同的条目数 / exact 输出数 | 单列用户可接受但影响漏洞结论的近邻误差 |
| Unknown/abstain | 未给版本的条目数 / 固定分母 | 展示方法的保守拒判能力，避免以猜测掩盖未知 |
| Independent verification | 独立核验数 / 所有输出和总分母 | 区分算法自报与真值支撑范围 |

### Ground truth 与盲测控制

- 对每个真值记录 firmware SHA-256、分区/path、文件 SHA-256、架构、组件 PURL/identity、上游版本或 commit、验证依据、验证人和日期。
- 允许真值为“未知/版本等价组”；不可为方便评测而强制单版本标签。
- 把已知官方包精确 hash、官方 source manifest/build mapping、人工反汇编/源码核对分开标注，避免用同一算法产生 prediction 和 ground truth。
- 建立完全新鲜 held-out cohort；一旦查看错误样本并增补规则，该 cohort 即变为 tuned set，不再作为泛化盲测成绩。
- 所有指标报告计数、固定分母、去重策略、组件类别（native/JAR/APK/kernel/vendor）及置信区间。小样本结果特别要展示区间，不能只给百分比。

## 推荐工作顺序与各阶段停止门槛

| 优先级 | 工作项 | 预期性质 | 继续条件 | 停止条件 |
|---|---|---|---|---|
| P0 | 固定真值切片、分母、盲测规则与版本分级 | 不直接增加命中，但避免虚假提升 | 有可审计 hash/path/版本来源，baseline 可复算 | 没有独立真值时只能报告 coverage proxy，暂停 accuracy claim |
| P1 | 匹配准确固件构建的 AOSP/source manifest + ELF source path + module/output | 身份覆盖中高，版本增量取决于构建链是否在手 | 能闭合 `image → manifest → project revision → module/output → target ELF` | manifest 只对应平台或路径归属无法唯一时降为 source provenance/identity |
| P1 | 官方发行制品/包库的 signed metadata + file-level exact hash | 低覆盖、高精度 | 至少新增若干独立确认的目标文件 exact 命中，且 hash 到官方发布记录的链条可复验 | 大多数真实目标属于厂商重编译/本地补丁而无匹配时停止扩大同一参考库 |
| P2 | NOTICE HTML/XML 结构化解析 | 较可能增加身份/license 证据，版本增量不预设 | 可证明记录与具体文件/模块的关联，身份核验 precision 达到内部门槛 | 只有 license 文本或宽泛项目名时，不投入版本定版规则 |
| P3 | C/C++ 跨版本 delta 小样本原型 | 有机会提升 unknown 中的版本召回，工程和验证成本高 | 同版本构建噪声与跨版本差异可分；blind test 提升达到第 4 节门槛 | 候选版本不可区分、近邻错误多、独立 precision 不能建立或成本过高 |

本次优先级属于结合公开规范能力与仓库已知结果形成的工程判断，不是来源保证的性能承诺。尤其 binary delta 的实际收益必须通过目标固件样本与盲测数据确认。

## 一手来源

- Android Repo manifest：<https://android.googlesource.com/tools/repo/+/HEAD/docs/manifest-format.md>
- Android build IDs/tags：<https://source.android.com/docs/setup/reference/build-numbers>
- AOSP Soong 模块模型：<https://android.googlesource.com/platform/build/soong>
- AOSP NOTICE 生成：<https://android.googlesource.com/platform/build/+/refs/heads/master/core/Makefile>
- AOSP Settings NOTICE 解析入口：<https://android.googlesource.com/platform/packages/apps/Settings/+/e9060a3/src/com/android/settings/LicenseHtmlLoader.java>
- NIST NSRL 简介与数据含义：<https://www.nist.gov/itl/csd/secure-systems-and-applications/national-software-reference-library-nsrl/about-nsrl/nsrl>
- NIST RDS 当前下载与版本：<https://www.nist.gov/itl/csd/secure-systems-and-applications/national-software-reference-library-nsrl/nsrl-download-0>
- Debian package authenticity：<https://www.debian.org/doc/manuals/debian-handbook/sect.package-authentication.el.html>
- Debian buildinfo 文件：<https://wiki.debian.org/ReproducibleBuilds/BuildinfoFiles>
- CycloneDX identity evidence：<https://cyclonedx.org/guides/sbom/evidence>
- CycloneDX 1.7 JSON schema/reference：<https://cyclonedx.org/docs/1.7/json/>
- SPDX 2.3 package/file relationships：<https://spdx.github.io/spdx-spec/v2.3/relationships-between-SPDX-elements/>
- SPDX 2.3.1 package/file checksum guidance：<https://spdx.github.io/spdx-spec/v2.3.1/how-to-use/>
- Google BinDiff matching concepts：<https://github.com/google/bindiff/blob/main/docs/concepts.md>
- Compiler optimization and binary diff empirical study：<https://arxiv.org/abs/2103.12357>
- OSV high-quality data criteria：<https://google.github.io/osv.dev/data_quality.html>

## 与仓库现有研究的关系

本文件补充 [firmware-sbom-roadmap-research-2026-11-20.md](firmware-sbom-roadmap-research-2026-11-20.md)、[firmware-sbom-roadmap-review-2026-11-20.md](firmware-sbom-roadmap-review-2026-11-20.md)、[version-apis-and-database-provenance-2026-11-20.md](version-apis-and-database-provenance-2026-11-20.md) 中已有的路线图与证据口径，聚焦把它们转成可执行的构建归属闭环、官方制品文件级 hash 闭环、NOTICE 边界、binary delta 试验门槛及统一评测方案；不替代现有固件实测报告。
