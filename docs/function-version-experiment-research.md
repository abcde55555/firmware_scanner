# 无 banner 二进制版本识别：函数语义与版本敏感特征研究

基线：`a4a93cca2f4661213833b39d3a5d590c57e5740e`（`codex/function-version-experiment`）。本文件整理方法与实验建议，论文数据不代表本项目效果。主 agent 后续实际重扫及其边界见[实验结果](function-version-experiment-results-2026-11-18.md)。

## 结论先行

- **有限静态语义解码**适合做可审计、低误报的候选证据：寻找版本 getter 的返回值构造、`VerifyVersion` 的常量比较/错误分支和特定版本新增行为。它不要求先建全版本函数库，但覆盖窄、易受编译器变换影响，而且“看见版本常量”可能只说明编译头文件版本。
- **多版本函数指纹库**覆盖面更广，能比较库函数在多个发行版间的变化；但纯函数相似度更多回答“像哪个函数”，不能单独证明版本。较可信的方案需对已知库做版本对照、利用版本差分并要求多条独立证据相互吻合。LibvDiff 是直接版本识别先例；LibAM、BinCoFer 是复用/函数匹配先例，不是同等的版本识别验证。
- 可审计结果应保留候选版本、命中的函数/地址、反汇编或伪代码证据、区分该版本的语义谓词、冲突证据和拒判原因。只有在冻结的独立真值集上相对当前基线提升版本级指标且误报受控，才称“提升”。

## 一手研究与边界

### LibvDiff：版本差分驱动的二进制版本识别

ICSE 2024 论文把离线签名生成和在线版本识别分开：收集函数名、字符串、导出符号等粗特征；以 Asteria 函数 embedding 比较目标二进制与参考版本；从相邻源版本提取函数/字符串增删改差异；再按版本坐标筛候选，最后用版本确认算法检查候选。论文还用从导出函数到内部函数的调用路径缩小匹配搜索空间。[论文原文](https://gentlecp.github.io/pdfs/LibvDiff_ICSE_2024.pdf)；[作者官方实现](https://github.com/GentleCP/LibvDiff-public/)

这与“多版本函数指纹库”最接近，但不是只对每个函数做哈希后投票：核心是跨版本差异、候选过滤和逐版本确认的组合。论文摘要报告含版本字符串数据集 precision 94.5%、无版本字符串数据集 78.7%；这些数字只属于论文数据集及其实验设定，不能外推为本项目指标。其作者实现 README 也把示例标为 FreeType cross-optimization，并说明实验预生成了相关特征。跨架构/优化的论文结果应按其具体数据集和设置理解，不能据此推断对任意 ISA、编译器、LTO 或固件构建均稳健。

### LibAM：函数锚点加调用图区域

LibAM 的任务是识别二进制是否复用了第三方库及其复用区域。它先用函数 embedding 找锚点，再沿函数调用图生成区域，结合结构相似度和一对一锚点对齐长度过滤单函数误匹配。[论文原文](https://arxiv.org/abs/2305.04026)；[ACM 版本](https://doi.org/10.1145/3625294)；[作者源码](https://github.com/Siyuan-Li201/LibAM)

可借鉴点是：独立函数相似度会产生相似但非同源的误匹配；调用关系和相邻函数证据可提高复用判断的可解释性。限制是其核心输出是库/复用区域，不是细粒度版本；论文也指出跨架构与优化下区域定位表现会下降。因而“匹配到某库函数”应作为身份或局部支持证据，不能直接当成准确版本结论。

### BinCoFer：净化候选库并聚合函数证据

BinCoFer 先净化二进制特征库，突出核心函数，再提取函数级特征；它明确指出仅用单函数相似度阈值判断复用不准确，改用核心函数相似度加权聚合。[作者论文预印本](https://arxiv.org/abs/2504.19551)；[作者论文 PDF](https://wu-yueming.github.io/Files/JSS2025_BinCoFer.pdf)

可借鉴点是候选库去冗余、识别低区分度函数，并按特征可靠度加权；这些适用于构建版本参考库。限制同样关键：论文评估的是第三方库检测，ArchLinux 等自身编译数据不能说明版本级 top-1/拒判质量，更不能把论文 accuracy 或 precision 移植成本项目效果。版本识别还要证明相邻版本之间的差异特征能被目标二进制观察到。

## 官方源码提供的语义锚点

- **zlib v1.2.13**：官方稳定 tag 的头文件声明 `zlibVersion()`，并说明可与编译期 `ZLIB_VERSION` 比较；初始化函数会检查调用方假设版本与库版本兼容性。[v1.2.13 `zlib.h`](https://github.com/madler/zlib/blob/v1.2.13/zlib.h)；官方示例检查首字符并比较完整字符串。[v1.2.13 `example.c`](https://github.com/madler/zlib/blob/v1.2.13/test/example.c)。
- **libpng v1.6.40**：官方稳定 tag 的 `png_get_libpng_ver()` 返回库构建所用源码版本；注释区分 header/library 版本，并指出该版本实现中 getter 与 header getter 相同。[v1.6.40 `png.c`](https://github.com/pnggroup/libpng/blob/v1.6.40/png.c)；版本宏和声明见[同 tag `png.h`](https://github.com/pnggroup/libpng/blob/v1.6.40/png.h)。固定 tag 仅用于说明 API/源码语义，不暗示目标样本采用这些版本。
- **Protocol Buffers v21.12（3.21.12）**：本研究固定依据实际对象对应的官方 [v21.12 `common.h`](https://github.com/protocolbuffers/protobuf/blob/v21.12/src/google/protobuf/stubs/common.h) 与 [`common.cc` 中 `VerifyVersion` 定义](https://github.com/protocolbuffers/protobuf/blob/v21.12/src/google/protobuf/stubs/common.cc)，不引用 `main` 分支的新版签名/逻辑。该版函数签名是 `VerifyVersion(int headerVersion, int minLibraryVersion, const char* filename)`；第一道检查是 `GOOGLE_PROTOBUF_VERSION < minLibraryVersion`，第二道独立检查是 `headerVersion < kMinHeaderVersionForLibrary`。第一条错误路径把 `minLibraryVersion` 格式化为所需版本，并把库内 `GOOGLE_PROTOBUF_VERSION` 格式化为已安装版本；第二条路径格式化的是 `headerVersion` 和库版本。该区分意味着识别器应优先定位**库内定义函数**及其版本常量/格式化调用，不应把应用调用方传入的 header 常量误当作被测库版本。

  对应原始样本中的 `cmp esi,3021013; jl` 是版本 `3021012` 的 **version+1 排他上界检查**，不是说库版本为 `3.21.13`。错误消息路径对 `VersionString` 实际传入 `3021012`，按 `VersionString` 的十进制拆分逻辑得到 `3.21.12`。这是直接按语义与数据流解释机器码的反例：若只把比较立即数或 `minLibraryVersion` 上界当作版本标签，会产生 off-by-one 误报；应沿错误路径追踪 `VersionString` 的实参，并结合 v21.12 函数定义及编译进库的 `GOOGLE_PROTOBUF_VERSION` 判断。这里讨论的是对象中被定位到的库函数实现，不是仅凭应用调用处传入的版本常量推断。

这类官方实现**证明可研究的特征存在**，不证明特征在目标固件里保留。字符串/符号可能被剥离，getter 可能未被调用或被内联，`VerifyVersion` 也可能只在应用启动代码中；LTO、常量传播、函数合并和包装器都可能改变形态。

## 两条路线的比较

| 维度 | 有限静态语义解码 | 多版本函数指纹库 |
|---|---|---|
| 基本做法 | 为少数已知 getter / 校验函数定义语义模式，恢复返回常量、比较条件、错误路径或特定新增行为 | 收集多个发行版本编译产物中的函数，建立函数/版本对应，目标函数与库中版本候选比对 |
| 优势 | 特征可解释；若能恢复版本常量或独有分支，候选证据直接；初期数据和算力需求较低 | 可覆盖无专用 getter 的组件与代码变化；有机会跨架构/优化匹配；可复用函数匹配技术 |
| 主要误报源 | 编译头文件常量被嵌入应用；常量碰撞；相同兼容性代码跨多个版本不变；相似比较逻辑 | 通用/复制函数、相邻版本函数高度相似、错配架构/优化、候选库冗余、部分复用、函数边界识别误差 |
| 主要漏报源 | getter 未调用、被内联/裁剪、版本路径无区分性、静态模式过窄 | 函数未保留/未调用、只复用少量区域、架构/优化变化造成 embedding 漂移、库参考构建不匹配 |
| 适合定位 | 高置信锚点或版本候选的强支持/排除条件 | 广覆盖的候选排序；结合版本差异和调用图再确认 |
| 相关先例 | 官方源码确有 getter/VerifyVersion；将其用于静态二进制版本识别属于待验证的应用方式 | LibvDiff 直接做版本识别；LibAM、BinCoFer 验证了函数/区域匹配与降噪，但目标主要是复用检测 |

建议采用分层证据而非二选一：先对可识别 getter/verify 语义做高精度探测；再对多个参考版本做函数级匹配；最后检查相邻版本差异是否吻合，并用调用图、多个独立函数或明确矛盾特征作复核。证据不够时输出版本区间/未知，不强行给单一版本。

## 小实验建议与验收

1. **锁定问题和真值**：选 2–3 个有官方源码且版本历史清楚的库（例如 zlib、libpng、protobuf），只围绕现有无 banner 样本或可控构建样本；记录真实源码 tag、二进制哈希、架构、编译器/版本、优化级别、LTO/strip、静态/动态链接。将按源码 tag 和构建配置确认的版本作为真值；不能从待测识别结果反向定义真值。
2. **隔离版本**：按版本家族分割训练参考库和测试版本；留出至少一个相邻版本和一个较远版本作未见版本。对同一源码版本的不同构建不得跨训练/测试泄漏。另设不同架构和优化级别的留出组，单独报告结果。
3. **对照三种方法**：A 当前基线；B 仅有限 getter/VerifyVersion 语义规则；C 多版本函数指纹；再加 D 二者结合。统一候选库、组件识别前提、阈值调参数据和拒判规则。记录每个候选的证据链，而不只存一个分数。
4. **负例必须包含**：未收录的同类库/版本、同一库但版本不在候选库、应用自身或其他组件中出现 protobuf/zlib 风格版本常量、相似 getter、被内联的校验逻辑、同依赖家族函数、仅头文件版本与实际链接库版本不一致的构建。负例用于测错误归因，不能只用随机无关二进制。
5. **未见架构/优化评估**：按整组留出 ISA、编译器或优化配置，报告分层结果；至少检查 `-O0` 对高优化、strip、LTO、静态链接/动态链接。没有可运行的反汇编支持或函数边界不可靠时单列为不可判定，不从总体分母悄悄移除。若暂时无法构建目标架构，明确标 `NOT_TESTED`，不声称跨架构泛化。
6. **指标与验收门槛**：报告 exact-version top-1 accuracy、macro-F1、覆盖率/拒判率、错误版本率；另报告在固定覆盖率下的 precision，及版本区间命中率。按库、版本距离、架构、优化分层给混淆矩阵和样本数，并对错误结论逐例复核。预先约定“提升”门槛：相对 A，D 在独立测试集 exact-version precision 的改善需有置信区间支持，且错误版本率不恶化；若只提高覆盖率或库识别率，应按对应指标准确命名，不宣称版本准确率提升。小样本时给原始计数/区间，不做强显著性结论。

**创新性限度**：函数级跨架构相似度、调用图区域过滤、版本差分指导的版本识别都已有先例；把 getter/VerifyVersion 语义作为可审计特征也属于对已知官方源码行为的工程利用。若后续做出新贡献，可能在于针对固件无 banner 场景定义可解释证据模型、保守拒判和可复现评估协议；是否构成研究创新，需与完整相关工作和实际新方法对照后再判断，不能仅因本项目组合了已有技术便称原创。

## 来源清单

1. Dong et al., *LibvDiff: Library Version Difference Guided OSS Version Identification in Binaries*, ICSE 2024，[论文 PDF](https://gentlecp.github.io/pdfs/LibvDiff_ICSE_2024.pdf)，[作者实现](https://github.com/GentleCP/LibvDiff-public/)。
2. Li et al., *LibAM: An Area Matching Framework for Detecting Third-party Libraries in Binaries*, ACM TOSEM 2024，[论文](https://doi.org/10.1145/3625294)，[作者代码](https://github.com/Siyuan-Li201/LibAM)。
3. Zou et al., *BinCoFer: Three-Stage Purification for Effective C/C++ Binary Third-Party Library Detection*, [作者论文预印本](https://arxiv.org/abs/2504.19551)，[作者 PDF](https://wu-yueming.github.io/Files/JSS2025_BinCoFer.pdf)。
4. 官方源码固定版本：[zlib v1.2.13 `zlib.h`](https://github.com/madler/zlib/blob/v1.2.13/zlib.h) 与 [`test/example.c`](https://github.com/madler/zlib/blob/v1.2.13/test/example.c)；[libpng v1.6.40 `png.c`](https://github.com/pnggroup/libpng/blob/v1.6.40/png.c) 与 [`png.h`](https://github.com/pnggroup/libpng/blob/v1.6.40/png.h)；[Protocol Buffers v21.12 `common.h`](https://github.com/protocolbuffers/protobuf/blob/v21.12/src/google/protobuf/stubs/common.h) 与 [`common.cc`](https://github.com/protocolbuffers/protobuf/blob/v21.12/src/google/protobuf/stubs/common.cc)。源码链接固定到对应 tag 文件，不附加未经 raw 文件核对的行号锚点；可在文件内按 `VerifyVersion`、`zlibVersion` 或 `png_get_libpng_ver` 符号定位。
