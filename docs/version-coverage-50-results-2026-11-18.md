# 两份固件版本覆盖率 50% 实验结果

日期：2026-11-18。分支：`codex/version-coverage-50`，代码基点 `132591c`。

本文保留前一生产阶段结果；后续修正及再次实扫见[二次实测报告](version-coverage-next-results-2026-11-18.md)。

**验收状态：50% 未达标。** 本轮实现了容器读取、明确元数据、有限函数语义、厂商构建版本和真实参考样本管线，并对实际镜像重扫。已知版本的数量仍不足以满足目标，不能把扩库、单元测试或候选范围当作 50% 达标。

用户确认目前只有两份固件。本轮未依赖供应商 SBOM、源码清单或构建 manifest，也没有运行目标二进制、动态加载目标库、上传固件或使用付费识别服务。所有子 agent 均使用 GPT-6 Luna。

## 输入与实扫范围

| 输入 | 字节数 | SHA-256 |
|---|---:|---|
| `sun8iw6p1_android_perf3_v1_0_uart0.img` | 653989888 | `208399eb1e5b43603a22836450a244f9017a859a8a1d68f18cdf8989e8ba121f` |
| Allwinner 内的 ext4 system 分区 | 805306368 | `87c2d561464ec8144f2c580ce5f781262f0506f57a506d534e652e96099f0cf2` |
| `system.img` | 2309611520 | `ff9025e0f73e6784f57ef9d3dd5b90ce648d524dd4c20d8cfe5dc2b66ccc4ce4` |

原始输入位于 `/home/kali/Desktop/work/project/vulnscan/`。Allwinner 是 Android 4.4.4 的 IMAGEWTY 容器；本轮扫描其从原始偏移 `18891776` 提取的 system 分区，记录原始容器摘要，**不声称本轮扫描了其他 boot 等分区**。另一个输入是 Android 16 的 ext4 system 镜像。

实际调用产品 `AndroidSystemScanner` 和 CLI 的 `_deduplicate_components`，从只读 mmap/ext4 获取字节。每次先复制当时的 `src/`，再从副本导入产品；每个 ELF 记录路径、字节数、SHA-256 和所有输出声明。输出同时包含 CycloneDX SBOM 与输入哈希。重现命令见[实验说明](../experiments/version_coverage/README.md)。

`metrics.json` 的 Git revision 是工作区代码基点，不能单独代表未提交源代码；每次的 `source-sha256.json` 与 `source/` 才标识实际被测实现。Allwinner 冻结副本早于仅影响 APEX 统计的修正，其实际 APEX 数为零。扫描之后还整理了导入、注释、未使用局部变量命名及等价的元数据来源字符串格式，并补上损坏 APEX 顶层 manifest 的 `zlib.error` 捕获；后者先复现失败，再通过回归，并只对受影响的 34 个实际模块 manifest 路径重扫，结果与完整扫描一致、无告警。该定向重扫明确跳过了未变的 payload 分析，未冒充第三次全盘扫描。最终仓库代码再次通过完整回归。

## 统计口径

冻结基线为上一轮有限函数实验的 `after` 输出：Allwinner 582 条、其中原生库 312 条；system 1129 条、其中原生库 774 条。基线修订为 `e890f0c`；原报告 SHA-256 分别为 `0f79b19314ac97e4a6206aa2fa1832fdbef068e1eeab7fa11442ca0b2ad4c85b`、`3f42ee7b56a0d061daa56de48a716181e7df95e7aba6f83e675a83945bdc58e3`。

原生库要求 `component_type=library` 且描述明确为 native library，不把文件名带 `.so` 的 APK 算进去。相同身份、版本、类型的多位置观察按现有产品规则去重；这仍是输出组件记录数，不等于独立上游项目数。

填充率是非空版本字段占比，**不等于整体准确率**。正确版本覆盖率需要独立真值；本轮没有覆盖所有输出的独立真值集。有限核查通过也不能推导剩余样本准确。冻结队列中的缺失/重分类记录继续占分母；新增容器内容和依赖记录单列。候选范围、接口/ABI/编译器版本，以及宿主 Android/APK/APEX 版本均不回填原生库版本。

### 最终扩展输出

| 固件 | 基线全部有版本 | 最终全部有版本 | 基线原生库有版本 | 最终原生库有版本 |
|---|---:|---:|---:|---:|
| Allwinner | 119/582，20.4% | **122/582，21.0%** | 21/312，6.7% | **24/312，7.7%** |
| Android 16 system | 155/1129，13.7% | **306/1454，21.0%** | 27/774，3.5% | **29/917，3.2%** |

扩展读取使新识别对象和重复观察发生变化，不能把不同分母的百分比直接解读为原队列识别能力提升。Android 16 最终分析了更多无版本库，原生库的版本填充比例下降。首轮扩展输出曾为 307/1459；最终剔除 BoringSSL 兼容串误报、修正 APEX 内可执行文件类型和去重后，为上表数值。

### 冻结队列比较与 50% 门槛

| 固件/队列 | 固定分母 | 匹配到原记录 | 最终有版本 | 未匹配仍占分母 | 距 50% 至少还缺的有版本记录 |
|---|---:|---:|---:|---:|---:|
| Allwinner 全部 | 582 | 582 | 122 | 0 | 169 |
| Allwinner 原生库 | 312 | 312 | 24 | 0 | 132 |
| system 全部 | 1129 | 1126 | 154 | 3 | 411 |
| system 原生库 | 774 | 773 | 26 | 1 | 361 |

这里将现有非空版本全部视为正确，也仍达不到 50%；实际正确版本门槛只可能更严格。Allwinner 的三个新增厂商构建标识经过有限独立核查，覆盖评估文件记录其三条 verified map。system 未提供完整独立 oracle，评估文件中的 verified/correct 为零表示未建立该映射，不表示 306 条输出全错。

system 的三条未匹配记录是：旧 `webview` 与 `AndroidMediaShell` 占位名称在完整 APK 读取后换成实际 package 身份；旧的独立 `ICU` 行现在归入本体 `libicuuc.so` 的 76.1 证据。按约定未强行别名映射以抬高冻结覆盖率，三条仍作为未匹配占分母。扩展输出有 328 条未匹配原队列的新记录，Allwinner 为零。

| 运行 | 分析 ELF 数 | 原始组件观察 | 最终记录 | APEX 模块 | 扫描器告警 | 耗时 | 峰值 RSS |
|---|---:|---:|---:|---:|---:|---:|---:|
| Allwinner system 分区 | 444 | 625 | 582 | 0 | 0 | 483.553 秒 | 662032 KiB |
| Android 16 system | 2134 | 3429 | 1454 | 34 | 0 | 741.222 秒 | 1136756 KiB |

告警为零只表示本次产品路径没有报告超限/损坏等警告，不证明已经发现镜像中每一种格式、每一个静态链接组件。仅在上述实际范围内报告覆盖。

## 本轮实际改变及收益边界

1. **完整读取 ZIP 尾部与更大 APK 内的原生库。** 新增 ext4 随机范围读取和只读 seekable 适配器，不再依赖前 128 MiB 恰好含中央目录。真实 WebView APK 为 335044058 字节，内含 133052052 / 186714544 字节的 x86 / x86-64 库；MediaShell APK 为 135862588 字节，内含 95414896 字节的 `libcast_shell.so`。单库/总量/条目仍有预算，读取失败和超限有告警。
2. **深入 APEX payload。** 新增 ext4/EROFS payload、`original_apex` 嵌套和 `.capex` 读取；记录 `outer.apex!/apex_payload.img/...` 来源。模块 versionCode 只归模块，payload 的 `bin/` ELF 归 application；它们不增加 APEX 模块计数。
3. **提取独立依赖声明。** Maven `pom.properties`、AndroidX `.version`、有完整三字段约束的已知 Google/Firebase SDK properties 均单独归属坐标。冲突或占位值保持未知；不把编译器、语言、宿主版本用于依赖填充。SDK properties 的规则和官方样本验证通过，但这两个固件没有带来该路径的新增版本命中。
4. **接入经过回归的有限函数证据。** 整数 getter、ARM/Thumb 返回字符串、x86-64 Protobuf 数据流和 ICU wrapper 进入产品；保留完整厂商后缀，兼容的整数 API 基础版本不覆盖完整版本。支持范围由符号、架构和控制流限制，未包装成通用 stripped 库识别能力。
5. **补充三条实际厂商构建版本。** Allwinner 的 `libIMGegl.so`、`libGLESv2_POWERVR_SGX544_115.so` 提取 `1.12@3052601` DDK 构建标识；`libWVStreamControlAPI_L3.so` 的两个已定义 getter 静态返回一致的 `4.5.0.10113`。三条标为 `vendor-build`，不冒充通用上游发布版本。[PowerVR 构建标识格式](https://android.googlesource.com/kernel/x86_64/+/8ac3b7cbf14fa5d328213b1592efce6ae16f1167/drivers/staging/imgtec/pvrversion.h)
6. **剔除兼容性误报。** APEX `libopenjdk.so` 含 `OpenSSL 1.1.1 (compatible; BoringSSL)`。这是 BoringSSL 的兼容说明，已去掉对应 OpenSSL 发布版本声明；同文件另有独立真实 OpenSSL 版本时仍保留。兼容字符串的含义可由[BoringSSL 官方头文件](https://boringssl.googlesource.com/boringssl/+/refs/heads/main/include/openssl/crypto.h)核查。

### 独立证据回读

三条厂商构建版本的实际文件摘要、字符串偏移和 getter 虚拟地址记录在 `vendor-observations.json`，并对冻结队列的三个 observation key 建立有限 verified map。该三条样本核对不代表全部原生库准确率。

元数据核查脚本独立打开对应 APK/JAR 的 ZIP 成员，比较原文、路径坐标、purl 和输出版本，不调用产品的元数据解析器作为真值。**152 条元数据组件、1070 个组件×位置证据均与声明一致，未发现不一致**，其中 AndroidX 1012 次、Maven 58 次。每个成员记录原文和 SHA-256。它证明扫描器忠实读取声明，未验证 DEX/native 实现与声明的对应，不能据此声称整体代码版本准确率 100%。

## 参考库扩充的真实效果

新增 `binary_samples.json` 与可重建导入器：**108 条记录、100 个不同整文件 SHA-256、27 个发布产物版本、3 个 Maven 坐标、2 种 native 库文件名**。分别为 AndroidX Graphics Path 11 个版本、TensorFlow Lite 7 个版本、LiteRT 9 个版本。不能将 108 条记录说成 108 种组件库。

下载缓存包含 55 个 AAR/POM 文件，重新核对摘要全部一致；AAR 合计约 107.95 MiB。来源、产物内路径、架构、发布/预发布性质均保留。8 组跨版本相同哈希保留候选集合；无任意选择版本。TensorFlow Lite 2.17.0 的 POM 已重定位到 LiteRT 1.0.1，因此没有制造旧坐标 2.17.0 的二进制样本。[官方重定位 POM](https://repo.maven.apache.org/maven2/org/tensorflow/tensorflow-lite/2.17.0/tensorflow-lite-2.17.0.pom)

**实际目标的 9 个相关 native 文件，整文件精确哈希命中为 0/9，版本覆盖增益为零。** 这说明公开 AAR 字节与固件内重打包/重编译字节存在差异，不能把导入成功算成识别成功。公开发布产物是本轮来源，不声称已具备编译器、优化选项和厂商分支构建矩阵。[Google Graphics 发布记录](https://developer.android.com/jetpack/androidx/releases/graphics)

## 创新方向的实际试验

### 代码候选检索：有缩小范围的效果，没有精确版本增益

实际运行 Ghidra 12.2 的 `GenerateSignatures.java`，对 Tubesky 中的 x86-64 `libandroidx.graphics.path.so` 与 11 个官方产物做静态分析，使用 `medium_nosize`。这里比较的是具有至少 10 个不同特征的 **BSim 特征向量完全相等**，不是完整 BSim 加权相似度/显著性评分。

目标共有 8 个符合门槛的函数向量；8/8 同时匹配 `1.1.0-alpha01`、`1.1.0-beta01`、`1.1.0-rc01`、`1.1.0`，在其余 7 个被比较版本上为 0。进一步核对这四个参考产物与目标的 `.text`、`.rodata`、`.data.rel.ro`、`.note.android.ident`，对应节字节完全相同，但整文件不同。**结论仅是这四个候选相关，无法从这些证据分辨其中一个版本。** 未向正式 SBOM 写入任意精确版本。

该结果验证了行业的“两阶段识别”方向：相似性有助于候选检索，精确版本需要候选之间有区分力的差异。[Ghidra BSim 官方说明](https://github.com/NationalSecurityAgency/ghidra/blob/master/GhidraDocs/GhidraClass/BSim/BSimTutorial_Intro.md)。方法已有研究先例，不能宣称首创。当前是单家族实验，未证明跨编译器、优化、架构、厂商分支、静态裁剪及未收录版本的普遍效果。

### FreeType 配对函数语义：实际 0/4，未进入产品

实验尝试把 `FT_New_Library` 的版本字段初始化与 `FT_Library_Version` 读取配对。[FreeType 上游源码](https://raw.githubusercontent.com/freetype/freetype/VER-2-13-3/src/base/ftobjs.c)。合成编译样例及错误控制通过，但对 system 镜像内四个实际 `libft2.so` 均未识别出版本。四个文件确实存在、已通过只读 ext4 实际读取，不把宿主 `/system` 路径测试的四次 skip 算成实测。

该模块保留在 `experiments/version_coverage/freetype_version.py`，没有接入 `BinaryInventory`。Cronet 的实际 getter 存在间接调度，当前有限证明路径也没有获得新的精确版本；未以 SONAME 中的数字作为替代。

## 验证与剩余工作

- 最终仓库测试：`PYTHONPATH=src <项目 Python> -m pytest tests -q -rs`，**242 passed、4 skipped、6 warnings**。4 次 skip 是仅检查宿主 `/system` 的可选 FreeType 测试；实际镜像 0/4 另有记录。告警是既有 Pydantic 配置弃用及故意重复 ZIP 成员的反例。
- 新增生产模块及实验脚本经 Ruff 检查；格式检查与 Git staged diff 检查在提交前运行。有限 getter 样例不当作上游真实构建语料。
- Luna 独立审查发现 malformed ext4 inode group 可除零，以及损坏 DEFLATE 成员可中断后续扫描；均先复现再修复。另补可执行文件类型、APEX 计数、BoringSSL 兼容串误报回归。最新专项复核未发现可复现 P1/P2，相关 34 项测试通过；这不代表整体产品准确率已获得认证。
- 未实现通用函数参考索引服务、DEX 结构库识别、候选之间自动差异判别及广泛构建矩阵；本轮不能将这些列为已交付收益。参考库整文件匹配在实际目标上的零命中，说明后续投入需覆盖构建变体，而非继续仅增加相同类型的哈希记录。
- 两份镜像的 50% 正确版本覆盖率仍需继续工作，本提交不得作为该目标的验收通过。对代码相同的多个发布版本，只能保留候选或寻找额外来源，不能承诺仅凭相同代码必定恢复唯一发布号。

## 本机证据索引

证据根目录：`reports/version-coverage-50-20261118/`，按仓库规则忽略，未提交原固件、下载二进制或大型报告。

| 证据 | 内容 |
|---|---|
| `baseline.json` | 冻结记录数、基线报告摘要和版本口径 |
| `final/{allwinner,system}/` | 实际源副本、源哈希、输入哈希、分析 JSON、SBOM、逐文件观察、运行成本、冻结队列比较 |
| `vendor-observations.json` / `allwinner-verified.json` | 三条厂商构建证据及有限验证映射 |
| `metadata-audit-final.json` / `.md` | 元数据独立回读原文、摘要和比较 |
| `references/checksum-manifest.json` | 55 个公开参考文件摘要、重定位警告和导入数量 |
| `aar-target-matches.json` | 9 个实际目标文件的零整文件命中 |
| `bsim/` | 真实输入摘要、11 版本来源、Ghidra 项目与日志、签名、逐函数比较和节字节比较 |
| `bsim-repro/` | 用提交脚本重新准备的 11 个参考与实际 query，摘要一致 |
| `freetype-real-results.json` | 四个实际目标文件摘要与零命中 |
| `apex-final-manifest-verification.json` | 最后修正后的 34 模块 manifest 定向回读及源文件摘要 |
| `commit-tests.log` | 最后一次完整仓库测试 |

实现计划见[计划文件](superpowers/plans/2026-11-18-version-coverage-50.md)，前置行业调查见[研究报告](industry-version-recognition-strategy-2026-11-18.md)。
