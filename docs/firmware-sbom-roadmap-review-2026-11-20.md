# 固件 SBOM 路线审查与 0.14.0 实测结论

Date: 2026-11-20
Baseline commit: `a1ab86b37ab160f581d93d97fcf76ad56a5b48ab`

## 结论

路线图的长期方向可以作为架构参考，但不能按文档中的旧基线和时间表直接排期：

- 文档仍以 `5691133` 的 21.3%/13.6% 作为当前起点，但当前固定分母基线已经达到
  Android 785/1,129（其中 exact 225）、Allwinner 190/582（其中 exact 119）。
  两边各有 39 项来自明确隔离的平台构建基线，不能算作第三方上游版本命中。
- “只扫第一个 DEX”和“缺少内容缓存”已经修复；“版本字段覆盖”仍不能称为
  “版本准确率”。
- Rust 源码位置、NOTICE 项目路径和 LICENSE 只能提供候选或归因，不能单独证明
  具体上游 release。
- 直接建设 PostgreSQL + Ghidra BSim、全量 Version-Delta 和 Top 500 Rust 索引
  成本很高，但路线没有先给出这组目标固件上的可测增量。

本轮优先验证了成本更低、证据更强的路线：**ELF 内源码路径 + 镜像哈希匹配的
source manifest + 项目 revision + 声明版本的源码文件**。它比继续增加字符串
正则更适合作为当前创新点。

## 路线中仍然正确的部分

1. 版本必须分为 exact、explicit estimate、source revision、parent package、
   range/conflict 和 unknown；“非空版本”不是 accuracy。
2. 子系统和宿主库要分开归因。`libbpf 1.6.x`、APEX parent version 和
   `contains-evidence-for` 不能被当成同一个语义。
3. 二分/三分法分母是必要的。Android 平台模块、明确第三方 OSS 和 vendor
   proprietary 不能用同一套版本目标衡量。
4. 重型相似度/BSim 只能在前序证据不足、目标样本确实稀少时作为门控兜底。
5. Held-out 必须与规则开发隔离，并固定镜像、源码、规则锁和评测器版本。

## 需要修正的路线判断

| 路线判断 | 当前事实/修正 |
|---|---|
| 仍以 2026-11-19 的初始覆盖率为基线 | 本轮开始时的同分母基线是 Android 690/1,129、原生 567/774；Allwinner 146/582、原生 48/312 |
| 多 DEX 只扫第一个 | 当前已遍历 `classes*.dex`，有单 DEX 64 MiB、总解压 256 MiB 和 64 个成员配额 |
| 缺少 SHA-256 内容缓存 | `BinaryInventory` 已有内容缓存，复扫时命中字节相同路径 |
| Rust 位置可以直接精确求解 | 位置记录只是源码线索；仍需要版本历史、构建配置和冲突样本 |
| 332 个 NOTICE 单仓候选可形成确定增量 | 候选量不是命中量；必须先证明目标 revision 和版本声明 |
| 先建设全量 Version-Delta/BSim | 应先做 20 个明确 unknown 的门控试点，达不到增量门槛就不建设全量 |
| 24 周 KPI 可直接承诺 70% | 当前只有 coverage，没有完整图像独立真值，不能承诺独立准确率 |

## 本轮新增的有效方法

### 0. Android framework 平台构建基线

0.13.0 只对同时满足以下条件的未解析条目附加镜像的 Android build：

- `component_type=framework`；
- 规范名以 `framework/` 开头；
- 证据路径位于 `/system/framework/` 或分区根目录 `/framework/`；
  `/vendor/framework/` 和 `/product/framework/` 明确排除。

结果写入 `estimated-platform-build`，并同时声明
`platform-build-not-upstream-release` 和 `platform-first-party`。Modern 的
baseline 是 `16-BP2A.250805.005-1775195212`，Allwinner 是
`4.4.4-KTU84Q-20180511`。

这不是第三方库版本识别算法。它解决的是第一方平台构件“没有独立上游
release”时的构建归属问题。exact 数量、原生库覆盖率和第三方 OSS 切片均
未变化；39 个条目也没有进入 OSV 查询或 VEX 的 `affects`。

### 1. 公开版本 getter 与版本对象

缺少版本线索的高频库优先接入有明确 API/对象的探针：

- 字符串 getter：libsndfile、libsamplerate、libyaml、LZO、libzip、libaom、
  Pango、Cairo、Pixman、libpsl、XZ、bzip2、libffi。
- 整数 getter：libjxl、seccomp。
- 版本对象/结构：GMP、GdkPixbuf、libunistring、nghttp2、nghttp3、ngtcp2。

所有探针都要求定义符号、可映射的只读对象或结构、版本格式一致和证据偏移。

### 2. 源码路径约束的 manifest 归因

现代 Android 镜像的 SHA-256 精确匹配内置 source manifest。扫描器现在从 ELF
中提取真实源码文件路径，并且只接受以下条件同时成立的映射：

- 文件名规则匹配组件；
- ELF 内出现该 manifest 项目的源码路径；
- manifest 中的项目 revision 唯一；
- 输出保留项目、revision、路径证据和作用域。

这套方法覆盖了 rust-openssl、Rust aconfig 模块、OpenSSH、Neven、ANGLE、
compiler-rt、fsverity、libbase、logging、RenderScript、libmeminfo、
libziparchive、Wi-Fi、media 和 hardware interface 支持库。

### 3. 项目清单中的声明版本

只有项目 revision 同时具有以下材料时才升级为 exact：

- `Cargo.toml`/`Android.bp` 的 package version；
- `version.h`/`configure.ac` 的 release 宏；
- 与镜像 source manifest 完全一致的 40 位 revision；
- HTTPS 来源和可审计文件路径。

本轮新增：

- rust-openssl `0.10.64`；
- OpenSSH `9.0p1`。

其余项目保留 `git:<revision>`，明确标注
`estimated-source-revision`，不会进入精确 CVE 版本查询。

### 4. 评测器精度修正

原来的 coverage evaluator 将 APEX/APK parent version 和 source revision 计为
exact。现在：

- `estimated-parent-package`、`estimated-source-revision`、wildcard estimate
  计为 estimated；
- `conflict-unresolved` 不计为 usable；
- 一个去重后的 BOM 行可以覆盖多个固定基线路径；
- exact、estimated、range、unknown 和独立已核验结果分开报告。

## 实测结果

### Modern Android 16

固定分母：1,129 个组件，其中原生库 774 个。

| 指标 | 本轮前 | 0.14.0 |
|---|---:|---:|
| 全部组件 usable | 690/1,129, 61.12% | **785/1,129, 69.53%** |
| 原生库 usable | 567/774, 73.26% | **621/774, 80.23%** |
| 全部 exact | 172 | **225** |
| 原生库 exact | 54 | **102** |
| 全部 explicit estimate/source revision/parent/platform | 518 | **560** |
| unknown | 428 | **336** |
| independent accuracy | 未建立 | **未建立** |

0.12.0 的同分母结果是 746/1,129。0.13.0 新增的 39 项全部是
`platform-first-party` 的 framework build baseline；第三方 OSS 固定切片仍为
100 项，其中 87 exact、13 estimated。因此 69.53% 是当前冻结分母的字段覆盖，
不能与路线图中“第三方 OSS 50%”直接等同。

0.14.0 没有改变 Modern 的分桶。Allwinner 增加 5 个固定分母版本，均为
带 AOSP `android-4.4.4_r2` 来源的精确 build 估算；其中 libjpeg 还要求目标
二进制执行 ABI 62 检查，但该 ABI 被多种兼容实现使用，因此不升级为 exact。
另外四项是 libexif、SpeexDSP、STLport、Jhead。这 5 个条目有独立
来源真值，评测结果为 **5/5 correct, 0 errors**；它们属于开发校准集，不是
held-out。

明确第三方 OSS 切片中，固定分母 100 项全部有非空版本：87 exact、13
estimated。这里的 100% 是字段覆盖，不是 100% 准确率；该子集只包含已有明确
source project 或外部 PURL 的记录，存在按可获得证据形成的选择偏差，也不能作为
完整第三方 OSS 召回率。

### 两个数据库的实际效果

Modern Android：

- BLintDB 查询 1,789 个唯一 ELF，21 个文件产生 23 个候选，归并后确认 9 个组件身份；
- 8 个 exact 目标版本与 BLint 参考构建版本不同，保留为诊断信息，不覆盖目标版本；
- 1 个 parent-package version 标为 `not-comparable`，不再伪装成版本错误；
- NSRL 精确查询 1,789 个文件，命中 0。

Allwinner：

- BLintDB 查询 430 个唯一 ELF，确认 4 个第三方组件身份；
- NSRL 查询 430 个文件，命中 0。

因此数据库在这两份镜像上的主要价值是身份确认、taxonomy 证据和参考构建差异，
不是直接补版本号。NSRL 的精确文件哈希机制可用，但这组重新编译固件没有命中；
后续应保留数据库并继续用于其他固件，不能因为两份样本零命中而删除。

### 精确版本与漏洞层验证

- 43 个 Rust crate 由 revision-pinned `Cargo.toml` 转换为 Cargo PURL；
- exact 总量从 177 提升到 225，原生库 exact 从 54 提升到 102；
- modern BOM 的可查询组件从 223 增至 266；
- OSV 找到 43 个 Cargo 查询中的 4 条 Rust 生态漏洞：
  `anyhow 1.0.97`、`protobuf 3.2.0` 和 `rand 0.8.5`；
- Modern 总计 470 条漏洞候选，Allwinner 总计 1,500 条漏洞候选。它们是候选，
  尚未完成可达性、补丁回移或厂商状态确认。

### Allwinner Android 4.4

| 指标 | 结果 |
|---|---:|
| 全部组件 usable | 190/582, 32.65% |
| 原生库 usable | 53/312, 16.99% |
| exact | 119 |
| estimated | 71 |
| unknown | 385 |
| independently verified | **5，5 correct / 0 errors** |

Allwinner 新增的 39 项同样是 `estimated-platform-build`。它没有与分区镜像
哈希匹配的 source manifest，因此不得把 Modern Android 的 revision 映射外推
到该镜像，也不得把平台 build 写成 AOSP 或第三方库 release。

### Debian stripped libraries

| 数据集 | 最终 usable | exact | estimated | wrong | 精度 |
|---|---:|---:|---:|---:|---:|
| 54 库开发集 | 41/54, 75.93% | 39 | 2 | 0 | 100% among claims |
| 20 库冷启动首跑 | 2/20 | 2 | 0 | 0 | 100% |
| 20 库加入通用 getter 后 | 12/20 | 12 | 0 | 0 | 100% |

20 库从 2/20 到 12/20 证明通用 API 缺口是冷启动主要问题，但该集合在调参后
已不再是完整 held-out。下一步必须用新的跨发行版集合验证泛化。

## 路线调整建议

1. **Phase 0** 增加 source manifest、规则锁、三态版本和固定分母回归；不要只
   做统一解析框架。
2. **Phase 1** 顺序改为：包/语言元数据、官网 getter/版本对象、源码路径归因、
   项目声明版本、参考构建哈希。Rust 位置求解放在已有位置候选的小样本试验后。
3. **Phase 2** 的 C/C++ Delta 先覆盖目标固件实际出现的 20–50 个库，并设定
   可停止条件：新增 usable `>= 5pp`、独立精度 `>= 95%`、错误数不增加。
4. **Phase 3 BSim** 只对以下样本启动：没有源码路径、没有版本对象、没有可靠
   reference hash，且属于明确第三方 OSS。先用 20 个样本测增量，再决定是否部署
   PostgreSQL。
5. 每个阶段同时报告：
   - 组件身份精度；
   - exact 版本精度；
   - usable version coverage；
   - 独立核验覆盖率；
   - 错误/冲突数量；
   - 扫描时间、峰值内存和数据库版本。

## 当前仍不能宣称

- 不能把 69.53% usable coverage 宣称为 69.53% accurate。
- 不能把 source revision、APEX parent version 或 source archive 版本当作目标
  二进制已证明的上游 release。
- 不能把 39 个 `estimated-platform-build` 当作第三方版本召回，也不能用它
  查询上游 CVE。
- 不能把 Debian 54/20 库结果直接外推到 Android/Allwinner。
- 不能让 `libbpf 1.6.x`、Capstone `5.0.x` 等 generation estimate 用于单点 CVE
  版本查询。
- 不能把未复测的 BSim、Top 300/500 索引和 QEMU 结果写成已实现能力。
- 不能把 5 条 AOSP 校准结果外推为 Allwinner 全镜像准确率；其余 577 条固定
  记录仍没有独立真值。

## 机器可读结果

- `reports/version-coverage-getters-20261120/final-summary.json`
- `reports/version-coverage-getters-20261120/modern-fixed-cohort-extended.json`
- `reports/version-coverage-getters-20261120/allwinner-fixed-cohort-cli-equivalent.json`
- `reports/heldout-debian-54-20261120-final/heldout-report.json`
- `reports/heldout-debian-independent-20-20261120-final/heldout-report.json`
- `reports/version-coverage-getters-20261120/schema-validation.json`
- `experiments/version_coverage/verified/allwinner-ktu84q-aosp-4.4.4.json`
- `docs/firmware-sbom-roadmap-research-2026-11-20.md`
