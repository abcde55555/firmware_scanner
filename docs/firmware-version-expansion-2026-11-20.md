# 固件版本识别扩展与路线图复核

Date: 2026-11-20  
Scanner: 0.16.0  
Rule release: `builtin-2026.11.20.4`

## 结论

用户提供的 `firmware_sbom_solution_roadmap.md` 可以作为通用商业产品路线，
其中“多层证据、版本语义分层、held-out、关系图和 License”方向正确。它的
旧基线、已修代码问题和未经目标固件验证的收益不能直接纳入实施承诺。

本轮继续选择低成本的强证据路线：公开版本 getter、精确 SONAME 和 AOSP
release tag。新增规则没有使用“字符串里出现版本号就算命中”，也没有把源码
tag 版本升级成 exact。它们输出 `estimated-aosp-release`，不会进入 exact
OSV 查询。

## 路线图中需要修正的判断

- 路线图把 commit `5691133` 的 13.6%/21.3% 写成当前基线。0.15.0 固定队列
  已是 Android 16 `785/1,129`、Allwinner `190/582`；这些是 usable 字段
  覆盖，不是独立验证准确率。
- 多 DEX 截断和内容缓存问题已经修复。当前仍存在普通 system ELF 的 32 MiB
  读取上限，但 Allwinner 目标库没有超过该上限，因此它不是本次 Allwinner
  版本缺口的主要原因。
- Rust 源码位置、NOTICE 项目路径和 License 文本都属于候选或归因证据，
  不能单独证明具体 release。
- 全量 Version-Delta、Top 500 Rust 索引和 Ghidra BSim 的工程量明显高于
  当前两项收益。它们应先做有独立真值和停止条件的试点。
- 规则数量不是覆盖指标。应以新增 usable、exact、estimated、错误 claims
  和独立真值结果为验收口径。

## 通用原生库 getter 扩展

新增以下公开 API 的静态返回指针识别：

| 组件 | 定义符号 | 版本 |
|---|---|---|
| libfuse | `fuse_pkgversion` | 包版本字符串 |
| libarchive | `archive_version_string` / `archive_version_number` | 双证据 |
| json-c | `json_c_version` | 发布字符串 |
| Jansson | `jansson_version_str` | 发布字符串 |
| MaxMind DB | `MMDB_lib_version` | 发布字符串 |
| liborc | `orc_version_string` | 发布字符串 |
| libsodium | `sodium_version_string` | 发布字符串 |

探针只接受定义函数和可映射的只读 NUL 结尾字符串。`fuse_version()` 一类
ABI 整数不会被当作补丁版本。

## 第三方 20 库泛化实验

为避免在已知两批目录上继续过拟合，本轮冻结了第三批与现有目录不重合的 20
个 Debian 原生库，先用 0.15.0 规则盲跑，再依据失败补强通用 getter：

| 指标 | 规则补强前 | getter 补强后 |
|---|---:|---:|
| 身份命中 | 19/20 | 20/20 |
| exact | 3 | 7 |
| estimated | 0 | 0 |
| wrong / wrong estimate | 0 / 0 | 0 / 0 |
| unknown | 17 | 13 |
| usable coverage | 15% | **35%** |

新增 exact 为 Jansson `2.14`、MaxMind DB `1.12.2`、liborc `0.4.42` 和
libsodium `1.0.18`。由于该目录的盲跑结果参与了后续规则开发，补强后的
35% 不再属于完整 held-out；它证明缺口类型和规则价值，不证明跨发行版准确率。

## Modern Android 16 实扫

0.16.0 完整扫描结果与 0.15.0 完全一致：

| 切片 | 结果 |
|---|---:|
| 全部组件 usable | 785/1,129, 69.53% |
| 原生库 usable | 621/774, 80.23% |
| exact | 225 |
| estimated | 560 |
| 独立核验 | 0 |

新增 getter 和 Android 4.4.4 source-tag 规则没有为 Modern 固定队列增加
usable 条目。完整扫描耗时 581.464 秒，峰值 RSS 2,429,176 KiB。该结果没有
新增独立真值，因此仍不能把 69.53% 解释为准确率。

## Allwinner 固件实测

Allwinner 固件仍使用同一镜像 SHA-256 和固定基线。新增 0.16.0 结果与
0.15.0 同脚本结果对比如下：

| 切片 | 0.15.0 usable | 0.16.0 usable | 增量 |
|---|---:|---:|---:|
| 全部组件 | 190/582, 32.65% | **193/582, 33.16%** | +3 |
| 原生库 | 53/312, 16.99% | **56/312, 17.95%** | +3 |
| exact | 119 | 119 | 0 |
| estimated | 71 | 74 | +3 |
| independent verified | 5 correct / 0 error | 5 correct / 0 error | 不变 |

剔除包装库误归因后的最终扫描在提交 `87fffdf` 上完成。输入分区 SHA-256
保持 `87c2d561464ec8144f2c580ce5f781262f0506f57a506d534e652e96099f0cf2`；
内容结果稳定，但本轮主机负载较高，单次耗时 359.137 秒，不能用于性能回归结论。

三个新增条目均为 explicit estimate：

- `libmtp` 1.0.1，来自 `android-4.4.4_r2` 的 `configure.ac AC_INIT`；
- `libvorbisidec.so` 0.07，来自同 tag 的 Tremolo README；
- `libwebviewchromium.so` 33.0.1750.166，来自同 tag 的 `chrome/VERSION`。

所有规则同时要求固件 `ro.build.version.release=4.4.4`、build ID
`KTU84Q`、精确 SONAME 和唯一 source tag。版本仍可能受 OEM patch 影响，
因此 3 项都保留 estimate 语义，不能作为单点上游 CVE 结论。

## 仍需解决

- Allwinner 固定队列达到 50% 仍缺大量条目；本轮 +4 是可靠增量，不是
  50% 目标的突破。
- 剩余 20 库实验中的 c-ares、liburing、libidn2、GnuPG error、SASL、
  LDAP、MIT Kerberos、Nettle、libtasn1、libunwind、cap-ng 和 libmnl
  需要继续区分“没有 release API”和“有 API 但需要参数/结构解析”。
- 不能给自产函数或未安装的库制造版本证据；没有稳定 API 的库应继续
  unknown，或进入有独立真值的差分试点。
- BSim、全量 Rust 索引和 C++ Delta 只有在目标固件上新增 verified/usable
  数量达到门槛后才值得扩建。

## 下一步优先级

1. 新建与现有三批均不重合的第四套跨发行版 held-out，对 0.16.0 做一次
   不参与规则开发的盲测。
2. 实现 `check_version(NULL)` 这类有分支但返回唯一 release 指针的跨架构
   证明，优先覆盖 GnuTLS、libidn2 和 libtasn1。
3. 对 Allwinner 明确第三方库构造逐个组件的真值表，继续优先处理 SONAME、
   定义符号和 AOSP tag 可唯一连接的项目。
4. 在真正缺少静态线索的 10–20 个第三方库上试点 Version-Delta，先测
   exact/adjacent/wrong，再决定是否扩展。
5. 保持数据库、规则包和报告可重放；版本覆盖、独立准确率和漏洞候选必须
   分开报告。

## 复现证据

- `reports/version-coverage-getters-20261120/provenance-expansion-allwinner-87fffdf/system_analysis.json`
- `reports/version-coverage-getters-20261120/provenance-expansion-allwinner-87fffdf/evaluation-fixed.json`
- `src/firmware_scanner/data/provenance/android-release-project-estimates.json`
- `src/firmware_scanner/data/rules.lock.json`
- `tests/unit/test_static_version.py`
- `tests/unit/test_android_provenance.py`
- `reports/heldout-debian-independent3-20261120-blind/heldout-report.json`
- `reports/heldout-debian-independent3-20261120-tuned/heldout-report.json`
- `reports/version-coverage-getters-20261120/provenance-expansion-allwinner-87fffdf/schema-validation.json`
- `reports/version-coverage-getters-20261120/provenance-expansion-modern-2831fe4/evaluation-fixed.json`
- `reports/version-coverage-getters-20261120/provenance-expansion-modern-2831fe4/schema-validation.json`
- `reports/version-coverage-getters-20261120/wheel-0.16.0/wheel-verification.json`
