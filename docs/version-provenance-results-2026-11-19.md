# 镜像来源校验与 SQLite 版本对象实测

日期：2026-11-19。前一提交：`e872bd7`；分支：`codex/version-coverage-50`。

**50% 目标未达到，本次固定队列覆盖率没有增长。** SQLite 新增一个真实文件的版本识别，其他四个实际库增加了独立对象证据；镜像来源调查没有被当作组件精确版本。用户仍只提供了两份固件，以下 manifest/NOTICE 来自镜像内部，参考归档和源码来自公开上游。

## 实扫结果

固定分母、原始输入摘要及一对一评估规则保持不变。Allwinner 只重扫原 IMAGEWTY 中已提取的 system 分区；system 重扫包含实际展开的 APK/APEX。没有执行目标二进制。

| 固定队列 | 上次有版本 | 本次有版本 / 固定分母 | 比例 | 未匹配仍占分母 |
|---|---:|---:|---:|---:|
| Allwinner 全部 | 124 | 124 / 582 | 21.3% | 2 |
| Allwinner 原生库 | 22 | 22 / 312 | 7.1% | 2 |
| system 全部 | 154 | 154 / 1129 | 13.6% | 6 |
| system 原生库 | 26 | 26 / 774 | 3.4% | 4 |

这里统计的是非空版本标识，不是已独立确认正确的比例。有限真值表仍只有三个 Allwinner 厂商构建例子，三项一致、零错误；system 没有全量真值。即便将所有已填版本都当作正确，上表仍低于 50%；不能宣称总体版本准确率。

| 本次扩展输出 | 有版本 / 记录数 | 原生库有版本 / 记录数 | ELF / APEX | 告警 | 耗时 | 峰值 RSS |
|---|---:|---:|---:|---:|---:|---:|
| Allwinner system | 129 / 586 | 27 / 316 | 444 / 0 | 0 | 88.918 秒 | 801832 KiB |
| Android 16 system | 308 / 1453 | 31 / 916 | 2134 / 34 | 0 | 365.736 秒 | 1759032 KiB |

原始组件观察数仍为 640 / 3440。system 的 `/system/lib/libsqlite.so` 从未知变为 `3.44.5`，与 x86-64 的同名同版本记录合并，因此输出少一条未知记录。冻结的一对一匹配不重复使用合并行，原队列多一条未匹配，仍计入分母。这是实际文件识别改善，但不能说成固定队列分子增加。耗时和内存未做受控负载实验，不作性能提升结论。

## SQLite 改变及边界

生产 `object_version.py` 新增 SQLite 自有 `sqlite3_version` 数组路径。[官方 API 文档](https://www.sqlite.org/c3ref/libversion.html) 将它定义为库自身的版本声明。提取要求唯一的已定义 global/weak 对象、完整只读文件映射、对象大小内恰好终止的完整版本，以及三个定义于可执行映射的库 API；拒绝导入、可写对象、指针、缺少身份、截断和填充数组。保留完整后缀，未给引用 SQLite 的宿主文件赋版本，CryptoAuth 路径保留。

| 实际文件 | 对象声明 |
|---|---|
| system `/system/lib/libsqlite.so` | `3.44.5`，本次新增文件级识别 |
| system `/system/lib64/libsqlite.so` | `3.44.5`，补充对象证据 |
| system `/system/lib/arm/libsqlite.so` | `3.44.3`，补充对象证据 |
| system `/system/lib64/arm64/libsqlite.so` | `3.44.3`，补充对象证据 |
| Allwinner `/lib/libsqlite.so` | `3.7.11`，补充对象证据 |

`reports/version-corpus-20261118/sqlite-object-readback.json` 保存五个目标 SHA、对象 VA/文件范围及实际声明。getter 或对象的自报值仍不是完整源码构建证明；同一固件内不同变体的值也不能相互继承。

## 来源及候选调查的实际收益

完整调查和固定源码链接见[来源核查](waydroid-build-provenance-research-2026-11-18.md)。

- 下载公开 GAPPS ZIP，实际验证 1,001,886,694 bytes、SHA-256 `ddf5995f9104fe7164ad326def8bbed5cbf6340b55da5012e240b5855c44953b`。其唯一 `system.img` 成员长度 2,309,611,520 bytes、SHA-256 `ff9025e0f73e6784f57ef9d3dd5b90ce648d524dd4c20d8cfe5dc2b66ccc4ce4`，与重新计算的用户文件摘要一致。一次校验失败的断点缓存已隔离，结论仅用重新下载并通过摘要的归档。
- 镜像内 manifest 有 1148 个源码 project pin。冻结 system 未知原生库 748 条中，646 条有直接 NOTICE 许可归属，332 条能关联到单一源码路径候选。这些候选没有源码到目标 ELF 的构建证明，未填入组件版本。
- 同一 libevent 固定源码的 configure 声明 `2.1.12-stable`，Bionic 头文件却声明 `2.1.8-stable`，目标 getter 也返回后者。不能由差异直接断言 NOTICE 陈旧，也不能将 getter 自报值认证为上游实现版本。SQLite 根 METADATA 的 `3.42.0` 同样不能覆盖实际选择的多个构建版本。
- 版本 API 普查实际重读 system 1210 条路径 / 1208 个不同 ELF、Allwinner 286 / 286，逐一核对原文件观察 SHA；无读取跳过或解析错误。七条候选记录属于六个家族。该支持表固定在 `e872bd7`，不把后来增加的 SQLite 对象路径说成当时已有。
- libbpf 的三个真实 API 只给出 `v1.4`、major 1、minor 4；官方实现省略 patch，未制造 `1.4.0`。libdrm 的 `1.3.0` 是固定接口版本，不是包的 `2.4.x` release，亦未填入版本。
- libext2_blkid 的库内 API 实际声明 e2fsprogs `1.46.6` / `1.41.14`。这是后续可验证的项目版本路径；不能改称独立 util-linux libblkid 版本或外推给其他文件。本提交尚未接入该 API。
- 现有 108 条公开参考记录对九个真实目标的 GNU Build-ID 比较仍为零命中。Build-ID 本身也不是源码或版本证明，没有将无命中说成识别提升。

这些调查排除了错误捷径、找到了后续验证路径，没有带来大规模精确版本增长。

## 验证及复现

- SQLite 新测试先出现预期四项失败，新增路径后 25 项对象测试通过；GPT-6 Luna 独立复审未发现 P1/P2 阻塞。
- 两项旧真实文件测试已支持从 `FIRMWARE_SYSTEM_IMAGE` 或 `FREETYPE_SYSTEM_IMAGE` 只读读取 ext4，并校验固定 ELF SHA。最终 `FREETYPE_SYSTEM_IMAGE=<system.img> PYTHONPATH=src <项目 Python> -m pytest tests -q -rs`：**411 passed，0 skipped，6 个既有告警**。
- 本次修改的生产模块、测试和 census 脚本 Ruff 通过，`git diff --check` 通过；不据此宣称全仓无 lint 问题。
- 实扫目录为 `reports/version-corpus-20261118/scan/{allwinner,system}/`，含输入、分析 JSON、CycloneDX、逐文件声明、成本及源副本。两份源副本的 142 个文件一致，均与本轮生产源码相同。扫描时尚未提交，所以 metrics 的 revision 为前一提交 `e872bd7`；实际源码由 `source-sha256.json` 标识。
- `scan-readback.json` 重新核对原输入、固定基线、源副本、分析文件摘要、SBOM 根摘要/组件数及警告，并确认四 ABI TFLite runtime、十个 Allwinner / 三个 system Protobuf ELF32 定点命中保留。它是数据一致性核查，不是全量版本真值。

复现命令见 [README](../experiments/version_coverage/README.md)。本提交记录验证过的增量；**不能作为“50% 版本覆盖率版本”验收**。
