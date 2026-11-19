# 二次实扫：完整版本、版本 API 与参考代码候选

日期：2026-11-18。分支：`codex/version-coverage-50`，前一生产提交 `c804110`。

**50% 目标仍未通过验收。** 本轮继续使用用户给出的两份固件，用户未额外提供源码、构建 manifest 或供应商 SBOM。后续从 system 镜像内部发现的 manifest 与公开发布校验见[来源核查](waydroid-build-provenance-research-2026-11-18.md)。新增识别进入实际生产扫描路径；候选、被拒绝的实验和字段填充比例不替代正确版本覆盖率。

## 实测口径

冻结队列仍为 Allwinner 582 条 / 312 条原生库、system 1129 条 / 774 条原生库。输入文件摘要与前一报告相同，完整 SHA-256、范围及前一阶段结果见[前一实测报告](version-coverage-50-results-2026-11-18.md)。Allwinner 本次读取原容器中已提取的 system ext4 分区；其他 IMAGEWTY 分区不在本次对比范围内。system 包含实际展开的 APK、APEX payload。

两个最终目录为 `reports/version-coverage-next-20261118/final-reviewed/{allwinner,system}/`。运行器先复制 `src/`，再从副本执行 `AndroidSystemScanner` 和 CLI 去重；`source-sha256.json` 标识实际代码。扫描时 Git revision 仍显示 `c804110`，不能据此将未提交改动误认为已经在旧提交中。

| 冻结队列 | 初始有版本 | 前一生产阶段 | 当前有版本 / 固定分母 | 当前比例 | 未匹配仍占分母 |
|---|---:|---:|---:|---:|---:|
| Allwinner 全部 | 119 | 122 | 124 / 582 | 21.3% | 2 |
| Allwinner 原生库 | 21 | 24 | 22 / 312 | 7.1% | 2 |
| system 全部 | 155 | 154 | 154 / 1129 | 13.6% | 5 |
| system 原生库 | 27 | 26 | 26 / 774 | 3.4% | 3 |

前一阶段为 `c804110` 所记录的生产结果。按上述已填字段作最乐观估计，全部队列距 50% 仍分别至少缺 167 / 411 条；原生库队列仍至少缺 134 / 361 条。新增组件不能填补冻结队列中其他未知文件的版本。

| 当前扩展输出 | 有版本 / 全部记录 | 有版本 / 原生库记录 | ELF / APEX | 告警 | 耗时 | 峰值 RSS |
|---|---:|---:|---:|---:|---:|---:|
| Allwinner system 分区 | 129 / 586（22.0%） | 27 / 316（8.5%） | 444 / 0 | 0 | 91.910 秒 | 662032 KiB |
| Android 16 system | 308 / 1454（21.2%） | 31 / 917（3.4%） | 2134 / 34 | 0 | 330.997 秒 | 1086632 KiB |

原始组件观察数分别为 640 / 3440。耗时、内存是在本次虚拟机负载下测得，没有隔离 cache/负载变化，不能作为与前一阶段的受控性能对比。零告警也不证明已覆盖全部格式或静态链接组件。

上述有版本数量是非空版本标识的计数，包含完整开发/厂商构建标识；不代表所有条目已经独立验证正确。前一阶段建立的三个 Allwinner 厂商构建样本继续保留有限 verified map。没有全量真值，不能给出总体准确率；即便乐观地把所有已填字段都视为正确，当前也不满足 50%。

冻结匹配仍使用原来的一对一规则，不通过更换名称或类型追回分数。Allwinner 的 BusyBox/pppd 改为 application 后，旧 library 行仍占分母。当前去重可将同名、同版本、不同架构的库合并；相应实际文件的新增命中应同时查看逐文件观察，不能把文件数说成新增独立组件数。

system 的两个 i386 Protobuf 本体现在得到 3.21.12，与已有同名同版本的其他架构记录合并。一对一评估未重复使用合并行，另两个旧 Protobuf 行仍作为未匹配；其余三条未匹配与前一阶段相同。因此冻结字段计数没有增长，不代表这两个实际文件仍然未知。

## 已接入产品的改变

- **命令版本及类型归属。** 识别 dhcpcd、hostapd_cli；BusyBox SMP 与 pppd 使用同族证据。hostapd、wpa_cli、wpa_supplicant 保留 `2.0-devel-4.4.4_rtw_r10450.20140220` 全串。BusyBox 的 `udhcp` vendor class 使用 `BB_VER`，完整标识一致时归 applet 事实；不同版本和后缀不被截断或静默合并。[AOSP version.h](https://android.googlesource.com/platform/external/wpa_supplicant_8/+/android-4.4.4_r2/src/common/version.h)、[BusyBox 源码](https://coral.googlesource.com/busybox/+/refs/heads/release-chef/networking/udhcp/dhcpc.c)
- **libvpx 与 libevent 的完整版本。** 配对整数与字符串 API，保留 libvpx Git 后缀；32 位 x86 也走字符串路径。实际 Allwinner 恢复 `1.2.0-5082-g58f7543` / `1.3.0`，system 的 payload 库为 `1.15.0-1679-ge326c38abc`。libevent 保留 `-stable`；`libevent using: %s` 只是后端名称消息，只用于身份。[libvpx 实现](https://chromium.googlesource.com/webm/libvpx/+/master/vpx/src/vpx_codec.c)、[libevent 实现](https://raw.githubusercontent.com/libevent/libevent/release-1.4.13-stable/event.c)
- **CryptoAuthLib 自有发布对象。** 读取已定义、长度正确、有相关定义 API 的 `atca_version`，验证 yyyymmdd 日期。实际值 `20160108` 归 CryptoAuthLib，未给宿主 `libatsha204.so` 填版本。上游历史代码明确将该对象作为发布标识；没有用编译日期代替版本。[Microchip 历史实现](https://github.com/MicrochipTech/cryptoauth-openssl-engine/blob/master/cryptoauthlib/lib/basic/atca_basic.c)
- **Protobuf ELF32。** 对 ARM/Thumb、i386 的 `VerifyVersion` 定义证明 minLibraryVersion 失败边和传入 `VersionString` 的库自身常量。原八个 Allwinner 定向位置均命中；最终整扫另命中 Widevine 与 WebRTC 容器，总计十个位置、七个不同 ELF，得到 2.3.0 / 2.5.0。system 的 i386 full/lite 本体及 `service.incremental.so` 内嵌库共三个文件为 3.21.12。它们不是宿主、调用方头文件或最小兼容版本。[上游角色定义](https://android.googlesource.com/platform/external/protobuf/+/master/src/google/protobuf/stubs/common.cc)
- **TensorFlow Lite 运行库。** 四 ABI 的 `nativeRuntimeVersion` 经本地返回字符串 helper 到 JNI `NewStringUTF` 参数均指向 `2.22.0`。正式输出独立 `TensorFlowLite-runtime`，标记 `runtime`；JNI/Maven/LiteRT 产物版本仍未知。上游文档区分 TFLite 自身版本、TensorFlow 版本及其他版本字段；本轮没有推断 Maven 坐标。[TensorFlow 版本说明](https://www.tensorflow.org/guide/versions)、[JNI 函数表](https://docs.oracle.com/en/java/javase/26/docs/specs/jni/functions.html#newstringutf)

版本函数的值还必须来自有界、可证明的静态路径。新增控制拒绝可写全局变量初值、寄存器覆盖、错误 flags/frame/stack、不可达边及伪造 PLT/GOT 对应。最终复审还复现了 TFLite 可写地址池和 Protobuf 越过 UD2/UDF 等 trap 的反例；现在地址计算 literal 也须只读，Protobuf 前缀与失败块只接受支持的连续指令形态。对未知形态保留未知，未执行或加载目标 ELF。

## 扩库及创新试验的实际效果

规则目录本轮为 84 条 reference 记录；这不是新增 84 个库家族。公开二进制样本仍为 108 条记录、100 个不同整文件摘要、27 个产物版本、3 个 Maven 坐标，未把目标固件的未知字节反向标注后灌入已知库。

1. **独立 checker 对照。** 使用本机 CVE Binary Tool 3.4 的 365 个 checker，实读 Allwinner 302 条未知库路径、system 1566 条直接 ELF 路径。候选核查暴露了编译器版本、兼容版和版本截断，未产生大规模可靠新增版本。方法、范围及有限反例见[对照报告](version-checker-comparison-2026-11-18.md)。
2. **代码节候选。** 新增离线可复现的 `compare_sections.py`，先验证公开 AAR 与 native 成员摘要，再比较四个节的全部字节、VA、flags 及架构。9 个实际目标中，5 个 Graphics Path 文件均对应 `1.1.0-alpha01` / `beta01` / `rc01` / `1.1.0` 四个参考发布；4 个 TFLite 文件无同节 profile。代码字节改变反例被拒绝，附加无引用尾部不影响 profile。它扩大了前一单 ABI 试验的候选定位范围，**精确版本增益仍为 0**；没有将候选放入产品版本字段。
3. **FreeType 配对函数。** 收紧可变数据、重叠内存写、寄存器和 getter 分支控制后，真实 system 四库仅 x86-64/AArch64 两个得到 2.13.2；i386/ARM 与 Allwinner 库拒绝。旧 generic fallback 已禁用。主审另复现并修复 NULL 输出分支跳过后续输出的反例。仍只保留实验，未接入 `BinaryInventory`，不计为产品增益。
4. **Rust 候选筛查。** 按 `.dylib.so` 后缀筛查的 93 个未知文件没有得到可验证 crate 发布号。工具链路径和 Tokio 主版本线不当作 crate 精确版本；也未凭后缀断言全部文件均为 Rust。

代码候选、版本差异确认与真实参考库是前一[行业调查](industry-version-recognition-strategy-2026-11-18.md)已有的技术路线，不宣称本轮首创。当前证据支持继续做带来源的参考样本和区分实验；不支持从单家族结果外推到所有 stripped、编译器或厂商变体。

## 验证与证据

- `FREETYPE_SYSTEM_IMAGE=<system.img> PYTHONPATH=src <项目 Python> -m pytest tests -q -rs`：**397 passed，0 skipped，6 warnings**。告警为既有 Pydantic 弃用及有意重复 ZIP 成员的反例。真实镜像通过只读方式获取，未将宿主路径不存在导致的 skip 算作命中。
- 新增生产模块、语义提取器、新增/更新实验及相关测试经 Ruff 检查。旧 inventory/static/deep 文件存在既有 lint 项，未据此宣称全仓 lint 无告警。
- GPT-6 Luna 主线审查的完整后缀、可写变量和 applet 反例均已进入回归；新路径还经主 agent 的控制流、返回寄存器、JNI receiver 与 epilogue 反例核查。最终两项反例经修复前失败、修复后通过，以及 Luna 独立重现确认关闭；其定向 77 项测试与四 ABI TFLite、选定 Protobuf 回读通过。有限审查/测试不等同于总体准确率认证。
- 扫描 JSON、CycloneDX、逐 ELF SHA-256/声明、成本和源副本保留在最终目录。`section-candidates-final.json` 记录 108 条参考、9 个目标、每个候选与控制结果；`protobuf/`、`tflite/`、`freetype/` 保留定点证据。原始固件、下载二进制、报告目录均未提交 Git。
- `final-reviewed-readback.json` 核对两份实际源快照完全相同且与当前生产源码一致、冻结输入摘要不变、SBOM 根哈希和组件数与分析 JSON 一致、四个 JNI 文件仍无产物版本而独立 runtime 字段正确输出。两份分析 JSON 与最终两项审查修复前的结果完全相同；原真实命中保留，新增反例被拒绝。该检查是数据一致性核查，不是全体版本真值认证。

复现入口见 [README](../experiments/version_coverage/README.md)。本提交记录已验证的增量，**不是“50% 版本覆盖率版本”交付**；全量准确率真值、广泛参考构建矩阵与精确版本区分仍未建立。
