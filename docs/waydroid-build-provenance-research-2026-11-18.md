# WayDroidATV Android 16 构建来源与文件级 provenance 核查

研究日期：2026-11-18；主 agent 于 2026-11-19 补充实际归档及镜像校验。初始 Luna 调查限于公开来源和已提取材料，未下载大于 100 MiB 的文件；随后主 agent 下载公开发布 ZIP，流式读取其中的镜像并与用户文件比较。未上传或运行目标。

## 结论

**已下载并校验公开发布 ZIP；其中 `system.img` 的 SHA-256 与用户文件完全一致，发布来源链路已经建立。仍未找到每个 ELF 对应的组件版本/源码 commit 构建证明。** 镜像内 pinned manifest 提供了源码仓库及 commit 声明，适合限定来源候选；它本身不证明这些源码实际产出了某个 ELF，也不能覆盖预编译件、生成物或构建差异。公开镜像身份相同，不能直接补齐组件自己的精确版本。

研究对象为 `system.img`：Android 16 / Lineage 23.0-20260403-UNOFFICIAL-WayDroidATV-waydroid_tv_x86_64，build ID `BP2A.250805.005`，大小 2,309,611,520 bytes，SHA-256 `ff9025e0f73e6784f57ef9d3dd5b90ce648d524dd4c20d8cfe5dc2b66ccc4ce4`。本地 [覆盖率报告](version-coverage-next-results-2026-11-18.md) 的 `build_info` 与发布日期、设备及 Android 版本吻合；这些是镜像属性，不是各库版本证据。

## 找到的发布和可验证摘要

WayDroid-ATV 的 [20260403 Android TV 16 x86-64 发布页](https://github.com/WayDroid-ATV/waydroid-androidtv-builds/releases/tag/20260403) 将其描述为 LineageOS 23.0 / Android 16 QPR0，并提供 GAPPS、VANILLA system ZIP 及 MAINLINE vendor ZIP。与目标变体名称相符的附件是 `lineage-23.0-20260403-GAPPS-waydroid_tv_x86_64-system.zip`：[GitHub release API JSON](https://api.github.com/repos/WayDroid-ATV/waydroid-androidtv-builds/releases/tags/20260403) 给出长度 **1,001,886,694 bytes**、SHA-256 **`ddf5995f9104fe7164ad326def8bbed5cbf6340b55da5012e240b5855c44953b`**。主 agent 下载后的实际长度、完整 SHA-256 与此一致。发布还列有 218,939,865-byte vendor ZIP 和 732,856,622-byte VANILLA system ZIP；它们不是目标 GAPPS system 变体。

OTA 仓库在 [`974361ff` 发布提交](https://github.com/WayDroid-ATV/ota/commit/974361ff84191ecd7dcdd7b5edfe443a53818c84) 更新了 A16 TV 的 GAPPS/VANILLA system 与 MAINLINE vendor 索引。对应 [GAPPS.json 原文](https://raw.githubusercontent.com/WayDroid-ATV/ota/974361ff84191ecd7dcdd7b5edfe443a53818c84/a16-tv/system/lineage/waydroid_x86_64/GAPPS.json) 记录同一文件名、大小和 64 位摘要（字段 `id`）；这些值与 GitHub release 附件元数据的 SHA-256 和大小完全一致。由此可确认：OTA 索引指向该 release ZIP，且发布 ZIP 的完整归档摘要有公开值。

公开索引只提供 ZIP 容器摘要。主 agent 进一步流式读取已校验 ZIP 的唯一成员 `system.img`：长度 **2,309,611,520 bytes**，SHA-256 **`ff9025e0f73e6784f57ef9d3dd5b90ce648d524dd4c20d8cfe5dc2b66ccc4ce4`**，与再次计算的用户文件摘要相同。[实际校验记录](../reports/version-corpus-20261118/public-release-image-readback.json) 因此支持“目标镜像字节 → 已公布摘要的发布归档”；它仍没有把具体 ELF 的实现连接到某个源码 commit。一次断点续传缓存未通过完整 SHA，已隔离；结论仅使用重新下载并通过完整摘要的归档。

## Pinned manifest 的证据边界

本地已提取的 [system-build-manifest.xml](../reports/version-corpus-20261118/system-build-manifest.xml)（SHA-256 `7fc439a3ad859f4bac4fdc28db49e22bc015d462cbb60cce0d7242d4f0016361`）将默认分支声明为 LineageOS `lineage-23.0`，并包含 1,148 个 project 条目。它提供真实的候选源码仓库与 pinned revisions，例如：

| manifest project | pinned revision | 用途/边界 |
|---|---|---|
| [WayDroid-ATV/android_device_waydroid_waydroid](https://github.com/WayDroid-ATV/android_device_waydroid_waydroid/commit/d9da6db921b374650d33e8ffbbc38bf197bb2d1d) | `d9da6db921b374650d33e8ffbbc38bf197bb2d1d` | Waydroid device/product 配置 |
| [WayDroid-ATV/android_vendor_waydroid](https://github.com/WayDroid-ATV/android_vendor_waydroid/commit/3c25ab25ebb2f1d866b70a6a7e0e4225e119d284) | `3c25ab25ebb2f1d866b70a6a7e0e4225e119d284` | Waydroid vendor 改动 |
| [WayDroid-ATV/android_external_ffmpeg](https://github.com/WayDroid-ATV/android_external_ffmpeg/commit/9552caeebc441c762f7f10eb6ce9a455d635fdb6) | `9552caeebc441c762f7f10eb6ce9a455d635fdb6` | FFmpeg 源仓库 pin |
| [WayDroid-ATV/android_external_mesa](https://github.com/WayDroid-ATV/android_external_mesa/commit/25212b84ebcf1120d1196d6f8930869803b87421) | `25212b84ebcf1120d1196d6f8930869803b87421` | Mesa 源仓库 pin |
| [WayDroid-ATV/android_external_libva](https://github.com/WayDroid-ATV/android_external_libva/commit/9f7869a259074f8ef13623084d444ff924aff42e) | `9f7869a259074f8ef13623084d444ff924aff42e` | libva 源仓库 pin |

manifest 中还包含 AOSP/LineageOS 与 WayDroid-ATV fork 的其他源码 pins。上述 commit 说明 manifest 声明了哪些仓库状态；除非另有构建记录将 manifest digest、构建任务、产物 digest 和具体安装文件对应起来，不能把 pin 当成 ELF 实现版本真值。尤其不能将 Android 16、ABI、APEX 或分支号外推为库版本。

## 构建记录、CI 与其他产物

- [Android TV builds 仓库 BUILDING.md](https://github.com/WayDroid-ATV/waydroid-androidtv-builds/blob/main/BUILDING.md) 介绍本地同步、应用补丁和构建流程；其示例仍写 Android TV 11/13 的 lineage 分支，没有针对 20260403 这次构建给出可复现 job、manifest digest、builder identity 或产物证明。
- 检查 [`waydroid-androidtv-builds` Actions](https://github.com/WayDroid-ATV/waydroid-androidtv-builds/actions)、[`waydroid-builds` Actions](https://github.com/WayDroid-ATV/waydroid-builds/actions) 与两仓库 `.github/workflows` 入口：前者 0 个 workflow runs 且没有该 workflow 目录；后者也没有可见 workflow runs/目录。发布仓库附件只有三个完整 ROM ZIP，没有发现 target_files、installed-files 清单、逐文件 hash manifest 或构建 SBOM 附件。release tag 所指向的 `a4d6a6c` 是 README 更新提交，不是可关联到产物的构建执行记录。
- [OTA A16 TV 历史提交](https://github.com/WayDroid-ATV/ota/commit/974361ff84191ecd7dcdd7b5edfe443a53818c84) 保存的是 ROM ZIP 发布索引，字段含文件名、归档 SHA、大小、ROM 类型、ASB 日期和 Lineage 版本；没有 ELF 文件表或组件级 source revision。
- 本地 [system-NOTICE.xml](../reports/version-corpus-20261118/system-NOTICE.xml) 有 5,297 个 `file-name` 和 429 个 `file-content` 条目。它把安装路径映射到 `lib`/包标签及许可内容标识，不含对应 ELF 整文件 SHA-256。固定 build 源码的 [`gen_notice_xml.py`](https://github.com/LineageOS/android_build/blob/083aa4a4442dae34a6922395a8191cdcaedb5775/tools/sbom/gen_notice_xml.py) 从包 `METADATA` 读取 `name` 和 `third_party.version` 构造标签；这是包合规元数据，不是二进制实现证明。两个实际差异须分开理解，见下节。
- 本次未在 WayDroid-ATV 发布页、OTA 索引、上述构建仓库和已检查的公开 workflow 入口找到与该发布绑定的 target_files、installed-files、构建 SBOM 或逐 ELF SHA 清单。这个结论限于所列公开入口和本次检查范围，不声称全网绝无其他私有或未索引材料。

## 对版本覆盖工作可采用的判断

### 同一源码也可能同时声明不同版本

libevent 的 manifest pin 为 `67b0e8c658b80d176b5b1a497cbc7e954f3d5266`。同一固定源码的 [configure.ac](https://android.googlesource.com/platform/external/libevent/+/67b0e8c658b80d176b5b1a497cbc7e954f3d5266/configure.ac) 声明 `2.1.12-stable`，[Bionic 专用头文件](https://android.googlesource.com/platform/external/libevent/+/67b0e8c658b80d176b5b1a497cbc7e954f3d5266/include/event2/event-config-bionic.h) 却声明 `EVENT__VERSION "2.1.8-stable"`，[event.c](https://android.googlesource.com/platform/external/libevent/+/67b0e8c658b80d176b5b1a497cbc7e954f3d5266/event.c) 的 getter 返回该宏。目标 x86-64 ELF 的 getter 经反汇编直接返回只读字符串 `2.1.8-stable`。因此不能仅凭两个数字不一致就断言 NOTICE 陈旧，API 报告值也不自动等于实现代码对应的上游 release。

SQLite 的 pinned [METADATA](https://github.com/LineageOS/android_external_sqlite/blob/baf592af5d4c0344932b411f7a655fb3b2daaffa/METADATA) 为 `3.42.0`；该源码同时包含多个 SQLite 版本，并在 `dist/Android.bp` 通过构建配置选择。目标 x86 的两个库自身 `sqlite3_version` 对象为 `3.44.5`，ARM 翻译层两个库为 `3.44.3`。官方 [SQLite API 文档](https://www.sqlite.org/c3ref/libversion.html) 说明此对象是库自身的版本声明。它反证从根目录 METADATA 直接给所有安装库填版本的做法，但尚不构成完整源码构建证明。原始目标 SHA、对象范围及静态 getter 证据保存在 [定点回读](../reports/version-corpus-20261118/notice-getter-counterexamples.json) 和 [四 ABI 对象回读](../reports/version-corpus-20261118/sqlite-object-readback.json)。

主 agent 对冻结 system 未知原生库 748 条的 NOTICE 候选统计得到：646 条有直接许可归属，332 条能由标签与 manifest 得到单一源码路径候选。这些是待核查候选，不是 332 个已验证版本或 commit。

| 证据 | 当前可支持的结论 | 不支持的结论 |
|---|---|---|
| OTA JSON + GitHub 元数据 + 实际 ZIP/成员摘要 | 已公布摘要的 GAPPS ZIP 与目标镜像字节完全相同，可复现读取其中 ELF | 某个 ELF 对应哪个源码 commit 或组件自身 release |
| 镜像内 `build-manifest.xml` | 镜像自带的源码仓库与 pinned commit 声明，可缩小待核查候选 | 某个 pin 的源码就是某个 ELF 的实际实现，或某库精确 release/version |
| `NOTICE.xml` / METADATA 标签 | 包及许可归属线索 | ELF 内容摘要、准确运行库版本、源码 commit |
| 仅目标 ELF 整文件 SHA-256 | 可对精确相同字节做匹配键 | 如果公开材料没有同一文件 SHA 与 provenance 对照表，哈希本身不能推导版本 |

本次建立了真实发布镜像身份，并发现了镜像自带的源码和许可候选；**这些 provenance 候选本身没有增加精确版本覆盖率**。后续可利用与具体产物绑定的构建证明、可复现源码构建，或有版本区分力且经过反例检验的二进制证据，继续验证组件版本。源码分支、build ID、NOTICE 标签、同名组件和 ZIP 摘要均不足以单独证明它。

## 本次查询入口

1. WayDroid-ATV Android TV 20260403 GitHub release 页与该 tag 的 release API JSON（附件名称、尺寸、digest）。
2. WayDroid-ATV OTA 仓库 `974361ff` 提交、A16 TV GAPPS JSON 与历史发布路径。
3. `waydroid-androidtv-builds`、`waydroid-builds` 的 BUILDING/README、Actions runs 和 `.github/workflows` 目录入口。
4. 镜像内已提取的 `system-build-manifest.xml` 与 `system-NOTICE.xml`；NOTICE 生成逻辑参考 AOSP `platform/build/tools/sbom/gen_notice_xml.py`。
