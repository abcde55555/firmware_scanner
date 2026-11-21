# Android APK SBOM 工具路线调研：逆向特征与构建期清单

日期：2026-11-21

## 结论

当前项目没有集成 APKiD、LibScout、Quark-Engine，也没有把 Apktool 或 JADX 作为产品扫描依赖。现有 APK 路径使用自研 AXML、DEX string/class parser、Maven/AndroidX metadata parser 和递归解包。

两类方案的有效性边界不同：

1. **Apktool/JADX + APKiD/LibScout/Quark-Engine** 面向已经交付的 APK。它们可以揭示构建方式、资源、Smali/Java 和类结构，但 Apktool/JADX 本身不是组件识别器；APKiD 和 Quark-Engine 也不生成依赖清单。
2. **CycloneDX Gradle Plugin / AOSP `m sbom`** 面向可重现源码或构建环境。它们根据真实解析后的依赖图或 Soong product metadata 生成 SBOM，精度最高，但不能对只有 APK 的黑盒样本凭空恢复同等信息。

在本次 Grammalecte APK 上，第一种方案的实验增益有限：

| 工具/路线 | 实测结果 | 对最终 BOM 的直接增益 |
|---|---|---:|
| APKiD 3.2.0 | 识别到 DEX 编译器 `r8` 和 `Resources Confusion` 特征 | 0 个组件 |
| Apktool 3.0.3 | 约 9 秒生成 359 个 Smali 文件和完整资源；保留 `com.dokar.quickjs` 等类结构 | 0 个组件、0 个版本 |
| JADX 1.5.6 | 约 48 秒生成 338 个 Java 文件，319 个在 `defpackage`，报告 7 个反编译错误 | 0 个组件、0 个版本 |
| LibScout 2.3.2 | 使用针对 Kotlin 2.4.21、coroutines 1.11.0 定制的同版本 profile；完整匹配 0、部分匹配 0，只有 Kotlin 包级提示 | 0 个完整组件 |
| Syft | 原 APK、展开目录、单独 DEX 和 SO 均为 0 个包 | 0 个组件 |

因此，**不建议先投入“把 Apktool/JADX/LibScout 串成默认 APK 扫描链”**。更高收益的顺序是：

1. 增加 APK 内确定性元数据和内容指纹解析，例如 `META-INF/*.version`、Kotlin builtins、AAR native library SHA-256。
2. 对存在源码、Gradle 或 Soong 构建环境的样本，生成并导入构建期 CycloneDX/SPDX sidecar，再与黑盒结果做身份和版本对齐。
3. APKiD 只作为低成本的混淆/加固分流器；Apktool/JADX 作为可选深度证据视图；LibScout 只对非 R8、保留类层次的旧 APK 做候选实验。
4. Quark-Engine 不进入 SBOM 主路径，它适合恶意行为或 API 使用分析。

## 当前项目是否已经使用

### 已经实现

- 自研 AXML parser，不依赖 Apktool 或 aapt：[`src/firmware_scanner/android/axml.py`](../src/firmware_scanner/android/axml.py)
- APK ZIP section 选择，包括 SO、DEX、Manifest、部分 assets 和 version/property 文件：[`src/firmware_scanner/firmware/formats/apk.py`](../src/firmware_scanner/firmware/formats/apk.py)
- 直接读取 DEX string pool 和 defined class descriptors，再按已知包名前缀映射组件：[`src/firmware_scanner/extraction/smart_analyzer.py`](../src/firmware_scanner/extraction/smart_analyzer.py)
- Maven `pom.properties`、`pom.xml` 和 AndroidX `.version` 解析：[`src/firmware_scanner/extraction/archive_metadata.py`](../src/firmware_scanner/extraction/archive_metadata.py)
- AOSP source manifest/provenance pack 和 image-hash 匹配：[`src/firmware_scanner/cli/app.py`](../src/firmware_scanner/cli/app.py)

### 尚未实现

- 没有调用 `apktool`、`jadx`、`apkid`、LibScout 或 Quark-Engine。
- 没有从 Android Gradle project 生成 CycloneDX SBOM。
- 没有导入 AOSP `m sbom` 输出并合并到 `analyze` 的黑盒组件结果。
- `vuln-scan` 可以读取 CycloneDX/SPDX SBOM 做漏洞扫描，但该输入路径服务于漏洞匹配，不是 APK 组件恢复或 SBOM 合并：[`src/firmware_scanner/cli/app.py`](../src/firmware_scanner/cli/app.py#L403)。

## 工具能力与一手来源

### APKiD

APKiD 的输入是 APK、DEX 或目录，基于规则识别 compiler、packer、obfuscator、anti-VM 等“APK 如何生成”的特征。它可以帮助选择后续分析路径，但不提供第三方库 inventory、版本或依赖关系。

本次 Grammalecte APK 的 APKiD 结果是：

```json
{
  "compiler": ["r8"],
  "manipulator": ["Resources Confusion"]
}
```

该结果是分析策略信号，不能直接写入 BOM。

来源：[APKiD repository](https://github.com/rednaga/APKiD)

### Apktool

Apktool 可以解码 Manifest、资源表和 DEX 到 Smali，并重新构建 APK。它适合为类结构规则和证据检索提供稳定中间视图，但不会判断某个类树来自哪个 Maven/AAR 版本。

本次实验中：

- 解码耗时约 9 秒；
- 输出约 25 MiB、427 个文件；
- 输出 359 个 Smali 文件；
- `com.dokar.quickjs` 等未被 R8 改名的包仍可看到；
- 大量 Kotlin/coroutines 实现被改名为 `a`、`b`、`a0` 等顶层类。

来源：[Apktool decoding](https://apktool.org/wiki/the-basics/decoding/)

### JADX

JADX 把 DEX 反编译成 Java，并明确说明通常无法反编译 100% 的代码。它适合人工审查、API 使用分析和少量高价值规则，不适合对每个 APK 默认执行完整反编译。

本次 7.6 MiB APK 的 `--no-res` 实验：

- 耗时约 48 秒；
- 生成 338 个 Java 文件；
- 319 个位于 `defpackage`；
- 报告 7 个反编译错误；
- 能看到 `kotlinx.coroutines` 字符串和 QuickJS 调用，但没有恢复组件版本。

来源：[JADX repository](https://github.com/skylot/jadx)

### LibScout

LibScout 最接近“识别 APK 中第三方 Java 库”的目标。它支持：

- 从原始 JAR/AAR 生成 library profile；
- 用已知版本的 profile 与 APK 类层次匹配；
- 输出完整匹配、部分匹配及候选版本；
- 对常见 identifier renaming 和部分控制流/反射混淆具有鲁棒性。

但它的能力仍然依赖已知 library profile。公开 profile 仓库最后生成于 2019 年，包含 8,542 个版本，但没有 Kotlin stdlib、kotlinx-coroutines、QuickJS 或 Grammalecte profile。LibScout 主仓库最后一次实质性更新为 2019-10-25。

本次实验用 Maven 原版构件生成了同版本 profile：

| 原版构件 | profile |
|---|---|
| `kotlin-stdlib-2.4.21.jar` | Kotlin Stdlib 2.4.21 |
| `kotlinx-coroutines-core-jvm-1.11.0.jar` | Kotlin Coroutines Core JVM 1.11.0 |
| `quickjs-kt-android-1.0.15.aar` 的 `classes.jar` | 旧 WALA 无法读取 Java 11 classfile，profile 为空 |

在完整版本 profile 已存在的情况下，LibScout 对 APK 的结果仍为：

```json
{
  "lib_matches": [],
  "lib_packageOnlyMatches": {
    "Kotlin Stdlib": "kotlin"
  }
}
```

这说明这份 APK 的 R8 full mode 已将类层次、方法裁剪和包结构改变到 LibScout 2.3.2 的 profile 匹配无法区分的程度。LibScout 可以用于非混淆或保留类层次的 APK 实验，但不能作为当前 R8 全量混淆时代的主识别路径。

来源：

- [LibScout repository](https://github.com/reddr/LibScout)
- [LibScout profiles](https://github.com/reddr/LibScout-Profiles)

### Quark-Engine

Quark-Engine 基于 API 调用链和行为规则进行恶意行为评分。它适合回答“APK 是否表现出某种行为”，不是“APK 包含哪些第三方库及版本”。相同 API 行为可能来自应用代码或不同库，不能作为 BOM 组件身份的唯一证据。

来源：[Quark-Engine repository](https://github.com/ev-flow/quark-engine)

## 构建期 SBOM

### CycloneDX Gradle Plugin

插件从 Gradle 已解析的 dependency graph 生成 CycloneDX JSON/XML，记录冲突解析后的组件和关系，并支持 direct/aggregate SBOM。它适用于能够访问 Gradle project、插件和依赖解析环境的构建期流程。

关键边界：

- 可以给出 APK 中看不到的 Maven 坐标、传递依赖和关系；
- 可能包含未实际打入 APK 的 compile-only、test 或被裁剪依赖；
- 因此不能不加对齐地声称它就是最终 APK 的实际组件清单。

来源：[CycloneDX Gradle Plugin](https://github.com/CycloneDX/cyclonedx-gradle-plugin)

### AOSP `m sbom`

AOSP 官方文档要求在对应 target 环境中执行：

```sh
source build/envsetup.sh
lunch TARGET
m sbom
```

输出位于 `out/dist/sbom*`，采用与 SPDX 2.3 兼容的格式。它适合可重现的 AOSP/Soong 产品构建，不是任意供应商 APK 的通用逆向入口。

来源：

- [Create a software bill of materials](https://source.android.com/docs/setup/create/create-sbom)
- [Soong `gen_sbom.py`](https://android.googlesource.com/platform/build/+/main/tools/sbom/gen_sbom.py)

## 对项目扫描率的预期

### 对本次 APK

- Apktool/JADX/APKiD/LibScout/Quark 这条组合路线：**0 个新的完整组件、0 个准确版本**。
- 构建期 SBOM：如果能获得与 APK 对应的源码/构建环境或签名发布的 sidecar SBOM，可以恢复完整 Maven 坐标和依赖关系，但必须再与最终 APK 去重和对齐。
- 当前黑盒最高 ROI 仍然是确定性的资源/内容指纹：
  - `assets/grammalecte/UPSTREAM.txt` → Grammalecte 2.3.0；
  - `META-INF/kotlinx_coroutines_core.version` → 1.11.0；
  - `kotlin/*.kotlin_builtins` → Kotlin 2.4.21；
  - `lib/*/libquickjs.so` 整文件 SHA-256 → quickjs-kt Android 1.0.15；
  - QuickJS `nativeGetVersion` → runtime 2026-06-04。

### 对通用 APK 集合

这些路线能提升，但提升面不同：

| 样本类型 | 最有效路线 |
|---|---|
| 有源码或 CI 的 Gradle Android App | CycloneDX Gradle Plugin + 最终 APK 对齐 |
| 有源码/构建环境的 AOSP 产品 | `m sbom` + build/image hash provenance |
| 非 R8、保留包/类层次的 APK | LibScout + 最新 library profiles |
| R8/ProGuard full mode APK | META-INF、resource、DEX 指纹、AAR/native hash；LibScout 增益不稳 |
| 加固或动态加载 APK | APKiD 分流 + 模拟器/Frida 定向动态取证 |
| 普通第三方库样本 | Apktool/JADX 仅作辅助证据，不默认全量执行 |

## 建议

不建议把“APKiD + Apktool/JADX + LibScout + Quark”作为一条默认产品链路。推荐按证据来源分层：

1. **低成本静态入口**
   - APKiD 识别 R8/packer，决定后续策略；
   - 自研 DEX/资源解析直接提取包名、字符串和 metadata；
   - 不默认为每个 APK 调用 JADX。

2. **确定性组件证据**
   - `META-INF/*.version`
   - Kotlin builtins、Coroutines marker
   - AAR/JAR资源哈希
   - native library整文件/符号/版本 getter
   - 已知 Maven/AAR参考索引

3. **可选深度模式**
   - Apktool Smali 或 JADX Java 只用于候选组件附近的 API、控制流和人工核查；
   - 输出为证据视图，不直接把反编译代码命中写成正式组件版本。

4. **可获得源码时**
   - 生成构建期 CycloneDX/SPDX sidecar；
   - 将构建依赖与最终 APK 的 DEX/资源/ELF 证据对齐；
   - 区分 packaged、compile-only、trimmed 和 duplicate POM/AAR records。

5. **LibScout 试点**
   - 先在非 R8/老 APK 上测召回和误归属；
   - 为新库补 profile，但必须先验证 profile 与最终 APK 的类重写方式兼容；
   - 本次 R8 full mode 结果不足以支持将其接入主路径。

## 实验复现

关键版本：

- APKiD 3.2.0
- Apktool 3.0.3
- JADX 1.5.6
- LibScout 2.3.2
- Android SDK platform 36
- Grammalecte APK SHA-256 `43538f909caaf4b91d56146b3176cf168c163c6d171a449d9dfeb1d62424aca7`

实验命令摘要：

```sh
apkid -j -m grammalecte-android-1.0.0.apk
apktool d -f grammalecte-android-1.0.0.apk -o /tmp/apktool-grammalecte
jadx --no-res --show-bad-code -d /tmp/jadx-grammalecte grammalecte-android-1.0.0.apk

java -jar LibScout.jar --opmode match \
  --profiles-dir profiles \
  --android-sdk android.jar \
  --json-dir /tmp/libscout-json \
  grammalecte-android-1.0.0.apk
```

实验只使用公开源码、官方构件和本地样本，不执行 APK，不访问目标设备。
