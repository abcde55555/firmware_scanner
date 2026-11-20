# 二进制版本 checker 的实物对照

日期：2026-11-18。输入仍为原来的两份固件，没有供应商源码或 SBOM。本轮用本机 CVE Binary Tool 3.4 的 **365 个 checker** 排查产品遗漏，候选再回到原始 ELF 和上游源码核验。这不是整个 CVE 扫描器的评测，也不能据此计算全体组件准确率。

## 方法与实际范围

`experiments/version_coverage/compare_cve_checkers.py` 从 ext4 只读回读 ELF，支持直接文件及一层 APK/ZIP 成员；提取长度至少 3 的 ASCII 字符串，调用该工具的 `Checker.get_version()`。不初始化 CVE 数据库、不执行目标程序。这个 API 的输入与作用见[官方 checker 文档](https://cve-bin-tool.readthedocs.io/en/stable/CHECKERS.html)。

| 输入集合 | 回读路径数 | 不同 ELF SHA-256 | 跳过 / checker 异常 | 有非工具链版本候选的路径 | 耗时 |
|---|---:|---:|---:|---:|---:|
| Allwinner 当前未知库 census，包含 APK 内副本 | 302 | 288 | 0 / 0 | 9 | 106.464 秒 |
| Android 16 当前未知项关联的直接 ELF 路径 | 1566 | 1387 | 0 / 0 | 8 | 146.363 秒 |

路径不是组件数；同一哈希、`/bin` 与 `/system/bin` 路径及 APK 副本不重复算成独立库。第二行没有覆盖 APEX 嵌套位置，也没有据此改动原来的冻结队列。

原始结果位于 ignored 的 `reports/version-coverage-next-20261118/cve-{allwinner,system}-unknown.json`，记录输入哈希、checker 源文件哈希、命中字符串和逐文件结果。`cve-scout-source-{allwinner,system}.py` 保存了两次实际运行的脚本字节，SHA-256 与结果记录一致。提交的实验脚本另补充了公共 helper 源码哈希，不声称旧运行使用了修改后的脚本。

## 回读发现

| 对照候选 | 固件实际证据 | 处理 |
|---|---|---|
| Allwinner 302 个库中的 GCC 4.6 / 4.7 | `.comment` 的编译器标识 | 保留工具链事实，不作为这些库的发布版本 |
| curl `8.12.0` | `/system/bin/curl` 同时含 `curl/8.12.0-DEV`、`libcurl/8.12.0-DEV` 和完整自身 banner | 产品保留 `-DEV`；不引入截断值 |
| libjpeg-turbo `2.1.5` | 两个 `camera.v4l2.so` 内是 `libjpeg-turbo version 2.1.5.1 (build )` | 产品保留第四段 `.1` |
| 同一 camera ELF 中的 libjpeg `6b` | libjpeg-turbo 会根据 `JPEG_LIB_VERSION` 保留 `6b 27-Mar-1998` | 不能把它当作另一个已确认的现代库发布版本 |
| libsnapshot 中的 Zstandard `15.0.0` | 产品对定义的版本函数恢复出 zstd `1.5.7`；checker 的跨行模式还匹配了周围无关文本 | 不采用 `15.0.0`；LZ4、Brotli 仍独立归属 |
| iperf `3.6` | 原始字符串是 `iperf 3.6+` | 不把带有未确定后续改动的标识截成精确稳定版 `3.6` |
| 四个 Allwinner ELF 的 libevent `1.4.13` | `libevent using: %s` 后邻接 `1.4.13-stable` | 先确认 libevent 身份；附近字符串本身不升级为函数数据流证明 |

这里列出的是有限样本的核查结果，不是两个工具的总体准确率排名。libjpeg 的兼容性边界可直接核查 [libjpeg-turbo 的 jversion.h](https://android.googlesource.com/platform/external/libjpeg-turbo/+/ecd3481eaf0a4aad5d72fba3ff3a8df8ec7505cc/jversion.h)。

libevent 的源码尤其容易误读：`libevent using: %s` 实际输出事件后端名称 `base->evsel->name`；版本由另一个 `event_get_version()` 返回。产品增加该消息的身份识别，以及有定义、有可证明常量返回路径的版本 getter；缺少这种证明时保留未知。[libevent 1.4.13 源码](https://raw.githubusercontent.com/libevent/libevent/release-1.4.13-stable/event.c)

## 对后续实现的约束

增加 checker 数量可以提高候选召回，进入正式 BOM 的版本仍需核对完整后缀、证据归属和 API 语义。版本函数识别还要拒绝不可达代码、条件写入、寄存器覆盖和字段偏移误配。新的 FreeType、Protobuf 原型只有通过这些控制后才能进入产品计数；命中几个原型样本不等于已经实现 50% 覆盖。

当前的 50% 目标继续按原来的全部记录及原生库冻结分母核算，候选、编译器版本和新发现组件均不能用来改写分母或替代精确版本真值。
