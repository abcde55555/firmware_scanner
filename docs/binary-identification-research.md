# 固件组件与版本识别：实测后的方法选择

2026-11-18。范围为用户提供的 Allwinner Android 容器及 2.2 GiB ext4 镜像。选择依据是可追溯证据与实扫结果，不能把组件数量、规则数量或版本字段非空率等同于准确率。

采用分层识别：先包/APEX/APK/Maven 元数据，再明确版本 banner，再已定义符号组合，再解析有限的版本返回函数；剩余情况保持未知，并保存接口、ABI、编译器、系统构建背景。组件身份与版本分开判断，内嵌库证据与宿主文件分别输出，多版本保留、同身份冲突显式标注。EMBA 官方也采用包元数据、归档、静态规则和动态验证等多层来源，而不是单一字符串或哈希。[EMBA 方法](https://github.com/e-m-b-a/emba/wiki/Increase-component-identification-rate)

完整 SHA-256 可以验证与一个已知构建的字节一致性，但版本标签仍依赖参考语料的可信来源。单独 `.rodata` 或 `.text` 相同不能证明整个文件的版本；本轮已用真实编译出的“相同数据、不同代码”样本复现反例。GNU Build ID 标识链接产物，可以由链接选项指定，文件之后变化也不一定改变该 ID，故只适合查询有来源的构建索引，不能直接转换成发布版本。[GNU ld 文档](https://sourceware.org/binutils/docs/ld/Options.html)

版本 getter 的静态解析已经实现为严格白名单：解析已定义函数，证明返回指针对应的只读字符串，保留完整后缀；遇到不支持的控制流或指令就拒绝。本轮支持 x86-64 和 AArch64 的有限路径，不执行固件。它能补充无专用 banner 的库；对于运行时计算版本、ARM/Thumb、间接指针及厂商修改仍有明显覆盖边界。

下一阶段更值得投入的是：有来源的多架构/编译配置语料、函数级候选检索、版本敏感差异特征及留出固件评估。B2SMatcher 在程序和函数两个层面提取版本敏感特征，先识别项目、再区分版本；这支持两阶段设计的研究方向，不能据此声称本项目已经实现同等精度或跨编译器不变性。[B2SMatcher 原论文](https://link.springer.com/article/10.1186/s42400-021-00085-7)

较新的研究进一步说明了两类任务需要分开：LibAM 处理函数调用图中的库复用区域，LibvDiff（ICSE 2024）利用符号和函数代码差异区分相近版本，BinCoFer（2025）通过核心函数筛选与证据聚合降低公共代码特征的误匹配。这些已有工作意味着“函数相似度识库”本身不能作为新颖性主张。更合适的下一步是选择少量高频库，构建带编译器、架构、优化选项与版本标签的真实构建语料，分别评估身份识别、精确版本和未见构建；禁止直接套用论文数据集上的准确率。[LibAM 代码与数据](https://github.com/Siyuan-Li201/LibAM)、[LibvDiff 作者论文](https://gentlecp.github.io/pdfs/LibvDiff_ICSE_2024.pdf)、[BinCoFer 作者论文](https://wu-yueming.github.io/Files/JSS2025_BinCoFer.pdf)

本轮人工核验也发现编译优化会改变版本常量的表面值：Protobuf `VerifyVersion` 中 `cmp esi,0x2e18d5; jl ...` 表示检查参数是否小于“当前版本加一”，错误消息路径实际传给 `VersionString` 的常量为 `0x2e18d4`，按上游编码解得 **3.21.12**。把比较边界直接解码会误报为 3.21.13。后续自动解码必须验证参数、比较方向、分支与消息路径，不能扫描窗口内的任意四字节整数。[上游 VerifyVersion 实现](https://raw.githubusercontent.com/protocolbuffers/protobuf/v21.12/src/google/protobuf/stubs/common.cc)、[上游整数版本编码](https://raw.githubusercontent.com/protocolbuffers/protobuf/v21.12/src/google/protobuf/stubs/common.h)

有产品价值的差异点是：每条识别结果可追溯到镜像、分区、文件、函数或字符串位置；版本/ABI/开发快照/冲突状态明确；对厂商分支分别记录观测版本与补丁证据。该方向目前属于工程改进建议，不宣称论文或专利新颖性。补丁状态必须通过具体代码证据验证，不能从 Android SPL 或上游版本号自动推断。

本轮以 Syft 1.57.1 对 15 个选定的真实二进制交叉检查，只发现 curl 8.12.0；原始字符串为 8.12.0-DEV。结果说明工具交叉比对可发现分歧，但任何工具输出都不能自动当真值。[Syft 官方项目](https://github.com/anchore/syft)

当前仍待完成：APEX payload 深入识别、更多大文件的分段读取、ARM/Thumb getter、Protobuf 常量的参数数据流验证，以及持续维护的真实构建指纹库。仅两份镜像和局部人工核验不足以测得全量召回率。
