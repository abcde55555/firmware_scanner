# 函数版本语义实验（原型）

基线：`a4a93cc`，2026-11-18。用户授权在已提交的识别改进之上，研究并实测函数级方法。

问题：在不执行固件、不把 ABI/头文件/任意整数当发布版本的前提下，能否补出当前仍未知的版本？

本轮先试有限函数语义，而非立即构建所有版本的函数指纹库。后者需要真实的跨版本、编译器和架构参考语料；相关研究与本项目效果应分开。原型依赖实际定义的已知 API，不宣称可识别任意 stripped 文件。

已比较基线与附加原型，保留文件位置和新证据；分别记录新增版本、已有结果冲突、拒判和负例。覆盖 Protobuf 比较边界与消息参数的交叉约束、简单版本 getter 的返回值，以及 ARM/Thumb 可支持路径。AArch64 ICU 额外要求 getter、只读版本字符串、PLT/GOT 重定位与已定义解析函数相连。禁止从单个相似函数直接给出精确版本。

原型代码放在本目录，不默认接入产品。真实镜像、源文件摘录、构建和结果放在 Git 忽略的 `reports/function-version-experiment-20261118/`。试验结论写入 `docs/`；只有证据充分的路径才考虑集成。

本轮新增 9 条文件/组件版本观测；带版本的 native 记录净增 8 条（44 → 52），另暴露一条厂商后缀冲突。32 个定向检查点在统一修订标签后为 29 → 31 个通过。这些计数不代表总体精确率或召回率。[完整结果与限制](../../docs/function-version-experiment-results-2026-11-18.md)。

在项目根目录、安装项目依赖的 Python 环境中运行：

```bash
PYTHONPATH=src python experiments/function_versions/run_scan.py \
  /path/to/system.ext4.img /path/to/new-output-directory
PYTHONPATH=src python experiments/function_versions/verify_controls.py
PYTHONPATH=src python experiments/function_versions/verify_icu_controls.py
PYTHONPATH=src python experiments/function_versions/compare_results.py
```

`run_scan.py` 接收 ext4 分区，不接收 Allwinner 外层容器。三个验证/比较脚本依赖本次本地 `reports/` 和原有只读 system 挂载中的文件，路径在源码中列明；它们不是自包含的可移植测试集。`verify_controls.py` 还需要 GCC、Clang、strip，构建的 ELF 不会被执行。

已知限制：仅支持保留了特定定义符号及受限函数形态的 ELF；`strip --strip-all` 样本仍保留动态导出符号。API 形态夹具的 `-O0` 路径拒判；复杂 ICU、运行时 FreeType getter、大 APK/APEX 与无符号静态库仍有漏检。数字 getter 不能恢复 DEV/GIT/厂商补丁后缀，已知完整字符串不应被它缩短。`VersionConfidence` 数值是启发式权重，不能当作已测精确率。
