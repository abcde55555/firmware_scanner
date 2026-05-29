# 批量测试报告

## 测试日期
2026-05-29 (最终版)

## 测试样本结果

| 样本 | 大小 | 类型 | 组件数 | 有版本号 | 耗时 | 关键发现 |
|------|------|------|:-----:|:-------:|:----:|---------|
| rtos/freertos_sample.bin | 311B | RTOS 二进制 | 1 | 1 | 0.8s | FreeRTOS@10.4.3 |
| rtos/threadx_sample.bin | 324B | RTOS 二进制 | 1 | 0 | 0.6s | ThreadX 检测到 |
| rtos/collection.zip | 1.2KB | ZIP 合集 | 3 | 3 | 0.6s | FreeRTOS+ThreadX+Zephyr 全部有版本 |
| iot/openwrt-kernel.bin | 5MB | U-Boot + gzip 内核 | 3 | 1 | 4.1s | Linux Kernel + OpenWrt 识别成功 |
| iot/IoTGoat.img | 33MB | OpenWrt 镜像 | 6 | 1 | 14.1s | Linux + OpenWrt + lwIP 等 |
| apk/F-Droid.apk | 12MB | Android APK | 14 | 2 | 8.3s | AndroidX, Kotlin, Glide, RxJava 等 |
| zip/FreeRTOS-LTS.zip | 26MB | SDK ZIP | 16 | 14 | 80s | 14个组件精确版本号 (87%) |

## 发现的问题及修复状态

### P0 - 已修复

| 问题 | 根因 | 修复方案 |
|------|------|---------|
| Deep scan 卡在 99.5% | 大段扫描耗时过长 | 每段上限 8MB + 30s 超时 |
| 依赖报错 (GHIDRA_INSTALL_DIR) | pyhidra import 触发环境检查 | except Exception 全捕获 |
| APK 检测 0 组件 | 无 DEX 字符串池解析 | 实现 SmartSectionAnalyzer + DEX parser |
| OpenWrt .bin 检测 0 组件 | U-Boot gzip 解压失败 + 无 Linux 签名 | 修复 raw deflate + 添加 Linux 签名 |
| 进度消息污染 JSON 输出 | console.print 走 stdout | Rich Console 改走 stderr |

### P1 - 已修复

| 问题 | 根因 | 修复方案 |
|------|------|---------|
| 误报 RT-Thread/ThreadX | 单个模式匹配就报告 | 要求 2+ 不同签名命中 |
| "Ethernet 2.0" 误报 | 签名太通用 | 移除 + 版本号过滤 802.x |
| SDK ZIP 版本识别率低 | 未解析 manifest.yml | ManifestScannerExtractor |
| 不同文件类型统一分析 | 无文件类型感知 | SmartSectionAnalyzer 分派 |

### P2 - 已知限制

| 问题 | 后续计划 |
|------|---------|
| APK 组件版本号大多 unknown | 需从 DEX 常量池提取版本字符串 |
| 128MB ZIP 内存占用高 | 需改为流式处理 |
| IoTGoat IMG 仍有部分误报 | 需 SquashFS 提取后逐文件分析 |

## 版本识别率分析（最终）

| 固件类型 | 平均组件数 | 版本识别率 |
|---------|:---------:|:---------:|
| RTOS SDK (ZIP) | 16 | **87%** |
| IoT 设备固件 (IMG/BIN) | 3-6 | 17-33% |
| RTOS 二进制 (BIN) | 1-3 | 50-100% |
| Android APK | 14 | 14% |

## 性能数据

| 文件大小范围 | 平均耗时 |
|------------|:-------:|
| < 1KB | 0.6s |
| 1-5MB | 1-4s |
| 10-35MB | 8-15s |
| 128MB | ~40s |

## 优化建议优先级

1. **DEX 字符串池解析** - 让 APK 分析能识别 Java/Kotlin 依赖库
2. **流式 ZIP 处理** - 避免 128MB 全量加载
3. **Linux 生态签名扩充** - iptables, OpenSSH, dnsmasq, hostapd 等
4. **ELF .comment 段解析** - 编译器版本和构建信息
5. **固件文件系统提取** - SquashFS/JFFS2 内文件逐个扫描
