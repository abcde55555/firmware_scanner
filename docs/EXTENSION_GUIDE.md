# rtos-firmware-analyzer 扩展架构指南

本文档详细介绍 `rtos-firmware-analyzer` 的插件化扩展架构，帮助开发者在不修改现有代码的前提下添加新的固件格式支持、RTOS 检测插件和组件提取器。

---

## 目录

1. [扩展架构概览](#1-扩展架构概览)
2. [如何添加新的固件格式](#2-如何添加新的固件格式)
3. [如何添加新的组件提取器](#3-如何添加新的组件提取器)
4. [如何添加新的签名模式](#4-如何添加新的签名模式)
5. [扩展路线图](#5-扩展路线图)
6. [外部集成 API](#6-外部集成-api)

---

## 1. 扩展架构概览

### 整体设计理念

`rtos-firmware-analyzer` 采用 **插件化架构(Plugin-based Architecture)**，核心原则是**开放-封闭原则**：对扩展开放，对修改封闭。新格式、新检测器和新提取器可以通过简单注册的方式添加，无需修改已有代码。

### 三大扩展点

```
rtos-firmware-analyzer/
├── firmware/formats/          ← 扩展点 1: 固件格式处理器
│   ├── base.py               (FirmwareFormat 抽象基类)
│   ├── elf.py
│   ├── intel_hex.py
│   ├── srec.py
│   ├── raw_binary.py
│   ├── esp_idf.py
│   ├── uboot.py
│   └── compressed.py
├── rtos/plugins/              ← 扩展点 2: RTOS 检测插件
│   ├── freertos.py
│   ├── zephyr.py
│   ├── rt_thread.py
│   ├── esp_idf.py
│   ├── vxworks.py
│   ├── threadx.py
│   ├── nuttx.py
│   ├── liteos.py
│   └── ucos.py
└── extraction/extractors/     ← 扩展点 3: 组件提取器
    ├── base.py               (BaseExtractor 抽象基类)
    ├── string_patterns.py
    ├── symbol_table.py
    ├── disassembly.py
    ├── binary_signatures.py
    ├── radare2_ext.py
    └── ghidra_ext.py
```

### 数据流

```
固件文件(.bin/.elf/.hex/...)
    │
    ▼
┌─────────────────────────────┐
│  FirmwareUnpacker           │  ← 根据 FORMAT_HANDLERS 列表自动检测格式
│  (firmware/unpacker.py)     │
└─────────────────────────────┘
    │ UnpackResult (sections)
    ▼
┌─────────────────────────────┐
│  ArchDetector               │  ← 架构检测（ARM/MIPS/RISC-V 等）
│  (arch/detector.py)         │
└─────────────────────────────┘
    │ ArchInfo
    ▼
┌─────────────────────────────┐
│  RTOSRegistry.detect()      │  ← 遍历所有 RTOS 插件，按置信度排序
│  (rtos/registry.py)         │
└─────────────────────────────┘
    │ RTOSPlugin + confidence
    ▼
┌─────────────────────────────┐
│  ExtractionOrchestrator     │  ← 运行所有可用提取器，交叉验证结果
│  (extraction/orchestrator.py)│
└─────────────────────────────┘
    │ list[Component]
    ▼
┌─────────────────────────────┐
│  SBOM Generator             │  ← 生成 CycloneDX / HTML 报告
│  (sbom/generator.py)        │
└─────────────────────────────┘
```

### 注册机制

本工具支持两种注册方式：

1. **代码内注册**：直接将 Handler 类添加到 `FORMAT_HANDLERS` 列表，或使用 `@RTOSRegistry.register` 装饰器
2. **Entry-point 注册**（推荐用于第三方扩展）：通过 `pyproject.toml` 的 `[project.entry-points]` 声明

---

## 2. 如何添加新的固件格式

### 核心接口：FirmwareFormat

```python
# src/rtos_firmware_analyzer/firmware/formats/base.py

from abc import ABC, abstractmethod
from pathlib import Path
from ...extraction.models import UnpackResult

class FirmwareFormat(ABC):
    @classmethod
    @abstractmethod
    def can_handle(cls, data: bytes, path: Path) -> float:
        """返回 0.0-1.0 的置信度，表示此处理器能否解析该数据。"""
        ...

    @abstractmethod
    def unpack(self, data: bytes, path: Path) -> UnpackResult:
        """将固件解包为可分析的 sections。"""
        ...

    @property
    @abstractmethod
    def format_name(self) -> str:
        """返回格式名称，如 'ELF'、'Intel HEX' 等。"""
        ...
```

### 通用步骤

1. 在 `src/rtos_firmware_analyzer/firmware/formats/` 创建新文件
2. 实现 `FirmwareFormat` 抽象类的三个方法
3. 在 `firmware/unpacker.py` 的 `FORMAT_HANDLERS` 列表中注册
4. 编写对应的单元测试

### 示例 A：Android system.img 格式

Android 系统镜像使用 sparse image 或 ext4/erofs 文件系统，具有特定的 magic bytes。

```python
# src/rtos_firmware_analyzer/firmware/formats/android_img.py

"""Android system.img format handler (sparse image & raw ext4)."""

import struct
from pathlib import Path

from .base import FirmwareFormat
from ...extraction.models import UnpackResult, FirmwareSection


# Android sparse image magic
SPARSE_HEADER_MAGIC = 0xED26FF3A
# ext4 superblock magic (at offset 0x438)
EXT4_SUPER_MAGIC = 0xEF53
# EROFS magic
EROFS_MAGIC = 0xE0F5E1E2


class AndroidImgFormat(FirmwareFormat):
    """处理 Android system.img 格式（sparse image 和 raw ext4/erofs）。"""

    @property
    def format_name(self) -> str:
        return "Android IMG"

    @classmethod
    def can_handle(cls, data: bytes, path: Path) -> float:
        if len(data) < 32:
            return 0.0

        # 检查 Android sparse image magic: 0xED26FF3A (little-endian)
        if len(data) >= 4:
            magic = struct.unpack_from("<I", data, 0)[0]
            if magic == SPARSE_HEADER_MAGIC:
                return 0.95

        # 检查 ext4 superblock magic (位于偏移 0x438)
        if len(data) >= 0x43A:
            ext4_magic = struct.unpack_from("<H", data, 0x438)[0]
            if ext4_magic == EXT4_SUPER_MAGIC:
                # 检查文件名是否包含 "system" 或 "vendor"
                name_lower = path.name.lower()
                if any(kw in name_lower for kw in ("system", "vendor", "product")):
                    return 0.85
                return 0.6

        # 检查 EROFS magic (位于偏移 1024)
        if len(data) >= 1028:
            erofs_magic = struct.unpack_from("<I", data, 1024)[0]
            if erofs_magic == EROFS_MAGIC:
                return 0.90

        # 文件扩展名辅助判断
        if path.suffix.lower() == ".img":
            name_lower = path.name.lower()
            if any(kw in name_lower for kw in ("system", "vendor", "boot", "recovery")):
                return 0.3

        return 0.0

    def unpack(self, data: bytes, path: Path) -> UnpackResult:
        """解包 Android IMG，提取文件系统内容。"""
        magic = struct.unpack_from("<I", data, 0)[0]

        if magic == SPARSE_HEADER_MAGIC:
            return self._unpack_sparse(data, path)
        else:
            return self._unpack_raw_ext4(data, path)

    def _unpack_sparse(self, data: bytes, path: Path) -> UnpackResult:
        """解析 Android sparse image 格式。

        Sparse header 结构 (28 bytes):
          magic:         u32  (0xED26FF3A)
          major_version: u16
          minor_version: u16
          file_hdr_sz:   u16
          chunk_hdr_sz:  u16
          blk_sz:        u32
          total_blks:    u32
          total_chunks:  u32
          image_checksum: u32
        """
        if len(data) < 28:
            return UnpackResult()

        (magic, major, minor, file_hdr_sz, chunk_hdr_sz,
         blk_sz, total_blks, total_chunks, checksum) = struct.unpack_from(
            "<IHHHHIIII", data, 0
        )

        # 将 sparse image 转换为 raw image
        raw_data = self._sparse_to_raw(data, file_hdr_sz, chunk_hdr_sz,
                                        blk_sz, total_blks, total_chunks)

        sections = [
            FirmwareSection(
                name="filesystem",
                offset=0,
                size=len(raw_data),
                data=raw_data[:4 * 1024 * 1024],  # 限制内存，只保留前 4MB 用于分析
                section_type="data",
                permissions="R",
            )
        ]

        return UnpackResult(
            sections=sections,
            metadata={
                "sparse_version": f"{major}.{minor}",
                "block_size": blk_sz,
                "total_blocks": total_blks,
                "total_chunks": total_chunks,
                "original_size": blk_sz * total_blks,
            },
        )

    def _sparse_to_raw(self, data: bytes, file_hdr_sz: int, chunk_hdr_sz: int,
                        blk_sz: int, total_blks: int, total_chunks: int) -> bytes:
        """将 sparse image chunks 还原为 raw 数据。"""
        output = bytearray()
        offset = file_hdr_sz

        CHUNK_TYPE_RAW = 0xCAC1
        CHUNK_TYPE_FILL = 0xCAC2
        CHUNK_TYPE_DONT_CARE = 0xCAC3

        for _ in range(total_chunks):
            if offset + chunk_hdr_sz > len(data):
                break

            chunk_type, _, chunk_sz, total_sz = struct.unpack_from(
                "<HHIi", data, offset
            )
            offset += chunk_hdr_sz

            if chunk_type == CHUNK_TYPE_RAW:
                chunk_data_sz = chunk_sz * blk_sz
                output.extend(data[offset:offset + chunk_data_sz])
                offset += chunk_data_sz
            elif chunk_type == CHUNK_TYPE_FILL:
                fill_val = data[offset:offset + 4]
                output.extend(fill_val * (chunk_sz * blk_sz // 4))
                offset += 4
            elif chunk_type == CHUNK_TYPE_DONT_CARE:
                output.extend(b"\x00" * (chunk_sz * blk_sz))

            # 安全限制：只还原前 8MB
            if len(output) > 8 * 1024 * 1024:
                break

        return bytes(output)

    def _unpack_raw_ext4(self, data: bytes, path: Path) -> UnpackResult:
        """处理 raw ext4 镜像，提取基本结构信息。"""
        sections = [
            FirmwareSection(
                name="ext4_superblock",
                offset=0x400,
                size=min(1024, len(data) - 0x400),
                data=data[0x400:0x800] if len(data) > 0x800 else data[0x400:],
                section_type="data",
                permissions="R",
            ),
            FirmwareSection(
                name="filesystem_data",
                offset=0,
                size=len(data),
                data=data[:4 * 1024 * 1024],  # 前 4MB 用于字符串扫描
                section_type="data",
                permissions="R",
            ),
        ]

        return UnpackResult(
            sections=sections,
            metadata={
                "filesystem_type": "ext4",
                "image_size": len(data),
            },
        )
```

### 示例 B：Android APK 格式

APK 本质上是 ZIP 文件，包含 `classes.dex`、`AndroidManifest.xml`、native `.so` 库等。

```python
# src/rtos_firmware_analyzer/firmware/formats/android_apk.py

"""Android APK format handler."""

import struct
import zipfile
import io
from pathlib import Path

from .base import FirmwareFormat
from ...extraction.models import UnpackResult, FirmwareSection


# ZIP local file header magic
ZIP_MAGIC = b"PK\x03\x04"


class AndroidAPKFormat(FirmwareFormat):
    """处理 Android APK 文件（ZIP 容器，含 DEX、SO、Manifest）。"""

    @property
    def format_name(self) -> str:
        return "Android APK"

    @classmethod
    def can_handle(cls, data: bytes, path: Path) -> float:
        if len(data) < 4:
            return 0.0

        # 首先必须是 ZIP 格式
        if data[:4] != ZIP_MAGIC:
            return 0.0

        # 文件扩展名为 .apk 则高置信度
        if path.suffix.lower() == ".apk":
            return 0.92

        # 尝试检查 ZIP 内部是否有 APK 特征文件
        try:
            zf = zipfile.ZipFile(io.BytesIO(data))
            names = set(zf.namelist())

            apk_indicators = 0
            if "classes.dex" in names:
                apk_indicators += 1
            if "AndroidManifest.xml" in names:
                apk_indicators += 1
            if any(n.startswith("lib/") and n.endswith(".so") for n in names):
                apk_indicators += 1
            if "resources.arsc" in names:
                apk_indicators += 1

            if apk_indicators >= 2:
                return 0.90
            elif apk_indicators == 1:
                return 0.5

            zf.close()
        except Exception:
            pass

        return 0.0

    def unpack(self, data: bytes, path: Path) -> UnpackResult:
        """解包 APK，提取 native libraries 和 DEX 文件。"""
        sections: list[FirmwareSection] = []
        metadata: dict = {"apk_contents": []}

        try:
            zf = zipfile.ZipFile(io.BytesIO(data))
        except Exception:
            return UnpackResult(
                sections=[FirmwareSection(
                    name="raw", offset=0, size=len(data),
                    data=data, section_type="unknown",
                )],
            )

        for info in zf.infolist():
            name = info.filename
            metadata["apk_contents"].append(name)

            # 提取 native .so 库（这是固件分析的重点）
            if name.startswith("lib/") and name.endswith(".so"):
                try:
                    so_data = zf.read(name)
                    sections.append(FirmwareSection(
                        name=name,
                        offset=info.header_offset,
                        size=len(so_data),
                        data=so_data,
                        section_type="code",
                        permissions="RX",
                    ))
                except Exception:
                    continue

            # 提取 DEX 文件
            elif name.endswith(".dex"):
                try:
                    dex_data = zf.read(name)
                    sections.append(FirmwareSection(
                        name=name,
                        offset=info.header_offset,
                        size=len(dex_data),
                        data=dex_data,
                        section_type="code",
                        permissions="R",
                    ))
                except Exception:
                    continue

        zf.close()

        # 提取架构信息
        arch_dirs = set()
        for s in sections:
            if s.name.startswith("lib/"):
                parts = s.name.split("/")
                if len(parts) >= 2:
                    arch_dirs.add(parts[1])  # arm64-v8a, armeabi-v7a, x86, etc.

        metadata["native_architectures"] = sorted(arch_dirs)
        metadata["native_lib_count"] = sum(1 for s in sections if s.name.endswith(".so"))

        return UnpackResult(
            sections=sections,
            metadata=metadata,
        )
```

### 示例 C：路由器固件（TRX/Broadcom 头部）

路由器固件常用 TRX 格式封装，包含引导加载器、内核和文件系统。

```python
# src/rtos_firmware_analyzer/firmware/formats/router_trx.py

"""Router firmware with TRX/Broadcom headers."""

import struct
import zlib
from pathlib import Path

from .base import FirmwareFormat
from ...extraction.models import UnpackResult, FirmwareSection


# TRX header magic: "HDR0"
TRX_MAGIC = b"HDR0"
TRX_MAGIC_INT = 0x30524448

# Broadcom (Asus/Linksys) 额外头部
ASUS_MAGIC = b"#---"  # Asus 固件头标识

# SquashFS magic bytes (常见于路由器固件的文件系统)
SQSH_MAGIC_LE = b"hsqs"  # little-endian SquashFS
SQSH_MAGIC_BE = b"sqsh"  # big-endian SquashFS

# LZMA magic (压缩内核)
LZMA_MAGIC = b"\x5d\x00\x00"


class RouterTRXFormat(FirmwareFormat):
    """处理路由器固件 TRX 格式（支持 Broadcom/Asus/Linksys/TP-Link 等）。"""

    @property
    def format_name(self) -> str:
        return "Router TRX"

    @classmethod
    def can_handle(cls, data: bytes, path: Path) -> float:
        if len(data) < 32:
            return 0.0

        # 直接 TRX magic 检测
        if data[:4] == TRX_MAGIC:
            return 0.95

        # 有些厂商在 TRX 前面加了自有头部，搜索前 256 字节
        trx_offset = data.find(TRX_MAGIC, 0, 256)
        if trx_offset > 0:
            return 0.90

        # 检查 Broadcom CFE bootloader 标识
        if b"CFE" in data[:512] and b"Broadcom" in data[:1024]:
            return 0.70

        # TP-Link 固件头部检测
        if len(data) >= 4:
            tp_magic = struct.unpack_from(">I", data, 0)[0]
            # TP-Link 常见 magic: 各型号不同，但通常是固定值
            if tp_magic in (0x01000000, 0x02000000, 0x03000000):
                if b"TP-LINK" in data[:512] or b"tp-link" in data[:512]:
                    return 0.85

        # 文件名启发式
        name_lower = path.name.lower()
        if path.suffix.lower() in (".bin", ".trx", ".chk"):
            if any(kw in name_lower for kw in (
                "firmware", "fw_", "openwrt", "dd-wrt", "tomato",
                "router", "linksys", "netgear", "asus", "tplink"
            )):
                return 0.4

        return 0.0

    def unpack(self, data: bytes, path: Path) -> UnpackResult:
        """解包 TRX 路由器固件。"""
        # 找到 TRX 头部起始位置
        trx_offset = 0
        if data[:4] != TRX_MAGIC:
            trx_offset = data.find(TRX_MAGIC, 0, 256)
            if trx_offset < 0:
                # 无 TRX 头，尝试直接搜索已知文件系统
                return self._fallback_scan(data)

        return self._parse_trx(data, trx_offset)

    def _parse_trx(self, data: bytes, trx_offset: int) -> UnpackResult:
        """解析 TRX 头部结构。

        TRX v1 header (28 bytes):
          magic:    u32  ("HDR0")
          len:      u32  (整个镜像长度)
          crc32:    u32
          flags:    u16
          version:  u16
          offsets:  u32[3]  (最多 3 个分区的偏移)

        TRX v2 header (32 bytes):
          增加 offsets[3] 共 4 个分区偏移
        """
        if trx_offset + 28 > len(data):
            return UnpackResult()

        header = data[trx_offset:]
        magic, length, crc32_val, flags, version = struct.unpack_from(
            "<IIHH", header, 0
        )
        # 注意：TRX 的 len 字段已包含 magic(4) 所以直接 unpack 后取后续
        # 重新解析完整头部
        magic, length, crc32_val, flags_version = struct.unpack_from(
            "<IIIH", header, 0
        )
        version = struct.unpack_from("<H", header, 14)[0]

        # 读取分区偏移
        num_offsets = 4 if version >= 2 else 3
        offsets = []
        for i in range(num_offsets):
            off = struct.unpack_from("<I", header, 16 + i * 4)[0]
            if off > 0:
                offsets.append(off)

        sections: list[FirmwareSection] = []

        # 如果有厂商前缀头，也作为一个 section
        if trx_offset > 0:
            sections.append(FirmwareSection(
                name="vendor_header",
                offset=0,
                size=trx_offset,
                data=data[:trx_offset],
                section_type="data",
                permissions="R",
            ))

        # 解析各分区
        partition_names = ["bootloader/kernel_loader", "kernel", "rootfs", "extra"]
        for idx, off in enumerate(offsets):
            abs_offset = trx_offset + off
            # 计算分区大小
            if idx + 1 < len(offsets):
                next_off = trx_offset + offsets[idx + 1]
                size = next_off - abs_offset
            else:
                size = min(length - off, len(data) - abs_offset)

            if abs_offset >= len(data) or size <= 0:
                continue

            partition_data = data[abs_offset:abs_offset + size]
            section_type = self._identify_partition_type(partition_data)

            sections.append(FirmwareSection(
                name=partition_names[idx] if idx < len(partition_names) else f"partition_{idx}",
                offset=abs_offset,
                size=size,
                data=partition_data[:4 * 1024 * 1024],  # 最多保留 4MB 用于分析
                section_type=section_type,
                permissions="RX" if section_type == "code" else "R",
            ))

        return UnpackResult(
            sections=sections,
            entry_point=0,
            metadata={
                "trx_version": version,
                "trx_length": length,
                "trx_offset": trx_offset,
                "partition_count": len(offsets),
                "crc32": hex(crc32_val),
            },
        )

    def _identify_partition_type(self, data: bytes) -> str:
        """识别分区内容类型。"""
        if len(data) < 4:
            return "unknown"
        # SquashFS
        if data[:4] in (SQSH_MAGIC_LE, SQSH_MAGIC_BE):
            return "filesystem"
        # JFFS2
        if data[:2] in (b"\x19\x85", b"\x85\x19"):
            return "filesystem"
        # LZMA 压缩内核
        if data[:3] == LZMA_MAGIC:
            return "code"
        # gzip 压缩
        if data[:2] == b"\x1f\x8b":
            return "code"
        # Linux kernel
        if b"Linux version" in data[:4096]:
            return "code"
        return "data"

    def _fallback_scan(self, data: bytes) -> UnpackResult:
        """无 TRX 头时，扫描已知文件系统签名。"""
        sections = []

        # 搜索 SquashFS
        for magic in (SQSH_MAGIC_LE, SQSH_MAGIC_BE):
            offset = data.find(magic)
            if offset >= 0:
                sections.append(FirmwareSection(
                    name="squashfs",
                    offset=offset,
                    size=len(data) - offset,
                    data=data[offset:offset + 4 * 1024 * 1024],
                    section_type="filesystem",
                    permissions="R",
                ))
                break

        # 整体作为 raw 分析
        if not sections:
            sections.append(FirmwareSection(
                name="raw_firmware",
                offset=0,
                size=len(data),
                data=data[:4 * 1024 * 1024],
                section_type="unknown",
                permissions="R",
            ))

        return UnpackResult(sections=sections)
```

### 注册新格式

在 `src/rtos_firmware_analyzer/firmware/unpacker.py` 中添加：

```python
from .formats.android_img import AndroidImgFormat
from .formats.android_apk import AndroidAPKFormat
from .formats.router_trx import RouterTRXFormat

FORMAT_HANDLERS: list[type[FirmwareFormat]] = [
    ELFFormat,
    UBootFormat,
    CompressedFirmwareFormat,
    ESPIDFFormat,
    IntelHEXFormat,
    SRecordFormat,
    AndroidAPKFormat,       # ← 新增
    AndroidImgFormat,       # ← 新增
    RouterTRXFormat,        # ← 新增
    RawBinaryFormat,        # 保持 RawBinaryFormat 在最后（兜底）
]
```

**注意**：`RawBinaryFormat` 必须保持在列表最后，因为它是兜底处理器（始终返回低置信度）。其余处理器按照 magic 检测的确定性从高到低排列。

### 格式检测优先级规则

`FirmwareUnpacker.detect_format()` 会遍历所有处理器，调用 `can_handle()` 并选择置信度最高的。你的 `can_handle()` 实现应该：

| 情况 | 建议置信度 |
|------|-----------|
| 精确匹配 magic bytes | 0.90 - 0.95 |
| magic + 文件名验证 | 0.85 - 0.95 |
| 仅文件扩展名匹配 | 0.30 - 0.50 |
| 内容启发式（字符串扫描等） | 0.50 - 0.80 |
| 无法识别 | 0.0 |

---

## 3. 如何添加新的组件提取器

### 核心接口：BaseExtractor

```python
# src/rtos_firmware_analyzer/extraction/extractors/base.py

from abc import ABC, abstractmethod
from ...core.context import AnalysisContext
from ..models import Component

class BaseExtractor(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        """提取器唯一名称。"""
        ...

    @abstractmethod
    def is_available(self) -> bool:
        """检查此提取器的依赖是否可用。"""
        ...

    @abstractmethod
    async def extract(self, context: AnalysisContext) -> list[Component]:
        """执行提取，返回发现的组件列表。"""
        ...

    @property
    def priority(self) -> int:
        """执行优先级，数值越大越先执行（默认 50）。"""
        return 50
```

### 示例：添加 YARA 规则提取器

```python
# src/rtos_firmware_analyzer/extraction/extractors/yara_scanner.py

"""YARA rules-based component extractor."""

from pathlib import Path
from ...core.context import AnalysisContext
from ..models import Component, VersionConfidence, ExtractionMethod
from .base import BaseExtractor

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False


class YaraExtractor(BaseExtractor):
    """使用 YARA 规则扫描固件，识别已知组件和恶意代码。"""

    RULES_DIR = Path(__file__).parent.parent.parent / "data" / "yara_rules"

    @property
    def name(self) -> str:
        return "yara_scanner"

    @property
    def priority(self) -> int:
        return 70  # 高于默认优先级

    def is_available(self) -> bool:
        return YARA_AVAILABLE and self.RULES_DIR.exists()

    async def extract(self, context: AnalysisContext) -> list[Component]:
        components: list[Component] = []

        # 编译所有 .yar 规则文件
        rules = self._compile_rules()
        if not rules:
            return components

        # 对每个 section 执行扫描
        if context.unpack_result:
            for section in context.unpack_result.sections:
                if not section.data:
                    continue
                matches = rules.match(data=section.data)
                for match in matches:
                    comp = self._match_to_component(match, section.name)
                    if comp:
                        components.append(comp)

        # 也对 raw data 执行扫描
        if context.raw_data:
            matches = rules.match(data=context.raw_data[:8 * 1024 * 1024])
            for match in matches:
                comp = self._match_to_component(match, "raw")
                if comp:
                    components.append(comp)

        return components

    def _compile_rules(self):
        """编译 YARA 规则目录下的所有 .yar 文件。"""
        try:
            rule_files = {}
            for yar_file in self.RULES_DIR.glob("*.yar"):
                rule_files[yar_file.stem] = str(yar_file)
            if rule_files:
                return yara.compile(filepaths=rule_files)
        except Exception:
            pass
        return None

    def _match_to_component(self, match, section_name: str) -> Component | None:
        """将 YARA match 转换为 Component。"""
        # 从规则的 meta 字段提取组件信息
        meta = match.meta
        name = meta.get("component_name", match.rule)
        vendor = meta.get("vendor", "")
        version = meta.get("version", "detected")
        comp_type = meta.get("component_type", "library")

        return Component(
            name=name,
            vendor=vendor,
            versions=[VersionConfidence(
                version=version,
                confidence=0.80,
                method=ExtractionMethod.BINARY_SIGNATURE,
                evidence=f"YARA rule '{match.rule}' matched in {section_name}",
            )],
            component_type=comp_type,
        )
```

### 注册提取器

**方式一：代码内注册**

在 `src/rtos_firmware_analyzer/extraction/orchestrator.py` 的 `_build_extractors()` 方法中添加：

```python
from .extractors.yara_scanner import YaraExtractor

all_extractors: list[BaseExtractor] = [
    StringPatternExtractor(),
    SymbolTableExtractor(),
    DisassemblyExtractor(),
    BinarySignatureExtractor(),
    YaraExtractor(),            # ← 新增
    Radare2Extractor(r2_path),
    GhidraExtractor(ghidra_path),
]
```

**方式二：entry-point 注册（推荐用于第三方包）**

在你的包的 `pyproject.toml` 中声明：

```toml
[project.entry-points."rtos_firmware_analyzer.extractors"]
yara_scanner = "your_package.extractors.yara_scanner:YaraExtractor"
```

安装该包后，`rtos-firmware-analyzer` 启动时会自动发现并加载你的提取器。

---

## 4. 如何添加新的签名模式

### PluginManager 签名文件

`rtos-firmware-analyzer` 的 `PluginManager` 支持从 JSON 文件加载自定义签名和版本模式，无需编写 Python 代码。

### JSON 文件格式

将 JSON 文件放置在插件目录中（默认为 `~/.rtos-firmware-analyzer/plugins/` 或通过配置指定）。

```json
{
  "name": "my_custom_signatures",
  "version": "1.0.0",
  "description": "自定义 IoT 设备组件签名库",
  "signatures": [
    {
      "pattern": "Mongoose/([0-9]+\\.[0-9]+)",
      "name": "Mongoose Web Server",
      "vendor": "Cesanta",
      "type": "library"
    },
    {
      "pattern": "wolfSSL\\s+([0-9]+\\.[0-9]+\\.[0-9]+)",
      "name": "wolfSSL",
      "vendor": "wolfSSL Inc.",
      "type": "library"
    },
    {
      "pattern": "lwIP\\s+([0-9]+\\.[0-9]+\\.[0-9]+)",
      "name": "lwIP",
      "vendor": "Swedish Institute of Computer Science",
      "type": "library"
    },
    {
      "pattern": "MQTT[Cc]lient\\s+v?([0-9]+\\.[0-9]+)",
      "name": "Paho MQTT Client",
      "vendor": "Eclipse Foundation",
      "type": "library"
    },
    {
      "pattern": "coap_([0-9]+\\.[0-9]+\\.[0-9]+)",
      "name": "libcoap",
      "vendor": "libcoap",
      "type": "library"
    }
  ],
  "version_patterns": [
    {
      "pattern": "Mongoose/([0-9]+\\.[0-9]+\\.[0-9]+)",
      "name": "Mongoose Web Server",
      "vendor": "Cesanta",
      "type": "library"
    },
    {
      "pattern": "wolfSSL\\s+([0-9]+\\.[0-9]+\\.[0-9]+[-a-z]*)",
      "name": "wolfSSL",
      "vendor": "wolfSSL Inc.",
      "type": "library"
    }
  ]
}
```

### 字段说明

| 字段 | 类型 | 说明 |
|------|------|------|
| `pattern` | string | 正则表达式，捕获组(1)用于版本提取 |
| `name` | string | 组件名称 |
| `vendor` | string | 供应商名称 |
| `type` | string | 组件类型：`library`、`operating-system`、`framework`、`firmware` |

### 使用方式

```python
from rtos_firmware_analyzer.core.plugin_manager import PluginManager
from pathlib import Path

pm = PluginManager()
# 注册插件目录
pm.add_plugin_dir(Path("~/.rtos-firmware-analyzer/plugins").expanduser())
# 或者直接加载单个签名文件
signatures = pm.load_signature_file(Path("my_signatures.json"))
```

### 创建 Python 插件（高级）

如果 JSON 签名不够灵活，可以编写 Python 插件，实现 `AnalyzerPlugin` 协议：

```python
# ~/.rtos-firmware-analyzer/plugins/my_plugin.py

"""自定义分析器插件示例。"""

from rtos_firmware_analyzer.core.context import AnalysisContext
from rtos_firmware_analyzer.extraction.models import Component, VersionConfidence, ExtractionMethod
from rtos_firmware_analyzer.extraction.deep_scanner import SignatureEntry, VersionPatternEntry


class MyCustomPlugin:
    """满足 AnalyzerPlugin Protocol 的自定义插件。"""

    @property
    def name(self) -> str:
        return "my_custom_plugin"

    @property
    def version(self) -> str:
        return "1.0.0"

    def get_signatures(self) -> list[SignatureEntry]:
        return [
            SignatureEntry(
                pattern=r"MyProprietaryLib\s+v(\d+\.\d+)",
                name="MyProprietaryLib",
                vendor="MyCompany",
                component_type="library",
            ),
        ]

    def get_version_patterns(self) -> list[VersionPatternEntry]:
        return [
            VersionPatternEntry(
                pattern=r"MyProprietaryLib\s+v(\d+\.\d+\.\d+)",
                name="MyProprietaryLib",
                vendor="MyCompany",
                component_type="library",
            ),
        ]

    async def analyze(self, context: AnalysisContext) -> list[Component]:
        """可选：执行自定义深度分析逻辑。"""
        components = []
        if b"MyProprietaryLib" in context.raw_data:
            components.append(Component(
                name="MyProprietaryLib",
                vendor="MyCompany",
                versions=[VersionConfidence(
                    version="detected",
                    confidence=0.75,
                    method=ExtractionMethod.BINARY_SIGNATURE,
                    evidence="Found proprietary string marker",
                )],
                component_type="library",
            ))
        return components
```

将此文件放入插件目录后，`PluginManager.load_plugins()` 会自动发现并加载它。

---

## 5. 扩展路线图

以下是建议的后续格式支持计划，按优先级和工作量估算：

### 高优先级

| 格式/平台 | 描述 | 工作量估算 | 复杂度 |
|-----------|------|-----------|--------|
| Android system.img | sparse image / ext4 / erofs | 2-3 天 | 中 |
| 路由器 TRX/BIN | Broadcom/TP-Link/Netgear 固件 | 2-3 天 | 中 |
| OpenWrt sysupgrade | 标准 OpenWrt 升级包 | 1-2 天 | 低 |
| Android boot.img | Linux kernel + ramdisk | 1-2 天 | 低 |
| UBI/UBIFS | NAND flash 文件系统 | 3-4 天 | 高 |

### 中优先级

| 格式/平台 | 描述 | 工作量估算 | 复杂度 |
|-----------|------|-----------|--------|
| Android APK | ZIP + DEX + native SO | 1-2 天 | 低 |
| Android OTA (payload.bin) | Chrome OS update_engine 格式 | 3-5 天 | 高 |
| JFFS2 文件系统 | 用于 NOR flash 的日志文件系统 | 2-3 天 | 中 |
| SquashFS 直接解包 | 需要 unsquashfs 或纯 Python 实现 | 2-3 天 | 中 |
| Qualcomm MBN/SBL | 高通基带/bootloader | 3-4 天 | 高 |

### 低优先级（未来）

| 格式/平台 | 描述 | 工作量估算 | 复杂度 |
|-----------|------|-----------|--------|
| 汽车 ECU 固件 | S19/A2L/ODX 格式，CAN 协议栈 | 5-7 天 | 高 |
| IoT 网关打包 | 各厂商私有格式 (Tuya/涂鸦等) | 3-5 天 | 中-高 |
| PLC 固件 | Siemens S7 / Allen-Bradley | 5-7 天 | 高 |
| FPGA bitstream | Xilinx/Altera 比特流格式 | 4-5 天 | 高 |
| ARM TrustZone image | Secure world 固件 | 3-4 天 | 高 |
| Bluetooth/BLE 固件 | nRF5x/CC2640 等 SoC 专用格式 | 2-3 天 | 中 |
| Zigbee/Thread OTA | OTA upgrade image (Zigbee/Thread) | 2-3 天 | 中 |
| MediaTek 路由器 | MT7621/MT7628 固件头部 | 1-2 天 | 低 |

### RTOS 插件扩展计划

| RTOS | 描述 | 工作量估算 |
|------|------|-----------|
| Mbed OS | ARM Mbed (已 EOL 但广泛使用) | 1-2 天 |
| RIOT OS | 开源 IoT 操作系统 | 1-2 天 |
| Contiki-NG | 传感器网络 OS | 1-2 天 |
| Azure RTOS (ThreadX) | 已有基础，需增强版本检测 | 1 天 |
| Huawei LiteOS-M | 鸿蒙内核精简版 | 2-3 天 |
| RT-Thread Smart | RT-Thread 混合内核版本 | 1-2 天 |
| QNX | 汽车/工业实时操作系统 | 3-4 天 |
| eCos | 嵌入式可配置操作系统 | 2-3 天 |

---

## 6. 外部集成 API

### 作为 Python 库使用

`rtos-firmware-analyzer` 可以直接作为 Python 库导入使用，无需通过 CLI 调用。

### 基本用法：固件解包

```python
from pathlib import Path
from rtos_firmware_analyzer.firmware.unpacker import FirmwareUnpacker

# 初始化解包器
unpacker = FirmwareUnpacker()

# 读取固件文件
firmware_path = Path("device_firmware.bin")
data = firmware_path.read_bytes()

# 检测格式
handler, confidence = unpacker.detect_format(data, firmware_path)
print(f"检测到格式: {handler.format_name} (置信度: {confidence:.2f})")

# 解包固件
result, format_name = unpacker.unpack(data, firmware_path)
print(f"解包完成: {len(result.sections)} 个 sections")
for section in result.sections:
    print(f"  - {section.name}: {section.size} bytes ({section.section_type})")
```

### 完整分析流水线

```python
import asyncio
from pathlib import Path
from rtos_firmware_analyzer.core.context import AnalysisContext
from rtos_firmware_analyzer.core.pipeline import AnalysisPipeline
from rtos_firmware_analyzer.firmware.unpacker import FirmwareUnpacker
from rtos_firmware_analyzer.arch.detector import ArchDetector
from rtos_firmware_analyzer.rtos.registry import RTOSRegistry
from rtos_firmware_analyzer.extraction.orchestrator import ExtractionOrchestrator


async def analyze_firmware(firmware_path: str) -> dict:
    """完整的固件分析流程。"""
    path = Path(firmware_path)
    data = path.read_bytes()

    # 1. 解包
    unpacker = FirmwareUnpacker()
    unpack_result, format_name = unpacker.unpack(data, path)

    # 2. 构建分析上下文
    import hashlib
    context = AnalysisContext(
        firmware_path=path,
        raw_data=data,
        file_hash_sha256=hashlib.sha256(data).hexdigest(),
        file_hash_md5=hashlib.md5(data).hexdigest(),
        unpack_result=unpack_result,
    )

    # 3. 架构检测
    arch_detector = ArchDetector()
    context.arch_info = arch_detector.detect(data, unpack_result)

    # 4. RTOS 检测
    rtos_results = RTOSRegistry.detect(context)
    if rtos_results:
        best_plugin, best_conf = rtos_results[0]
        context.detected_rtos = best_plugin.rtos_name
        context.rtos_confidence = best_conf
        # 运行 RTOS 专用分析
        rtos_components = await best_plugin.analyze(context)
        context.components.extend(rtos_components)

    # 5. 通用组件提取
    orchestrator = ExtractionOrchestrator()
    components = await orchestrator.run_all(context)
    context.components.extend(components)

    # 6. 返回结果
    return {
        "format": format_name,
        "architecture": context.arch_info.arch if context.arch_info else "unknown",
        "rtos": context.detected_rtos,
        "rtos_confidence": context.rtos_confidence,
        "components": [c.model_dump() for c in context.components],
        "errors": [e.model_dump() for e in context.errors],
    }


# 运行
result = asyncio.run(analyze_firmware("my_device.elf"))
print(f"RTOS: {result['rtos']} ({result['rtos_confidence']:.0%})")
print(f"发现 {len(result['components'])} 个组件")
```

### 仅使用特定模块

```python
# 只使用 RTOS 检测
from rtos_firmware_analyzer.rtos.registry import RTOSRegistry
from rtos_firmware_analyzer.core.context import AnalysisContext

context = AnalysisContext(
    firmware_path=Path("firmware.bin"),
    raw_data=Path("firmware.bin").read_bytes(),
)
detections = RTOSRegistry.detect(context)
for plugin, confidence in detections:
    print(f"  {plugin.rtos_name}: {confidence:.0%}")
```

```python
# 只使用插件系统加载自定义签名
from pathlib import Path
from rtos_firmware_analyzer.core.plugin_manager import PluginManager

pm = PluginManager()
pm.add_plugin_dir(Path("/path/to/my/plugins"))
pm.load_plugins()

# 查看已加载的插件
for info in pm.get_loaded_plugins():
    print(f"  插件: {info['name']} v{info['version']}")
```

### 与 CI/CD 集成

```python
# ci_firmware_check.py - 在 CI 流水线中检查固件安全性
import asyncio
import sys
from pathlib import Path
from rtos_firmware_analyzer.firmware.unpacker import FirmwareUnpacker
from rtos_firmware_analyzer.core.context import AnalysisContext
from rtos_firmware_analyzer.extraction.orchestrator import ExtractionOrchestrator


async def ci_check(firmware_path: str) -> int:
    """CI 固件安全检查，返回退出码。"""
    path = Path(firmware_path)
    data = path.read_bytes()

    unpacker = FirmwareUnpacker()
    unpack_result, _ = unpacker.unpack(data, path)

    context = AnalysisContext(
        firmware_path=path,
        raw_data=data,
        unpack_result=unpack_result,
    )

    orchestrator = ExtractionOrchestrator()
    components = await orchestrator.run_all(context)

    # 检查是否有已知漏洞组件（示例逻辑）
    vulnerable = []
    for comp in components:
        if comp.resolved_version and comp.resolved_version != "detected (version unknown)":
            # 这里可以对接 CVE 数据库进行漏洞匹配
            pass

    if vulnerable:
        print(f"[FAIL] 发现 {len(vulnerable)} 个潜在漏洞组件")
        return 1

    print(f"[PASS] 检测到 {len(components)} 个组件，未发现已知漏洞")
    return 0


if __name__ == "__main__":
    exit_code = asyncio.run(ci_check(sys.argv[1]))
    sys.exit(exit_code)
```

### SBOM 生成

```python
from rtos_firmware_analyzer.sbom.generator import SBOMGenerator
from rtos_firmware_analyzer.extraction.models import Component

# 假设已获得组件列表
components: list[Component] = [...]

generator = SBOMGenerator()
# 生成 CycloneDX JSON 格式 SBOM
sbom_json = generator.generate_cyclonedx(
    components=components,
    firmware_name="my_device_v2.1",
    firmware_version="2.1.0",
)

# 写入文件
Path("sbom.json").write_text(sbom_json)
```

---

## 附录：开发建议

### 测试新格式处理器

```python
# tests/test_formats/test_android_img.py

import pytest
from pathlib import Path
from rtos_firmware_analyzer.firmware.formats.android_img import AndroidImgFormat


class TestAndroidImgFormat:
    def test_sparse_magic_detection(self):
        """测试 sparse image magic bytes 检测。"""
        # sparse header magic: 0xED26FF3A (little-endian)
        sparse_data = b"\x3a\xff\x26\xed" + b"\x00" * 100
        confidence = AndroidImgFormat.can_handle(sparse_data, Path("system.img"))
        assert confidence >= 0.90

    def test_ext4_detection(self):
        """测试 ext4 superblock 检测。"""
        data = bytearray(0x500)
        # ext4 magic at offset 0x438
        data[0x438] = 0x53
        data[0x439] = 0xEF
        confidence = AndroidImgFormat.can_handle(
            bytes(data), Path("system.img")
        )
        assert confidence >= 0.80

    def test_non_img_returns_zero(self):
        """非 IMG 文件应返回 0.0。"""
        elf_data = b"\x7fELF" + b"\x00" * 100
        confidence = AndroidImgFormat.can_handle(elf_data, Path("app.elf"))
        assert confidence == 0.0


class TestRouterTRX:
    def test_trx_magic_detection(self):
        """测试 TRX magic 检测。"""
        from rtos_firmware_analyzer.firmware.formats.router_trx import RouterTRXFormat

        trx_data = b"HDR0" + b"\x00" * 100
        confidence = RouterTRXFormat.can_handle(trx_data, Path("firmware.trx"))
        assert confidence >= 0.90
```

### 项目结构约定

- 每个格式处理器一个文件，文件名使用小写下划线命名
- 所有处理器继承 `FirmwareFormat`
- `can_handle()` 是类方法（`@classmethod`），支持无实例化检测
- `unpack()` 返回 `UnpackResult`，包含解析出的 sections
- 对内存敏感：大文件只保留必要的前 N MB 用于分析

### 性能注意事项

- `can_handle()` 应当轻量（只检查 magic bytes 和头部），避免重 I/O
- `unpack()` 可以做更深入的解析，但建议对 section data 做大小限制
- 使用 `DeepScanner` 的多线程扫描时，注意线程安全
