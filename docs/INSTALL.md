# rtos-firmware-analyzer 安装指南

## 目录

- [快速开始](#快速开始)
- [依赖自动检测](#依赖自动检测)
- [可选工具安装 - Windows](#windows-安装)
- [可选工具安装 - Linux](#linux-安装)
- [可选工具安装 - macOS](#macos-安装)
- [配置文件](#配置文件)
- [故障排除](#故障排除)
- [最小化安装说明](#最小化安装说明)

---

## 快速开始

仅需 Python 3.9+ 环境即可安装核心功能：

```bash
pip install rtos-firmware-analyzer
```

安装完成后即可使用基础分析功能。所有必需的 Python 依赖（capstone、lief、intelhex、typer、rich、pydantic、packageurl-python）会通过 pip 自动安装。

如需可选的逆向工程集成能力，可额外安装对应包：

```bash
# radare2 集成
pip install r2pipe

# Ghidra 集成（需要先安装 Ghidra 并设置环境变量）
pip install pyhidra
```

验证安装：

```bash
rtos-firmware-analyzer --version
```

---

## 依赖自动检测

工具内置了依赖检测和初始化命令，帮助你快速了解当前环境状态。

### check-deps - 检查依赖状态

```bash
rtos-firmware-analyzer check-deps
```

该命令会扫描当前系统环境，报告：

- 核心 Python 包是否已安装
- 可选 Python 包（r2pipe、pyhidra）是否可用
- 外部工具（radare2、Ghidra、binwalk）是否在 PATH 中或已正确配置
- 配置文件是否存在及其内容是否有效

输出示例：

```
[Core Dependencies]
  capstone .............. OK (v5.0.1)
  lief .................. OK (v0.14.0)
  intelhex .............. OK (v2.3.0)
  typer ................. OK (v0.9.0)
  rich .................. OK (v13.7.0)
  pydantic .............. OK (v2.6.0)
  packageurl-python ..... OK (v0.15.0)

[Optional Python Packages]
  r2pipe ................ OK (v5.9.0)
  pyhidra ............... NOT INSTALLED

[External Tools]
  radare2 ............... OK (v5.9.0) @ C:\tools\radare2\bin\radare2.exe
  Ghidra ................ NOT CONFIGURED (GHIDRA_INSTALL_DIR not set)
  binwalk ............... OK (v2.3.4)
```

### init - 交互式初始化

```bash
rtos-firmware-analyzer init
```

该命令会：

1. 运行依赖检查
2. 自动探测已安装工具的路径
3. 生成配置文件 `~/.rtos-analyzer/config.json`
4. 提示你确认或手动输入工具路径

---

## Windows 安装

### radare2

1. 从 GitHub Releases 下载最新版本：
   - 访问 https://github.com/radareorg/radare2/releases
   - 下载 `radare2-x.y.z-w64.zip`（64 位 Windows 版本）

2. 解压到目标目录，例如 `C:\tools\radare2`

3. 将 radare2 添加到系统 PATH：
   - 打开「设置」->「系统」->「关于」->「高级系统设置」->「环境变量」
   - 在「系统变量」中找到 `Path`，点击「编辑」
   - 添加 `C:\tools\radare2\bin`
   - 确认并重启终端

4. 安装 Python 绑定：

   ```bash
   pip install r2pipe
   ```

5. 验证：

   ```bash
   radare2 -v
   python -c "import r2pipe; print('r2pipe OK')"
   ```

### Ghidra

1. 下载 Ghidra：
   - 访问 https://ghidra-sre.org/
   - 下载最新版本的 ZIP 包（如 `ghidra_11.0_PUBLIC_20240101.zip`）

2. 解压到目标目录，例如 `C:\tools\ghidra`

3. 安装 JDK 17+（Ghidra 依赖 Java）：
   - 下载 Adoptium JDK：https://adoptium.net/
   - 安装后确保 `java -version` 可用

4. 设置环境变量 `GHIDRA_INSTALL_DIR`：
   - 打开「环境变量」设置
   - 新建系统变量：
     - 变量名：`GHIDRA_INSTALL_DIR`
     - 变量值：`C:\tools\ghidra\ghidra_11.0_PUBLIC`（指向包含 `ghidraRun.bat` 的目录）

5. 安装 pyhidra：

   ```bash
   pip install pyhidra
   ```

6. 首次运行时 pyhidra 会自动初始化 Ghidra 的 Java 桥接，可能需要数分钟。

7. 验证：

   ```bash
   python -c "import pyhidra; pyhidra.start(); print('pyhidra OK')"
   ```

### binwalk

方式一：通过 pip 安装（推荐）

```bash
pip install binwalk
```

方式二：下载 Windows 预编译版本

- 访问 https://github.com/ReFirmLabs/binwalk/releases
- 下载对应 Windows 版本并添加到 PATH

验证：

```bash
binwalk --help
```

> 注意：Windows 上 binwalk 的部分高级提取功能可能需要额外安装 7-Zip、sasquatch 等工具。

---

## Linux 安装

### radare2

**Debian/Ubuntu：**

```bash
# 方式一：使用官方安装脚本（推荐，获取最新版本）
git clone https://github.com/radareorg/radare2.git
cd radare2
sys/install.sh

# 方式二：使用包管理器（版本可能较旧）
sudo apt install radare2
```

**Arch Linux：**

```bash
sudo pacman -S radare2
```

**通过 Homebrew（如已安装 Linuxbrew）：**

```bash
brew install radare2
```

安装 Python 绑定：

```bash
pip install r2pipe
```

验证：

```bash
radare2 -v
python3 -c "import r2pipe; print('r2pipe OK')"
```

### Ghidra

**方式一：通过 Snap（Ubuntu/Debian）**

```bash
sudo snap install ghidra
```

Snap 安装后 `GHIDRA_INSTALL_DIR` 通常为 `/snap/ghidra/current/lib/ghidra`。

**方式二：通过 apt（如发行版仓库提供）**

```bash
sudo apt install ghidra
```

**方式三：手动安装（推荐，获取最新版本）**

```bash
# 安装 JDK 17+
sudo apt install openjdk-17-jdk

# 下载并解压 Ghidra
wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.0_build/ghidra_11.0_PUBLIC_20240101.zip
unzip ghidra_11.0_PUBLIC_20240101.zip -d /opt/
```

设置环境变量（添加到 `~/.bashrc` 或 `~/.zshrc`）：

```bash
export GHIDRA_INSTALL_DIR=/opt/ghidra_11.0_PUBLIC
```

安装 pyhidra：

```bash
pip install pyhidra
```

验证：

```bash
python3 -c "import pyhidra; pyhidra.start(); print('pyhidra OK')"
```

### binwalk

```bash
# Debian/Ubuntu
sudo apt install binwalk

# Arch Linux
sudo pacman -S binwalk

# Fedora
sudo dnf install binwalk
```

验证：

```bash
binwalk --help
```

---

## macOS 安装

### radare2

```bash
brew install radare2
```

安装 Python 绑定：

```bash
pip install r2pipe
```

验证：

```bash
radare2 -v
python3 -c "import r2pipe; print('r2pipe OK')"
```

### Ghidra

```bash
# 安装 JDK 17+
brew install openjdk@17

# 通过 Homebrew Cask 安装 Ghidra
brew install --cask ghidra
```

Homebrew 安装后 Ghidra 路径通常为：

```
/Applications/Ghidra.app/Contents/Resources/ghidra
```

或通过 Homebrew 安装的路径：

```
/opt/homebrew/Caskroom/ghidra/<version>/ghidra_<version>_PUBLIC
```

设置环境变量（添加到 `~/.zshrc`）：

```bash
export GHIDRA_INSTALL_DIR="/Applications/Ghidra.app/Contents/Resources/ghidra"
```

安装 pyhidra：

```bash
pip install pyhidra
```

验证：

```bash
python3 -c "import pyhidra; pyhidra.start(); print('pyhidra OK')"
```

### binwalk

```bash
brew install binwalk
```

验证：

```bash
binwalk --help
```

---

## 配置文件

工具使用 `~/.rtos-analyzer/config.json` 作为配置文件。你可以通过 `rtos-firmware-analyzer init` 自动生成，也可以手动创建。

### 字段说明

| 字段 | 类型 | 说明 |
|------|------|------|
| `radare2_path` | string | radare2 可执行文件的完整路径。设为空字符串 `""` 表示跳过 radare2 集成（不会报错）。 |
| `ghidra_install_dir` | string | Ghidra 安装根目录路径。设为空字符串 `""` 表示跳过 Ghidra 集成（不会报错）。 |
| `binwalk_path` | string | binwalk 可执行文件路径。设为空字符串 `""` 表示跳过 binwalk 集成（不会报错）。 |
| `default_arch` | string | 默认分析架构（如 `"arm"`, `"mips"`, `"x86"`），未指定时工具会自动检测。 |
| `output_format` | string | 默认输出格式：`"json"`, `"text"`, `"html"` |
| `log_level` | string | 日志等级：`"debug"`, `"info"`, `"warning"`, `"error"` |
| `analysis_timeout` | int | 单次分析超时时间（秒），默认 300 |

### 关键行为：空字符串 = 跳过该工具

将任何工具路径设为空字符串 `""` 时，工具会优雅地跳过对应的集成功能，**不会产生错误或警告**。这意味着你无需安装所有可选工具即可正常使用。

### Windows 配置示例

```json
{
  "radare2_path": "C:\\tools\\radare2\\bin\\radare2.exe",
  "ghidra_install_dir": "C:\\tools\\ghidra\\ghidra_11.0_PUBLIC",
  "binwalk_path": "",
  "default_arch": "arm",
  "output_format": "json",
  "log_level": "info",
  "analysis_timeout": 300
}
```

### Linux 配置示例

```json
{
  "radare2_path": "/usr/bin/radare2",
  "ghidra_install_dir": "/opt/ghidra_11.0_PUBLIC",
  "binwalk_path": "/usr/bin/binwalk",
  "default_arch": "arm",
  "output_format": "json",
  "log_level": "info",
  "analysis_timeout": 300
}
```

### macOS 配置示例

```json
{
  "radare2_path": "/opt/homebrew/bin/radare2",
  "ghidra_install_dir": "/Applications/Ghidra.app/Contents/Resources/ghidra",
  "binwalk_path": "/opt/homebrew/bin/binwalk",
  "default_arch": "arm",
  "output_format": "json",
  "log_level": "info",
  "analysis_timeout": 300
}
```

### 仅使用核心功能的最简配置

```json
{
  "radare2_path": "",
  "ghidra_install_dir": "",
  "binwalk_path": "",
  "default_arch": "arm",
  "output_format": "json",
  "log_level": "info",
  "analysis_timeout": 300
}
```

---

## 故障排除

### GHIDRA_INSTALL_DIR 未设置

**错误信息：**
```
Error: GHIDRA_INSTALL_DIR environment variable is not set.
Cannot initialize pyhidra without Ghidra installation path.
```

**解决方法：**

1. 确认 Ghidra 已下载并解压
2. 找到包含 `ghidraRun`（Linux/macOS）或 `ghidraRun.bat`（Windows）的目录
3. 设置环境变量指向该目录：

   - Windows（PowerShell）：
     ```powershell
     [System.Environment]::SetEnvironmentVariable("GHIDRA_INSTALL_DIR", "C:\tools\ghidra\ghidra_11.0_PUBLIC", "User")
     ```
   - Linux/macOS（添加到 shell 配置文件）：
     ```bash
     export GHIDRA_INSTALL_DIR=/opt/ghidra_11.0_PUBLIC
     ```

4. 重启终端使环境变量生效

### r2pipe 连接失败

**错误信息：**
```
Error: Cannot connect to radare2. Is radare2 installed and in PATH?
```

**解决方法：**

1. 确认 radare2 已安装：`radare2 -v`
2. 确认 radare2 在系统 PATH 中
3. 如果使用自定义路径，在配置文件中设置 `radare2_path`
4. Windows 用户：确认使用的是完整路径包含 `.exe` 后缀

### pyhidra 初始化超时

**错误信息：**
```
Timeout: pyhidra initialization took too long
```

**解决方法：**

- pyhidra 首次启动需要初始化 JVM 和 Ghidra 运行时，可能需要 1-3 分钟
- 确认 JDK 17+ 已正确安装：`java -version`
- 增加配置中的 `analysis_timeout` 值
- 检查系统内存是否充足（Ghidra 建议至少 4GB 可用内存）

### binwalk 提取功能不完整（Windows）

**问题：** binwalk 可以识别文件系统但无法提取内容。

**解决方法：**

Windows 上 binwalk 的提取依赖额外工具：
- 安装 7-Zip 并添加到 PATH
- 部分文件系统类型需要在 WSL 中运行 binwalk

### pip install 失败（capstone 编译错误）

**解决方法：**

- Windows：安装 Visual Studio Build Tools
- Linux：`sudo apt install build-essential python3-dev`
- macOS：`xcode-select --install`
- 或尝试安装预编译版本：`pip install --only-binary :all: capstone`

### 配置文件权限错误

**错误信息：**
```
Permission denied: ~/.rtos-analyzer/config.json
```

**解决方法：**

```bash
# Linux/macOS
mkdir -p ~/.rtos-analyzer
chmod 755 ~/.rtos-analyzer
chmod 644 ~/.rtos-analyzer/config.json

# Windows - 以管理员身份运行或检查文件属性是否为只读
```

---

## 最小化安装说明

**rtos-firmware-analyzer 仅需 `pip install` 即可完整运行核心功能。** 所有可选工具只是提供更深层次的分析能力，并非必需。

### 核心功能（无需任何可选工具）

仅通过 pip 安装后，你已经可以：

- RTOS 类型识别（FreeRTOS、Zephyr、RT-Thread、ThreadX 等）
- 固件格式解析（ELF、Intel HEX、binary）
- 符号表分析
- 内存布局映射
- SBOM（软件物料清单）生成
- 基础漏洞检测
- 配置提取

### 可选工具增强的能力

| 工具 | 增强能力 |
|------|----------|
| radare2 | 深度反汇编、控制流分析、交叉引用、字符串搜索、高级模式匹配 |
| Ghidra | 反编译为伪代码、高级数据类型恢复、函数签名识别、完整程序分析 |
| binwalk | 固件解包、嵌套文件系统提取、熵分析、签名扫描 |

### 推荐安装策略

1. **入门用户**：仅 `pip install rtos-firmware-analyzer`，体验核心功能
2. **日常分析**：额外安装 radare2 + r2pipe，获得反汇编能力
3. **深度逆向**：安装全部工具，获得完整分析能力

```bash
# 入门 - 最小安装
pip install rtos-firmware-analyzer

# 日常 - 添加 radare2 支持
pip install rtos-firmware-analyzer r2pipe

# 完整 - 所有可选依赖
pip install rtos-firmware-analyzer r2pipe pyhidra binwalk
```

无论选择哪种安装方式，工具都会根据可用的依赖自动调整分析策略，不会因为缺少可选工具而报错。
