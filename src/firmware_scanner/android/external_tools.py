"""Optional external tool wrappers for Android image processing.

All tools are optional - the scanner works with pure-Python parsers by default.
External tools provide better performance for large images and handle edge cases
that pure-Python parsers may not cover.
"""

import shutil
import subprocess
import tempfile
from pathlib import Path
from dataclasses import dataclass


@dataclass
class ToolInfo:
    name: str
    path: str | None
    available: bool
    version: str = ""


class ExternalToolManager:
    """Manages optional external tools for Android image processing."""

    KNOWN_TOOLS = {
        "simg2img": "Convert Android sparse images to raw",
        "lpunpack": "Extract partitions from super.img",
        "debugfs": "Extract files from ext4 images",
        "fsck.erofs": "Check/extract EROFS images",
        "payload-dumper-go": "Extract partitions from payload.bin",
        "brotli": "Decompress brotli-compressed OTA data",
    }

    def __init__(self, tools_dir: str = ""):
        self._tools_dir = tools_dir
        self._cache: dict[str, ToolInfo] = {}

    def is_available(self, tool: str) -> bool:
        """Check if an external tool is available."""
        info = self._find_tool(tool)
        return info.available

    def get_tool_status(self) -> list[ToolInfo]:
        """Get status of all known tools."""
        results = []
        for name in self.KNOWN_TOOLS:
            results.append(self._find_tool(name))
        return results

    def _find_tool(self, tool: str) -> ToolInfo:
        """Find a tool on the system."""
        if tool in self._cache:
            return self._cache[tool]

        # Check custom tools directory first
        if self._tools_dir:
            custom_path = Path(self._tools_dir) / tool
            if custom_path.exists() and custom_path.is_file():
                info = ToolInfo(name=tool, path=str(custom_path), available=True)
                self._cache[tool] = info
                return info
            # Try with .exe extension on Windows
            custom_path_exe = Path(self._tools_dir) / f"{tool}.exe"
            if custom_path_exe.exists():
                info = ToolInfo(name=tool, path=str(custom_path_exe), available=True)
                self._cache[tool] = info
                return info

        # Check PATH
        which_result = shutil.which(tool)
        if which_result:
            info = ToolInfo(name=tool, path=which_result, available=True)
        else:
            info = ToolInfo(name=tool, path=None, available=False)

        self._cache[tool] = info
        return info

    def simg2img(self, sparse_data: bytes, output_path: Path | None = None) -> bytes | None:
        """Convert sparse image to raw using simg2img tool."""
        info = self._find_tool("simg2img")
        if not info.available:
            return None

        try:
            with tempfile.NamedTemporaryFile(suffix='.simg', delete=False) as tmp_in:
                tmp_in.write(sparse_data)
                tmp_in_path = tmp_in.name

            if output_path is None:
                tmp_out = tempfile.NamedTemporaryFile(suffix='.raw', delete=False)
                out_path = tmp_out.name
                tmp_out.close()
            else:
                out_path = str(output_path)

            result = subprocess.run(
                [info.path, tmp_in_path, out_path],
                capture_output=True,
                timeout=300,
            )

            if result.returncode == 0:
                raw_data = Path(out_path).read_bytes()
                return raw_data

        except Exception:
            pass
        finally:
            try:
                Path(tmp_in_path).unlink(missing_ok=True)
                if output_path is None:
                    Path(out_path).unlink(missing_ok=True)
            except Exception:
                pass

        return None

    def lpunpack(self, super_img_path: Path, output_dir: Path) -> dict[str, Path]:
        """Extract partitions from super.img using lpunpack."""
        info = self._find_tool("lpunpack")
        if not info.available:
            return {}

        output_dir.mkdir(parents=True, exist_ok=True)

        try:
            result = subprocess.run(
                [info.path, str(super_img_path), str(output_dir)],
                capture_output=True,
                timeout=600,
            )

            if result.returncode == 0:
                # List extracted files
                extracted = {}
                for f in output_dir.iterdir():
                    if f.suffix == '.img':
                        extracted[f.stem] = f
                return extracted

        except Exception:
            pass

        return {}

    def extract_ext4_file(self, img_path: Path, file_path: str) -> bytes | None:
        """Extract a single file from ext4 image using debugfs."""
        info = self._find_tool("debugfs")
        if not info.available:
            return None

        try:
            with tempfile.NamedTemporaryFile(delete=False) as tmp_out:
                tmp_out_path = tmp_out.name

            result = subprocess.run(
                [info.path, '-R', f'dump {file_path} {tmp_out_path}', str(img_path)],
                capture_output=True,
                timeout=60,
            )

            if result.returncode == 0:
                return Path(tmp_out_path).read_bytes()

        except Exception:
            pass
        finally:
            try:
                Path(tmp_out_path).unlink(missing_ok=True)
            except Exception:
                pass

        return None
