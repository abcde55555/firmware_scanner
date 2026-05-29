"""Android APK and generic ZIP format handlers."""

import zipfile
import io
from pathlib import Path

from ..extension_api import ZipBasedFormat
from ...extraction.models import UnpackResult, FirmwareSection


class APKFormat(ZipBasedFormat):
    """Android APK format handler."""

    @property
    def format_name(self) -> str:
        return "Android APK"

    @classmethod
    def can_handle(cls, data: bytes, path: Path) -> float:
        if path.suffix.lower() != ".apk":
            if data[:2] != b"PK":
                return 0.0
            try:
                zf = zipfile.ZipFile(io.BytesIO(data[:65536]))
                names = zf.namelist()
                zf.close()
                if "AndroidManifest.xml" in names:
                    return 0.9
            except Exception:
                return 0.0
            return 0.0
        if data[:2] == b"PK":
            return 0.95
        return 0.0

    def _get_files_to_analyze(self, zf: zipfile.ZipFile) -> list[str]:
        targets = []
        for name in zf.namelist():
            if name.endswith(".so"):
                targets.append(name)
            elif name.endswith(".dex"):
                targets.append(name)
            elif name in ("AndroidManifest.xml", "META-INF/MANIFEST.MF"):
                targets.append(name)
            elif "assets/" in name and name.endswith((".json", ".txt", ".cfg")):
                targets.append(name)
            # Gradle metadata and build info
            elif name.endswith((".properties", ".gradle")) or "build" in name.lower():
                targets.append(name)
            # Version files
            elif "version" in name.lower() or name.endswith(("pom.xml", "pom.properties")):
                targets.append(name)
        return targets


class GenericZIPFormat(ZipBasedFormat):
    """Generic ZIP archive handler for SDK distributions and firmware packages."""

    @property
    def format_name(self) -> str:
        return "ZIP Archive (SDK/Package)"

    @classmethod
    def can_handle(cls, data: bytes, path: Path) -> float:
        if data[:2] != b"PK":
            return 0.0
        if path.suffix.lower() in (".zip",):
            return 0.80
        return 0.0

    def _get_files_to_analyze(self, zf: zipfile.ZipFile) -> list[str]:
        """Select key files for component/version analysis from ZIP archives."""
        targets = []
        names = zf.namelist()

        for name in names:
            lower = name.lower()
            # Manifest/version files (highest value)
            if name.endswith(("manifest.yml", "manifest.yaml", "manifest.json")):
                targets.append(name)
            elif "version" in lower and name.endswith((".h", ".txt", ".json", ".py", ".cmake")):
                targets.append(name)
            elif name.endswith("CMakeLists.txt") and "Source" in name:
                targets.append(name)
            elif name.endswith("package.json"):
                targets.append(name)
            # Key source headers with version defines
            elif name.endswith(".h") and any(
                kw in lower for kw in ["freertos.h", "task.h", "lwipopts.h",
                                        "config.h", "version.h", "conf.h", "init.h"]
            ):
                targets.append(name)
            # Binary libraries
            elif name.endswith((".a", ".lib", ".so", ".elf", ".bin")):
                info = zf.getinfo(name)
                if info.file_size > 1000:
                    targets.append(name)
            # History/changelog (version info)
            elif name.endswith(("History.txt", "CHANGELOG.md", "CHANGES")):
                targets.append(name)

        return targets[:200]
