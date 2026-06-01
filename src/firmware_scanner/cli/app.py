"""CLI application root using Typer."""

import asyncio
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from ..core.config import AnalysisConfig
from ..core.context import AnalysisContext
from ..core.pipeline import AnalysisPipeline
from ..core.plugin_manager import PluginManager
from ..core.user_config import UserConfig, DependencyChecker, print_dependency_report, init_config
from ..firmware.loader import FirmwareLoader
from ..firmware.unpacker import FirmwareUnpacker
from ..arch.detector import ArchDetector
from ..rtos.registry import RTOSRegistry
from ..extraction.orchestrator import ExtractionOrchestrator
from ..extraction.deep_scanner import DeepScanner, ComponentDatabase
from ..firmware.recursive_unpacker import RecursiveUnpacker
from ..sbom.generator import SBOMGenerator

app = typer.Typer(
    name="firmware-scanner",
    help="Firmware security analysis tool - recursive unpacking, component extraction, and SBOM generation.",
    no_args_is_help=True,
)

console = Console(stderr=True)


@app.command()
def analyze(
    firmware: Path = typer.Argument(..., help="Path to firmware file", exists=True),
    output: Optional[Path] = typer.Option(None, "-o", "--output", help="Output directory or file path"),
    format: Optional[list[str]] = typer.Option(None, "-f", "--format", help="Output formats: sbom,html,json (multiple allowed)"),
    rtos_hint: Optional[str] = typer.Option(None, "--rtos", help="Expected RTOS type"),
    arch_hint: Optional[str] = typer.Option(None, "--arch", help="Expected architecture"),
    extractors: Optional[list[str]] = typer.Option(None, "-e", "--extractor", help="Specific extractors to use"),
    skip_extractors: Optional[list[str]] = typer.Option(None, "--skip-extractor", help="Extractors to skip"),
    r2_path: Optional[str] = typer.Option(None, "--r2-path", help="Path to radare2"),
    ghidra_path: Optional[str] = typer.Option(None, "--ghidra-path", help="Path to Ghidra"),
    plugin_dir: Optional[Path] = typer.Option(None, "--plugin-dir", help="Directory with custom plugins"),
    timeout: int = typer.Option(300, "--timeout", help="Analysis timeout in seconds"),
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Verbose output"),
    deep: bool = typer.Option(True, "--deep/--no-deep", help="Enable deep per-section scanning"),
    android_max_apks: int = typer.Option(200, "--android-max-apks", help="Max APKs to scan in Android images"),
    android_max_libs: int = typer.Option(300, "--android-max-libs", help="Max native libs to scan in Android images"),
    android_tools_dir: Optional[Path] = typer.Option(None, "--android-tools", help="Dir with Android image tools (simg2img, lpunpack)"),
):
    """Perform full firmware analysis and generate reports.

    Output formats (use -f multiple times for multiple outputs):
      sbom  - CycloneDX 1.5 JSON SBOM
      html  - Standalone HTML report
      json  - Raw JSON analysis data
      all   - All formats at once

    If -o is a directory, files are named automatically.
    If -o is a file path, format is inferred from extension.
    """
    config = AnalysisConfig(
        radare2_path=r2_path or "r2",
        ghidra_path=ghidra_path or "",
        timeout=timeout,
        extractors=extractors or [],
        skip_extractors=skip_extractors or [],
        rtos_hint=rtos_hint or "",
        arch_hint=arch_hint or "",
        verbose=verbose,
        android_max_apks=android_max_apks,
        android_max_libs=android_max_libs,
        android_external_tools_dir=str(android_tools_dir) if android_tools_dir else "",
    )

    context = _run_analysis(firmware, config, plugin_dir=plugin_dir, deep_scan=deep)

    # Determine output formats
    formats = _resolve_formats(format, output)

    # Generate outputs
    _export_results(context, formats, output, firmware)

    if verbose:
        _print_summary(context)


@app.command()
def unpack(
    firmware: Path = typer.Argument(..., help="Path to firmware file", exists=True),
    output_dir: Path = typer.Option("./unpacked", "-o", "--output-dir", help="Output directory"),
    verbose: bool = typer.Option(False, "-v", "--verbose"),
):
    """Unpack firmware into constituent sections."""
    config = AnalysisConfig(verbose=verbose)
    loader = FirmwareLoader(config)
    unpacker = FirmwareUnpacker()

    console.print("[*] Loading firmware...")
    data, sha256, md5 = loader.load(firmware)
    console.print("[*] Detecting format...")
    result, format_name = unpacker.unpack(data, firmware)

    console.print(f"[bold]Format:[/bold] {format_name}")
    console.print(f"[bold]Sections:[/bold] {len(result.sections)}")

    if result.entry_point:
        console.print(f"[bold]Entry point:[/bold] {result.entry_point:#010x}")

    output_dir.mkdir(parents=True, exist_ok=True)
    for section in result.sections:
        section_path = output_dir / f"{section.name}.bin"
        section_path.write_bytes(section.data)
        console.print(
            f"  [{section.section_type}] {section.name}: "
            f"{section.size} bytes @ {section.offset:#x} -> {section_path}"
        )

    console.print(f"\n[green]Unpacked {len(result.sections)} sections to {output_dir}[/green]")


@app.command()
def detect(
    firmware: Path = typer.Argument(..., help="Path to firmware file", exists=True),
    verbose: bool = typer.Option(False, "-v", "--verbose"),
):
    """Detect architecture and RTOS type."""
    config = AnalysisConfig(verbose=verbose)
    loader = FirmwareLoader(config)
    data, sha256, md5 = loader.load(firmware)

    # Architecture detection
    arch_detector = ArchDetector()
    arch_info = arch_detector.detect(data)

    # RTOS detection
    context = AnalysisContext(
        firmware_path=firmware,
        raw_data=data,
        arch_info=arch_info,
    )

    # Extract symbols if ELF for RTOS detection
    if data[:4] == b"\x7fELF":
        try:
            import lief
            binary = lief.parse(list(data))
            if binary and hasattr(binary, "symbols"):
                context.elf_symbols = [s.name for s in binary.symbols if s.name]
        except Exception:
            pass

    rtos_results = RTOSRegistry.detect(context)

    # Display results
    table = Table(title="Firmware Analysis Results")
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="green")
    table.add_column("Confidence", style="yellow")

    table.add_row("File", str(firmware.name), "")
    table.add_row("Size", f"{len(data):,} bytes", "")
    table.add_row("SHA-256", sha256[:16] + "...", "")
    table.add_row("CPU Family", arch_info.cpu_family.value, f"{arch_info.confidence:.0%}")
    table.add_row("Endianness", arch_info.endianness.value, "")
    table.add_row("Word Size", f"{arch_info.word_size}-bit", "")
    table.add_row("File Type", arch_info.file_type.value, "")

    if arch_info.specific_model:
        table.add_row("Specific Model", arch_info.specific_model, "")

    if rtos_results:
        for plugin, confidence in rtos_results[:3]:
            table.add_row("Detected RTOS", plugin.rtos_name, f"{confidence:.0%}")
    else:
        table.add_row("Detected RTOS", "Unknown", "0%")

    console.print(table)


@app.command()
def plugins():
    """List available analysis plugins and extractors."""
    table = Table(title="Available RTOS Plugins")
    table.add_column("RTOS", style="cyan")
    table.add_column("Vendor", style="green")
    table.add_column("Status", style="yellow")

    for plugin_cls in RTOSRegistry.get_all():
        plugin = plugin_cls()
        table.add_row(plugin.rtos_name, plugin.vendor, "active")

    console.print(table)

    # Extractors
    ext_table = Table(title="Available Extractors")
    ext_table.add_column("Extractor", style="cyan")
    ext_table.add_column("Available", style="green")
    ext_table.add_column("Priority", style="yellow")

    from ..extraction.extractors.string_patterns import StringPatternExtractor
    from ..extraction.extractors.symbol_table import SymbolTableExtractor
    from ..extraction.extractors.disassembly import DisassemblyExtractor
    from ..extraction.extractors.binary_signatures import BinarySignatureExtractor
    from ..extraction.extractors.radare2_ext import Radare2Extractor
    from ..extraction.extractors.ghidra_ext import GhidraExtractor

    all_ext = [
        StringPatternExtractor(),
        SymbolTableExtractor(),
        DisassemblyExtractor(),
        BinarySignatureExtractor(),
        Radare2Extractor(),
        GhidraExtractor(),
    ]

    for ext in all_ext:
        available = "[green]Yes[/green]" if ext.is_available() else "[red]No[/red]"
        ext_table.add_row(ext.name, available, str(ext.priority))

    console.print(ext_table)


@app.command(name="check-deps")
def check_deps():
    """Check availability of all dependencies and show status."""
    checker = DependencyChecker()
    results = checker.check_all()
    report = print_dependency_report(results)
    console.print(report)


@app.command(name="init")
def init_command():
    """Initialize configuration file with default settings."""
    config = init_config()
    console.print(f"Config file created at: {config.config_path}")
    console.print("Edit this file to configure tool paths (leave empty to skip):")
    console.print(f"  radare2_path: path to r2 binary")
    console.print(f"  ghidra_path: path to Ghidra installation directory")
    console.print(f"  binwalk_path: path to binwalk binary")
    console.print("")
    console.print("Running dependency check...")
    checker = DependencyChecker()
    results = checker.check_all()
    report = print_dependency_report(results)
    console.print(report)


def _resolve_formats(format_list: list[str] | None, output: Path | None) -> list[str]:
    """Determine which output formats to generate."""
    if format_list:
        formats = []
        for f in format_list:
            for part in f.split(","):
                part = part.strip().lower()
                if part == "all":
                    return ["sbom", "html", "json"]
                if part in ("sbom", "cyclonedx"):
                    formats.append("sbom")
                elif part in ("html", "report"):
                    formats.append("html")
                elif part == "json":
                    formats.append("json")
        return formats if formats else ["sbom"]

    # Infer from output file extension
    if output:
        suffix = output.suffix.lower()
        if suffix == ".html":
            return ["html"]
        elif suffix == ".json":
            return ["sbom"]
        # If output is a directory, default to all
        if output.is_dir() or not suffix:
            return ["sbom"]
    return ["sbom"]


def _export_results(context: AnalysisContext, formats: list[str], output: Path | None, firmware: Path) -> None:
    """Export analysis results in requested formats."""
    from ..sbom.html_report import generate_html_report

    base_name = firmware.stem

    # If output is a directory, generate files there
    if output and output.suffix == "" and len(formats) > 1:
        output.mkdir(parents=True, exist_ok=True)

    for fmt in formats:
        if fmt == "sbom":
            sbom_content = SBOMGenerator().generate(context)
            if output and len(formats) > 1:
                out_path = (output / f"{base_name}_sbom.json") if output.is_dir() else output.with_suffix(".json")
            elif output:
                out_path = output
            else:
                print(sbom_content)
                continue
            out_path.write_text(sbom_content, encoding="utf-8")
            console.print(f"[green]SBOM written to {out_path}[/green]")

        elif fmt == "html":
            html_content = generate_html_report(context)
            if output and len(formats) > 1:
                out_path = (output / f"{base_name}_report.html") if output.is_dir() else output.with_suffix(".html")
            elif output:
                out_path = output
            else:
                console.print(html_content)
                continue
            out_path.write_text(html_content, encoding="utf-8")
            console.print(f"[green]HTML report written to {out_path}[/green]")

        elif fmt == "json":
            _output_json_report(context, output if len(formats) == 1 else
                               ((output / f"{base_name}_analysis.json") if output and output.is_dir() else
                                (output.with_suffix(".analysis.json") if output else None)))


def _run_analysis(
    firmware: Path,
    config: AnalysisConfig,
    plugin_dir: Path | None = None,
    deep_scan: bool = True,
) -> AnalysisContext:
    """Run the full analysis pipeline."""
    loader = FirmwareLoader(config)
    unpacker = FirmwareUnpacker()
    arch_detector = ArchDetector()

    # Initialize plugin manager
    plugin_mgr = PluginManager()
    if plugin_dir:
        plugin_mgr.add_plugin_dir(plugin_dir)
        plugin_mgr.load_plugins()
        loaded = plugin_mgr.get_loaded_plugins()
        if loaded:
            console.print(f"[*] Loaded {len(loaded)} plugins from {plugin_dir}")

    # Load
    console.print("[*] Loading firmware...")
    data, sha256, md5 = loader.load(firmware)
    console.print(f"    Size: {len(data):,} bytes")

    context = AnalysisContext(
        firmware_path=firmware,
        raw_data=data,
        file_hash_sha256=sha256,
        file_hash_md5=md5,
    )

    # Unpack
    console.print("[*] Unpacking firmware...")
    result, format_name = unpacker.unpack(data, firmware)
    context.unpack_result = result
    context.metadata["format"] = format_name
    console.print(f"    Format: {format_name}")
    if result.sections:
        console.print(f"    Sections: {len(result.sections)}")

    # Determine if this is an Android system image
    is_android_system = format_name in (
        "Android System Image", "Android OTA Payload", "Android Block OTA"
    )

    # OS / RTOS detection
    if is_android_system:
        console.print("[*] Detecting OS type...")
        console.print("    OS: Android (identified from image format)")
        context.detected_rtos = "Android"
        context.rtos_confidence = 0.98
        context.metadata["os_type"] = "android"
    else:
        # Arch detection
        console.print("[*] Detecting architecture...")
        arch_info = arch_detector.detect(data)
        context.arch_info = arch_info
        console.print(f"    Arch: {arch_info.cpu_family.value} {arch_info.endianness.value}-endian")

        # Symbol extraction for ELF
        if data[:4] == b"\x7fELF":
            try:
                import lief
                binary = lief.parse(list(data))
                if binary and hasattr(binary, "symbols"):
                    context.elf_symbols = [s.name for s in binary.symbols if s.name]
                    console.print(f"    ELF symbols: {len(context.elf_symbols)}")
            except Exception:
                pass

        # RTOS detection (only for non-Android images)
        console.print("[*] Detecting RTOS...")
        rtos_results = RTOSRegistry.detect(context)
        if rtos_results:
            best_plugin, best_confidence = rtos_results[0]
            context.detected_rtos = best_plugin.rtos_name
            context.rtos_confidence = best_confidence
            console.print(f"    RTOS: {best_plugin.rtos_name} ({best_confidence:.0%})")
        else:
            console.print("    RTOS: Unknown")

    # =========================================================================
    # Android-specific scanning path
    # =========================================================================
    components: list = []

    if is_android_system:
        console.print("[*] Running Android system scan...")
        android_components = _run_android_system_scan(data, result, config, context)
        components.extend(android_components)
        console.print(f"    Android scan found: {len(android_components)} components")

        # Also scan each unpacked section individually
        if result.sections:
            console.print(f"[*] Scanning {len(result.sections)} extracted sections individually...")
            from ..extraction.smart_analyzer import SmartSectionAnalyzer
            smart = SmartSectionAnalyzer()
            section_components = []
            for i, section in enumerate(result.sections):
                if len(section.data) > 16:
                    try:
                        found = smart.analyze_section(section.name, section.data)
                        section_components.extend(found)
                    except Exception:
                        pass
                    # For APK sections, also do APK-specific analysis
                    if section.section_type == "apk" or section.name.lower().endswith('.apk'):
                        apk_comps = _scan_apk_section(section.name, section.data)
                        section_components.extend(apk_comps)
                if config.verbose and (i + 1) % 50 == 0:
                    console.print(f"    ... scanned {i + 1}/{len(result.sections)} sections")
            console.print(f"    Section scan found: {len(section_components)} components")
            components.extend(section_components)

        # Raw binary scan: find APKs and build.prop in the raw image data
        console.print("[*] Scanning raw image data for embedded files...")
        raw_components = _scan_raw_android_image(data, config)
        if raw_components:
            console.print(f"    Raw scan found: {len(raw_components)} components")
            components.extend(raw_components)

    # =========================================================================
    # Standard firmware scanning path (also runs for Android as supplementary)
    # =========================================================================
    else:
        # Component extraction (original extractors)
        console.print("[*] Running extraction engines...")
        orchestrator = ExtractionOrchestrator(
            r2_path=config.radare2_path,
            ghidra_path=config.ghidra_path,
            enabled_extractors=config.extractors or None,
            skip_extractors=config.skip_extractors or None,
        )
        ext_components = asyncio.run(orchestrator.run_all(context))
        console.print(f"    Extractors found: {len(ext_components)} hits")
        components.extend(ext_components)

        # Deep scanning (new exhaustive per-section scanner)
        if deep_scan:
            console.print("[*] Deep scanning all sections...")
            comp_db = ComponentDatabase()
            plugin_mgr.enrich_database(comp_db)

            def _deep_progress(done: int, total: int, detail: str) -> None:
                if total > 1:
                    pct = done / total * 100
                    bar_w = 30
                    filled = int(bar_w * done / total)
                    bar = "#" * filled + "-" * (bar_w - filled)
                    sys.stderr.write(f"\r    [{bar}] {pct:5.1f}% ({done}/{total}) {detail[:40]}")
                    sys.stderr.flush()
                    if done >= total:
                        sys.stderr.write("\n")
                        sys.stderr.flush()

            deep_scanner = DeepScanner(
                comp_db,
                max_threads=config.max_threads if hasattr(config, 'max_threads') else 4,
                progress_callback=_deep_progress,
            )
            deep_components = deep_scanner.scan(context)
            console.print(f"    Deep scan found: {len(deep_components)} components")
            components.extend(deep_components)

        # Recursive unpacking + smart analysis
        console.print("[*] Recursive unpacking & smart analysis...")
        from ..extraction.smart_analyzer import SmartSectionAnalyzer
        recursive = RecursiveUnpacker(max_depth=3)
        recursive.unpack(data, firmware.name)
        all_files = recursive.get_all_files()
        summary = recursive.get_summary()
        console.print(f"    Recursively unpacked: {summary['total_files']} files (max depth {summary['max_depth']})")

        smart = SmartSectionAnalyzer()
        smart_components = []
        for uf in all_files:
            if len(uf.data) > 16:
                try:
                    smart_components.extend(smart.analyze_section(uf.name, uf.data))
                except Exception:
                    pass
        if smart_components:
            console.print(f"    Smart analyzer found: {len(smart_components)} components")
            components.extend(smart_components)

        # RTOS plugin analysis
        if not is_android_system and rtos_results:
            best_plugin, _ = rtos_results[0]
            try:
                rtos_components = asyncio.run(best_plugin.analyze(context))
                components.extend(rtos_components)
            except Exception:
                pass

    # Plugin analysis
    if plugin_mgr.get_loaded_plugins():
        console.print("[*] Running plugin analysis...")
        plugin_components = asyncio.run(plugin_mgr.run_all_plugins(context))
        components.extend(plugin_components)

    context.components = _deduplicate_components(components)
    console.print(f"[+] Total unique components: {len(context.components)}")

    return context


def _scan_apk_section(name: str, data: bytes) -> list:
    """Scan an APK (ZIP) section to extract manifest info."""
    from ..android.axml import AXMLParser
    from ..extraction.models import Component, VersionConfidence, ExtractionMethod
    import zipfile
    import io

    if data[:2] != b'PK':
        return []

    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except Exception:
        return []

    components = []
    axml_parser = AXMLParser()

    # Extract AndroidManifest.xml
    try:
        if 'AndroidManifest.xml' in zf.namelist():
            manifest_data = zf.read('AndroidManifest.xml')
            info = axml_parser.get_manifest_info(manifest_data)
            if info.package_name:
                version = info.version_name or (str(info.version_code) if info.version_code else "")
                confidence = 0.95 if version else 0.80
                components.append(Component(
                    name=info.package_name,
                    component_type="application",
                    resolved_version=version,
                    versions=[VersionConfidence(
                        version=version if version else "detected",
                        confidence=confidence,
                        method=ExtractionMethod.MANIFEST_BINARY,
                        evidence=f"AndroidManifest.xml in {name}",
                    )],
                    purl=f"pkg:apk/{info.package_name}@{version}" if version else "",
                    description=f"targetSdk={info.target_sdk_version}" if info.target_sdk_version else "",
                ))
    except Exception:
        pass

    # Also scan .so files inside the APK
    try:
        for entry in zf.namelist():
            if entry.endswith('.so') and 'lib/' in entry:
                so_data = zf.read(entry)
                if so_data and so_data[:4] == b'\x7fELF':
                    from ..extraction.smart_analyzer import SmartSectionAnalyzer
                    analyzer = SmartSectionAnalyzer()
                    so_comps = analyzer.analyze_section(f"{name}/{entry}", so_data)
                    components.extend(so_comps)
    except Exception:
        pass

    try:
        zf.close()
    except Exception:
        pass

    return components


def _scan_raw_android_image(data: bytes, config: AnalysisConfig) -> list:
    """Scan raw image binary data to find embedded APKs, build.prop, and ELFs.

    This is a fallback for when filesystem readers fail on the image.
    It searches for known magic bytes and file signatures directly in the raw data.
    """
    from ..extraction.models import Component, VersionConfidence, ExtractionMethod
    from ..android.build_prop import BuildPropParser
    from ..android.axml import AXMLParser
    import zipfile
    import io

    components: list = []
    scanned_apks = 0
    max_apks = config.android_max_apks

    # 1. Scan for build.prop content patterns in raw data
    build_prop_components = _find_build_prop_in_raw(data)
    components.extend(build_prop_components)

    # 2. Find all PK (ZIP/APK) signatures and try to extract APKs
    console.print("    Searching for APK files in raw image...")
    offset = 0
    apk_offsets: list[int] = []

    while offset < len(data) - 4 and scanned_apks < max_apks:
        # Find next PK signature
        pos = data.find(b'PK\x03\x04', offset)
        if pos == -1:
            break

        # Try to open as ZIP
        try:
            # Find end of ZIP by looking for End of Central Directory
            # Search within a reasonable window (up to 100MB from PK start)
            search_end = min(pos + 100 * 1024 * 1024, len(data))
            eocd_pos = data.rfind(b'PK\x05\x06', pos, search_end)

            if eocd_pos != -1 and eocd_pos > pos:
                # EOCD is at least 22 bytes, zip data is from pos to eocd_pos + 22
                zip_end = eocd_pos + 22
                # Check if there's a comment (last 2 bytes of EOCD = comment length)
                if zip_end + 2 <= len(data):
                    comment_len = int.from_bytes(data[eocd_pos + 20:eocd_pos + 22], 'little')
                    zip_end += comment_len

                zip_data = data[pos:min(zip_end, len(data))]

                if len(zip_data) > 100:  # Minimum viable ZIP
                    try:
                        zf = zipfile.ZipFile(io.BytesIO(zip_data))
                        names = zf.namelist()

                        # Check if this is an APK (has AndroidManifest.xml)
                        if 'AndroidManifest.xml' in names:
                            apk_comps = _scan_apk_section(
                                f"raw_offset_{pos:#x}.apk", zip_data
                            )
                            components.extend(apk_comps)
                            scanned_apks += 1
                            offset = zip_end
                            continue

                        zf.close()
                    except Exception:
                        pass

        except Exception:
            pass

        offset = pos + 4  # Move past this PK signature

    if scanned_apks > 0:
        console.print(f"    Found and scanned {scanned_apks} APK files in raw image")

    # 3. Find ELF binaries and scan them
    elf_count = 0
    max_elfs = config.android_max_libs
    offset = 0

    while offset < len(data) - 16 and elf_count < max_elfs:
        pos = data.find(b'\x7fELF', offset)
        if pos == -1:
            break

        # Try to determine ELF size from header
        if pos + 64 <= len(data):
            # Read e_shoff (section header offset) + e_shnum * e_shentsize for approximate size
            ei_class = data[pos + 4]  # 1=32bit, 2=64bit
            if ei_class == 2 and pos + 64 <= len(data):
                import struct
                try:
                    e_shoff = struct.unpack_from('<Q', data, pos + 40)[0]
                    e_shnum = struct.unpack_from('<H', data, pos + 60)[0]
                    e_shentsize = struct.unpack_from('<H', data, pos + 58)[0]
                    elf_size = e_shoff + e_shnum * e_shentsize
                    if 100 < elf_size < 50 * 1024 * 1024:  # Reasonable ELF size
                        elf_data = data[pos:pos + elf_size]
                        from ..extraction.smart_analyzer import SmartSectionAnalyzer
                        analyzer = SmartSectionAnalyzer()
                        elf_comps = analyzer.analyze_section(
                            f"elf_{pos:#x}.so", elf_data
                        )
                        if elf_comps:
                            components.extend(elf_comps)
                        elf_count += 1
                        offset = pos + elf_size
                        continue
                except Exception:
                    pass
            elif ei_class == 1 and pos + 52 <= len(data):
                import struct
                try:
                    e_shoff = struct.unpack_from('<I', data, pos + 32)[0]
                    e_shnum = struct.unpack_from('<H', data, pos + 48)[0]
                    e_shentsize = struct.unpack_from('<H', data, pos + 46)[0]
                    elf_size = e_shoff + e_shnum * e_shentsize
                    if 100 < elf_size < 50 * 1024 * 1024:
                        elf_data = data[pos:pos + elf_size]
                        from ..extraction.smart_analyzer import SmartSectionAnalyzer
                        analyzer = SmartSectionAnalyzer()
                        elf_comps = analyzer.analyze_section(
                            f"elf_{pos:#x}.so", elf_data
                        )
                        if elf_comps:
                            components.extend(elf_comps)
                        elf_count += 1
                        offset = pos + elf_size
                        continue
                except Exception:
                    pass

        offset = pos + 4

    if elf_count > 0:
        console.print(f"    Found and scanned {elf_count} ELF binaries in raw image")

    return components


def _find_build_prop_in_raw(data: bytes) -> list:
    """Search raw image data for build.prop content patterns."""
    from ..android.build_prop import BuildPropParser
    from ..extraction.models import Component

    components: list = []

    # Search for the distinctive ro.build.fingerprint pattern
    markers = [
        b'ro.build.version.release=',
        b'ro.build.fingerprint=',
        b'ro.build.version.security_patch=',
    ]

    for marker in markers:
        pos = data.find(marker)
        if pos == -1:
            continue

        # Found a build.prop-like region. Extract surrounding text block.
        # Go back to find the start (look for non-text or null)
        start = max(0, pos - 4096)
        # Find actual start of properties block
        for i in range(pos, start, -1):
            if data[i:i+1] == b'\x00' or data[i:i+1] == b'\xff':
                start = i + 1
                break

        # Find end of properties block
        end = min(len(data), pos + 8192)
        for i in range(pos + len(marker), end):
            # Properties end when we hit a run of null bytes
            if data[i:i+4] == b'\x00\x00\x00\x00':
                end = i
                break

        prop_data = data[start:end]

        # Parse it
        parser = BuildPropParser()
        info = parser.parse(prop_data)
        if info.android_version:
            components.extend(parser.to_components(info))
            break  # Only need one build.prop

    return components


def _run_android_system_scan(data: bytes, unpack_result, config: AnalysisConfig, context: AnalysisContext) -> list:
    """Run Android-specific filesystem scanning when an Android system image is detected."""
    import struct
    from ..android.sparse import SparseImageParser
    from ..android.ext4_reader import Ext4Reader
    from ..android.erofs_reader import ErofsReader
    from ..android.system_scanner import AndroidSystemScanner

    raw_data = data

    # Convert sparse to raw if needed
    if len(data) >= 4 and struct.unpack_from('<I', data, 0)[0] == 0xED26FF3A:
        console.print("    Converting sparse image to raw...")
        sparse_parser = SparseImageParser()
        raw_size = sparse_parser.get_raw_size(data)
        if 0 < raw_size < 2 * 1024 * 1024 * 1024:
            converted = sparse_parser.to_raw(data)
            if converted:
                raw_data = converted
                console.print(f"    Sparse -> raw: {len(raw_data):,} bytes")

    # Try ext4 filesystem scan
    if len(raw_data) > 0x43A and raw_data[0x438:0x43A] == b'\x53\xEF':
        console.print("    Attempting ext4 filesystem scan...")
        reader = Ext4Reader(raw_data)
        if reader.is_valid():
            try:
                scanner = AndroidSystemScanner(
                    reader,
                    max_apks=config.android_max_apks,
                    max_libs=config.android_max_libs,
                )
                result = scanner.scan()
                if result.components:
                    _store_android_build_info(context, result)
                    console.print(f"    ext4 scan: {result.apk_count} APKs, {result.lib_count} libs")
                    return result.components
                else:
                    console.print("    ext4 reader valid but no files found - will use raw scan fallback")
            except Exception as e:
                console.print(f"    ext4 scan failed: {e} - will use raw scan fallback")
        else:
            console.print("    ext4 superblock found but reader validation failed - will use raw scan fallback")

    # Try EROFS filesystem scan
    if len(raw_data) > 0x404 and struct.unpack_from('<I', raw_data, 0x400)[0] == 0xE0F5E1E2:
        console.print("    Attempting EROFS filesystem scan...")
        reader = ErofsReader(raw_data)
        if reader.is_valid():
            try:
                scanner = AndroidSystemScanner(
                    reader,
                    max_apks=config.android_max_apks,
                    max_libs=config.android_max_libs,
                )
                result = scanner.scan()
                if result.components:
                    _store_android_build_info(context, result)
                    console.print(f"    EROFS scan: {result.apk_count} APKs, {result.lib_count} libs")
                    return result.components
                else:
                    console.print("    EROFS reader valid but no files found - will use raw scan fallback")
            except Exception as e:
                console.print(f"    EROFS scan failed: {e} - will use raw scan fallback")
        else:
            console.print("    EROFS magic found but reader validation failed - will use raw scan fallback")

    # Filesystem scan didn't work - components will come from raw binary scan
    console.print("    Filesystem-level scan unavailable; raw binary scan will identify components")
    return []


def _store_android_build_info(context: AnalysisContext, result) -> None:
    """Store Android build info in context metadata."""
    context.metadata["android_build_info"] = {
        "version": result.build_info.android_version,
        "security_patch": result.build_info.security_patch,
        "manufacturer": result.build_info.manufacturer,
        "model": result.build_info.model,
        "build_fingerprint": result.build_info.build_fingerprint,
    }


def _deduplicate_components(components: list) -> list:
    """Final deduplication and filtering pass."""
    seen: dict[str, any] = {}
    for comp in components:
        key = comp.name.lower().replace(" ", "").replace("-", "").replace("/", "")
        if key not in seen:
            seen[key] = comp
        else:
            existing = seen[key]
            existing.versions.extend(comp.versions)
            if comp.resolved_version and not existing.resolved_version.replace("detected", ""):
                existing.resolved_version = comp.resolved_version
            if comp.purl and not existing.purl:
                existing.purl = comp.purl
            if comp.vendor and not existing.vendor:
                existing.vendor = comp.vendor

    # Filter out low-confidence components with no vendor and short names (likely false positives)
    filtered = {}
    for key, comp in seen.items():
        max_conf = max((v.confidence for v in comp.versions), default=0)
        methods = set(v.method.value for v in comp.versions)
        # Keep if: has vendor, or high confidence, or detected by multiple methods
        if comp.vendor or max_conf >= 0.4 or len(methods) >= 2:
            filtered[key] = comp

    return list(filtered.values())


def _output_json_report(context: AnalysisContext, output: Optional[Path]):
    """Output full analysis as JSON (not SBOM format)."""
    import json

    report = {
        "firmware": {
            "path": str(context.firmware_path),
            "sha256": context.file_hash_sha256,
            "md5": context.file_hash_md5,
            "size": len(context.raw_data),
            "format": context.metadata.get("format", "unknown"),
        },
        "architecture": context.arch_info.model_dump() if context.arch_info else None,
        "rtos": {
            "name": context.detected_rtos,
            "confidence": context.rtos_confidence,
        },
        "components": [c.model_dump() for c in context.components],
        "warnings": context.warnings,
        "errors": [e.model_dump() for e in context.errors],
    }

    json_str = json.dumps(report, indent=2, default=str)
    if output:
        output.write_text(json_str)
        console.print(f"[green]Report written to {output}[/green]")
    else:
        console.print(json_str)


def _print_summary(context: AnalysisContext):
    """Print analysis summary table."""
    console.print()

    if context.components:
        table = Table(title="Detected Components")
        table.add_column("Component", style="cyan")
        table.add_column("Version", style="green")
        table.add_column("Type", style="blue")
        table.add_column("Vendor", style="magenta")
        table.add_column("Methods", style="yellow")

        for comp in context.components:
            methods = ", ".join(sorted(set(v.method.value for v in comp.versions)))
            table.add_row(
                comp.name,
                comp.resolved_version,
                comp.component_type,
                comp.vendor,
                methods,
            )

        console.print(table)

    if context.warnings:
        console.print(Panel("\n".join(context.warnings[:5]), title="Warnings", style="yellow"))

    if context.errors:
        for err in context.errors:
            console.print(f"[red]Error in {err.stage}: {err.message}[/red]")


def main():
    app()
