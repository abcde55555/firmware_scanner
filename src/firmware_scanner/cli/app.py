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

    # RTOS detection
    console.print("[*] Detecting RTOS...")
    rtos_results = RTOSRegistry.detect(context)
    if rtos_results:
        best_plugin, best_confidence = rtos_results[0]
        context.detected_rtos = best_plugin.rtos_name
        context.rtos_confidence = best_confidence
        console.print(f"    RTOS: {best_plugin.rtos_name} ({best_confidence:.0%})")
    else:
        console.print("    RTOS: Unknown")

    # Component extraction (original extractors)
    console.print("[*] Running extraction engines...")
    orchestrator = ExtractionOrchestrator(
        r2_path=config.radare2_path,
        ghidra_path=config.ghidra_path,
        enabled_extractors=config.extractors or None,
        skip_extractors=config.skip_extractors or None,
    )
    components = asyncio.run(orchestrator.run_all(context))
    console.print(f"    Extractors found: {len(components)} hits")

    # Deep scanning (new exhaustive per-section scanner)
    if deep_scan:
        console.print("[*] Deep scanning all sections...")
        comp_db = ComponentDatabase()
        plugin_mgr.enrich_database(comp_db)

        # Progress callback for deep scanner
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

    # Smart analyze each recursively unpacked file
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
    if rtos_results:
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
