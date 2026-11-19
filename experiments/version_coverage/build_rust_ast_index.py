"""Collect bounded Rust source references and build a zero-compilation AST site index."""
from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import importlib.util
import io
import json
import sys
import tarfile
from pathlib import Path, PurePosixPath

DEFAULT_LOCATIONS = Path("reports/version-corpus-20261118/rust-locations-validated-context.json")
DEFAULT_SOURCES = Path("reports/version-corpus-20261118/rust-ast-sources")
DEFAULT_INDEX = Path("reports/version-corpus-20261118/rust-ast-index.json")
DEPENDENCIES = Path("reports/version-corpus-20261118/rust-ast-dependencies")
DEFAULT_PIN = "c991cad10330f37e93d82926bd6dae7f4f6647f6"
MAX_BATCH_SIZE = 10
MAX_DOWNLOAD_BUDGET = 256 * 1024 * 1024
MAX_SOURCE_BYTES = 2 * 1024 * 1024
MAX_ARCHIVE_BYTES = 32 * 1024 * 1024
ARITHMETIC_OPERATORS = {"+": "add", "-": "sub", "*": "mul", "/": "div", "%": "rem",
                        "<<": "shl", ">>": "shr", "&": "bitand", "|": "bitor", "^": "bitxor"}
PANIC_MACROS = {
    "panic", "assert", "assert_eq", "assert_ne", "debug_assert", "debug_assert_eq",
    "debug_assert_ne", "unreachable", "unimplemented", "todo",
}


def _load_parser():
    dependency_path = str(DEPENDENCIES.resolve())
    if dependency_path not in sys.path:
        sys.path.insert(0, dependency_path)
    import tree_sitter
    import tree_sitter_rust
    from tree_sitter import Language, Parser

    language = Language(tree_sitter_rust.language())
    return Parser(language), tree_sitter, tree_sitter_rust


def validate_source_file(path: str) -> str:
    if not isinstance(path, str) or not path or "\\" in path or "\x00" in path:
        raise ValueError(f"invalid Rust source path: {path!r}")
    pure = PurePosixPath(path)
    if pure.is_absolute() or pure.as_posix() != path or any(part in ("", ".", "..") for part in path.split("/")):
        raise ValueError(f"invalid Rust source path: {path!r}")
    if pure.suffix != ".rs":
        raise ValueError(f"invalid Rust source path: {path!r}")
    return path


def parse_source(source: bytes):
    if len(source) > MAX_SOURCE_BYTES:
        raise ValueError("Rust source exceeds AST parse budget")
    parser, _, _ = _load_parser()
    tree = parser.parse(source)
    return tree, tree.root_node.has_error


def _node_line_column(source: bytes, node) -> tuple[int, int]:
    row, _byte_column = node.start_point
    line_start = source.rfind(b"\n", 0, node.start_byte) + 1
    prefix = source[line_start:node.start_byte]
    column = len(prefix.decode("utf-8", errors="replace")) + 1
    return row + 1, column


def _macro_name(node) -> str | None:
    macro = node.child_by_field_name("macro")
    if macro is None:
        return None
    return macro.text.decode("utf-8", errors="replace").split("::")[-1]


def _call_kind(node) -> str | None:
    function = node.child_by_field_name("function")
    if function is None or function.type != "field_expression":
        return None
    field = function.child_by_field_name("field")
    if field is None:
        return None
    name = field.text.decode("utf-8", errors="replace")
    return f"{name}_call" if name in {"unwrap", "expect"} else None


def index_source(file: str, source: bytes) -> list[dict]:
    validate_source_file(file)
    tree, _ = parse_source(source)
    sites = []

    pending = [tree.root_node]
    while pending:
        node = pending.pop()
        if node.type == "ERROR":
            continue
        kind = None
        if node.type == "macro_invocation":
            name = _macro_name(node)
            if name in PANIC_MACROS:
                kind = f"{name}_macro"
        elif node.type == "call_expression":
            kind = _call_kind(node)
        elif node.type == "index_expression":
            kind = "index_expression"
        elif node.type == "binary_expression":
            operator = next((child.type for child in node.children if child.type in ARITHMETIC_OPERATORS), None)
            if operator:
                kind = f"arithmetic_{ARITHMETIC_OPERATORS[operator]}"
        if kind and not node.has_error:
            line, column = _node_line_column(source, node)
            sites.append({"file": file, "line": line, "column": column, "kind": kind})
        pending.extend(reversed(node.children))
    return sorted(sites, key=lambda row: (row["file"], row["line"], row["column"], row["kind"]))


def eligible_locations(path: Path) -> dict[str, set[str]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    locations: dict[str, set[str]] = {}
    for row in data.get("rows", []):
        for location in row.get("locations", []):
            crate = location.get("crate")
            if not (isinstance(crate, str) and location.get("code_references")
                    and location.get("corroborated_calls")):
                continue
            source_file = validate_source_file(location.get("source_file"))
            locations.setdefault(crate, set()).add(source_file)
    return locations


def _grammar_record() -> dict:
    _load_parser()
    from tree_sitter_rust import _binding

    binding = Path(_binding.__file__)
    return {
        "runtime": {"name": "tree-sitter", "version": importlib.metadata.version("tree-sitter")},
        "grammar": {"name": "tree-sitter-rust", "version": importlib.metadata.version("tree-sitter-rust"),
                    "sha256": hashlib.sha256(binding.read_bytes()).hexdigest()},
        "parser": "tree-sitter Python bindings",
    }


def _reference_archive(corpus_path, package, record):
    path = corpus_path.parent / ".cache" / "crates" / f"{package}-{record['version']}.crate"
    with path.open("rb") as handle:
        raw = handle.read(MAX_ARCHIVE_BYTES + 1)
    if len(raw) > MAX_ARCHIVE_BYTES:
        raise ValueError("Rust archive exceeds verification budget")
    digest = hashlib.sha256(raw).hexdigest()
    if digest != record.get("archive_sha256") or digest != record.get("index_checksum"):
        raise ValueError("Rust archive disagrees with registry checksum")
    return tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz")


def build_index(corpus_path: Path, output_path: Path) -> dict:
    corpus = json.loads(corpus_path.read_text(encoding="utf-8"))
    families = []
    source_hashes = {}
    parse_errors = []
    for crate_record in sorted(corpus.get("crates", []), key=lambda row: row.get("package_name") or row.get("crate_path", "")):
        package_name = crate_record.get("package_name")
        prior_version = crate_record.get("declared_version")
        if not package_name or not prior_version:
            continue
        family = {
            "crate": package_name,
            "prior_version": prior_version,
            "prior_source": crate_record["manifest"]["url"],
            "prior_source_files": {},
            "releases": [],
            "collection_errors": list(crate_record.get("errors", [])),
        }
        for file, record in sorted(crate_record.get("pinned_files", {}).items()):
            validate_source_file(file)
            source_path = corpus_path.parent / record["path"]
            content = source_path.read_bytes()
            digest = hashlib.sha256(content).hexdigest()
            if digest != record.get("sha256"):
                raise ValueError(f"pinned source hash mismatch: {source_path}")
            family["prior_source_files"][file] = digest
        for version_record in sorted(crate_record.get("versions", []), key=lambda row: row.get("version", "")):
            if not version_record.get("files"):
                continue
            release = {
                "version": version_record["version"],
                "source": version_record["archive_url"],
                "source_sha256": version_record.get("archive_sha256"),
                "source_file_hashes": {},
                "sites": [],
                "source_errors": list(version_record.get("errors", [])),
                "missing_files": list(version_record.get("missing_files", [])),
            }
            with _reference_archive(corpus_path, package_name, version_record) as archive:
                for file, file_record in sorted(version_record.get("files", {}).items()):
                    validate_source_file(file)
                    source_path = corpus_path.parent / file_record["path"]
                    with source_path.open("rb") as handle:
                        content = handle.read(MAX_SOURCE_BYTES + 1)
                    if len(content) > MAX_SOURCE_BYTES:
                        raise ValueError("Rust source exceeds AST parse budget")
                    digest = hashlib.sha256(content).hexdigest()
                    if digest != file_record.get("sha256"):
                        raise ValueError(f"release source hash mismatch: {source_path}")
                    member = archive.getmember(f"{package_name}-{version_record['version']}/{file}")
                    if not member.isfile() or member.size != len(content):
                        raise ValueError("Rust source differs from official archive member")
                    with archive.extractfile(member) as handle:
                        if handle.read(MAX_SOURCE_BYTES + 1) != content:
                            raise ValueError("Rust source differs from official archive member")
                    release["source_file_hashes"][file] = digest
                    source_hashes[f"{package_name}/{version_record['version']}/{file}"] = digest
                    sites = index_source(file, content)
                    release["sites"].extend(sites)
                    _, has_error = parse_source(content)
                    if has_error:
                        parse_errors.append({"crate": package_name, "version": version_record["version"], "file": file})
            release["sites"].sort(key=lambda row: (row["file"], row["line"], row["column"], row["kind"]))
            family["releases"].append(release)
        families.append(family)
    result = {
        "schema_version": 1,
        "families": families,
        "grammar": _grammar_record(),
        "source_file_hashes_sha256": hashlib.sha256(
            json.dumps(source_hashes, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
        "parse_errors": parse_errors,
        "warning": "AST source sites are reference candidates; they do not establish binary-exact versions.",
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


def collect_batches(locations_path: Path, sources_dir: Path, crates: list[str] | None, *,
                    pin: str, batch_size: int, total_budget_mib: int) -> Path:
    if not 1 <= batch_size <= MAX_BATCH_SIZE:
        raise ValueError(f"batch size must be 1-{MAX_BATCH_SIZE}")
    budget = total_budget_mib * 1024 * 1024
    if not 1 <= budget <= MAX_DOWNLOAD_BUDGET:
        raise ValueError("download budget must be between 1 MiB and 256 MiB")
    locations = eligible_locations(locations_path)
    selected = sorted(set(crates) if crates else locations)
    unknown = sorted(set(selected) - locations.keys())
    if unknown:
        raise ValueError(f"crates lack eligible corroborated locations: {', '.join(unknown)}")
    collector_path = Path(__file__).with_name("collect_rust_sources.py")
    spec = importlib.util.spec_from_file_location("collect_rust_sources_for_ast", collector_path)
    collector = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(collector)
    for offset in range(0, len(selected), batch_size):
        batch = selected[offset:offset + batch_size]
        corpus = collector.collect_from_locations(
            locations, batch, sources_dir, radius=2, pin=pin, total_budget=budget,
        )
        state = corpus.get("download_budget", {})
        print(f"batch {offset // batch_size + 1}: {len(batch)} crates; "
              f"downloaded {state.get('used_bytes', 0)} / {state.get('limit_bytes', budget)} bytes",
              file=sys.stderr)
    return sources_dir / "corpus.json"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--locations", type=Path, default=DEFAULT_LOCATIONS)
    parser.add_argument("--sources-dir", type=Path, default=DEFAULT_SOURCES)
    parser.add_argument("--index-output", type=Path, default=DEFAULT_INDEX)
    parser.add_argument("--collect", action="store_true", help="collect Android pin and nearby official crate releases")
    parser.add_argument("--crates", help="optional comma-separated actual crate paths for a bounded pilot")
    parser.add_argument("--pin", default=DEFAULT_PIN)
    parser.add_argument("--batch-size", type=int, default=MAX_BATCH_SIZE)
    parser.add_argument("--total-budget-mib", type=int, default=256)
    args = parser.parse_args()
    if args.collect:
        corpus_path = collect_batches(
            args.locations, args.sources_dir,
            [item.strip() for item in args.crates.split(",") if item.strip()] if args.crates else None,
            pin=args.pin, batch_size=args.batch_size, total_budget_mib=args.total_budget_mib,
        )
    else:
        corpus_path = args.sources_dir / "corpus.json"
    result = build_index(corpus_path, args.index_output)
    print(json.dumps({"index": str(args.index_output), "families": len(result["families"]),
                      "releases": sum(len(row["releases"]) for row in result["families"]),
                      "parse_errors": len(result["parse_errors"])}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
