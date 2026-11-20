"""Build checksum-verified public Rust references; never execute firmware.

Published crate source is compiled by an isolated official toolchain. Resulting
ELFs are parsed, never loaded. Compiler, command, archive, lockfile and output
digests are retained. A match in this finite reference set is not an exact-version
assignment: unchanged releases and vendor patches need separate treatment.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tarfile
from pathlib import Path, PurePosixPath

from rust_locations import extract_locations


def unpack_source(archive: Path, destination: Path, root: str):
    """Extract regular source files only, within a checked distribution root."""
    total = 0
    with tarfile.open(archive, "r|gz") as tar:
        for index, member in enumerate(tar):
            parts = PurePosixPath(member.name).parts
            if (index >= 10_000 or not parts or parts[0] != root or member.name.startswith("/")
                    or ".." in parts or not (member.isfile() or member.isdir())):
                raise ValueError("unsafe or oversized source archive")
            target = destination.joinpath(*parts[1:])
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            total += member.size
            if not 0 <= member.size <= 8 * 1024 * 1024 or total > 64 * 1024 * 1024:
                raise ValueError("source extraction budget exceeded")
            content = tar.extractfile(member).read(member.size + 1)
            if len(content) != member.size:
                raise ValueError("incomplete source member")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)


def write_report(path, report):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(report, indent=2) + "\n")
    temporary.replace(path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus", type=Path)
    parser.add_argument("toolchain", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--crates", default="strsim,ryu,memchr")
    parser.add_argument("--optimizations", default="1,3")
    parser.add_argument("--ryu-std-wrapper", action="store_true",
                        help="link no_std ryu into a documented std reference wrapper")
    args = parser.parse_args()
    corpus_bytes = args.corpus.read_bytes()
    corpus = json.loads(corpus_bytes)
    selected = set(args.crates.split(","))
    optimizations = args.optimizations.split(",")
    if not optimizations or any(value not in ("0", "1", "2", "3") for value in optimizations):
        raise ValueError("unsupported optimization")
    args.output = args.output.resolve()
    args.output.mkdir(parents=True, exist_ok=True)
    compiler, cargo = args.toolchain.resolve() / "bin/rustc", args.toolchain.resolve() / "bin/cargo"
    compiler_version = subprocess.check_output([str(compiler), "--version"], text=True).strip()
    environment = os.environ.copy()
    for key in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS"):
        environment.pop(key, None)
    environment.update(RUSTC=str(compiler), CARGO_HOME=str(args.output / "cargo-home"),
                       CARGO_NET_RETRY="1", CARGO_HTTP_TIMEOUT="20")
    report = {"compiler": compiler_version, "compiler_path": str(compiler),
              "corpus_sha256": hashlib.sha256(corpus_bytes).hexdigest(),
              "parser_sha256": hashlib.sha256(Path(__file__).with_name("rust_locations.py").read_bytes()).hexdigest(),
              "warning": "finite reference candidates only; no target exact versions assigned",
              "rows": [], "errors": []}
    report_path = args.output / "builds.json"
    for crate in corpus["crates"]:
        if crate["crate_path"] not in selected:
            continue
        name = crate["package_name"]
        for version in crate["versions"]:
            release = version["version"]
            root = f"{name}-{release}"
            expected = version.get("archive_sha256")
            if not expected or expected != version.get("index_checksum"):
                report["errors"].append({"crate": name, "version": release,
                                         "error": "reference has no verified archive"})
                continue
            candidates = list(args.corpus.parent.rglob(root + ".crate"))
            valid = [path for path in candidates if hashlib.sha256(path.read_bytes()).hexdigest() == expected]
            if not valid:
                raise ValueError(f"verified source archive unavailable: {root}")
            source = args.output / "sources" / root
            if source.exists():
                raise ValueError(f"reference source directory already exists; use a fresh output: {source}")
            source.mkdir(parents=True)
            unpack_source(valid[0], source, root)
            build_source, library_name = source, name.replace("-", "_")
            wrapper_hash = None
            if name == "ryu" and args.ryu_std_wrapper:
                build_source = args.output / "wrappers" / root
                (build_source / "src").mkdir(parents=True)
                manifest = ('[package]\nname = "rust_location_reference_ryu"\nversion = "0.0.0"\n'
                            'edition = "2021"\n[lib]\ncrate-type = ["dylib"]\n[dependencies]\n'
                            'ryu = { path = ' + json.dumps(str(source)) + ' }\n')
                wrapper = """// Reference harness only; public crate source remains unchanged.
#[no_mangle]
pub extern "C" fn reference_f64(value: f64) -> u64 {
    let mut buffer = ryu::Buffer::new();
    buffer.format(value).bytes().fold(0u64, |acc, byte| acc.wrapping_mul(257).wrapping_add(byte as u64))
}
#[no_mangle]
pub extern "C" fn reference_f32(value: f32) -> u64 {
    let mut buffer = ryu::Buffer::new();
    buffer.format(value).bytes().fold(0u64, |acc, byte| acc.wrapping_mul(257).wrapping_add(byte as u64))
}
"""
                (build_source / "Cargo.toml").write_text(manifest)
                (build_source / "src/lib.rs").write_text(wrapper)
                wrapper_hash = hashlib.sha256(wrapper.encode()).hexdigest()
                library_name = "rust_location_reference_ryu"
            for optimization in optimizations:
                record = {"crate": crate["crate_path"], "package_name": name, "version": release,
                          "optimization": optimization, "archive_sha256": expected}
                build_dir = args.output / "target" / (root + "-O" + optimization)
                command = [str(cargo), "rustc", "--release", "--lib", "--crate-type", "dylib",
                           "--jobs", "1", "--manifest-path", str(build_source / "Cargo.toml"),
                           "--target-dir", str(build_dir), "--", "-C", "opt-level=" + optimization,
                           "-C", "prefer-dynamic", "-C", "overflow-checks=on", "-C", "codegen-units=1",
                           "--remap-path-prefix=" + str(source) + "=external/rust/android-crates-io/crates/" + crate["crate_path"]]
                build_environment = environment.copy()
                if wrapper_hash:
                    # Remap only the dependency's absolute path. The wrapper must
                    # not masquerade as upstream ryu source through a relative remap.
                    build_environment["CARGO_ENCODED_RUSTFLAGS"] = "\x1f".join([
                        "-C", "opt-level=" + optimization, "-C", "overflow-checks=on",
                        "--remap-path-prefix=" + str(source) + "=external/rust/android-crates-io/crates/ryu",
                    ])
                    record.update(wrapper_sha256=wrapper_hash,
                                  dependency_rustflags=build_environment["CARGO_ENCODED_RUSTFLAGS"].split("\x1f"))
                else:
                    command.append("--remap-path-prefix=src=external/rust/android-crates-io/crates/"
                                   + crate["crate_path"] + "/src")
                log = args.output / (root + "-O" + optimization + ".log")
                try:
                    with log.open("w") as handle:
                        completed = subprocess.run(command, check=False, cwd=build_source, env=build_environment,
                                                   stdout=handle, stderr=subprocess.STDOUT, timeout=180)
                    record.update(command=command, returncode=completed.returncode, log=str(log))
                    if completed.returncode:
                        raise ValueError("reference compilation failed; see log")
                    binaries = [path for path in (build_dir / "release").glob("lib*.so")
                                if path.name == "lib" + library_name + ".so"]
                    if len(binaries) != 1:
                        raise ValueError("unique output dylib not found")
                    binary = binaries[0]
                    data = binary.read_bytes()
                    saved = args.output / (root + "-O" + optimization + ".so")
                    shutil.copyfile(binary, saved)
                    lock = build_source / "Cargo.lock"
                    record.update(library_path=str(saved), library_sha256=hashlib.sha256(data).hexdigest(),
                                  cargo_lock_sha256=hashlib.sha256(lock.read_bytes()).hexdigest() if lock.exists() else None,
                                  **extract_locations(data))
                except (ValueError, OSError, subprocess.TimeoutExpired) as exc:
                    record.update(status="build-error", error=f"{type(exc).__name__}: {exc}")
                report["rows"].append(record)
                write_report(report_path, report)
                print(json.dumps({key: record.get(key) for key in
                                  ("crate", "version", "optimization", "status", "error")}), flush=True)
    write_report(report_path, report)


if __name__ == "__main__":
    main()
