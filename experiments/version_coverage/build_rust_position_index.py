"""Build a public-reference position index, rechecking each source and ELF hash."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from collections import defaultdict
from pathlib import Path

from firmware_scanner.extraction.rust_locations import extract_locations


def merge_indices(compiled, ast):
    """Union reference features only when release-source provenance agrees."""
    output = copy.deepcopy(ast)
    output["compiled_corpus_sha256"] = compiled.get("corpus_sha256")
    by_crate = {row["crate"].replace("_", "-"): row for row in output["families"]}
    for incoming in compiled["families"]:
        key = incoming["crate"].replace("_", "-")
        if key not in by_crate:
            family = copy.deepcopy(incoming)
            output["families"].append(family)
            by_crate[key] = family
            continue
        family = by_crate[key]
        family["builds"] = copy.deepcopy(incoming.get("builds", []))
        releases = {row["version"]: row for row in family["releases"]}
        for reference in incoming["releases"]:
            current = releases.get(reference["version"])
            if current is None:
                family["releases"].append(copy.deepcopy(reference))
                continue
            if (current["source"] != reference["source"]
                    or current["source_sha256"] != reference["source_sha256"]):
                raise ValueError("reference release sources disagree")
            combined = {(row["file"], row["line"], row["column"], row["kind"])
                        for row in current["sites"] + reference["sites"]}
            current["sites"] = [{"file": file, "line": line, "column": column, "kind": kind}
                                for file, line, column, kind in sorted(combined)]
        family["releases"].sort(key=lambda row: tuple(map(int, row["version"].split("."))))
    output["families"].sort(key=lambda row: row["crate"])
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("builds", nargs="+", type=Path)
    parser.add_argument("--ast-index", type=Path)
    args = parser.parse_args()
    corpus_raw = args.corpus.read_bytes()
    corpus = json.loads(corpus_raw)
    sources = {row["crate_path"]: row for row in corpus["crates"]}
    positions = defaultdict(lambda: defaultdict(set))
    build_evidence = defaultdict(list)
    for path in args.builds:
        report = json.loads(path.read_bytes())
        for row in report["rows"]:
            if row.get("status") != "analyzed":
                continue
            crate, version = row["crate"], row["version"]
            source = next(item for item in sources[crate]["versions"] if item["version"] == version)
            if source["archive_sha256"] != source["index_checksum"]:
                raise ValueError("source archive disagrees with registry index")
            archives = list(args.corpus.parent.rglob(f"{sources[crate]['package_name']}-{version}.crate"))
            if not any(hashlib.sha256(item.read_bytes()).hexdigest() == source["archive_sha256"]
                       for item in archives):
                raise ValueError("public source archive no longer matches its recorded checksum")
            binary = Path(row["library_path"])
            data = binary.read_bytes()
            if hashlib.sha256(data).hexdigest() != row["library_sha256"]:
                raise ValueError("reference binary differs from recorded build")
            parsed = extract_locations(data)
            if parsed["status"] != "analyzed":
                raise ValueError("reference binary is no longer supported by parser")
            selected = {(site["source_file"], site["line"], site["column"])
                        for site in parsed["locations"] if site["crate"].replace("_", "-") == crate.replace("_", "-")
                        and site["code_references"] and site["corroborated_calls"]}
            positions[crate][version].update(selected)
            build_evidence[crate].append({"version": version, "optimization": row["optimization"],
                                          "binary_sha256": row["library_sha256"],
                                          "compiler": report["compiler"],
                                          "cargo_lock_sha256": row.get("cargo_lock_sha256"),
                                          "wrapper_sha256": row.get("wrapper_sha256")})
    families = []
    for crate, releases in sorted(positions.items()):
        source = sources[crate]
        family = {"crate": source["package_name"], "prior_version": source["declared_version"],
                  "prior_source": source["manifest"]["url"],
                  "prior_source_sha256": source["manifest"]["decoded_sha256"],
                  "builds": build_evidence[crate], "releases": []}
        for version, sites in sorted(releases.items()):
            release = next(item for item in source["versions"] if item["version"] == version)
            family["releases"].append({"version": version, "source": release["archive_url"],
                                       "source_sha256": release["archive_sha256"],
                                       "sites": [{"file": file, "line": line, "column": column,
                                                  "kind": "compiled-panic"}
                                                 for file, line, column in sorted(sites)]})
        families.append(family)
    output = {"schema_version": 1, "families": families,
              "warning": "finite public reference builds; output versions are estimates",
              "corpus_sha256": hashlib.sha256(corpus_raw).hexdigest()}
    if args.ast_index:
        raw = args.ast_index.read_bytes()
        output = merge_indices(output, json.loads(raw))
        output["ast_index_sha256"] = hashlib.sha256(raw).hexdigest()
        families = output["families"]
    args.output.write_text(json.dumps(output, separators=(",", ":"), sort_keys=True) + "\n")
    print(json.dumps({"families": len(families), "versions": sum(len(r["releases"]) for r in families),
                      "sites": sum(len(v["sites"]) for r in families for v in r["releases"]),
                      "output_sha256": hashlib.sha256(args.output.read_bytes()).hexdigest()}))


if __name__ == "__main__":
    main()
