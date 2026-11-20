"""Compare finite Rust source-position reference sets without assigning versions."""
from __future__ import annotations

import argparse
import hashlib
import json
from collections import defaultdict
from pathlib import Path


def features(row, crate, context_only=True):
    return {(site["source_file"], site["line"], site["column"])
            for site in row.get("locations", []) if site["crate"] == crate
            and site.get("code_references")
            and (not context_only or site.get("corroborated_calls"))}


def rank(query, versions):
    """Retain ties and report corpus-relative uniqueness, never exact releases."""
    union = set().union(*versions.values()) if versions else set()
    rows = []
    for version, reference in versions.items():
        others = set().union(*(sites for key, sites in versions.items() if key != version))
        matches = query & reference
        rows.append({"version": version, "matched_positions": len(matches),
                     "target_positions": len(query), "reference_positions": len(reference),
                     "unique_in_this_corpus_matches": len(matches - others),
                     "matching_source_files": sorted({site[0] for site in matches})})
    rows.sort(key=lambda item: (-item["matched_positions"], item["version"]))
    maximum = rows[0]["matched_positions"] if rows else 0
    top = [row["version"] for row in rows if maximum >= 5 and row["matched_positions"] == maximum]
    return {"top_reference_versions": top, "comparisons": rows,
            "target_positions_absent_from_all_references": len(query - union), "exact_version": None}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("targets", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("builds", nargs="+", type=Path)
    args = parser.parse_args()
    versions = defaultdict(lambda: defaultdict(set))
    references = []
    for path in args.builds:
        for row in json.loads(path.read_text())["rows"]:
            if row.get("status") != "analyzed":
                continue
            selected = features(row, row["crate"])
            versions[row["crate"]][row["version"]].update(selected)
            references.append(row)
    targets = []
    for target in json.loads(args.targets.read_text())["rows"]:
        host = target["identity"].split("|")[1].removeprefix("lib").removesuffix(".dylib.so")
        for crate in versions:
            if host.replace("_", "-") != crate.replace("_", "-"):
                continue
            selected = features(target, crate)
            targets.append({"identity": target["identity"], "location": target["location"],
                            "sha256": target["sha256"], "crate": crate, **rank(selected, versions[crate])})
    heldout = []
    for row in references:
        # Entire source release is absent, not only one optimization variant.
        subset = {version: sites for version, sites in versions[row["crate"]].items()
                  if version != row["version"]}
        heldout.append({"crate": row["crate"], "withheld_version": row["version"],
                        "optimization": row["optimization"], **rank(features(row, row["crate"]), subset)})
    result = {"input_sha256": {str(path): hashlib.sha256(path.read_bytes()).hexdigest()
                               for path in [args.targets, *args.builds]},
              "warning": "finite-corpus candidates only; a top score is not an exact version",
              "targets": targets, "version_heldout_controls": heldout,
              "exact_versions_added": 0}
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"targets": len(targets), "reference_builds": len(references),
                      "heldout_controls": len(heldout), "exact_versions_added": 0}))


if __name__ == "__main__":
    main()
