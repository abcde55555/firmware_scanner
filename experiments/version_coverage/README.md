# Version coverage experiments

These commands use the product Android scanner and preserve source/input hashes.
They do not execute firmware binaries. Raw images, downloaded AARs, Ghidra projects
and reports stay in the ignored `reports/` directory. Install the project and its
test dependencies into a Python environment first; run from the repository root.

## Real scans and frozen denominator

```sh
PYTHONPATH=src python experiments/version_coverage/run_scan.py \
  reports/accuracy-20261118/evidence/allwinner-system.img \
  reports/version-coverage-50-20261118/reproduction/allwinner \
  --origin /home/kali/Desktop/work/project/vulnscan/sun8iw6p1_android_perf3_v1_0_uart0.img

PYTHONPATH=src python experiments/version_coverage/run_scan.py \
  /home/kali/Desktop/work/project/vulnscan/system.img \
  reports/version-coverage-50-20261118/reproduction/system

python experiments/version_coverage/evaluate.py \
  reports/function-version-experiment-20261118/after/system/system_analysis.json \
  reports/version-coverage-50-20261118/reproduction/system/system_analysis.json \
  --baseline-commit e890f0c
```

Use a new output directory for every scan. The runner copies `src/` before
importing it. `source-sha256.json` identifies the actual dirty or committed source;
`metrics.json`'s Git revision alone does not. Each ELF observation includes its
SHA-256, container location and claims. The Allwinner command scans its extracted
ext4 system partition and records the original image hash; it does not scan the
other IMAGEWTY partitions.

The evaluator keeps every baseline row, including missing or reclassified rows.
`exact_versions` is a populated-field count, not an accuracy measurement. The 50%
gate uses independently established expected versions passed with `--verified`:
a JSON object mapping `observation_key(baseline_record)` to an exact version.
An omitted verification map means unverified, not that every output is wrong.
Native rows are libraries described as native libraries, not names containing
`.so`. Range/candidate claims do not pass the exact-version gate.

## Independent checker candidate scout

Use the Python environment containing an installed `cve-bin-tool`:

```sh
PYTHONPATH=src <cve-bin-tool-python> \
  experiments/version_coverage/compare_cve_checkers.py \
  <ext4-image> <locations.json> <candidate-output.json>
```

The locations file is a JSON list of strings, or objects with `location`/`path`.
The script calls local binary checkers without a CVE database or target execution.
It supports direct files and one ZIP member level, caps each ELF at 64 MiB and
reports skips. Results are candidates, including compiler and compatibility
versions; they are not imported into the product BOM. Tool/checker/source hashes
are recorded. See `docs/version-checker-comparison-2026-11-18.md` for the measured
scope and original frozen scout scripts.

## Pinned reference artifacts

```sh
python experiments/version_coverage/build_sample_index.py \
  --references-dir reports/version-coverage-50-20261118/references \
  --output reports/version-coverage-50-20261118/rebuilt-binary-samples.json
```

The importer reads `reference_sources.json`, validates companion POM coordinates,
records AAR/POM checksums, and reads bounded native members. It uses existing cache
files when available. Maven relocation is recorded without assigning the old
coordinate to the new artifact. The bundled index contains hashes and public
provenance, not binary bytes. Equal binary bytes in several indexed releases retain
all candidate releases and do not produce an arbitrary exact version. A source URL
is not a build-configuration record; this corpus consists of published artifacts.

## BSim candidate experiment

Prepare the actual unknown x86-64 library and 11 official reference versions:

```sh
PYTHONPATH=src python experiments/version_coverage/prepare_bsim.py \
  /home/kali/Desktop/work/project/vulnscan/system.img \
  reports/version-coverage-50-20261118/references \
  reports/version-coverage-50-20261118/bsim-reproduction
```

Generate signatures with a local Ghidra installation. The measured run used Ghidra
12.2, Temurin 25.0.5, one analysis CPU and a 384 MiB heap. Adjust the installation
path for another machine. Ghidra's launcher must select a supported installed JDK.
Create the output project/signature directories before running the command:

```sh
mkdir -p reports/version-coverage-50-20261118/bsim-reproduction/project \
  reports/version-coverage-50-20261118/bsim-reproduction/signatures

GHIDRA_HEADLESS_MAXMEM=384m \
  GHIDRA_HEADLESS_JAVA_OPTIONS='-XX:ActiveProcessorCount=1' \
  /home/kali/.local/share/ghidra/ghidra_12.2_PUBLIC/support/analyzeHeadless \
  reports/version-coverage-50-20261118/bsim-reproduction/project coverage \
  -import reports/version-coverage-50-20261118/bsim-reproduction/inputs \
  -recursive -max-cpu 1 -analysisTimeoutPerFile 60 \
  -postScript GenerateSignatures.java \
  reports/version-coverage-50-20261118/bsim-reproduction/signatures medium_nosize

python experiments/version_coverage/compare_bsim.py \
  reports/version-coverage-50-20261118/bsim-reproduction
```

Check Ghidra's per-file analysis/import status before interpreting signatures.
`compare_bsim.py` compares exact feature-vector equality, requiring at least ten
distinct features. It does **not** implement weighted BSim similarity/significance,
prove exact versions, or update the product's version claims. The real query
matches eight vectors in four distinct releases; ties remain candidates.

The section comparison extends this finite experiment to the nine indexed target
locations, without Ghidra or target execution:

```sh
PYTHONPATH=src python experiments/version_coverage/compare_sections.py \
  /home/kali/Desktop/work/project/vulnscan/system.img \
  reports/version-coverage-50-20261118/references \
  reports/version-coverage-50-20261118/aar-target-matches.json \
  reports/version-coverage-next-20261118/section-candidates-reproduction.json
```

It validates AAR/member checksums, then compares architecture and all bytes,
virtual addresses and flags of `.text`, `.rodata`, `.data.rel.ro` and
`.note.android.ident`. Missing sections are unsupported. On the measured inputs,
five Graphics Path files each match the same four reference releases; the four
TensorFlow Lite files have no matching profile. All exact versions remain unset.
In-memory controls change a code byte and append an unreferenced trailer; the
former changes the profile and the latter changes only the whole-file hash.
This is candidate evidence, not general cross-compiler matching or a product
version-coverage gain.

Protobuf's bounded ELF32 ARM/Thumb and i386 proof is now in
`extraction/protobuf_version.py`; its experiment CLI delegates to that module.
TensorFlow Lite's JNI runtime proof is in `extraction/tflite_version.py`. It emits
an independently attributed runtime identifier, marked `runtime`, and leaves the
JNI/Maven artifact version unknown. Both are called by `BinaryInventory`.

The separate FreeType paired-function prototype remains experimental. Its
optional image tests use read-only `debugfs` extraction and assert input hashes:

```sh
FREETYPE_SYSTEM_IMAGE=/home/kali/Desktop/work/project/vulnscan/system.img \
  PYTHONPATH=src python -m pytest tests/unit/test_freetype_version.py -q
```

The tightened proof currently matches two of the four real system libraries
(x86-64 and AArch64, 2.13.2); i386/ARM and the Allwinner library are refused.
Unknown memory writes, field overlaps and getter branches are negative controls.
The old generic fallback is disabled. This is not integrated into
`BinaryInventory` and adds no product version coverage. The previous 0/4 result
in the earlier report describes the earlier prototype, not the current one.

The direct-library API census reads the two images again and checks every ELF
against its earlier file-observation SHA-256. It excludes nested archive paths
and bounds each read to 64 MiB. Its support comparison is explicitly pinned to
`e872bd7`; the SQLite object adapter added afterwards is not part of that baseline.

```sh
PYTHONPATH=src python experiments/version_coverage/census_version_apis.py \
  --system-image /home/kali/Desktop/work/project/vulnscan/system.img \
  --allwinner-image reports/accuracy-20261118/evidence/allwinner-system.img \
  --output reports/version-corpus-20261118/census.json
```

This uses `final-reviewed/{allwinner,system}/file-observations.json` from the
previous production scan. Candidate records and distinct families are counted
separately. Version-like symbol names are leads: libbpf's `v1.4` series, interface
versions and module versions do not become exact whole-library releases.

`object_version.py` now also recognizes SQLite's bounded read-only
`sqlite3_version` array with three defined identity APIs. It records the library's
declared identifier, independently of source-manifest and NOTICE labels. The two
real semantic controls use `FIRMWARE_SYSTEM_IMAGE` (or `FREETYPE_SYSTEM_IMAGE`) to
read the original ext4 image and assert fixed ELF hashes, avoiding a mounted-file
dependency.
