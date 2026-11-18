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

The separate FreeType paired-function prototype is also experimental. Its four
optional host-path tests skip when `/system/...` is not mounted. The reported
0/4 actual result was obtained by reading the four files from the image, not from
those skipped tests. It is not integrated into `BinaryInventory`.
