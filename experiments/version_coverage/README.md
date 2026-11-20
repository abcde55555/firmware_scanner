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
  reports/version-coverage-50-20261118/reproduction/system \
  --blintdb reports/existing-databases-20261119/blint.db \
  --nsrl-db reports/existing-databases-20261119/nsrl/android_minimal.db

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
`exact_versions` counts single observed claims; `estimated_versions` counts single
selected estimates with an estimate marker. Neither is an accuracy measurement.
`usable_versions` and `usable_coverage` include both; `usable_target_50_percent`
tests the requested output-coverage target. The separate accuracy gate named
`target_50_percent` uses independently established expected versions passed with `--verified`:
a JSON object mapping `observation_key(baseline_record)` to an exact version.
An omitted verification map means unverified, not that every output is wrong.
Native rows are libraries described as native libraries, not names containing
`.so`. Range/candidate-only claims and text such as `detected (version unknown)`
do not pass either coverage gate. `adjacent_estimates` counts verified differences
of one numeric patch within the same major/minor line; these remain strict errors
and are separately included in `accepted_verified` under the user's tolerance.

## Rust estimated releases and DEX inventory

The runtime reads the bundled `data/rust_version_positions.json`; no network,
Rust compiler or tree-sitter dependency is required during firmware scans. The
ELF64 x86-64 decoder requires owned crate paths, relocations, code references and
bounded core-panic argument context. At least three distinct owned coordinates
must support a reference. A selected release is marked `estimated-release`, with
candidate releases, source/archive hashes and its selection rule. A source pin
only breaks ties inside the matching candidates; it is not binary source proof.
Observed release claims and explicit conflicts are preserved.

Offline corpus work needs the `corpus` extra (also included in `dev`). The AST
builder rechecks each registry archive and source member without extracting it
to an uncontrolled location. It records parser versions and a native grammar
hash. Recovered nodes outside syntax-error regions may contribute; parse errors
remain in the index. Generated source positions are reference features, not proof
that all compiler panic sites have the same AST coordinates.

```sh
PYTHONPATH=src python experiments/version_coverage/build_rust_ast_index.py \
  --collect --batch-size 10 --total-budget-mib 256

PYTHONPATH=src python experiments/version_coverage/build_rust_position_index.py \
  reports/version-corpus-20261118/rust-sources/corpus.json \
  reports/version-corpus-20261118/rebuilt-rust-positions.json \
  reports/version-corpus-20261118/rust-reference-builds-1/builds.json \
  reports/version-corpus-20261118/rust-reference-builds-2/builds.json \
  reports/version-corpus-20261118/rust-reference-builds-ryu-wrapper/builds.json \
  reports/version-corpus-20261118/rust-reference-builds-3/builds.json \
  --ast-index reports/version-corpus-20261118/rust-ast-index.json
```

The current index contains 36 crate families, 169 nonempty releases and 38,369
source/compiled sites. Four empty AST release entries were excluded. These counts
describe reference coverage, not target firmware accuracy or a 50% result.

APK and framework ZIP paths scan all supported root `classes*.dex` members, up to
64 members, 64 MiB per DEX and 256 MiB total decompression per archive. Framework
JARs use random reads when supported. DEX library inventory uses `class_defs`,
not merely referenced types; this follows the [official DEX layout](https://source.android.com/docs/core/runtime/dex-format).
DEX 041 containers and reverse-endian DEX are not currently parsed. Unknown
versions stay empty; namespaces do not supply a numeric release. OkHttp's
[`okhttp3`](https://raw.githubusercontent.com/square/okhttp/parent-4.12.0/okhttp/src/main/kotlin/okhttp3/OkHttpClient.kt)
and Retrofit's [`retrofit2`](https://raw.githubusercontent.com/square/retrofit/2.11.0/retrofit/src/main/java/retrofit2/Retrofit.java)
namespaces are included. Only anchored own-product release banners can supply
DEX versions; unrelated diagnostic numbers are ignored.

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

Version 0.21.0 added a sixth disjoint 20-library Debian suite. Its untouched
blind run was 0/20; after adding documented runtime release APIs it reached 18/20
usable (15 exact and 3 estimated), with zero wrong claims and two deliberate
abstentions. The tuned result is not a held-out score.

The same probes added zero fixed-cohort claims to the current Allwinner and
Modern Android images because those libraries were absent in recognizable API
form. The product results remain Allwinner 194/582 (native 57/312) and Modern
786/1,129 (native 622/774). See
`docs/version-0.21-heldout-and-roadmap-results-2026-11-20.md`.

Version 0.22.0 moved the next expansion back to components present in the
supplied firmware. Allwinner now exposes six exact WebRTC audio-module versions
and four additional third-party identities. Its BOM grows from 599 to 607
components and its explicit third-party OSS taxonomy grows from 18 to 51.
Modern has no new component rows but its explicit third-party taxonomy grows
from 245 to 272. The historical fixed denominators remain unchanged at
Allwinner 194/582 (native 57/312) and Modern 786/1,129 (native 622/774).

The database report now includes identity-confirmation, reference-version
agreement and exact-file match rates. BLintDB confirms 4/5 reviewed Allwinner
components and 9/9 reviewed Modern components; its reference-version agreement
rate is 0% on both images. NSRL has zero exact-file matches. These databases are
retained as identity or exact-file evidence and never overwrite target versions.
See `docs/version-0.22-target-derived-components-2026-11-20.md`.

Version 0.23.0 fixes OpenSSH compatibility globs being mistaken for release
banners and allows exact source revisions to refine contained components. Modern
now resolves OpenSSH `9.0p1` and libevent `2.1.12-stable`. The fixed cohort
improves from 786/1,129 to **787/1,129** (native 622/774 to **623/774**).
BOM rows decrease from 1,577 to 1,572 because four incorrect parent-package
libevent variants and one duplicate generic zlib row consolidate into their
single source-pinned components. See
`docs/version-0.23-source-path-refinement-2026-11-20.md`.

Version 0.24.0 adds exact source pins for SpeexDSP `1.2.1` and libyuv `1883`.
Modern's fixed cohort rises to **788/1,129** usable fields and **624/774**
native libraries. The only BOM-row reduction is the expected libyuv
parent-version consolidation. No new source rule is applied to Allwinner, which
has no matching source manifest. See
`docs/version-0.24-source-declared-releases-2026-11-20.md`.

Version 0.25.0 matches Android release filename rules against real component
locations and evidence containers. Allwinner's canonical Tremolo component now
inherits the same explicit `0.07` AOSP estimate as its
`libvorbisidec.so` host. The frozen aggregate is unchanged because the host was
already counted; the BOM no longer contains a paired resolved host and
unresolved canonical subcomponent. See
`docs/version-0.25-component-location-releases-2026-11-20.md`.

Version 0.26.0 resolves Android BoringSSL `libcrypto.so` and `libssl.so` to the
image-pinned `git:ecc1358826150d6a1851c517c325b0e6c0e1b8be` revision only when
full `external/boringssl` source-path evidence is present. Missing, incomplete
or unrelated source-path evidence cannot trigger the rule, so ordinary OpenSSL
components remain ineligible. Modern's fixed cohort moves from 788/1,129 to
**789/1,129** usable and from 624/774 to **625/774** native usable fields; exact
and estimated rows are 228/561. The value is an estimated source revision, not a
BoringSSL release or OpenSSL version. The 111/111 fixed third-party result is
selected-taxonomy field coverage, not whole-image recall or accuracy. See
`docs/version-0.26-boringssl-source-revision-2026-11-20.md`.

Version 0.27.0 defers BLintDB's cross-project low-information filter until after
target symbols match reference binaries. A complete Modern scan with BLintDB and
NSRL queried 1,789 unique ELF content records, verified both database manifests,
completed NSRL and import-hash self-checks, and reported no database errors in
507.2 seconds. BLintDB produced 21 candidate files and confirmed 9/9 reviewed
component identities, but only 0/8 comparable reference versions agreed. NSRL
produced zero exact-file matches. Reference versions still never overwrite
target versions.

The same scan adds Perfetto `49.0` for `heapprofd_client.so` and
`heapprofd_client_api.so`, moving Modern's frozen cohort from 789/1,129 to
**791/1,129** usable and from 625/774 to **627/774** native usable fields.
Exact/estimated rows are 230/561. See
`docs/version-0.27-database-scale-and-perfetto-2026-11-20.md`.

Version 0.28.0 adds typed Android 4.4.4 source provenance to Allwinner:
mDNSResponder `320.10.80` from the official `MVERS` declaration, plus TinyALSA
and Sonivox as `estimated-aosp-source-revision` Git tree objects because those
projects do not declare an upstream semantic release in the pinned AOSP tree.
The database-enabled Allwinner scan queries both retained databases over 430
unique ELF content records with no errors, confirms 4/5 BLintDB identities and
finds zero NSRL exact files. The frozen cohort rises from 194/582 to **197/582**
usable and from 57/312 to **60/312** native usable fields, with exact/estimated
rows at 120/77. See
`docs/version-0.28-android-source-revisions-2026-11-20.md`.

Version 0.29.0 adds documented static getters for MPFR, MPC, PortAudio, FFADO
and YAJL. It also adds the 20-library Independent-7 catalog. Its untouched blind
run was 4/20 exact with zero wrong claims; after the five getter additions and
PortAudio banner normalization, the tuned regression run reached **9/20 exact,
zero wrong and 11 explicit unknowns**. The supplied firmware results remain
unchanged because none of these components are currently recognized in them.
See `docs/version-0.29-runtime-getters-and-heldout7-2026-11-20.md`.

Version 0.30.0 adds a targeted libsepol extractor for the official
`LIBSEPOL_3.11` ELF version definition plus release-specific symbols. The tuned
Independent-7 regression now reaches **10/20 exact, zero wrong and ten explicit
unknowns**, or 50% exact coverage with 100% precision among emitted claims. See
`docs/version-0.30-libsepol-version-namespace-2026-11-20.md`.

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
(x86-64 and AArch64, 2.13.2); i386/ARM builds with unsupported control flow are
refused. Unknown memory writes, field overlaps and getter branches are negative
controls. The old generic fallback is disabled. The probe is now packaged in
`firmware_scanner.extraction.freetype_version` and wired into
`BinaryInventory`; the separate legacy ARM32 probe handles the FreeType 2.4.12
Allwinner shape.

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

## Existing binary databases

`blint_db_probe.py` downloads the pinned ARM64 BLintDB OCI layer, verifies its
digest without loading it into RAM, and queries direct ELF observations. The OCI
media type says `+tar`, but the authenticated payload is raw SQLite.

```sh
PYTHONPATH=src python experiments/version_coverage/blint_db_probe.py \
  --download-db \
  --output reports/existing-databases-20261119/blintdb-probe.json
```

The raw result retains every symbol candidate. `analyze_blintdb.py` applies
defined-symbol filtering, low-information symbol suppression, target coverage,
Blint's binary-name gates, and Conan deploy-path parsing:

```sh
PYTHONPATH=src python experiments/version_coverage/analyze_blintdb.py \
  reports/existing-databases-20261119/blintdb-probe.json \
  --database reports/existing-databases-20261119/blint.db \
  --output reports/existing-databases-20261119/blintdb-gated.json
```

Raw candidates and reference-build versions never enter the product version
field without independent artifact evidence.

`nsrl_db_probe.py` performs exact SHA-256 plus size membership checks against an
NSRL RDSv3 SQLite database. Delta ZIP support reads literal FILE/PKG records,
proves the accepted SQL operation set, and runs a positive query control:

```sh
PYTHONPATH=src python experiments/version_coverage/nsrl_db_probe.py \
  reports/existing-databases-20261119/nsrl/android_minimal.db \
  --observations allwinner=reports/version-corpus-20261118/scan/allwinner/file-observations.json \
  --observations system=reports/version-corpus-20261118/scan/system/file-observations.json \
  --delta reports/existing-databases-20261119/nsrl/RDS_2026.06.1_android_minimal_delta.zip \
  --delta reports/existing-databases-20261119/nsrl/RDS_2026.09.1_android_minimal_delta.zip \
  --output reports/existing-databases-20261119/nsrl-probe.json
```

`PKG.version` is a distribution version and is not promoted to an upstream
native-library release.

## Held-out Debian truth set

`debian_heldout.py` uses Debian package metadata as truth, resolves one
explicitly mapped SONAME per package, copies it, and applies `strip --strip-all`
before scanning. Missing packages can be downloaded as `.deb` and extracted with
`dpkg-deb -x`; they are not installed.

```sh
PYTHONPATH=src python3 experiments/version_coverage/debian_heldout.py \
  --output reports/heldout-debian-54-20261120-final

PYTHONPATH=src python3 experiments/version_coverage/debian_heldout.py \
  --suite independent \
  --output reports/heldout-debian-independent-20-20261120-final

PYTHONPATH=src python3 experiments/version_coverage/debian_heldout.py \
  --suite independent2 \
  --output reports/heldout-debian-independent2-20261120-final-v5
```

The 54-library development suite returns 39 exact, 2 estimated, 13 unknown and
zero wrong claims: 41/54 usable coverage and 100% precision among version
claims. The separate 20-library suite was 2/20 on its first unseen run and 12/20
after general public getters were added; it is no longer fully held out after
that rule development. Catalog identity matching is explicit
filename/component mapping, not a claim of independent identity precision. See
`docs/heldout-debian-version-validation-2026-11-19.md`.

A second disjoint 20-library catalog was first run against 0.14.0 and produced
0/20 usable versions. General public-API probes then raised the tuned result to
**11/20 usable (55%)**: 10 exact, 1 estimated, 0 wrong and 9 unknown. The
blind and tuned results are preserved separately; the tuned set is no longer
fully held out.

## Android source and parent provenance

The production Android scanner parses image-local NOTICE mappings and applies
source revisions only from an image-SHA-256-matched manifest. It also records
APEX/APK parent versions and propagates provenance across byte-identical ELF
copies by SHA-256. The inventory additionally extracts embedded source-file
paths with their file offsets; a project revision is applied only when the
component-name rule and one of the manifest project paths agree.

`source-subproject-version-pins.json` resolves individual crates inside a
revision-pinned monorepo. Crate name/alias matching takes precedence over an
embedded dependency path, preventing linked code from selecting the wrong
release. Exact Rust crate and OpenSSH versions require a revision-bound
`Cargo.toml` or version header. Confirmed Rust crates receive
`pkg:cargo/<crate>@<version>` PURLs and can be queried by OSV. Other revision
values remain explicitly estimated and are excluded from CPE/OSV queries.

The exact-image Waydroid source pack and HAL namespace rules are in
`src/firmware_scanner/data/provenance/`. To evaluate a completed scan against the
frozen cohort:

```sh
PYTHONPATH=. python experiments/version_coverage/evaluate.py \
  reports/function-version-experiment-20261118/after/system/system_analysis.json \
  reports/version-estimates-20261119/source-revisions/scan-final/system_analysis.json \
  --baseline-commit e890f0c
```

On the frozen 1,129/774 cohort, the 0.15.0 evidence update produces 785/1,129
usable fields (69.53%) and 621/774 native libraries (80.23%): 225 exact and 560
explicit estimates. The 39-row increase is a scoped Android framework platform
baseline, not additional upstream releases or third-party exact matches.

Allwinner reaches 190/582 usable fields (32.65%) and 53/312 native libraries
(16.99%): 119 exact and 71 explicit estimates. Five entries have independent
AOSP-source expectations and evaluate 5/5 correct; this remains a development
calibration subset rather than full-firmware accuracy.

These are coverage values where no complete independent truth exists. See
`docs/firmware-sbom-roadmap-review-2026-11-20.md` and
`docs/database-and-rust-version-validation-2026-11-20.md`. The Allwinner
evidence hardening and frozen-source version fix are recorded in
`docs/version-evidence-hardening-2026-11-20.md`.
The scan-time and cache measurements are in
`docs/firmware-scanner-performance-2026-11-20.md`.

Run the Allwinner calibration gate:

```sh
PYTHONPATH=. python experiments/version_coverage/evaluate.py \
  reports/function-version-experiment-20261118/after/allwinner/system_analysis.json \
  reports/version-coverage-getters-20261120/final-allwinner/system_analysis.json \
  --baseline-commit e890f0c \
  --verified experiments/version_coverage/verified/allwinner-ktu84q-aosp-4.4.4.json
```
