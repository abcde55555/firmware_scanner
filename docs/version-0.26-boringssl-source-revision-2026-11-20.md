# Version 0.26.0: conservative BoringSSL source-revision resolution

Date: 2026-11-20

Scanner: 0.26.0

Rule release: `builtin-2026.11.20.11`

## Result

Version 0.26.0 resolves Android `libcrypto.so` and `libssl.so` to the image's
pinned BoringSSL source revision:

`git:ecc1358826150d6a1851c517c325b0e6c0e1b8be`

The resolution requires both:

- a component name matching
  `^lib(?:crypto|ssl)\.so(?:\.[0-9]+)*$`;
- full `firmware:source:path-evidence` whose project is
  `external/boringssl`.

The source manifest must already match the scanned image's SHA-256. The output
state is `estimated-source-revision`: it identifies the source project pin, not
a BoringSSL release, SemVer version or OpenSSL compatibility version.

The guard is intentionally strict. A matching filename with no source path, an
optional project marker without full evidence, or evidence belonging to another
source project does not resolve the component. This prevents ordinary OpenSSL
libraries from inheriting the Android BoringSSL revision.

## Real firmware result

### Modern Android 16

| Metric | Version 0.25.0 | Version 0.26.0 |
|---|---:|---:|
| BOM components | 1,571 | **1,569** |
| All usable version fields | 788/1,129, 69.80% | **789/1,129, 69.88%** |
| Native usable version fields | 624/774, 80.62% | **625/774, 80.75%** |
| Exact / estimated fixed rows | 228 / 560 | **228 / 561** |
| Unknown fixed rows | 341 | **332** |
| Fixed third-party OSS fields | 113/114, 99.12% | **111/111, 100%** |

The two component-row reductions are expected identity consolidations. The
usable-version gain is one fixed observation because the BoringSSL host was
already represented; the change makes its `libcrypto.so` and `libssl.so`
locations auditable against the pinned source revision.

`111/111` describes selected fixed third-party taxonomy rows. It is not
whole-image component recall, version recall or accuracy. The modern fixed
cohort still marks all 789 usable values as independently unverified because
this firmware does not include an independent version oracle.

### Allwinner Android 4.4.4

The rule requires an embedded `external/boringssl` source path. The Allwinner
image has no matching source manifest path for this case, so its verified 0.25.0
result remains:

| Metric | Result |
|---|---:|
| BOM components | 607 |
| All usable version fields | 194/582, 33.33% |
| Native usable version fields | 57/312, 18.27% |

## Roadmap assessment

The supplied roadmap is useful as a long-term architecture direction, but its
current-state baseline and several KPI promises are stale or unmeasured. Multi
DEX scanning, content-hash caching, version resolution state and the partial
three-way taxonomy path already exist. The repository has not established 95%
version precision or 70% whole-firmware third-party recall because neither
supplied image has an independent component-version oracle.

The highest next value is not another broad filename rule. It is a bounded
experiment over identity-known, version-unknown components:

1. use NOTICE or source-path mappings to narrow each component to one project;
2. harvest runtime version getters and stable read-only version objects where
   those have official release semantics;
3. for unresolved projects, build non-symmetric release deltas from strings,
   exported symbols, constants and version-object changes;
4. require at least two independent target observations and abstain on ties;
5. score new exact, adjacent, equivalence-class, wrong and still-unknown rows on
   samples excluded from rule development.

Rust source positions and Ghidra BSim remain research candidates. The roadmap's
Rust hit estimate and 50%/70% thresholds are forecasts, not measured gains.
BLintDB and NSRL remain identity/provenance evidence sources; their reference
package versions must not overwrite target versions.

This suggests a practical product differentiator: a version resolver that
separates release versions, source revisions, adjacent ranges and abstentions,
while preserving the evidence chain and explicitly blocking unsafe OSV queries
for non-exact values.

## Validation

- Full suite: 835 passed, 39 skipped, 7 known warnings.
- Modern CycloneDX 1.6 SBOM: valid with zero schema errors.
- All 177 files in the Modern frozen source snapshot match their recorded hashes.
- Isolated wheel verification reports version `0.26.0`, verifies rule lock
  `builtin-2026.11.20.11`, and resolves real ARM `libcrypto.so` and `libssl.so`
  samples to the pinned revision.
- The sixth 20-library Debian suite remains 18/20 usable, with 15 exact,
  3 estimated, zero wrong and two abstentions. It is a tuned regression suite,
  not an untouched blind score.

## Artifacts

- `reports/version-coverage-getters-20261120/version-0.26.0-modern-final3/`
- `reports/version-coverage-getters-20261120/version-0.26.0-final-summary.json`
- `reports/version-coverage-getters-20261120/wheel-0.26.0-final/`
- `reports/heldout-debian-independent6-20261120-v026-final/heldout-report.json`
