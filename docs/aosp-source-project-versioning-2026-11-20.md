# AOSP source-path project versioning and 0.19.0 firmware results

Date: 2026-11-20  
Scanner: 0.19.0  
Rule release: `builtin-2026.11.20.5`

## Result

The roadmap's useful core is now implemented for the Allwinner Android 4.4.4
image: an ELF can retain an auditable `external/<project>/...` source path, map
that project to the exact AOSP build tag, and receive the release value declared
by the pinned project source. The host wrapper remains unknown. This prevents a
Protobuf version embedded in `libAppDataSearch.so` or a Google TTS container
from being reported as a version of the wrapper itself.

Against the unchanged 582-item frozen Allwinner cohort:

| Metric | 0.18.0 | 0.19.0 | Change |
|---|---:|---:|---:|
| All usable | 193/582, 33.16% | **194/582, 33.33%** | +1 |
| Native usable | 56/312, 17.95% | **57/312, 18.27%** | +1 |
| Fixed-cohort exact | 119 | **120** | +1 |
| Fixed-cohort estimated | 74 | 74 | 0 |
| Fixed-cohort unknown | 382 | 381 | -1 |
| Full BOM components | 593 | **599** | +6 |
| Full BOM non-empty versions | 201 | **208** | +7 |
| Independently verified calibration | 5 correct / 0 error | 5 correct / 0 error | 0 |

This is a small fixed-cohort improvement. The useful gain is primarily at the
embedded-component layer, which the old file-level denominator did not model.
It must not be described as a large increase in the existing 582-item recall.

The newly resolved or newly separated Allwinner components are:

| Component | Version | Resolution |
|---|---:|---|
| LLVM host binary | `3.1svn` | Binary banner plus LLVM public API markers |
| WebRTC VoiceEngine | `4.1.0` | Binary banner, WebRTC source path and VoiceEngine API markers |
| Protobuf | `2.3.0` | Source path and AOSP pinned source declaration |
| V8 | `3.9.24.30` | Source path and AOSP pinned source declaration |
| OpenCV | `1.1.0` | Source path and AOSP pinned source header |
| RE2 | `20130115` | Source path and AOSP-pinned source archive version |
| marisa-trie | `0.1.5` | Versioned source directory in the AOSP tag |
| Chromium | `12.0.742.130` | Source path and AOSP pinned Chromium revision |

The six AOSP-derived project entries use the dedicated
`estimated-aosp-release` state and generic PURLs. They are provenance estimates,
not versions emitted by the wrapper binary and not exact OSV query inputs.

The Modern Android 16 image is unchanged at the fixed-cohort level:

| Metric | Result |
|---|---:|
| All usable | 785/1,129, 69.53% |
| Native usable | 621/774, 80.23% |
| Fixed-cohort exact / estimated | 225 / 560 |
| Components | 1,577 |
| Analysed ELF files | 2,134 |
| APEX modules | 34 |
| CycloneDX 1.6 | valid |

This is a non-regression check, not an accuracy claim. The Modern fixed cohort
still has no independent version truth set, so 69.53% remains version-field
coverage.

## Evidence rules

1. A source filename must match a concrete extension such as `.c`, `.cc`,
   `.cpp`, `.h`, `.hpp` or `.rs`.
2. The project prefix must equal a rule project such as `external/protobuf`.
3. The Android release and build ID must identify a pinned AOSP tag. For this
   image that is Android `4.4.4`, build `KTU84Q`, tag `android-4.4.4_r2`.
4. The rule must include an authoritative source file URL and version
   declaration.
5. The resulting component is separate from the host wrapper and carries the
   host location, source-path offset, AOSP tag and version authority.
6. Existing exact binary evidence remains higher priority. For example,
   `libpatts_engine_jni_api_ub.210030103.so` reports Protobuf `2.3.0` separately
   while its own file name version is not promoted to the library release.

The LLVM and WebRTC extractors require more than a banner. LLVM needs the
`LLVM (http://llvm.org/)` and `llvm-mc` banners plus exported LLVM APIs. WebRTC
needs the `VoiceEngine 4.1.0` banner, a WebRTC source-file marker and multiple
VoiceEngine implementation strings.

## Roadmap assessment

The supplied roadmap is directional, but its current priority ordering would
spend most effort on BSim, full Version-Delta and broad Rust indexing before
proving those methods on the target firmware. For these two images, the first
measurable gain came from build provenance already present in the ELF and from
small, auditable release APIs.

The recommended order remains:

1. Preserve source paths and map them to a pinned build manifest.
2. Attach release values only where the pinned source contains an authoritative
   declaration.
3. Keep NOTICE file-to-license evidence separate from project versions.
4. Use BLintDB and NSRL for identity/provenance, not target-version overwrite.
5. Run a new held-out set before generalizing new API patterns.
6. Invest in binary delta or BSim only after a bounded pilot shows a measurable
   exact-version gain with zero new independent errors.

## Remaining gaps

- The fixed 582-item denominator covers only source-bearing external projects
  and a few public version APIs; most vendor and proprietary wrappers remain
  unknown by design.
- The six AOSP-derived estimates are not independently verified for every
  vendor patch. They are source-provenance estimates.
- Embedded components need a broader truth set so that future reports can
  measure component identity and version precision independently from the old
  path inventory.
- Independent truth for the full Modern and Allwinner cohorts is still missing;
  the new source-derived rows cannot be promoted to an image-wide accuracy rate.

## Artifacts

- `reports/version-coverage-getters-20261120/aosp-source-projects-allwinner-20261120-final/system_analysis.json`
- `reports/version-coverage-getters-20261120/aosp-source-projects-allwinner-20261120-final/evaluation-fixed.json`
- `reports/version-coverage-getters-20261120/aosp-source-projects-allwinner-20261120-final/metrics.json`
- `reports/version-coverage-getters-20261120/aosp-source-projects-allwinner-20261120-final/schema-validation.json`
- `reports/version-coverage-getters-20261120/aosp-source-projects-allwinner-20261120-final/source-project-verification.json`
- `reports/version-coverage-getters-20261120/aosp-source-projects-modern-20261120-final/evaluation-fixed.json`
- `reports/version-coverage-getters-20261120/aosp-source-projects-modern-20261120-final/schema-validation.json`
- `reports/version-coverage-getters-20261120/wheel-0.19.0/wheel-verification.json`
- `docs/firmware-sbom-additional-methods-luna-2026-11-20.md`
