# Version evidence hardening and 0.15.0 revalidation

Date: 2026-11-20

## Result

Version 0.15.0 adds general public-version API probes on top of binary ABI
evidence, an official codec banner, and controlled AOSP release-project
estimates. Source revisions, parent package versions, platform builds, and
AOSP release derivations remain separate from upstream binary self-version
evidence.

| Metric | Modern Android 16 | Allwinner Android 4.4 |
|---|---:|---:|
| Fixed-cohort usable versions | **785/1,129 (69.53%)** | **190/582 (32.65%)** |
| Fixed-cohort exact versions | **225** | **119** |
| Fixed-cohort estimated versions | **560** | **71** |
| Native usable versions | **621/774 (80.23%)** | **53/312 (16.99%)** |
| Components | 1,577 | 593 |
| Source-verified calibration | 0 | **5/5 correct** |

Neither image has an independent complete version truth set, so these remain
coverage counts rather than statistically verified accuracy rates.

## New binary and source evidence

### Libjpeg ABI 62 and AOSP JPEG 6b estimate

Allwinner `libjpeg.so` defines both `jpeg_CreateDecompress` and
`jpeg_read_header`. The decompressor compares its ABI argument against the
immediate `0x3e` (`62`) and the JPEG structure size against `480`. AOSP
`android-4.4.4_r2` documents ABI 62 as IJG Version 6b.

The same ABI is retained by libjpeg-turbo, so ABI 62 alone is insufficient.
The probe is refused when a libjpeg-turbo banner is present. A Modern Android
2.1.5.1 file exposed exactly this false-positive case during validation and
now produces no IJG 6b claim. A stripped compatibility build could also hide
its turbo banner, so `6b` is emitted only as an estimated AOSP
`android-4.4.4_r2` source result. The binary contributes documented ABI
evidence rather than an exact release claim.

### 3GPP AMR-WB 6.0.0

`libnormal_audio.so` contains the official banner
`3GPP AMR-WB Floating-point Speech Decoder, v6.0.0, Dec 14, 2004` and defined
Speex/AMR-WB decoder APIs. The output is an independently named contained
component, not a version for the proprietary Allwinner container:

- `3GPP AMR-WB decoder = 6.0.0`;
- `firmware:vulnerability:query=not-queryable-no-canonical-osv-package`.

### Exact-build AOSP release estimates

For build ID `KTU84Q`, which the AOSP build-number table maps to
`android-4.4.4_r2`, the scanner requires both a binary identity and a pinned
AOSP project:

| Component | Version | State |
|---|---:|---|
| libjpeg | `6b` | `estimated-aosp-release` plus ABI 62 evidence |
| libexif | `0.6.21` | `estimated-aosp-release` |
| SpeexDSP | `1.2beta3` | `estimated-aosp-release` |
| STLport | `5.0` | `estimated-aosp-release` |
| Jhead | `2.87` | `estimated-aosp-release` |

These estimates are excluded from exact upstream CVE queries. A different
build ID, filename-only match, or missing binary identity does not qualify.

## Android framework platform baseline

Unresolved archives whose component type is `framework`, whose canonical name
starts with `framework/`, and whose evidence path is inside
`/system/framework/` or the partition root `/framework/` now receive the
enclosing image build ID. Vendor and product framework partitions are excluded.

| Image | Baseline | Added rows |
|---|---|---:|
| Modern Android 16 | `16-BP2A.250805.005-1775195212` | 39 |
| Allwinner Android 4.4.4 | `4.4.4-KTU84Q-20180511` | 39 |

These rows carry `firmware:version:resolution-state=estimated-platform-build`,
`firmware:version:scope=platform-build-not-upstream-release`, and
`firmware:taxonomy=platform-first-party`. At the 0.13.0 step, the exact count
remained 225 and 119 respectively. The native fixed-cohort result also
remained 621/774 and 48/312, and third-party OSS selection was unchanged.

The vulnerability matcher now rejects every explicitly declared
resolution-state other than `exact`. On both final BOMs, the 39 platform-build
components remain outside OSV queries and outside every VEX `affects`
reference.

## Fixed-cohort and contained-component effects

The AMR-WB result adds an independently named contained component. The frozen
evaluator counts the proprietary `libnormal_audio` host separately, so AMR-WB
does not turn that container into a versioned decoder row. By contrast, libjpeg,
libexif, SpeexDSP, STLport and Jhead are host libraries or carry an identity
that matches the frozen host, so they do increase the fixed cohort.

This distinction is deliberate. AOSP host libraries and their embedded
third-party contents must remain separate SBOM components.

## Evidence changes

- ARM32 and Thumb getters now support defined `LDR`/`ADD`/`BX` and
  `LDR`/`BX` return paths.
- A release string must map to read-only ELF memory. The extractor refuses a
  release located in writable memory.
- libFLAC requires agreeing `FLAC__VERSION_STRING` and
  `FLAC__VENDOR_STRING` declarations; mutable pointer objects are rejected.
- Legacy OpenSSL accepts the documented read-only `MD5_version` banner array
  and requires the complete `MD5 part of OpenSSL <release> <date>` shape.

On Allwinner, these changes add seven independent evidence claims to five
already exact components:

| Component | Release | Added evidence |
|---|---|---|
| OpenSSL | `0.9.8k` | two `MD5_version` object claims |
| libcrypto | `1.0.1e` | one `MD5_version` object claim |
| SQLite | `3.7.11` | one direct version-object claim |
| libvpx | `1.2.0-5082-g58f7543` | two Thumb getter claims |
| libvpx | `1.3.0` | one Thumb getter claim |

At the 0.10 hardening step, the number of components (591) and exact components
(37) stayed unchanged while total version evidence claims increased from 667
to **674**. Version 0.14.0 subsequently adds new component identities and
versions, so those historical counts are not the final totals.

## Source revisions reviewed

The 13 Modern Android third-party components that still carry a matched source
revision but no component release were reviewed against their revision-bound
source trees. **0/13 were safely promotable to exact.**

Examples:

- BoringSSL, PDFium, compiler-rt, ANGLE, libchrome, Sonic, Sonivox, Minijail,
  Neven and tinyalsa expose a commit, Android branch, or rolling upstream
  state, not an auditable component release at that revision.
- DNG SDK has a version format, but the available public tree did not prove
  the reported revision mapping.
- SELinux needs both revision proof and target binary confirmation.
- `libvsprintf_wrapper` cannot inherit a version from an arbitrary crate in the
  revision-pinned Rust monorepo.

These components remain `estimated-source-revision`.

## APEX executable parent provenance

Contained APEX executables now receive the parent module version with the
explicit `estimated-parent-package` state, matching the existing behavior for
native libraries. These values are build provenance and are not queryable as
upstream CVE versions.

On Modern Android:

- non-empty BOM versions increased from 1,134 to **1,173**;
- unknown rows decreased from 440 to **403**;
- parent-package applications increased by 39;
- the frozen fixed-cohort metric increased conservatively from 744 to
  **746/1,129**, because several APEX executables are not represented in that
  older baseline.

Two previously merged architecture copies of linker/linker64 became distinct
rows after only the APEX-contained copy received its parent version.

## Reproducibility and version management

The scan harness copies the repository `pyproject.toml` into the frozen source
bundle. A previous defect caused generated BOMs to report an unrelated
installed package version (`0.2.0`) instead of the source version. The final
0.15.0 wheel reports the source version correctly.

An isolated wheel install reports:

- module version: `0.15.0`;
- package metadata version: `0.15.0`;
- rule lock: `builtin-2026.11.20.3`;
- locked rule/provenance JSON files: 15.

## Validation

- Full Python suite: **748 passed, 39 skipped**.
- CycloneDX 1.5/1.6 BOM and VEX schemas: **8/8 valid**.
- BLintDB: Modern confirms 9 identities; Allwinner confirms 4 identities and
  reviews 5 comparable identity-confirmed components.
- NSRL: zero exact file matches on both images.
- Vulnerability records remain candidates: Modern 470, Allwinner 1,500.
- Platform-build components in VEX `affects`: **0 for both images**.
- AOSP calibration subset: **5/5 correct, 0 errors**.
- Second independent Debian catalog: blind 0/20; after general public-API
  expansion, **11/20 usable (55%), 10 exact, 1 estimated, 0 wrong**.

Machine-readable results:

- `reports/version-coverage-getters-20261120/final-summary.json`
- `reports/version-coverage-getters-20261120/schema-validation.json`
- `reports/version-coverage-getters-20261120/wheel-0.15.0/wheel-verification.json`
- `reports/heldout-debian-independent2-20261120-final-v5/heldout-report.json`
