# Version evidence hardening and 0.13.0 revalidation

Date: 2026-11-20

## Result

Version 0.13.0 preserves the hardened exact-version evidence and adds a scoped
Android platform build baseline without turning source revisions, parent
package versions, or platform builds into upstream releases.

| Metric | Modern Android 16 | Allwinner Android 4.4 |
|---|---:|---:|
| Fixed-cohort usable versions | **785/1,129 (69.53%)** | **185/582 (31.79%)** |
| Fixed-cohort exact versions | **225** | **119** |
| Fixed-cohort estimated versions | **560** | **66** |
| Native usable versions | **621/774 (80.23%)** | **48/312 (15.38%)** |
| Components | 1,576 | 591 |

Neither image has an independent complete version truth set, so these remain
coverage counts rather than statistically verified accuracy rates.

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
`firmware:taxonomy=platform-first-party`. The exact count remains 225 and 119,
respectively. The native fixed-cohort result also remains 621/774 and 48/312.
Third-party OSS selection is unchanged.

The vulnerability matcher now rejects every explicitly declared
resolution-state other than `exact`. On both final BOMs, the 39 platform-build
components remain outside OSV queries and outside every VEX `affects`
reference.

## Why the fixed denominators did not increase

The new Allwinner evidence strengthens versions on components that were
already identified, or identifies libraries embedded inside a platform host.
The frozen evaluator counts the platform host row separately, so a stronger
`libvpx`, libFLAC, OpenSSL, or SQLite claim cannot turn the containing
`libstagefright`, WebView, Widevine, or decoder host into that embedded library.

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

The number of components (591) and exact components (37) stays unchanged,
while total version evidence claims increase from 667 to **674**.

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
0.13.0 wheel reports the source version correctly.

An isolated wheel install reports:

- module version: `0.13.0`;
- package metadata version: `0.13.0`;
- rule lock: `builtin-2026.11.20.2`.

## Validation

- Full Python suite: **704 passed, 39 skipped**.
- CycloneDX 1.5/1.6 BOM and VEX schemas: **8/8 valid**.
- BLintDB: Modern confirms 9 identities; Allwinner confirms 4 identities.
- NSRL: zero exact file matches on both images.
- Vulnerability records remain candidates: Modern 470, Allwinner 1,500.
- Platform-build components in VEX `affects`: **0 for both images**.

Machine-readable results:

- `reports/version-coverage-getters-20261120/final-summary.json`
- `reports/version-coverage-getters-20261120/schema-validation.json`
- `reports/version-coverage-getters-20261120/wheel-0.13.0/wheel-verification.json`
