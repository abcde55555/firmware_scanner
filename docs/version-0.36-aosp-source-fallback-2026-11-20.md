# Version 0.36: AOSP build-ID source fallback

Date: 2026-11-20

Scanner: 0.36.0 (calibration release 0.36.1)

Rule release: `builtin-2026.11.20.14`

## Result

Version 0.36.0 adds two constrained provenance paths:

1. Official AOSP build-ID manifests can recover a project revision when
   `android_version`, exact `build_id`, an explicit component-to-project rule
   and embedded ELF source-path evidence all agree.
2. A small registry of stable AOSP platform SONAMEs can attach the enclosing
   system-partition build baseline to components that do not expose source paths.

Neither path emits an upstream release or an exact-version claim.

The AOSP build-ID fallback is `estimated-aosp-source-revision`. It records the
official manifest URL and project revision. The platform registry is
`estimated-platform-build` with scope
`platform-build-not-upstream-release`.

## Allwinner real firmware

Fixed cohort: 582 total rows, 312 native rows.

| Metric | v0.35.0 | v0.36.0 | Change |
|---|---:|---:|---:|
| All usable | 277/582, 47.59% | **292/582, 50.17%** | **+15** |
| Native usable | 123/312, 39.42% | **138/312, 44.23%** | **+15** |
| Exact | 120 | **120** | 0 |
| Estimated | 157 | **172** | +15 |
| Unknown | 298 | **283** | -15 |
| Platform-first-party | 119/119 | **126/126** | +7 |
| Third-party OSS | 33/35 | **41/43, 95.35%** | +8 usable |

The all-component 50% coverage target is met at 50.17%. Native coverage remains
44.23% and is not described as a 50% native result.

### Independent calibration check

The v0.36.1 calibration map binds the 15 new observations to official
`android-4.4.4_r2` manifest project revisions or the exact target image build
baseline.

| Metric | Result |
|---|---:|
| Independently verified new observations | 15 |
| Correct | **15** |
| Errors | **0** |
| Adjacent-only matches | **0** |

This is a source-verified calibration slice that informed the rules. It is not
an untouched whole-image holdout.

The eight build-ID source fallbacks are:

| Component | Project revision |
|---|---|
| libFFTEm | `external/neven@3fd3838250aa8de71932028ae1bbf5b4e7e79459` |
| libchromium_net | `external/chromium@3f6640e94b9354397c8dce53c91f54589360e00f` |
| libcompiler_rt | `external/compiler-rt@f6ad106035fcae4909b7ef6d903cb67b8a89b4f3` |
| libpac | `external/v8@5b3c8d4a3d91a25ffc5257519d459d4b2e8f429e` |
| libskia | `external/skia@65b06b7302197ce8ad4234d9cbac9f90c2121308` |
| libwebrtc_audio_preprocessing | `external/webrtc@d4d54e6466f6c3d4ea41db3887eb5b285f2f92c6` |
| audio.a2dp.default | `external/bluetooth/bluedroid@7dab6592721a74e5e32daac266779ecd4463773f` |
| bluetooth.default | `external/bluetooth/bluedroid@7dab6592721a74e5e32daac266779ecd4463773f` |

The official build mapping points `4.4.4 / KTU84Q` at
`android-4.4.4_r2`. The manifest repository revision is
`64f4f353b72203e5225b03fd3432f0825345f6bb`.

The scan completed in 156.884 seconds with 872,592 KiB peak RSS, 444 analysed
ELF files, 608 deduplicated SBOM components and zero warnings.

## Modern Android regression

| Metric | v0.35.0 | v0.36.0 | Change |
|---|---:|---:|---:|
| All usable | 864/1,129, 76.53% | **866/1,129, 76.71%** | **+2** |
| Native usable | 652/774, 84.24% | **654/774, 84.50%** | **+2** |
| Exact | 230 | **230** | 0 |
| Estimated | 634 | **636** | +2 |
| Unknown | 257 | **255** | -2 |
| Platform-first-party | 551/551 | **553/553** | +2 |
| Third-party OSS | 116/117 | **116/117** | 0 |

The scan completed in 384.798 seconds with 1,965,424 KiB peak RSS, 2,134
analysed ELF files, 34 APEX modules, 1,561 deduplicated SBOM components and
zero warnings.

The modern image already has an exact image-hash source manifest, which retains
precedence. The build-ID fallback therefore contributes zero rows there.

## Safety gates

- Source revision and platform build states remain non-exact.
- No new component in either firmware has a non-empty upstream CPE from these
  states.
- Vulnerability scanning rejects all new provenance states before OSV queries.
- Third-party dependency source paths are not promoted to the host component
  unless a matching component-to-project rule selects one project.
- Vendor and product partition paths do not qualify for the rule-only platform
  baseline.
- Exact counts remain unchanged at 120 for Allwinner and 230 for Modern.

## Database use

Both real scans queried the pinned databases.

| Metric | Allwinner | Modern |
|---|---:|---:|
| ELF files queried | 430 | 1,789 |
| BLintDB candidate files | 5 | 21 |
| BLintDB identity confirmations | 4/5 | 9/9 |
| BLintDB reference-version agreements | 0/3 comparable | 0/8 comparable |
| BLintDB non-comparable reference versions | 1 | 1 |
| NSRL exact-file matches | 0/430 | 0/1,789 |
| Query errors | 0 | 0 |

The database audit passed both SHA-256 manifests, schemas and production-query
positive controls. BLint reference versions remain diagnostic and NSRL no-match
remains distinct from component absence.

## Validation

- Full unit suite: 867 passed, 39 skipped, 7 known warnings.
- Real source snapshots: 178/178 files match; zero changed, missing or
  unexpected source files for both firmware scans.
- CycloneDX 1.6: both SBOMs valid with zero schema errors.
- The Allwinner calibration evaluation reports 15/15 new observations correct
  with zero adjacent-only matches and zero verification warnings.
- Fresh wheel: `firmware_scanner-0.36.1-py3-none-any.whl`, SHA-256
  `9ff073282f7ca7bcb76e86e9b56bcafc31131edbd10e8ed657de1c2042039de2`.
- Isolated wheel verification reports module/distribution version `0.36.1`,
  verifies all 16 rule files and exercises both the Skia source fallback and an
  AOSP platform component rule.

## Artifacts

- `reports/version-coverage-getters-20261120/version-0.36.0-allwinner-source-fallback/`
- `reports/version-coverage-getters-20261120/version-0.36.0-modern-source-fallback/`
- `reports/version-coverage-getters-20261120/version-0.36.0-database-audit.json`
- `reports/version-coverage-getters-20261120/version-0.36.1-final-summary.json`
- `reports/version-coverage-getters-20261120/wheel-0.36.1-final/wheel-verification.json`
- `experiments/version_coverage/verified/allwinner-ktu84q-aosp-provenance-0.36.json`

## Boundaries

- The AOSP build tag does not prove that a vendor tree contains no local
  patches. Source revisions remain estimates.
- The 50.17% result is version-field coverage. The supply/images do not provide
  an independent whole-image version oracle, so independently verified accuracy
  coverage remains zero.
- The remaining 283 fixed Allwinner rows are predominantly vendor/proprietary
  or binaries without attributable release evidence. They require component-
  specific evidence rather than broader platform propagation.
