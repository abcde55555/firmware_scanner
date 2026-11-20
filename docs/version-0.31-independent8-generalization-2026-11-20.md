# Version 0.31.0: Independent-8 generalization

Date: 2026-11-20

Scanner: 0.31.0

Rule release: `builtin-2026.11.20.13`

## Result

Version 0.31.0 adds a second fresh 20-library Debian corpus, Independent-8, and
keeps its untouched blind report separate from tuning runs.

| Run | Exact | Wrong | Unknown | Coverage | Claim precision |
|---|---:|---:|---:|---:|---:|
| Untouched blind | 2 | 0 | 18 | 10% | 100% |
| Tuned regression | **6** | **0** | **14** | **30%** | **100%** |

This lower generalization result is important: Independent-7's 50% coverage
does not imply that every Debian library family reaches 50%. The new suite
measures a different population and remains a regression set after tuning.

## New evidence

| Component | Evidence |
|---|---|
| GeoIP `1.6.12` | `GeoIP_lib_version` direct release-string return |
| HIDAPI `0.15.0` | `hid_version_str` direct release-string return |
| Unbound `1.24.2` | `ub_version` direct release-string return |
| S-Lang `2.3.3` | exported `SLang_Version_String` pointer plus required API symbols |

The pre-existing scanner rules already recognized:

- libmaxminddb `1.12.2`
- libsodium `1.0.18`

GPM is deliberately not versioned from `Gpm_GetLibVersion`: that function
returns ABI version `2.1.0`, while the containing Debian library release is
`1.20.7`. Treating the ABI version as a release would create a false match.

## Existing firmware

Neither supplied firmware contains the new Independent-8 component forms in a
recognizable state. Their authoritative fixed-cohort results remain unchanged:

| Firmware | All usable | Native usable |
|---|---:|---:|
| Modern Android 16 | 791/1,129, 70.06% | 627/774, 81.01% |
| Allwinner Android 4.4.4 | 197/582, 33.85% | 60/312, 19.23% |

## Validation

- Full suite: 843 passed, 39 skipped, 7 known warnings.
- Independent-8 blind and tuned reports are retained separately.
- Isolated `0.31.0` wheel verification recognizes the four new component forms
  and rejects unregistered getter names plus an incomplete S-Lang object.

## Artifacts

- `reports/heldout-debian-independent8-20261120-blind/`
- `reports/heldout-debian-independent8-20261120-tuned2/`
- `reports/version-coverage-getters-20261120/version-0.31.0-final-summary.json`
- `reports/version-coverage-getters-20261120/wheel-0.31.0-final/`
