# Version 0.29.0: runtime version getters and Independent-7

Date: 2026-11-20

Scanner: 0.29.0

Rule release: `builtin-2026.11.20.13`

## Result

Version 0.29.0 adds five documented version APIs to the static ELF getter
registry. The scanner still does not load or execute target firmware code; it
accepts only straight-line return paths that produce a string pointer or encoded
release integer.

| Component | Runtime evidence |
|---|---|
| MPFR | `mpfr_get_version` returns a NUL-terminated release string |
| MPC | `mpc_get_version` returns a NUL-terminated release string |
| PortAudio | `Pa_GetVersionText` returns the documented library-version banner |
| FFADO | `ffado_get_version` returns the documented library-version banner |
| YAJL | `yajl_version` returns `major * 10000 + minor * 100 + patch` |

PortAudio's target banner is
`PortAudio V19.7.0-devel, revision unknown`. The normalized release base is
`19.7.0`; the unmodified banner remains in the component evidence. This avoids
rejecting the Debian release solely because upstream labels its stable source
line as `-devel`.

## Independent-7 held-out

A new 20-library Debian catalog was selected from libraries not already present
in the maintained held-out catalogs. The first run used the pre-existing
scanner rules with no tuning for this catalog.

| Run | Exact | Wrong | Unknown | Usable coverage | Claim precision |
|---|---:|---:|---:|---:|---:|
| Untouched blind | 4 | 0 | 16 | 20% | 100% |
| First getter expansion | 8 | 1 | 11 | 40% | 88.89% |
| PortAudio normalization | **9** | **0** | **11** | **45%** | **100%** |

The first expansion emitted PortAudio `19.7.0-devel` against the Debian release
truth `19.7.0`; the evaluator correctly marked it wrong. After documenting and
normalizing the banner semantics, the tuned run reached 9/20 exact with zero
wrong claims. This suite is now a regression set and is no longer blind.

The five new correct claims are:

- YAJL `2.1.0`
- PortAudio `19.7.0`
- MPFR `4.2.2`
- MPC `1.3.1`
- FFADO `2.5.0`

The remaining 11 libraries do not currently expose a defensible release getter:
libunwind, libnuma, libinih, libevdev, Wayland client/server, xkbcommon,
libdrm, libaio, PAM and libsepol. libdrm's `drmGetLibVersion` reports the DRM API
version, not the `libdrm` release, so it remains deliberately unsupported.

## Existing firmware

Neither supplied firmware currently contains these newly supported components
in recognizable form. Their authoritative fixed-cohort results are unchanged:

| Firmware | All usable | Native usable |
|---|---:|---:|
| Modern Android 16 | 791/1,129, 70.06% | 627/774, 81.01% |
| Allwinner Android 4.4.4 | 197/582, 33.85% | 60/312, 19.23% |

This iteration improves future firmware coverage and held-out accuracy without
changing the two supplied image measurements.

## Validation

- Full suite: 842 passed, 39 skipped, 7 known warnings.
- Untouched Independent-7 report retained separately from tuned reports.
- Tuned Independent-7: 9/20 exact, zero wrong, 11 explicit abstentions.
- Isolated `0.29.0` wheel verification exercises all five getters on the
  stripped ELF inputs and reports zero mismatches.

## Artifacts

- `reports/heldout-debian-independent7-20261120-blind/`
- `reports/heldout-debian-independent7-20261120-tuned1/`
- `reports/heldout-debian-independent7-20261120-tuned2/`
- `reports/version-coverage-getters-20261120/version-0.29.0-final-summary.json`
- `reports/version-coverage-getters-20261120/wheel-0.29.0-final/`
