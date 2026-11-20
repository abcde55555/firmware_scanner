# Version 0.30.0: libsepol ELF version namespace

Date: 2026-11-20

Scanner: 0.30.0

Rule release: `builtin-2026.11.20.13`

## Result

Version 0.30.0 recognizes the official `LIBSEPOL_3.11` ELF version definition
and maps it to release `3.11` only when both release-specific identity symbols
are present:

- `cil_check_neverallows_against_pdb`
- `sepol_kernel_policydb_decls_to_cil`

The evidence is recorded as a targeted ELF version-definition rule with source
provenance:

<https://github.com/SELinuxProject/selinux/blob/3.11/libsepol/src/libsepol.map.in>

This is not inferred from a SONAME, a generic import, or a package filename.

## Independent-7 result

| Run | Exact | Wrong | Unknown | Coverage | Claim precision |
|---|---:|---:|---:|---:|---:|
| Untouched blind | 4 | 0 | 16 | 20% | 100% |
| Runtime getters | 9 | 0 | 11 | 45% | 100% |
| libsepol namespace | **10** | **0** | **10** | **50%** | **100%** |

The libsepol result crosses the 50% coverage target on the tuned Independent-7
regression suite while retaining zero wrong claims. The suite is no longer
blind and must not be described as a blind score.

The remaining ten Unknown libraries still lack a defensible release-version
interface:

- libunwind, libnuma, libinih, libevdev
- Wayland client/server and xkbcommon
- libdrm, libaio, PAM

Wayland object versions, libevdev driver versions, DRM API versions and SELinux
policy versions are not substitutes for their containing library release.

## Existing firmware

Neither supplied firmware contains the newly supported libsepol form in a
recognized component. Existing authoritative results are unchanged:

| Firmware | All usable | Native usable |
|---|---:|---:|
| Modern Android 16 | 791/1,129, 70.06% | 627/774, 81.01% |
| Allwinner Android 4.4.4 | 197/582, 33.85% | 60/312, 19.23% |

## Validation

- Full suite: 843 passed, 39 skipped, 7 known warnings.
- Independent-7 tuned regression: 10 exact, zero wrong, ten abstentions.
- Isolated `0.30.0` wheel verification recognizes libsepol and rejects an ELF
  with both identity functions but no `LIBSEPOL_3.11` version definition.

## Artifacts

- `reports/heldout-debian-independent7-20261120-tuned4/`
- `reports/version-coverage-getters-20261120/version-0.30.0-final-summary.json`
- `reports/version-coverage-getters-20261120/wheel-0.30.0-final/`
