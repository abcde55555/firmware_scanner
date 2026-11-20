# Public version API expansion and second held-out validation

Date: 2026-11-20
Scanner: 0.15.0

## Result

A new 20-library Debian catalog was created without overlap with the previous
development or independent suites. Its first blind run against the 0.14.0
probes produced:

| Metric | First blind run |
|---|---:|
| Identity matched | 20/20 |
| Exact versions | 0 |
| Estimated versions | 0 |
| Unknown | 20 |
| Usable coverage | **0%** |

The cold-start result showed that existing rules were concentrated on a small
set of libraries. A public-API probe was then added, requiring a documented
version banner, getter, exported object or integer encoding plus corroborating
library APIs. The rerun produced:

| Metric | 0.15.0 rerun |
|---|---:|
| Identity matched | 20/20 |
| Exact versions | **10** |
| Correct estimated version | **1** |
| Accepted adjacent version | 0 |
| Wrong exact or estimated version | 0 |
| Unknown | 9 |
| Usable coverage | **11/20 (55%)** |
| Precision among version claims | **100%** |

This catalog is no longer fully held out after its first failure was used to
add general probes. The 0% blind result and 55% tuned result are recorded
separately so the improvement is auditable.

## Exact releases recovered

| Component | Version | Evidence |
|---|---:|---|
| libcap | 2.75 | Shared-library banner plus cap APIs |
| GPGME | 2.1.2 | Official GPGME banner plus check-version/new APIs |
| libassuan | 3.0.2 | Official Libassuan banner plus check-version/connect APIs |
| libksba | 1.6.7 | Official Libksba banner plus check-version/reader APIs |
| nPth | 1.8 | Official nPth banner plus get-version/init APIs |
| libdevmapper | 1.02.205 | Release/date banner plus library-version/task APIs |
| GDBM | 1.26 | Defined `gdbm_version_number` object plus open/fetch APIs |
| Readline | 8.3 | Version pointer and packed integer agree |
| Little CMS | 2.17 | Documented integer getter `cmsGetEncodedCMMversion` |
| libidn | 1.43 | Literal returned by defined `stringprep_check_version` |

`libmagic` is reported as `5.46` with `interface` semantics from
`magic_version()` (`0x222`). It remains estimated because the API value is an
encoded engine/interface generation rather than a generic semantic release.

## Still unknown

The remaining nine libraries expose no release-specific evidence in the tested
stripped binaries:

- libattr, libacl, libltdl, libpopt and libaudit;
- libselinux and libapparmor, whose banners observed were ABI/symbol versions;
- libfuse3;
- libedit, whose Readline compatibility value is not the libedit release.

The scanner leaves these unknown. ABI versions, distribution package versions
or version-like diagnostic strings are not promoted to exact component
releases.

## Guardrails

- A banner is accepted only when the corresponding library APIs are defined.
- Version-pointer and packed-integer Readline values must agree.
- Integer getters use documented encodings; ambiguous encodings remain
  estimated.
- Exact and estimated claims are evaluated separately from unknown output.
- An estimated value is usable only when it equals truth or is an explicitly
  accepted adjacent release. Incorrect estimates are counted as errors rather
  than coverage.

## Artifacts

- `reports/heldout-debian-independent2-20261120/heldout-report.json`
- `reports/heldout-debian-independent2-20261120-final-v5/heldout-report.json`
