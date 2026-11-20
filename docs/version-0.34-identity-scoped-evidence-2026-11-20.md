# Version 0.34.0: identity-scoped ELF evidence

Date: 2026-11-20

Scanner: 0.34.0

Rule release: `builtin-2026.11.20.13`

## Problem

Deep ELF facts were attached to the host `.so`. When a symbol-set extractor
identified a contained component such as OpenCORE-AMR or PVMP3, taxonomy and
source facts could be lost or attributed to the host instead of the identity
that produced them.

A unit test could therefore pass while a real BOM still lacked the expected
component facts. This is a generalization bug affecting every future
symbol-set-derived component.

## Fix

`ELFExtractionResult` now carries `claim_facts`, keyed by component identity.
`BinaryInventory` applies those facts only to the matching contained component.
Host-level facts such as SONAME, NEEDED and toolchain remain host-level.

OpenCORE-AMR and PVMP3 now receive:

- `firmware:taxonomy = third-party-oss`
- `firmware:taxonomy:evidence = confirmed-symbol-set-identity`
- source scope `android-framework-derived-codec`
- source root `https://android.googlesource.com/platform/frameworks/av/`

Their versions remain `unknown` with structured abstention reasons because the
binary evidence identifies codec standards and wrapper provenance, not library
releases.

## Real firmware effect

The Allwinner BOM now classifies both OpenCORE-AMR occurrences and PVMP3 as
third-party OSS while retaining three version abstentions. The host `.so`
components do not inherit codec source/taxonomy facts they did not earn.
The fixed third-party taxonomy denominator grows from 33 to 35; 33 of those rows
are versioned and the two distinct codec identities remain explicit Unknown.

The fixed version denominators remain unchanged:

| Metric | Result |
|---|---:|
| Allwinner all usable | 197/582, 33.85% |
| Allwinner native usable | 60/312, 19.23% |
| Modern all usable | 791/1,129, 70.06% |
| Modern native usable | 627/774, 81.01% |

## Validation

- Full suite: 850 passed, 39 skipped, 7 known warnings.
- A compiled symbol-set fixture proves contained-component fact routing.
- The real Allwinner decoder ELFs expose the expected taxonomy and abstention
  properties.
- CycloneDX and source-snapshot checks are rerun for 0.34.0.

## Artifacts

- `reports/version-coverage-getters-20261120/version-0.34.0-allwinner-final/`
- `reports/version-coverage-getters-20261120/version-0.34.0-final-summary.json`
- `reports/version-coverage-getters-20261120/wheel-0.34.0-final/`
