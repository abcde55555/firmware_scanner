# Version 0.21.0: runtime release APIs, sixth held-out and firmware reality check

Date: 2026-11-20

Scanner: 0.21.0

Rule release: `builtin-2026.11.20.6`

## Result

Version 0.21.0 adds a second family of static, documented runtime-release
probes. It does not execute target code. Each accepted value requires a defined
API in the target ELF and follows that API's documented return shape:

- returned release strings: NNG, rabbitmq-c, libqrencode, libserialport and
  MariaDB Connector/C;
- output-parameter triplets: libzmq, CZMQ, Mosquitto and libqrencode;
- returned structures or pointer tables: libusb and libgphoto2;
- exported integer objects or packed getters: libmodbus, libpq and mbedcrypto;
- filename evidence: mbedTLS, Boost.Filesystem and NNG are retained only as
  explicit estimates;
- libgpiod's API version is retained only as `estimated/interface`, not as a
  proved library release.

The sixth Debian library suite was selected without overlap from the previous
five suites. Its untouched result and post-rule result are separate:

| Metric | Blind run | Rule-tuned run |
|---|---:|---:|
| Explicitly mapped identity | 20/20 | 20/20 |
| Exact versions | 0 | **15** |
| Estimated versions | 0 | **3** |
| Accepted adjacent estimates | 0 | 0 |
| Wrong claims | 0 | **0** |
| Usable versions | 0/20, 0% | **18/20, 90%** |
| Precision among version claims | not established | **18/18, 100%** |

The blind `0/20` is the cold-start result before these rules existed. The tuned
`18/20` result is not a held-out generalization score. The two unresolved
claims are intentionally unresolved:

- libhiredis has no confirmed runtime release API in the selected DSO; its
  header macros do not prove a stripped binary's release.
- `NormGetVersion()` reports `1.5.7`, while the Debian source package is
  `1.5.9`; the value is an implementation/API fact that is insufficient to
  select the package release.

The evaluator also corrects three source-package/library-release mismatches:

- libftdi's binary identifies `1.6rc1`;
- `libmariadb3` exposes MariaDB Connector/C `3.4.9`, not the server source
  release `11.8.6`;
- libserialport's public package-version getter returns `0.1.1`, distinct from
  the Debian source package `0.1.2`.

## Firmware results

Both images were rescanned through the product `AndroidSystemScanner`, frozen
source snapshot, CLI deduplication and CycloneDX generation. No target binary
was executed. The new probes added zero fixed-cohort claims on these two images:

| Firmware | All usable | Native usable | Exact / estimated |
|---|---:|---:|---:|
| Allwinner Android 4.4.4 | **194/582, 33.33%** | **57/312, 18.27%** | **120 / 74** |
| Modern Android 16 | **786/1,129, 69.62%** | **622/774, 80.36%** | **226 / 560** |

Allwinner completed in 171.962 seconds with 599 deduplicated components and 444
ELF analyses. Modern Android completed in 499.607 seconds with 1,577 components,
2,134 ELF analyses and 34 APEX modules.

The zero delta is substantive: neither image contains these target libraries in
a form where the documented runtime API is discoverable. It is not evidence
that the probes are broadly ineffective, and it is not evidence that the
Debian result transfers to Android. Expanding an unrelated x86-64 Debian catalog
will not, by itself, raise this firmware corpus.

The selected statistical truth remains limited:

- the Modern fixed cohort has no complete independent version oracle;
- Allwinner's independently checked calibration subset remains 5/5 correct,
  which is useful but far too small to characterize all 582 rows;
- both documented percentages are usable-version field coverage, not full-image
  accuracy.

The SBOMs are valid CycloneDX 1.6 documents with zero schema errors. Both scans
had zero analysis warnings and zero database errors.

## Verification

- Full suite: 819 passed, 39 skipped, 7 known warnings.
- Focused version-probe, held-out and filename suites: 105 passed, 2 skipped.
- Ruff on every changed Python file and `git diff --check`: clean.
- Fresh wheel: `firmware_scanner-0.21.0-py3-none-any.whl`.
- Isolated wheel import used the installed site-packages copy, reported module
  and distribution version `0.21.0`, verified rule lock
  `builtin-2026.11.20.6`, and recovered libusb `1.0.29` from the held-out binary.

## Roadmap assessment

The supplied roadmap is useful as a long-term architecture catalogue, but its
KPI and priority sections should not be executed literally.

Keep these parts:

1. Separate platform-first-party components, third-party OSS and proprietary
   vendor components.
2. Keep exact releases, explicit estimates, equivalence classes, conflicts and
   unknown values distinct.
3. Preserve deterministic, versioned rules and independent held-out evaluation.
4. Prefer binary-native evidence over directory metadata.
5. Gate expensive Version-Delta or BSim analysis after cheaper evidence fails.

Correct these parts before scheduling:

1. The document's historical blockers are stale. Multi-DEX traversal, bounded
   DEX reads, content hashing, version resolution states and restricted
   taxonomy support already exist.
2. "Version field coverage" is not recall, and Debian package versions are not
   always the linked upstream library release.
3. BLintDB and NSRL are useful identity or exact-file evidence, but neither
   produced direct version gains on these images. Database size is not a
   version KPI.
4. The Rust, DEX, Version-Delta and BSim sections contain targets and estimated
   benefits, not measured increments on this corpus.
5. The 24-week 70%/95% targets need fixed denominators, independent truth,
   architecture/build diversity and a separately frozen blind suite before they
   can be accepted.
6. The recommended next corpus should reflect the product target: vendor-built
   Android ARM32/AArch64, embedded Linux and stripped static components. A new
   random x86-64 Debian suite tests API modelling, but it does not measure the
   same population as the customer's firmware.

## Recommended next experiment

The current two-image corpus has little overlap with the sixth Debian suite.
The highest-value next experiment is therefore a target-derived unknown-library
census:

1. Select 40-60 identity-confirmed but version-unknown third-party components
   from the two images and additional customer-shaped firmware.
2. For each component, first test package/language metadata, exact hashes,
   documented getters/objects, and source-path plus revision evidence.
3. Only then test a bounded Version-Delta or BSim slice, with explicit stop
   conditions: at least five percentage points of new usable coverage, at least
   95% measured precision, no increase in wrong claims, and bounded runtime.
4. Keep newly discovered rules in the JSON or Python evidence layer with release
   lock, tests and a disjoint blind run.

This changes the research question from "can we add more library signatures?"
to "which evidence source resolves components that actually appear in
production firmware?" It is the necessary route to a meaningful version-recall
gain.

## Artifacts

- `reports/heldout-debian-independent6-20261120-blind-v2/heldout-report.json`
- `reports/heldout-debian-independent6-20261120-tuned-final2/heldout-report.json`
- `reports/version-coverage-getters-20261120/version-0.21.0-allwinner-final/`
- `reports/version-coverage-getters-20261120/version-0.21.0-modern-final/`
- `reports/version-coverage-getters-20261120/version-0.21.0-final-summary.json`
- `reports/version-coverage-getters-20261120/wheel-0.21.0-final/wheel-verification.json`
