# NULL-argument version APIs and database provenance

Date: 2026-11-20  
Scanner: 0.17.0  
Rule release: `builtin-2026.11.20.4`

## Result

Version 0.17.0 adds a bounded proof for public `check_version(NULL)` APIs and
promotes external database metadata into auditable scan-level evidence.

The third independent Debian catalog was not used to invent ABI-only versions.
The frozen stripped files from the previous run were replayed with the new
extractor:

| Metric | 0.16.0 | 0.17.0 |
|---|---:|---:|
| Identity matched | 20/20 | 20/20 |
| Exact versions | 7 | **9** |
| Estimated | 0 | 0 |
| Wrong exact / estimated | 0 / 0 | 0 / 0 |
| Unknown | 13 | 11 |
| Usable coverage | 35% | **45%** |

The two additions are libidn2 `2.3.8` and libtasn1 `4.21.0`. GnuTLS `3.8.13`
was already recovered by existing banner evidence, and the new path provides a
second independent proof.

## NULL-argument proof

The accepted pattern is:

1. A defined exported function has a bounded body.
2. Its first argument is tested against zero.
3. The zero branch targets a block inside the function.
4. That block performs only a supported constant pointer return.
5. The pointer maps to a read-only, NUL-terminated semantic version.

The implementation supports the tested x86-64 `test/je` and AArch64 `cbz`
forms, and reuses the existing ARM32/Thumb pointer parser. A branch that returns
NULL, an undefined function, a call-dependent string, or a non-version string is
rejected.

Current probes:

- GnuTLS `gnutls_check_version`
- libidn2 `idn2_check_version`
- libtasn1 `asn1_check_version`

## Database provenance

Scan reports now have top-level `database_provenance` with, for each enabled
database:

- kind, display name and release;
- immutable SHA-256 and byte size;
- database schema;
- source URL, license and architecture;
- manifest properties;
- integrity algorithm, result and status.

Component evidence includes a `sha256:<database-digest>` provenance ID in
addition to the existing release property. A hash-disabled scan is explicitly
marked `size-manifest-match-hash-not-verified`.

NSRL lookups now preserve:

- target file SHA-256 and size;
- returned match count;
- total match count;
- truncation state;
- database release and digest;
- distribution-package version semantics.

The scan report distinguishes a database being disabled, a failed lookup, zero
matches, and a successful exact match. Neither database is allowed to write a
component `resolved_version`.

## Real database controls

### NSRL

The product query path was exercised against one immutable row from the real
`2026.03.1` Android-minimal database:

- query SHA-256:
  `000000d40dca9c793e8fd21f6bbdc4f35865e6624a0fbaf2761d9e503a406c98`;
- size: `1,328`;
- expected file: `md_listitem_multichoice.xml`;
- result: one exact row;
- duration: 0.214 seconds;
- database digest:
  `2f3203615d96e6079fda9a65d39cad4b2a9100fa8f7e6f54a3c74cc5eee1d315`.

This proves the lookup mechanism and the index path. It is a control record,
not a hit counted against either firmware.

### BLintDB

The real integration path was run on Allwinner `/lib/libexpat.so`:

- target SHA-256:
  `14a7135bd66bcc169c3718f086ef20a29c186073ca4d5115a72a517c5115efda`;
- BLintDB confirmed component identity: `expat`;
- candidate reference version: `2.9.0`;
- target binary self-version: `2.1.0`;
- result: identity confirmed, version comparison `mismatch`,
  `diagnostic-only-no-version-overwrite`;
- database digest:
  `93bcb321c5c3bc8933cdad5c63454312838750f88053ed0223fd4c2e0da5112e`.

This is an important positive control: the database can identify the component
while its reference build version demonstrably disagrees with the target. The
scanner keeps the target evidence and does not manufacture agreement.

## Firmware impact

The two target BOM snapshots do not contain components named GnuTLS, libidn2 or
libtasn1 at top level. The new getters therefore have no claimed 0.17.0
fixed-cohort increment on these images. Their demonstrated gain is on the
stripped Debian regression corpus and future firmware.

NSRL still has zero exact-file matches on the two target firmware images.
BLintDB remains useful for identity confirmation and mismatch diagnostics, but
does not directly increase verified version coverage in these samples.

## Artifacts

- `reports/heldout-debian-independent3-20261120-null-getters/heldout-report.json`
- `reports/version-coverage-getters-20261120/database-positive-controls-20261120.json`
- `reports/version-coverage-getters-20261120/database-integration-positive-control-20261120.json`
- `src/firmware_scanner/extraction/semantic_version.py`
- `src/firmware_scanner/databases/manifest.py`
- `src/firmware_scanner/databases/enricher.py`
- `src/firmware_scanner/databases/nsrl.py`

## Next gaps

- Add documented optional-output APIs such as c-ares `ares_version`.
- Handle complete major/minor-only APIs such as Nettle without inventing patch
  versions.
- Run broader BLintDB identity positive controls across architectures.
- Preserve upstream archive/signature verification results when a database is
  acquired, in addition to the installed SQLite digest.
