# Firmware SBOM version evidence and database operations

Date: 2026-11-19

## Recommended product direction

The supplied commercial roadmap is useful as a menu of techniques, but its
coverage percentages are targets rather than measured results for this
repository. The next product improvement should be evidence quality and
auditable version resolution, followed by broader reference coverage.

The scan should keep these outcomes separate:

| State | Meaning | Vulnerability query policy |
|---|---|---|
| `exact` | A binary object, getter, version banner, or an exact pinned source revision declares a release with strong evidence. | Eligible when the component maps to an upstream project. |
| `estimated` | The release is inferred from a lower-confidence binary rule, filename, or source/build relation. | Not sent to upstream OSV/CPE matching. |
| `equivalence-class` | Several releases remain indistinguishable for a well-defined evidence set. | Not collapsed into a guessed version; not sent as a single release. |
| `conflict-unresolved` | Multiple observations disagree. | Not sent; preserve all conflicting evidence. |
| `unknown` | The component identity is useful, but no release was recovered. | No version query. |

`resolved_version` answers which value is most useful to display.
`firmware:version:resolution-state` answers how far that value may be trusted.
These are different fields and must not be replaced by a “version present”
metric.

## External database integration

Each database is an optional evidence source, not a source of target versions.
The Android filesystem pipeline and the generic section-analysis pipeline share
the same enricher and evidence semantics.

For generic firmware, database lookup happens for ELF files passed through
`SmartSectionAnalyzer`. A smoke scan of `/bin/echo` queried one unique ELF and
emitted the database/cache statistics in both JSON and CycloneDX metadata.

### BLintDB

Use BLintDB for:

- binary-to-project identity candidates;
- a reference build with symbols and dependencies;
- a prior for a later version-difference or source-revision proof.

Do not copy the version in a Conan deploy path into the scanned firmware
artifact. It describes the reference build that produced the database row.
Require informative identity symbols; a filename match alone, or a match based
on linker/runtime symbols shared across projects, is insufficient.

### NIST NSRL

Use NSRL for:

- exact file hash provenance;
- distribution/package context;
- confirming that a file is known to a publisher or release set.

Do not treat the NSRL package version as the upstream library version. Rebuilt
binaries, AOSP-adapted sources and vendor changes normally produce a different
hash, and a distribution version is not the version of an embedded library.

The pinned NSRL Android minimal database is about 40 GB. Integrity checks scan
the complete file, so the scanner caches the result by inode, size, mtime,
ctime and SHA-256. Normal scans reuse the verified digest unless file metadata
changes. `--skip-database-integrity` still performs manifest size, schema and
table compatibility checks, but omits the full-file SHA-256 read.

`files_queried` in database statistics counts unique binary-content cache
misses. Repeated byte-identical paths reuse the cached evidence instead of
querying SQLite again. `analysis_stats.content_cache_hits` reports the number
of reused paths, so the two counts should be read together.

BLintDB identity lookup now runs even when a target version is already known.
`blint_queried_files`, `blint_candidate_files`, and
`blint_identity_confirmations` show whether the database was exercised and
whether the candidate corroborated the component. The confirmed identity is
stored separately from the candidate's reference version. A high-confidence
identity can feed CPE synthesis and OSV package selection; the reference
version cannot replace the target version.

NSRL records `nsrl_queried_files` independently from
`nsrl_matched_files`. A zero-hit result therefore means all eligible ELF
contents were checked and no exact hash matched, rather than the database being
unused.

## Immutable source-version pins

The image source manifest gives a project and exact commit. The commit alone is
more useful than “unknown”, but a git hash is still a build revision rather
than an upstream release.

For source revisions that can be audited from the same tree, the scanner now
uses a `source-version-pins.json` record containing:

- exact project path and commit;
- declared release value;
- upstream/project source URL;
- the exact version authority, such as a version header or build definition.

A pin is ignored unless both the project path and full commit match. It cannot
apply merely because a future image has the same project name.

Explicit AOSP source paths also receive a conservative taxonomy:

- `external/*`: `third-party-oss`
- `frameworks/*`, `system/*`, `hardware/*`, `packages/modules/*`, `art/*`,
  `bionic/*` and selected platform projects: `platform-first-party`
- `vendor/*/opensource/*`: `vendor-open-source`
- other `vendor/*` projects: `vendor-proprietary`

Unattributed components remain without a taxonomy rather than being guessed
into a denominator. Components with an explicit external ecosystem PURL such as
Maven, Cargo, npm, PyPI, Go or Conan are classified as `third-party-oss`.

BLintDB-confirmed component identities can also establish
`third-party-oss` taxonomy because BLintDB entries are reference builds of
open-source C/C++ projects. Taxonomy provenance is recorded separately as
`firmware:taxonomy:evidence` with values such as `source-project-path`,
`external-ecosystem-purl` or `blintdb-confirmed-identity`.

An exact source pin has lower deployment portability than a binary getter, but
it prevents a common false positive: treating an AOSP build revision or parent
APEX version as the upstream library release. The source URL and authority are
also emitted in component properties so the result can be reviewed.

The initial pack covers current-image libraries including FreeType, HarfBuzz,
JsonCpp, libexif, TinyXML-2, ICU, libbpf, libnl, libcap, libevent, zlib,
libdrm, NTFS-3G, e2fsprogs, protobuf, libfuse, dav1d, libcap-ng, Ultra HDR,
libyuv and the Android 7-Zip LZMA SDK. Android `external/lzma` is explicitly
excluded from XZ Utils vulnerability queries because it is the LZMA SDK.

## Rule and database ownership

Keep the core binary rules, source-project rules, source-version pins and
packaged database manifests in this repository while their total volume remains
small. This keeps code, tests, provenance and scan behavior atomic.

`src/firmware_scanner/data/rules.lock.json` pins every bundled JSON data pack by
SHA-256 and records a release identifier. Scans verify it before unpacking and
write the release and lock digest into JSON and CycloneDX output. Run
`PYTHONPATH=. python3 tools/update_rules_lock.py --check` in CI and regenerate
the lock only when intentionally changing a rule or provenance file.

Move large or frequently updated reference corpora to a separate
`firmware-scanner-rules` repository. Consumers must pin an immutable tag and
verify a `rules.lock.json` containing:

- schema version;
- pack release/tag;
- content SHA-256;
- producer and source URLs;
- compatible scanner range;
- enabled rules and database schema requirements.

Database manifests follow the same rule: matching file size alone is not
enough. The release, schema, byte count and SHA-256 must all be pinned.

## Dependency and vulnerability boundaries

ELF `DT_NEEDED` is a static declaration. It becomes a CycloneDX dependency only
when the target firmware contains one unambiguous provider for the SONAME.
When several components provide the same SONAME, the scanner omits the edge
until linker namespace, ABI and search-path resolution disambiguate it.

An exact version is eligible for downstream vulnerability matching. Estimated
source revisions, parent package versions, equivalence classes and unresolved
conflicts are not. This avoids turning a coverage increase into an automatic
vulnerability false-positive increase.

CycloneDX round-trip parsing preserves component `properties` and the
component-level `cpe`. Without that preservation, scanning a previously
generated BOM would lose the resolution-state gate and could query estimated
versions against upstream OSV ecosystems. The parser therefore treats the BOM
as a loss-conscious interchange format, not only a display artifact.

BLint-confirmed identity is preferred over an opaque SONAME for upstream lookup
when no ecosystem PURL is available. For example, `libft2.so` maps to the
confirmed component `freetype`, producing the upstream CPE and OSV package
query while preserving the firmware filename as the BOM component identity.

## NOTICE license evidence

Android NOTICE HTML is parsed as image-local license evidence. Attribution
requires a strong license signature such as Apache 2.0, BSD, MIT, ISC, Zlib,
OpenSSL or the FreeType Project License. General copyright statements and
product names do not create an SPDX claim.

`/system/...` paths receive one controlled alias without the `/system` prefix
for older images whose filesystem root is the system partition. Existing
licenses are preserved. New notice-derived licenses carry:

- `firmware:license:evidence`;
- `firmware:license:match-confidence=0.95`.

The provenance report records pre-deduplication NOTICE binding counts, while
`license_stats` reports final unique-component coverage after all deduplication
and license merging. A component without a license makes the overall status
`incomplete`; the scanner never emits `compliant` from partial data.

APK/JAR archives add two scoped evidence sources. Root `META-INF/LICENSE`,
`LICENSE`, `NOTICE` and similarly named files apply only to the application
component. Maven `pom.xml` licenses apply only to the matching dependency when
the archive path, group, artifact and explicit version agree. Neither source is
propagated to unrelated embedded native libraries.

Binary getters can also supply exact evidence when newer compilers inline the
implementation. On the Allwinner ARM32 ICU libraries, `u_getVersion_51` loads a
read-only `51.1.0.1` literal and parses its four numeric fields directly rather
than tail-calling `u_versionFromString_51`. The scanner verifies the getter and
helper symbol pair, the public API generation, the PC-relative literal load and
the dotted-decimal value. It must not infer `5.1.x`: ICU's documented symbol
suffix transition makes `_51` ICU 51, while `_48` is ICU 4.8.

The same-source family pass is intentionally narrow. It requires one
unambiguous exact-or-estimated donor and known shared-source library names.
Inherited ICU and e2fsprogs siblings are stored with
`firmware:version:resolution-state=estimated` and `version_estimate`; they do
not become OSV-queryable merely because the donor was exact.

## Adoption order

1. Maintain exact binary objects/getters and audited source-version pins.
2. Expand identity fingerprints only from documented, distinctive API symbol
   combinations.
3. Use BLintDB candidates to prioritize version-difference work, not as final
   versions.
4. Add held-out truth fixtures before accepting the roadmap's precision and
   recall thresholds.
5. Evaluate C/C++ Version-Delta, Ghidra BSim, QEMU execution and RTOS/UEFI
   expansion against measured incremental hits, cost and false-attribution
   rates.

The immediate commercial improvement is therefore not “scan more strings”.
It is an auditable progression from component identity to declared release,
then to vulnerability-ready release semantics.
