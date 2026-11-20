# Version 0.32.0: standalone database audit

Date: 2026-11-20

Scanner: 0.32.0

Rule release: `builtin-2026.11.20.13`

## Result

Version 0.32.0 adds a standalone commercial database health check:

```sh
firmware-scanner database-audit \
  --blint-db /path/to/blint.db \
  --nsrl-db /path/to/android_minimal.db \
  --output database-audit.json
```

The command executes the same manifest selection and production query-control
paths used by scanning. It returns exit code 0 only when every requested check
passes and serializes failures without exposing local database paths.

## Checks

### BLintDB

- packaged manifest selection by expected file size;
- full SHA-256 verification with the existing immutable-file cache;
- required table and schema-version validation;
- import-hash schema capability;
- a real symbol → binary → build → project join;
- selection of a non-mechanical symbol for the positive control.

### NSRL

- packaged manifest selection and full SHA-256 verification;
- `FILE` and `PKG` schema checks;
- an exact SHA-256 plus file-size positive-control query;
- truncation metadata and package-version semantics.

Each check records duration and database release/digest provenance.

## Real database audit

The retained databases passed the standalone audit:

| Database | Release | Digest verified | Query control |
|---|---|---|---|
| BLintDB | v4 | yes | symbol/project join passed |
| NSRL Android Minimal RDS | 2026.03.1 | yes | exact-file lookup passed |

The BLintDB first-row mechanical symbol `$d` is no longer accepted as evidence;
the audit scans a bounded set of rows and selects a meaningful identity symbol.

The machine-readable artifact is:

`reports/version-coverage-getters-20261120/database-audit-0.32.0.json`

## Existing firmware and accuracy

This release changes database operability and auditability, not version-matching
rules. The authoritative firmware and held-out results therefore remain:

- Modern Android: 791/1,129 all usable; 627/774 native usable.
- Allwinner Android: 197/582 all usable; 60/312 native usable.
- Independent-7 tuned regression: 10/20 exact, zero wrong.
- Independent-8 tuned regression: 6/20 exact, zero wrong.

## Validation

- Full suite: 847 passed, 39 skipped, 7 known warnings.
- Real BLintDB and NSRL audit passes.
- Audit failures are serialized and return a non-zero CLI exit code.

## Artifacts

- `reports/version-coverage-getters-20261120/database-audit-0.32.0.json`
- `reports/version-coverage-getters-20261120/version-0.32.0-final-summary.json`
- `reports/version-coverage-getters-20261120/wheel-0.32.0-final/`
