# External database manifests

These JSON files describe optional external SQLite databases. They do not
contain the multi-gigabyte database payloads.

Each manifest pins:

- database kind and release;
- exact byte size and SHA-256;
- required database schema version;
- official source URL and license metadata;
- evidence semantics for target-version handling.

The scanner selects a manifest by database kind and byte size, then verifies
the SHA-256 unless integrity verification was explicitly skipped. Schema and
table compatibility checks always run.

To add a database release:

1. Obtain it from the recorded official source and retain the upstream
   signature or release checksum when available.
2. Calculate the raw SQLite file SHA-256 after decompression.
3. Add a new manifest rather than mutating an existing release manifest.
4. Test exact hit, no-hit, malformed-schema and integrity-mismatch paths.
5. Record whether each returned value is a target version, identity candidate,
   reference-build candidate or distribution-package version.

Database releases may stay outside this repository. Their manifests and tests
must remain version controlled with the scanner so an identical scan can
reference an immutable database release.
