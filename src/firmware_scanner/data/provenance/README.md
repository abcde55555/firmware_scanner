# Android provenance rule packs

This directory contains version-controlled source-provenance data used by the
Android system scanner.

## Files

- `waydroid-atv-20260403.json` is pinned to one exact system-image SHA-256 and
  contains the AOSP project revisions from that image's build manifest.
- `android_source_project_rules.json` maps unambiguous Android HAL namespaces
  to the AOSP project that emits them.

The image-specific manifest is never selected by filename, build fingerprint,
or project name alone. The scanner must calculate the input image SHA-256 and
match the `image_sha256` field exactly. An explicitly supplied manifest follows
the same rule.

## Schema rules

- Keep source repository, project path, and full revision in every image pack.
- Never store credentials or mutable branch references as the authoritative
  revision.
- Prefer a NOTICE file-to-project mapping. Use namespace rules only when the
  namespace belongs to one known AOSP project.
- Keep the rule generic. Vendor-specific observations belong in a new pack or
  a narrower pattern with a source URL and enabled-version conditions.
- Source revisions and parent package versions remain marked as estimates.
  They are excluded from upstream CPE generation and OSV version queries.

## Update workflow

1. Record the exact image SHA-256 and public release/source location.
2. Add or update the image pack and its project revisions.
3. Add a positive fixture and a wrong-hash/negative fixture.
4. Run the focused provenance, Android scanner, APEX, binary accuracy, and
   vulnerability-matcher tests.
5. Re-scan the affected firmware and compare the frozen version-coverage
   denominator before committing the rule pack with the code change.
