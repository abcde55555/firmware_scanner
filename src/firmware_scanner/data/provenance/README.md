# Android provenance rule packs

This directory contains version-controlled source-provenance data used by the
Android system scanner.

## Files

- `waydroid-atv-20260403.json` is pinned to one exact system-image SHA-256 and
  contains the AOSP project revisions from that image's build manifest.
- `android_source_project_rules.json` maps unambiguous HAL namespaces and
  product SONAMEs to the AOSP project that emits them.
- `source-version-pins.json` records releases declared by exact project
  revisions. Every row includes the source file that declares the version.
- `source-subproject-version-pins.json` records crate-level releases inside a
  revision-pinned monorepo. Rows include a relative subproject path, Cargo
  package identity and the revision-bound `Cargo.toml` URL.

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
- A source revision without a matching version pin remains an estimate and is
  excluded from upstream CPE generation and OSV version queries.
- A source version pin applies only when both the project path and the full
  40-character revision match. It must identify a file in that exact source
  tree, not a mutable branch, release note from another revision, or guess from
  the repository name.
- A monorepo revision does not establish the version of every component inside
  it. Subproject pins additionally require the component filename/alias to
  match the crate; an embedded dependency path cannot override the owned crate.
- Confirmed Cargo pins use `pkg:cargo/<package>@<version>`. The monorepo Git
  revision remains evidence metadata and is not substituted for crate release.
- Parent package versions remain estimates and are excluded from upstream CPE
  generation and OSV version queries.

## Update workflow

1. Record the exact image SHA-256 and public release/source location.
2. Add or update the image pack and its project revisions.
3. For a declared release, add or update a source-version pin with the exact
   revision, authority file URL, and release value.
4. Add a positive fixture, a wrong-hash fixture and a wrong-revision fixture.
5. Run the focused provenance, Android scanner, APEX, binary accuracy, and
   vulnerability-matcher tests.
6. Re-scan the affected firmware and compare the frozen version-coverage
   denominator before committing the rule pack with the code change.
