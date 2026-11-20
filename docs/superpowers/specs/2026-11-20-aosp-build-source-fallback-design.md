# AOSP build-ID source fallback

## Intent

Recover auditable source revisions for third-party projects embedded in Android
images whose vendor did not supply an image-matched source manifest, while
keeping source revisions distinct from upstream releases.

## Scope

- Add a release-controlled catalogue for known Android build ID/tag mappings.
- Require `android_version`, exact `build_id`, project revision and official
  AOSP manifest provenance.
- Accept a fallback only for an ELF with embedded source-path evidence:
  an explicit component-to-project rule, or one unambiguous source project.
- Prefer image-matched source manifests and platform build provenance over this
  fallback.
- Emit `estimated-aosp-source-revision`, never `exact`.

## Non-goals

- Do not claim that an AOSP tag proves a vendor tree contains no local changes.
- Do not assign sibling or dependency versions to a host ELF.
- Do not use source revisions for exact upstream OSV queries.

## Evaluation

Tests cover a unique external project, a rule-selected project among multiple
embedded projects, wrong build ID rejection, platform-build precedence and OSV
exclusion. Both supplied firmware images are rescanned.
