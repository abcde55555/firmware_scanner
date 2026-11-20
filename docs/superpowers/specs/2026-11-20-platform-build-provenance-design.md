# AOSP source-scoped platform build provenance

## Intent

Increase usable version attribution for Android first-party native components
without treating an image build identifier as an upstream component release.

## Scope

- Extend the existing `estimated-platform-build` state from framework archives
  to ELF components with explicit AOSP platform source-path evidence.
- Require source evidence to classify exclusively as `platform-first-party`.
- Keep embedded third-party components, vendor-proprietary source paths and
  mixed project evidence unknown through this rule.
- Preserve the existing scope marker
  `platform-build-not-upstream-release`, so the component remains ineligible
  for exact upstream OSV queries.
- Prefer an image-matched source revision when stronger evidence is available.

## Non-goals

- Do not assign an AOSP tag or platform build to third-party libraries.
- Do not infer source ownership from filenames alone.
- Do not change BLintDB or NSRL evidence semantics.
- Do not describe platform-build coverage as upstream-version accuracy.

## Evaluation

Unit tests cover positive AOSP source evidence, external/vendor negative cases,
embedded-component exclusion, source-revision precedence and OSV query
exclusion. The real Allwinner image is rescanned and the fixed cohort is
compared against v0.34.0. Evaluation reports estimated coverage by resolution
state so platform-build and source-revision gains remain visible separately.
