# Version 0.37.2: source revisions are not release versions

Date: 2026-11-21

Scanner: 0.37.2

## Problem

When only an image-matched source revision was known, the scanner used an
internal value such as:

```text
git:7ef2e61de22de800fec8a734bc4019a26448e8b1
```

That value is a useful source snapshot identifier, but CycloneDX and SPDX
consumers can interpret `version` as a comparable release. The `git:` prefix is
also a project-specific sentinel rather than a standard package-version format.

## Change

Standard SBOM serializers now separate source provenance from release versions:

- CycloneDX 1.6 omits `component.version` when only a source revision is known.
- CycloneDX 1.5 uses `"unknown"` because some enterprise consumers require a
  non-empty field.
- SPDX 3.0.1 omits `software_packageVersion`.
- Package URLs and BOM references must not contain `@git:<sha>`.

The component still retains:

- `firmware:source:project`
- `firmware:source:repository`
- `firmware:source:revision`
- `firmware:version:scope`
- `firmware:version:resolution-state`
- source evidence and confidence

The raw analysis JSON likewise keeps the internal revision for diagnostics, but
standard SBOM version fields no longer expose it as a release.

## Example

For AOSP `packages/modules/ConfigInfrastructure` at commit
`7ef2e61de22de800fec8a734bc4019a26448e8b1`:

Before:

```json
{
  "version": "git:7ef2e61de22de800fec8a734bc4019a26448e8b1"
}
```

After:

```json
{
  "properties": [
    {
      "name": "firmware:source:project",
      "value": "packages/modules/ConfigInfrastructure"
    },
    {
      "name": "firmware:source:revision",
      "value": "7ef2e61de22de800fec8a734bc4019a26448e8b1"
    },
    {
      "name": "firmware:version:resolution-state",
      "value": "estimated-source-revision"
    }
  ]
}
```

## Boundaries

- A source commit remains valuable provenance evidence.
- It is not an upstream release, distro version or guarantee that no later
  vendor patch exists.
- Source-revision components remain excluded from exact upstream vulnerability
  queries.
