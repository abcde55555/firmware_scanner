# Version 0.37.1: compact CycloneDX metadata

Date: 2026-11-21

Scanner: 0.37.1

## Problem

CycloneDX metadata contained the full internal provenance statistics payload as
one JSON string. A Modern Android 16 evaluation produced a
`firmware:provenance:stats` value of **361,515 characters** because it included
every platform-build, parent-package, source-revision and propagated-row entry.

The same metadata also duplicated database provenance and self-check details in
`firmware:database:stats`.

## Change

CycloneDX metadata now keeps bounded summaries:

- counters and rates;
- resolution-state totals;
- scope declarations;
- compact NOTICE/license attribution counters.

Detailed row arrays, self-check payloads and duplicated database provenance are
omitted from the metadata property. They remain available in the raw JSON
analysis output and per-component evidence.

## Measured effect

Using the existing Modern Android 16 analysis:

| Property | Before | After |
|---|---:|---:|
| `firmware:provenance:stats` | 361,515 chars | **733 chars** |
| `firmware:database:stats` | 3,044 chars | **704 chars** |
| Total metadata property payload | about 366.8 KB | **about 3.7 KB** |

Component-level properties are unchanged. Evidence locations, resolution states,
source revisions, confidence, relationships and database candidates remain
attached to the components that earned them.

## Boundaries

- The compact metadata property is intended for dashboards, policy gates and
  automated explanations.
- Full provenance rows are an internal audit format, not a stable CycloneDX
  component contract.
- Consumers needing every row should read the raw analysis JSON sidecar.
