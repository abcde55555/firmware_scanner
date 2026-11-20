# Version 0.33.0: structured version abstentions

Date: 2026-11-20

Scanner: 0.33.0

Rule release: `builtin-2026.11.20.13`

## Result

Version 0.33.0 makes version unknown states actionable. When a component has a
confirmed identity but no safe target release, the scanner now emits:

- `firmware:version:resolution-state = unknown`
- `firmware:version:evidence-tier = identity-only`
- `firmware:version:abstention-reason =
  identified-component-has-no-target-release-evidence`
- `firmware:version:required-evidence` describing what can promote the value

The provenance report also counts and lists every abstention. This preserves
component identity and explains why a version is absent instead of exposing a
bare empty field.

## Codec investigation

### OpenCORE-AMR

The Allwinner and Modern `librtp_jni.so` binaries contain the exported
OpenCORE AMR API and implementation symbols, including `AMRDecode`,
`Decoder_amr`, `cod_amr`, and GSM-AMR support functions.

The corresponding AOSP source identifies 3GPP AMR codec specifications such as
R99 3.2.0 and REL-4 4.0.0. Those are speech-codec standard versions, not the
release of the containing OpenCORE library. The decoder is also statically
embedded in an Android `frameworks/av` wrapper. No legal source-to-release
mapping is available for the target.

### PVMP3

The Allwinner `libstagefright_soft_mp3dec.so` binary exposes `pvmp3_*` decoder
symbols and MPEG-1/2/2.5 bitstream handling. Those MPEG markers identify the
codec format, not a library release.

The only additional source evidence is the Android
`frameworks/av/media/libstagefright/codecs/mp3dec/SoftMP3.cpp` wrapper path.
Assigning its platform revision to `pvmp3dec` would create misleading provenance.

## Real firmware effect

A full Allwinner scan emits three identified version abstentions:

- `opencore-amr` in `/lib/librtp_jni.so`
- `opencore-amr` in `/lib/libstagefright_soft_amrdec.so`
- `pvmp3dec` in `/lib/libstagefright_soft_mp3dec.so`

Existing usable-version coverage remains unchanged:

| Firmware | All usable | Native usable |
|---|---:|---:|
| Modern Android 16 | 791/1,129, 70.06% | 627/774, 81.01% |
| Allwinner Android 4.4.4 | 197/582, 33.85% | 60/312, 19.23% |

This release improves decision quality and user-facing uncertainty, not
headline coverage.

## Validation

- Full suite: 848 passed, 39 skipped, 7 known warnings.
- Allwinner scan confirms structured abstentions for both codec components.
- No AOSP wrapper or codec-standard version is promoted to a component release.

## Artifacts

- `reports/version-coverage-getters-20261120/version-0.33.0-allwinner-final/`
- `reports/version-coverage-getters-20261120/version-0.33.0-final-summary.json`
- `reports/version-coverage-getters-20261120/wheel-0.33.0-final/`
