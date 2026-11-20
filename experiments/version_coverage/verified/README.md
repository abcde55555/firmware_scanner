# Source-verified calibration subsets

These maps contain expected versions established from primary upstream or AOSP
sources. They are used to measure precision on a small, explicit calibration
subset.

They are not held-out datasets: the same source versions informed scanner
rules. A held-out result requires a separate firmware or artifact set whose
truths were not used during rule development.

## Allwinner `KTU84Q` / AOSP `android-4.4.4_r2`

`allwinner-ktu84q-aosp-4.4.4.json` maps frozen baseline observations to:

| Component | Expected | Primary source |
|---|---:|---|
| libjpeg | `6b` | The target enforces ABI 62 and AOSP `jversion.h` declares `6b`; this is an implementation estimate, not an ABI-only exact claim |
| libexif | `0.6.21` | AOSP `external/libexif` tag `android-4.4.4_r2` `configure.ac` |
| libspeexresampler | `1.2beta3` | AOSP `external/speex` tag `android-4.4.4_r2` `libspeex/arch.h` |
| libstlport | `5.0` | AOSP `external/stlport` tag `android-4.4.4_r2` `README` |
| libjhead | `2.87` | AOSP `external/jhead` tag `android-4.4.4_r2` `jhead.c` |

Run:

```sh
PYTHONPATH=. python experiments/version_coverage/evaluate.py \
  reports/function-version-experiment-20261118/after/allwinner/system_analysis.json \
  reports/version-coverage-getters-20261120/final-allwinner/system_analysis.json \
  --baseline-commit e890f0c \
  --verified experiments/version_coverage/verified/allwinner-ktu84q-aosp-4.4.4.json
```

### v0.36 AOSP build-ID and platform provenance calibration

`allwinner-ktu84q-aosp-provenance-0.36.json` maps the 15 newly resolved
calibration observations to either:

- the official AOSP `android-4.4.4_r2` manifest project revision for
  `external/chromium`, `external/compiler-rt`, `external/neven`,
  `external/skia`, `external/webrtc`, `external/v8` and
  `external/bluetooth/bluedroid`;
- the target image's `4.4.4-KTU84Q-20180511` build baseline for seven stable
  system-partition AOSP modules.

The manifest repository revision is
`64f4f353b72203e5225b03fd3432f0825345f6bb`. Project revisions were verified
against each Google Source repository's `refs/tags/android-4.4.4_r2`.

This calibration set informed the v0.36 rules and is not a held-out accuracy
set. It measures whether those newly accepted observations agree with their
primary source evidence.

```sh
PYTHONPATH=src python experiments/version_coverage/evaluate.py \
  reports/function-version-experiment-20261118/after/allwinner/system_analysis.json \
  reports/version-coverage-getters-20261120/version-0.36.0-allwinner-source-fallback/system_analysis.json \
  --baseline-commit e890f0c \
  --verified experiments/version_coverage/verified/allwinner-ktu84q-aosp-provenance-0.36.json
```
