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
