# Held-out Debian binary version validation

Date: 2026-11-19

## Method

This set is independent from the two firmware images used during scanner
development. It uses Debian package metadata as truth for one explicitly mapped
upstream library per package.

The harness:

- verifies the package is installed with `dpkg-query`;
- resolves one exact SONAME from the package file list;
- copies the real library and applies `strip --strip-all`;
- runs only `BinaryInventory`, with static parsing and no target execution;
- normalizes Debian epoch and package revision from the upstream release;
- reports exact, estimated, wrong and unknown outcomes separately.

The 21 samples are an initial held-out seed, not a production accuracy gate.
Catalog identity matching is based on explicit filename/component aliases and is
not an independent identity-precision claim.

Reproduce:

```bash
python3 experiments/version_coverage/debian_heldout.py \
  --output reports/heldout-debian-20261119
```

## Result

| Metric | Result |
|---|---:|
| Samples | 21 |
| Catalog identity matched | 21 |
| Exact version | 19 |
| Estimated version | 0 |
| Wrong exact version | 0 |
| Unknown version | 2 |
| Usable version coverage | 19/21, 90.48% |
| Exact coverage | 19/21, 90.48% |
| Precision among exact/version claims | 19/19, 100% |

The two unknown libraries are:

| Package | Library | Truth | Reason |
|---|---|---:|---|
| `libfreetype6` | `libfreetype.so.6` | 2.14.1 | The Debian build shape is not accepted by the fail-closed FreeType paired-API probe. |
| `libcapstone5` | `libcapstone.so.5` | 5.0.7 | `cs_version` exposes only major/minor `5.0`; patch `7` is not available. |

These remain unknown rather than being guessed from the Debian package version.

## Newly recovered evidence

- PCRE2 `10.46` from the release-date banner, with ABI-suffixed SONAMEs such as
  `libpcre2-8.so.0` attributed to the PCRE2 component.
- libssh2 `1.11.1` from the explicit SSH banner.
- Brotli `1.2.0` from `BrotliDecoderVersion`, attached as an exact
  `contains-evidence-for` component rather than promoted to the opaque host
  SONAME.
- FreeType production probe recovered `2.13.2` from the real modern Android
  AArch64 library. The same probe is fail-closed on the Debian FreeType build
  and on unsupported control-flow shapes.

The FreeType probe was promoted from `experiments/version_coverage` into the
packaged `firmware_scanner.extraction.freetype_version` module. The existing
negative tests continue to reject overlapping writes, conditional initializers,
wrong output paths and allocator bypasses.

## Boundary

Debian package metadata proves which upstream release was packaged, but it is
not a universal source of library versions. Normalization and package/library
mapping are explicit in the catalog. A new package must be mapped and reviewed
before it enters this held-out set.

The machine-readable report is:

`reports/heldout-debian-20261119/heldout-report.json`
