# Debian stripped-library version validation

Date: 2026-11-20
Scanner: 0.9.0

## Purpose and boundary

The harness evaluates `BinaryInventory` on real Debian shared libraries copied
from package files and stripped with `strip --strip-all`. Debian package
metadata is the truth for the one explicitly mapped upstream library in each
package. Target binaries are never executed.

Catalog identity is matched through explicit package/SONAME/component aliases.
That is useful for the version probe but is not an independent measurement of
component identity precision. These results also do not prove accuracy on the
Android firmware images.

Reproduce:

```bash
PYTHONPATH=src python3 experiments/version_coverage/debian_heldout.py \
  --output reports/heldout-debian-54-20261120-final

PYTHONPATH=src python3 experiments/version_coverage/debian_heldout.py \
  --suite independent \
  --output reports/heldout-debian-independent-20-20261120-final
```

Missing packages are downloaded as `.deb` files and extracted with
`dpkg-deb -x`; they are not installed.

## 54-library development suite

The initial 54-library run exposed two concrete failures:

- Debian `libbpf` `1.6.2` was reported as exact `1.6` even though
  `libbpf_version_string` only exposed major/minor generation information.
- `libyaml-0.so.2` normalized to `yaml0` and was not attached to the `yaml`
  catalog identity.

The final run also adds conservative getters and version objects for libjxl,
libsndfile, libsamplerate, libsoxr, libyaml, LZO, libzip, libaom, GMP, seccomp,
nghttp2, nghttp3 and ngtcp2.

| Metric | Initial 54 run | Final 0.9.0 |
|---|---:|---:|
| Catalog identity matched | 53/54 | 54/54 |
| Exact version | 27 | 39 |
| Explicit estimate | 1 | 2 |
| Wrong exact version | 1 | 0 |
| Unknown | 25 | 13 |
| Usable version | 28/54, 51.85% | 41/54, 75.93% |
| Exact coverage | 27/54, 50.00% | 39/54, 72.22% |
| Precision among version claims | 96.43% | 100% |

`libbpf` is now `estimated 1.6.x`; no patch release is fabricated. Ground-truth
`1.6.2` remains distinguishable from the narrower release declaration.

Machine-readable result:
`reports/heldout-debian-54-20261120-final/heldout-report.json`.

## 20-library cold-start suite

A separate 20-library suite was selected and run once before adding the new
getter coverage:

| Metric | First unseen run | After general getters |
|---|---:|---:|
| Catalog identity matched | 17/20 | 20/20 |
| Exact version | 2 | 12 |
| Wrong exact version | 0 | 0 |
| Unknown | 18 | 8 |
| Usable coverage | 10% | 60% |
| Precision among version claims | 100% | 100% |

The jump from 2/20 to 12/20 proves that familiar public APIs carried most of
the cold-start gap. It is no longer a fully held-out suite after those rules
were developed. Future accuracy claims should use a newly selected suite or a
cross-distribution corpus that remains untouched while rules are changed.

Machine-readable result:
`reports/heldout-debian-independent-20-20261120-final/heldout-report.json`.

## What remains unknown

- Capstone exposes only major/minor and cannot prove the Debian patch release.
- The current FreeType paired-API proof rejects the tested Debian build shape.
- libvorbisenc, libsndfile companion libraries, libexif, libsnappy, libdeflate,
  libtasn1, systemd/udev and several others do not expose an accepted release
  object or getter in the tested build.
- Project SONAME, ABI version nodes and library filenames are not treated as
  upstream releases.

The next step is a new independent corpus spanning Debian, Alpine and OpenWrt
with different compiler flags. Expanding the same 54 catalog after inspecting
it would improve the visible score without improving demonstrated generalization.
