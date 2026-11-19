# Rust source-location evidence for version differencing

**Date:** 2026-11-19
**Scope:** First-party Rust and Android sources; research only. The observations about the target ELF and candidate crate pin below are supplied by the task owner and were not independently re-parsed here.

## Finding

The decoded `{file_ptr, len, line, column}` records are plausible Rust panic/caller-location payloads and can be valuable source fingerprints. They are not a Rust ABI contract and do not identify an exact crate release by themselves. Treat each tuple as a location hint to compare against candidate source trees, then corroborate it with nearby panic text, constants, control flow, and other independent locations.

The task reports: 62 of 748 unknown native libraries are NOTICE candidates under `external/rust/android-crates-io`; candidate checkout pin `c991cad10330f37e93d82926bd6dae7f4f6647f6`; `libaho_corasick.dylib.so` has no `.rustc` or version path; ELF64 little-endian `SHT_ANDROID_RELR` (`0x6fffff00`) decodes to 127 read-only 24-byte records in GNU_RELRO, with file strings under `external/rust/android-crates-io/crates/aho-corasick/src/...rs`. The pin's `Cargo.toml` says `aho-corasick 0.7.20`; that is a source-checkout candidate, not proof that the shipped library is that version.

## What `Location` guarantees

At Rust 1.83.0, [`core::panic::Location`](https://github.com/rust-lang/rust/blob/1.83.0/library/core/src/panic/location.rs) has private `file: &str`, `line: u32`, and `col: u32` fields and no `#[repr(C)]`. The [Rust representation rules](https://doc.rust-lang.org/1.83.0/reference/type-layout.html#the-rust-representation) do not promise field order, padding, or stable layout for ordinary Rust-representation structs. Public methods expose `file()`, `line()`, and `column()`; this is an API-level semantic contract, not an in-memory wire format.

Thus a 64-bit file slice representation (pointer plus length) followed by two 32-bit integers is consistent with the observed 24-byte shape, but matching shape alone cannot establish the Rust type or compiler version. Layout can change with Rust/compiler implementation, target, and build. The tuple should be decoded from its surrounding pointers/strings and mapped to source, not treated as a serialized `Location` ABI.

## How source coordinates can move

- [`#[track_caller]`](https://doc.rust-lang.org/1.83.0/reference/attributes/codegen.html#the-track_caller-attribute) makes a function report its caller's location. Calls through chains of tracked functions can propagate the original call site, so a panic-related tuple may point at a crate caller rather than the helper containing the panic. The [official attribute docs](https://doc.rust-lang.org/1.83.0/reference/attributes/codegen.html#the-track_caller-attribute) describe this behavior; the [`Location::caller` implementation](https://github.com/rust-lang/rust/blob/1.83.0/library/core/src/panic/location.rs) obtains it through the compiler caller-location intrinsic.
- Rust's built-in [`file!`, `line!`, and `column!` macros](https://github.com/rust-lang/rust/blob/1.83.0/library/core/src/macros/mod.rs) report the first macro invocation leading to the builtin macro. Macro-generated panic code can therefore carry an invocation-site coordinate rather than the macro definition's textual line. The macros are 1-based for line/column as documented in that source.
- `rustc --remap-path-prefix` can rewrite source paths embedded in compiler output. The [rustc remapping guide](https://doc.rust-lang.org/1.83.0/rustc/remap-source-paths.html) specifically includes paths used by `file!` and panic messages; the mapping is textual and relative paths may be retained. A path's spelling is therefore build-configuration evidence, not a canonical checkout path.
- On nightly, `-Z location-detail` can omit file, line, or column details; see the [Rust Unstable Book](https://doc.rust-lang.org/1.83.0/unstable-book/compiler-flags/location-detail.html). Missing fields/strings are not evidence that a crate lacks panic sites.

## Why it can distinguish adjacent crate sources, and limits

For a known candidate source tree, a file-relative line/column narrows the search to a specific expression or macro invocation. A set of coordinates plus nearby panic literals, error constants, and branch structure can distinguish adjacent source revisions when those regions changed. This is especially useful when version strings and `.rustc` metadata are absent.

It remains source correspondence, not exact-version proof. Different releases can leave a site unchanged; line numbers can shift for unrelated edits; macros and `track_caller` can move the recorded site; path remapping can alter names; and the binary may be patched, backported, or built from a fork. The NOTICE candidate set and a pinned `Cargo.toml` supply provenance leads, not evidence that the exact pinned source was compiled. Report a version only when multiple independent source fingerprints and package/build provenance converge; otherwise report the crate/source family and candidate range as unresolved.

## Android relocation format boundaries

- Android's pinned [`elf.h`](https://android.googlesource.com/platform/bionic/+/4782b4e08510d709a0e2867fc86c2f99ca776490/libc/include/elf.h) names `SHT_ANDROID_RELR = 0x6fffff00`; it separately names legacy `SHT_ANDROID_REL`/`SHT_ANDROID_RELA` (`0x60000001`/`0x60000002`). `SHT_ANDROID_RELR` is an Android OS-private spelling of RELR, not APS2.
- Bionic documents that Android RELR arrived experimentally at API 28 and standard `SHT_RELR`/`DT_RELR` at API 30, and explicitly says RELR is unrelated to the older packed-relocation format ([pinned NDK note](https://android.googlesource.com/platform/bionic/+/1eacc0edc/android-changes-for-ndk-developers.md)). Do not infer the section's on-disk bounds from its name: validate ELF class/endianness, section type, `sh_offset + sh_size`, entry width/alignment, and bounds before decoding.
- RELR is a word stream: even entries give a relocation address; odd entries are bitmaps over subsequent machine-word slots. Bionic's [pinned decoder](https://android.googlesource.com/platform/bionic/+/47df89fcf/linker/linker.cpp) shows 64-bit words advancing by 8 bytes and a bitmap window of 63 following words. Guard address arithmetic, bitmap-window advancement, file/virtual-address translation, and every resulting read against overflow and mapped-file/segment bounds. RELR identifies relative relocation sites; it does not itself define the pointed-to record's Rust meaning.
- APS2 (“Android packed relocations”) is the distinct legacy `DT_ANDROID_REL[A]` stream. Bionic's [relocation-packer README](https://android.googlesource.com/platform/bionic/+/f5e0ba94d911ef2622ecfd3f7fabc4432a4806d3/tools/relocation_packer/README.TXT) describes run-length, delta, and LEB128 encoding. Its decoder must validate the APS2 magic/header, relocation count, group size/flags, signed LEB128 values, cumulative offset/addend arithmetic, and input exhaustion; do not pass APS2 bytes to a RELR bitmap decoder. Android's [linker changes](https://android.googlesource.com/platform/bionic/+/c630da59280dfe24ba5c72d78ad6f3ea72d0ee33/android-changes-for-ndk-developers.md) likewise distinguishes packed relocations from RELR.

## Source links

All repository links above are pinned to a Rust release tag or Android source commit where available. Official Rust reference/book URLs are versioned to 1.83.0. No blogs or vendor SBOMs were used. This note makes no accuracy-rate or novelty claim.
