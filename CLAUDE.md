# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with
code in this repository.

## What this is

`zfsdev`: pure-Rust access to OpenZFS through `/dev/zfs`. It issues the ioctls
itself, has its own packed-nvlist codec, and decodes the kernel's stat arrays
into typed structs. No libzfs, no FFI, no `zfs`/`zpool` output scraping. The
layer was split out of zfs-browser (`../zfs-browser`) with git-filter-repo,
keeping its history; zfs-browser consumes it with `features = ["write"]`, so
an API change here ripples there.

Modules (`src/`): `ioctl` (`ZfsHandle`, Linux-only), `nvlist` (codec),
`stats` (`vdev_stat_t`, `pool_scan_stat_t`, rebuild stats, `vdev_stats_ex`),
`vdev` (the vdev tree walker: depth, `zpool` name, `VdevRole`),
`enums` (C-enum mirrors, `Coded<E>`, `CEnum`), `props` (property names, value
enums, decode/parse, `PropEntry` over the `{value, source}` nvlists), `kstat`
(procfs SPL kstats: ARC, import progress, the debug log, the lock-free pool
list, and per pool txgs, tx-assign histogram, objset counters, state;
`kstat` feature), `wrapkey` (libzfs wrapping-key
derivation).

## Design rules

- **Decode, don't render.** The crate says what a value *means* (`PropValue`,
  typed stats, derived progress/rate/ETA). Units, wording and layout are the
  consumer's. No app concerns (UI, threads of a particular app, CLI flags) in
  code or comments.
- **Version differences are absorbed here, once.** Consumers never index raw
  stat arrays. A layout is told apart by the array length the kernel returns
  (no version probe where the length suffices). A field a kernel lacks is
  `Option`. Each decoder reads words in C field order (`stats.rs::Words`) so
  it can be checked line by line against `doc/reference/*/zfs.h`.
- **Closed value sets are enums.** C enums are `repr(u8)` strum mirrors in
  `enums.rs` (`FromRepr` + `Display`); property dispatch and value enums are
  in `props.rs`. Unknown raw values render as `?N`, never panic: the kernel
  or the disk can be newer than we are. Typed APIs carry kernel enums as
  `Coded<E>` (raw always, `get()` typed when known). Ioctl *arguments* that
  are C enums take the typed mirror, never a raw number.
- **Public types are `#[non_exhaustive]`** where new kernel fields or
  variants may appear, so adding one isn't a breaking change.

## Features

- `write` (off by default): every method issuing an `Ioc::mutates` ioctl
  lives in the `#[cfg(feature = "write")] impl ZfsHandle` block at the end of
  `ioctl.rs` (plus `recv_new` and the types only writes use). Without the
  feature `writes_allowed` is `cfg!`-false, so `ZfsHandle::ioctl` refuses
  every mutating request, pinned by `read_only_build_refuses_every_mutating_ioctl`.
  `write_ioctl` itself stays in the read build: SEND_NEW (a read) uses it for
  its structured error.
- `kstat` (on by default): the `kstat` module.
- `ioctl`, the `libc` dependency and kstat's procfs readers are
  `cfg(target_os = "linux")`; the rest must stay portable. Check with
  `cargo +nightly check -Zbuild-std=std,panic_abort --target
  x86_64-unknown-freebsd --lib` (needs nightly's `rust-src`).

## ABI hazards (read before touching ioctl.rs)

- `zfs_cmd_t` (mirrored as `ZfsCmd`) is **not a stable ABI** across OpenZFS
  releases. The layout matches 2.2.x; size is const-asserted (13744 bytes).
  The kernel copies `sizeof(zfs_cmd_t)` from userspace, so a wrong size means
  memory corruption; the const assertions must never be relaxed.
- Every command travels in a zeroed `CmdBuf` (default 16 KiB,
  `HandleOptions::cmd_buffer_size`) that derefs to `ZfsCmd`, so a module
  with a larger struct reads zeros past ours and writes into the padding.
  Build commands with `self.cmd()`, never a bare `ZfsCmd`.
- Ioctl numbers (`0x5a00 + n`, the `Ioc` enum, Display = C name sans
  `ZFS_IOC_`) are stable since at least 0.6.3, the `0x5a80` platform range
  (events) included. `ioc_ordinals_match_vendored_headers` pins them against
  every vendored `zfs.h`. `Ioc::mutates` is an exhaustive match, so a new
  ioctl must declare whether it writes.
- `ZfsHandle::ioctl` is the only place a request is issued. Its outer
  `Result` is the write gate (`ZfsError::WriteRefused`), the inner one the
  kernel's raw errno (callers branch on ENOMEM regrow, ESRCH end-of-list, …).
- Kernel gate: `KernelSupport` classifies the probed module
  (`/sys/module/zfs/version`) against the verified range, ZoL 0.8 ..=
  OpenZFS 2.4; a `.99` dev build counts as the next minor. Outside it, reads
  go through and mutating requests are refused unless
  `HandleOptions::allow_unverified_writes`. `ZfsHandle::open` uses the
  process-wide defaults (`set_default_handle_options`), `open_with` takes them
  per handle. Moving `NEWEST_VERIFIED` forward = vendor the release's headers
  under `doc/reference/<ver>/`, write its README analysis, and add it to the
  ordinal test.
- Write ioctls pass parameters as a packed native nvlist in `zc_nvlist_src`
  and read the per-element errors nvlist back from `zc_nvlist_dst`
  (`write_ioctl` → `ZfsError::Write { op, err, elements }`). New-style
  handlers validate innvl key *types* before resolving names: a mistyped key
  fails with ZFS_ERR_IOC_ARG_BADTYPE, which a canary against a nonexistent
  pool would otherwise mask behind ENOENT (CREATE's `type` must be int32).
- Per-ioctl quirks (back-filled ERROR_LOG buffers, USERSPACE_MANY's raw
  `zfs_useracct_t` array, the asymmetric HOLD/RELEASE nvlists, ATTACH using
  `zc_nvlist_conf`, VDEV_GET_PROPS returning computed props only when named,
  the ENOMEM retry restoring `zc_name`/`zc_cookie`, …) are documented on each
  method. Read the method's doc before changing its request shape.

## Kernel releases

Per-era analyses and headers live in `doc/reference/{0.6,0.7,0.8,2.0,2.1,2.3,2.4}/`
(the 2.2.2 set is at the top level).

- 2.0 / 2.1: `zfs_cmd_t` is byte-identical to 2.2. The one stats-layout break
  is 2.2 *inserting* `vs_noalloc` at `vdev_stat_t` index 45 (2.1 has
  `vs_pspace` there), picked by array length in `VdevStats::decode`.
- ZoL 0.8: `zfs_cmd_t` is 8 bytes shorter (no trailing `zc_zoneid`), safe
  since the kernel copies its own sizeof both ways. `dmu_objset_stats_t` has
  no `dds_redacted`, so `dds_origin` sits one byte earlier; that shim keys
  off `kernel_pre_2_0()`. `pool_scan_stat_t` slot 6 is `pss_to_process` (not
  `pss_skipped`) on every pre-2.2 kernel, so `ScanStats::skipped` is `None`
  on the 15-word layout.
- ZoL 0.7 / 0.6: `KernelSupport::Older`, not supported. 0.7 needs a
  `vdev_stat_t` index remap (a mid-array insert); 0.6.5 has a genuine
  mid-struct `zfs_cmd_t` break (`zinject_record_t` lacks `zi_nlanes`).
- 2.3 / 2.4: ABI-compatible with no code change. `zfs_cmd_t` keeps every 2.2
  offset (2.4 grew `zinject_record_t` inside a union and now
  `_Static_assert`s the size upstream); 2.3's `dds_flags` sits in tail
  padding; ordinals only append; `vdev_stat_t` appends `vs_dio_verify_errors`
  (2.3). Master (2.5-dev) appends `pss_pass_scrub_flags` to
  `pool_scan_stat_t`, which decodes fine.
- kstat schemas differ too (2.2 reworked ARC accounting: per-state
  data/metadata, `iohits`, `pd`/`pm` instead of `p`, no `arc_meta_limit`;
  the objset kstats gained the ZIL counters in 2.2, more in 2.3/2.4, and
  follow renames only from 2.3). Views are field-presence driven
  (`Kstat::has`), never version-branched; `doc/kstat/` holds 2.1 and 2.2
  dumps as parser fixtures. The `txgs`, `dmu_tx_assign` and `state` formats
  are unchanged from 0.8 to 2.4 (vendored `spa_stats.c`,
  `dataset_kstats.{c,h}`). Named-kstat lines are split at their type token
  (the first numeric token after the name's first word), not plainly by
  whitespace: `dmu_tx_assign`'s bucket names and string values such as
  `dataset_name` contain spaces. Compact hand-written lines parse too.

## Build / test

- `cargo build`, `cargo clippy --all-targets` (also with `--features write`
  and `--no-default-features`), `cargo test` (and `--features write`), and
  `RUSTDOCFLAGS='-D warnings' cargo doc --no-deps --all-features`.
- `tests/live_zfs.rs` exercises the real `/dev/zfs`, cross-checks against
  `zpool list`, and skips quietly without ZFS. It is the ABI canary: if
  `ZfsCmd` drifts from the kernel, it fails first. Write canaries target a
  pool that cannot exist (`NOPE_POOL`), proving numbers and layout with zero
  side effects. Round-trip tests need a delegated scratch dataset
  (`PLAYGROUND`) and skip without it. GET-style ioctls run unprivileged
  (`/dev/zfs` is world-rw); events, error log and history need root.
- Fuzzing: `fuzz/` (cargo-fuzz, nightly + a C++ compiler, its own workspace
  and excluded from the package) has `nvlist` (unpack, every list decoder,
  pack fixed point, histogram window and quantile order) and `kstat` (the
  text parsers, histogram window and quantile properties). Targets check a property where there is one, not just
  no-panic. `cargo run --example fuzz_seeds` cuts a corpus (synthetic shapes,
  this host's pool nvlists, `doc/kstat/`; gitignored, regenerate rather than
  commit); `fuzz/run-all.sh [secs]` sweeps every target without a sanitizer.
  A crash is fixed like any correctness finding: minimized, fixed, and pinned
  by a unit test next to the fix.
- Rust edition 2024, MSRV 1.88 (`rust-version` in Cargo.toml).

## Licensing

Crate code is MIT OR Apache-2.0. `doc/reference/` is vendored OpenZFS
material under the CDDL 1.0 (`doc/reference/LICENSE`, `doc/reference/README.md`):
reference only, never compiled in, and `doc/` is excluded from the package.
Keep new vendored files' CDDL headers intact, and keep that distinction in
the README and crate docs.
