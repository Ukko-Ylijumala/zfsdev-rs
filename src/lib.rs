// Copyright (c) 2026 Mikko Tanner. All rights reserved.
// Licensed under the MIT License or the Apache License, Version 2.0.
// SPDX-License-Identifier: MIT OR Apache-2.0

/*!
Pure-Rust access to OpenZFS through `/dev/zfs`, the ioctl interface the `zfs`
and `zpool` commands use internally. There is no libzfs, no FFI and no CLI
scraping.

- [`ioctl`]: [`ioctl::ZfsHandle`] and its typed requests. They cover pool
  configs and stats, datasets, snapshots and bookmarks, properties, holds,
  delegations, the event feed, the error log, space estimates,
  send/receive, encryption keys and pool maintenance.
- [`nvlist`]: the codec for packed name-value lists, the currency of the
  ioctl interface (and of on-disk vdev labels). It decodes the native and
  XDR encodings and encodes the native one.
- [`stats`]: decoders for the kernel's positional stat arrays
  (`vdev_stat_t`, `pool_scan_stat_t`, rebuild stats, `vdev_stats_ex`). They
  absorb the layout differences between releases: a field one kernel lacks
  is `None`.
- [`enums`], [`props`]: typed mirrors of the C enums and property values.
  [`enums::Coded`] keeps the raw number of a value newer than this crate.
- [`kstat`]: the SPL kstats in `/proc/spl/kstat/zfs`: ARC metrics, and per
  pool the txg history, the tx-assign delay histogram, the per-dataset I/O
  counters and the lock-free health word. It is plain procfs, with no ioctl
  involved.
- [`wrapkey`]: libzfs's native-encryption wrapping-key derivation (the
  userspace half of `zfs load-key`).

# Features and platforms

- `write` (off by default) adds the mutating requests: properties,
  snapshots, create/destroy/rename, delegation, holds, encryption keys,
  receive, and pool/vdev maintenance. Without it the crate cannot change
  pool, dataset or kernel state.
- `kstat` (on by default) adds the [`kstat`] module.

[`ioctl`] is Linux-only, as are kstat's procfs readers: the request encoding
and the event ioctls are those of OpenZFS's Linux port. The rest is portable;
the nvlist codec, the enums and the decoders work anywhere, for example on
vdev labels read from a disk image.

# Kernel compatibility

`zfs_cmd_t` is not a stable ABI across OpenZFS releases. The mirrors follow
2.2, and the verified range is ZoL 0.8 through OpenZFS 2.4
([`ioctl::KernelSupport`]). Outside that range reads still go through, while
mutating requests are refused unless [`ioctl::HandleOptions`] opts in. Every
command travels in a zeroed, padded buffer, so a kernel whose struct grew
cannot write past it.

# Reference material

`doc/reference/` holds OpenZFS headers and sources vendored as the ground
truth for the layouts and wire formats mirrored here. They are reference only:
nothing there is compiled into or linked with this crate. They stay under
their own license, the CDDL 1.0 (`doc/reference/LICENSE`), not this crate's
MIT OR Apache-2.0.
*/

pub mod enums;
#[cfg(target_os = "linux")]
pub mod ioctl;
#[cfg(feature = "kstat")]
pub mod kstat;
pub mod nvlist;
pub mod props;
pub mod stats;
pub mod wrapkey;
