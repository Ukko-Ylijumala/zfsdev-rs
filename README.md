# zfsdev

Pure-Rust access to [OpenZFS](https://github.com/openzfs/zfs) through
`/dev/zfs`, the ioctl interface the `zfs` and `zpool` commands use
internally.

**No libzfs, no FFI, no `zfs`/`zpool` output scraping.** The crate builds
`zfs_cmd_t` requests itself and speaks the kernel's packed-nvlist wire format
with its own codec. Every kernel layout that changed between OpenZFS releases
is decoded into typed structs, so callers get named fields instead of raw
arrays, and `None` for what the running kernel doesn't report.

The crate began as the kernel layer of
[zfs-browser](https://github.com/Ukko-Ylijumala/zfs-browser), a TUI for ZFS
pool and dataset internals. It was split out with its history intact, so code
that needs ZFS data without that application can use it too.

## Contents

| Module   | What it does |
|----------|--------------|
| `ioctl`  | `ZfsHandle` and its typed requests: pool configs, stats and properties; datasets, snapshots and bookmarks; holds and delegations; the kernel event feed; the permanent error log; space estimates; `zfs send` streams; pool history. With the `write` feature it also covers the mutations. |
| `nvlist` | The codec for packed name-value lists. It decodes both the native and XDR encodings and encodes the native one. |
| `stats`  | Decoders for the kernel's positional stat arrays: `vdev_stat_t`, `pool_scan_stat_t` (scrub, resilver, error scrub), sequential-rebuild stats, and `vdev_stats_ex` (queue depths, latency and request-size histograms). Each type has derived figures such as progress, pass rate and ETA, computed the way `zpool status` does. |
| `enums`  | Typed mirrors of the C enums: pool, vdev and scan states, vdev types, objset types, compression and checksum algorithms, DMU object types. `Coded<E>` keeps the raw number alongside the typed value, so a value newer than the crate still shows as `?N` instead of being lost. |
| `props`  | Property names, value enums and decoding. `prop_entry` reads a property from the nvlist an ioctl returns, unwrapping its `{value, source}` pair and decoding where the value comes from (`PropSource`, `zfs get`'s SOURCE column); `decode_prop_value` says what a stored number *means*; `parse_prop_value` turns user input into the typed value a set-property request needs. |
| `kstat`  | The SPL kstats in `/proc/spl/kstat/zfs`: `arc_summary`'s data, with ARC hit ratios and prefetcher metrics derived from whichever counters the kernel exports; and per pool the txg history, the tx-assign delay histogram (the write throttle), each open dataset's I/O and ZIL counters, and the pool's health word, which the kernel serves without taking a lock; the pool list itself, read without a ZFS lock. |
| `wrapkey` | libzfs's native-encryption wrapping-key derivation (PBKDF2 for a passphrase, hex and raw keys), the userspace half of `zfs load-key`. |

## Installation

```toml
[dependencies.zfsdev]
git = "https://github.com/Ukko-Ylijumala/zfsdev-rs"
version = "0.4"
```

To be able to change pool or dataset state, enable `write`:

```toml
[dependencies.zfsdev]
git = "https://github.com/Ukko-Ylijumala/zfsdev-rs"
version = "0.4"
features = ["write"]
```

Releases are tagged `vX.Y.Z`; use `tag = "v0.4.2"` instead of `version` to pin
one exactly. Rust 1.88 or newer is required.

### Features

| Feature | Default | Contents |
|---------|---------|----------|
| `kstat` | on  | The `kstat` module. It has no dependencies. |
| `write` | off | The mutating requests: set/inherit properties, snapshot, create, destroy, rename, `zfs allow`/`unallow`, holds, `zfs load-key`/`unload-key`, receive, pool history entries, and pool/vdev maintenance (scrub, clear, trim, initialize, online/offline, attach, detach, `zpool online -e`). |

Without `write`, the crate cannot issue a request that changes pool, dataset
or kernel state. The methods don't exist, and as a second guard the one
function that issues requests refuses any mutating request outright.

## Platform and kernel support

The `ioctl` module, and the procfs readers in `kstat`, are **Linux-only**:
the request encoding and the event ioctls are those of OpenZFS's Linux port.
Everything else is portable, so the nvlist codec, the enums and the decoders
work anywhere, for example on vdev labels read from a disk image.

`zfs_cmd_t`, the structure every request travels in, is **not a stable ABI**
across OpenZFS releases. The crate's mirror follows 2.2, and the range it has
been verified against is **ZoL 0.8 through OpenZFS 2.4**. The analysis for
each release lives in `doc/reference/<version>/README.md`.

| Kernel | `KernelSupport` | Reads | Writes |
|--------|-----------------|-------|--------|
| ZoL 0.8, OpenZFS 2.0–2.4 | `Verified` | yes | yes |
| newer than 2.4 (a `.99` dev build counts as the next minor) | `Newer` | yes | refused unless opted in |
| ZoL 0.6 / 0.7 | `Older` | yes; some stats decode wrong | refused unless opted in |
| no version could be probed | `Unknown` | yes | refused unless opted in |

Upstream has only ever appended to this ABI since 0.8, so reads stay
available on any kernel. Two guards protect against a newer kernel:

- **Padded buffer.** Every command travels in a zeroed buffer (16 KiB by
  default) that is larger than the struct. A kernel whose `zfs_cmd_t` grew
  reads zeros for its new fields and writes into the padding, never past the
  allocation.
- **Write gate.** Outside the verified range a handle refuses every mutating
  request with `ZfsError::WriteRefused`. The caller can opt in explicitly.

Both are set through `HandleOptions`. Set them per handle with
`ZfsHandle::open_with`, or process-wide with `set_default_handle_options`,
which `ZfsHandle::open` uses:

```rust
use zfsdev::ioctl::{HandleOptions, ZfsHandle, set_default_handle_options};

// a kernel whose struct outgrew the default 16 KiB padding
set_default_handle_options(HandleOptions::default().cmd_buffer_size(64 * 1024));
let zfs = ZfsHandle::open()?;
if !zfs.kernel_support().is_verified() {
    eprintln!("warning: {}", zfs.kernel_support());
}
```

### Privileges

`/dev/zfs` is world-readable and writable, and most read requests work
unprivileged: pool configs and stats, properties, dataset and snapshot
listings, holds, bookmarks, delegations and space estimates. A few reads are
privileged and return EPERM/EACCES otherwise: the event feed, the error log,
pool history, and other users' space accounting. The kernel decides whether a
write is allowed for the calling user: root, or a matching `zfs allow`
delegation.

## Usage

### Pools, vdevs and scans

```rust
use zfsdev::ioctl::ZfsHandle;
use zfsdev::stats::{ScanStats, VdevStats};

let zfs = ZfsHandle::open()?;
for pool in zfs.pool_configs()?.iter() {
    let stats = zfs.pool_stats(&pool.name)?;
    let Some(root) = stats.get_list("vdev_tree") else { continue };
    if let Some(vs) = VdevStats::from_vdev(root) {
        println!("{}: {}, {} of {} bytes allocated", pool.name, vs.state, vs.alloc, vs.space);
    }
    // the pool-wide scrub/resilver stats hang off the root vdev only
    if let Some(scan) = ScanStats::from_vdev(root).filter(ScanStats::is_active) {
        println!("  {} {:.1}% done", scan.func, scan.progress() * 100.0);
    }
}
```

`VdevStats::from_vdev` works on any vdev of the `vdev_tree`, so recurse
through its `children` for the whole layout. Fields that only some releases
have are `Option`, for example `noalloc` (2.2+), `pspace` (2.1+) and
`dio_verify_errors` (2.3+).

### Datasets and properties

```rust
use zfsdev::props::{PropSource, PropValue, decode_prop_value, prop_entry, prop_u64};

for ds in zfs.datasets("tank")? {
    let compression = prop_u64(&ds.props, "compression")
        .and_then(|v| decode_prop_value("compression", v));
    if let (Some(used), Some(PropValue::Name(alg))) = (prop_u64(&ds.props, "used"), compression) {
        println!("{}: {used} bytes used, compression={alg}", ds.name);
    }
    if let Some(PropSource::Inherited(Some(from))) =
        prop_entry(&ds.props, "compression").map(|e| e.source(&ds.name))
    {
        println!("  compression inherited from {from}");
    }
}
```

`datasets` lists direct children, `snapshots` lists a dataset's snapshots, and
`objset_stats` fetches one dataset. Each comes with its properties, plus
`ObjsetStats` (type, guid, creation txg, origin, …). Most property nvlists
wrap each value as a `{value, source}` pair; `prop_entry`, `prop_entries`,
`prop_u64` and `prop_str` unwrap it (and take the bare values of
`objset_zplprops` as they are). A property at its default is often absent:
the default is then yours to supply.

### The kernel event feed

```rust
let zfs = ZfsHandle::open()?;
zfs.events_seek_start()?;
// blocks in the kernel until the next event arrives (needs root)
while let Some((event, dropped)) = zfs.events_next(true)? {
    if dropped > 0 {
        eprintln!("({dropped} events lost to ring overflow)");
    }
    println!("{}", event.get_str("class").unwrap_or("?"));
}
```

### ARC statistics

```rust
use zfsdev::kstat::{self, ArcClass};

let arc = kstat::read_arcstats()?;
let ratio = kstat::hit_ratio(&arc, ArcClass::All).unwrap_or(0.0);
println!("ARC {} of {} bytes, {:.1}% hits", arc.u("size"), arc.u("c_max"), ratio * 100.0);
```

The counters are cumulative since boot. For a rate or a windowed hit ratio,
take the difference between two timed reads.

### Pool kstats

```rust
use zfsdev::kstat::{self, TxgState};

// listed and served without a ZFS lock, so they answer even while a pool
// is wedged and every /dev/zfs call blocks
for pool in kstat::pool_names()? {
    println!("{pool}: {}", kstat::read_pool_health(&pool)?);
}
let health = kstat::read_pool_health("tank")?;
let txgs = kstat::read_txgs("tank")?;
let now = kstat::hrtime_now();
if let Some(sync) = txgs.iter().find(|t| t.state == TxgState::Syncing) {
    let secs = sync.in_phase_for(now).unwrap_or(0) as f64 / 1e9;
    println!("{health}: txg {} has been syncing for {secs:.1}s", sync.txg);
}

let waits = kstat::read_tx_assign("tank")?;
println!("{} transactions waited over 100 ms", waits.longer_than(100_000_000));

if let Some(home) = kstat::find_objset_kstat("tank/home")? {
    println!("{} writes, {} ZIL commits", home.stats.u("writes"), home.stats.u("zil_commit_count"));
}
```

None of these reads does pool I/O or takes a pool lock. `find_objset_kstat`
scans the pool's objset kstats; to sample one dataset repeatedly, keep its
`objset` id and re-read it with `read_objset_kstat`.

### nvlists

```rust
use zfsdev::nvlist::NvList;

let mut nv = NvList::new();
nv.add_str("name", "tank").add_u64("guid", 42);
let packed = nv.pack()?;
assert_eq!(NvList::unpack(&packed)?.get_u64("guid"), Some(42));
```

`NvList::get` returns the typed `NvData` for any pair. `get_u64`, `get_str`,
`get_list`, `get_list_array` and `get_u64_array` cover the common shapes.

### Writes (`write` feature)

```rust
let zfs = ZfsHandle::open()?;
let snaps = vec!["tank/home@before-upgrade".to_string()];
if let Err(e) = zfs.snapshot("tank", &snaps, None) {
    // "create snapshot: File exists (os error 17) (already exists) — tank/home@…"
    eprintln!("{e}");
}
```

When an operation fails in the kernel, the error is `ZfsError::Write { op,
err, elements }`. `elements` lists the per-element errors the kernel reported
(which snapshot, hold or vdev failed, with its own errno), and `errno()`
returns the overall errno for matching.

Loading an encryption key derives the wrapping key in userspace, exactly as
libzfs does. The kernel only ever sees the derived 32 bytes:

```rust
use zfsdev::props::{KeyFormat, prop_u64};
use zfsdev::wrapkey::derive_wrapping_key;

let (_, props) = zfs.objset_stats("tank/secret")?;
let salt = prop_u64(&props, "pbkdf2salt").unwrap_or(0);
let iters = prop_u64(&props, "pbkdf2iters").unwrap_or(0);
let key = derive_wrapping_key(KeyFormat::Passphrase, b"correct horse", salt, iters)?;
zfs.load_key("tank/secret", &key, false)?; // a wrong passphrase fails with EACCES
```

### Threads and blocking calls

A `ZfsHandle` is `Send` but not `Sync`: give each thread its own handle.
`events_next(true)`, `send_new` and `recv_new` block in the kernel for as long
as the operation takes, so run them on dedicated threads. A send or receive is
cancelled by closing the far end of its pipe; the blocked call then fails with
EPIPE.

## Testing

```sh
cargo test                  # read-only build
cargo test --features write # adds the write canaries
```

The unit tests need no ZFS. They include an ordinal check that every ioctl
number matches the vendored `zfs.h` of each verified release.

`tests/live_zfs.rs` exercises the real `/dev/zfs` and skips quietly on a
machine without it. These tests are the ABI canary: if the `zfs_cmd_t` mirror
drifts from the kernel, they fail first. The write canaries target a pool name
that cannot exist. That proves the request numbers and layout of the
mutating path with no side effects, because a layout error would surface as
EFAULT/EINVAL instead of a clean "no such pool". Tests that need a delegated
scratch dataset skip when it is absent.

### Fuzzing

`fuzz/` holds [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) targets in
a workspace of their own (they need nightly and a C++ compiler; the crate
itself needs neither):

- `nvlist`: decodes arbitrary bytes, runs every decoder that reads a decoded
  list (property entries and sources, the stat decoders and their derived
  figures), and checks that whatever decodes re-packs to a fixed point.
- `kstat`: the kstat text parsers, with the tx-assign histogram's window
  arithmetic checked for consistency.

```sh
cargo run --example fuzz_seeds   # seed corpus, from this host's pools if any
fuzz/run-all.sh 60               # every target for 60 s, no sanitizer
```

## Reference material

`doc/reference/` holds OpenZFS headers and sources vendored as the ground truth
for the layouts, request numbers and wire formats mirrored here. The 2.2.2
files are at the top level, and the ioctl-ABI headers of every other release
line sit next to their analyses in subdirectories. `doc/kstat/` holds kstat
dumps from 2.1 and 2.2 systems, which the parser tests use as fixtures.

**The vendored OpenZFS files are reference only, and are under a different
license than this crate.** They are licensed under the CDDL 1.0
([`doc/reference/LICENSE`](doc/reference/LICENSE)), not MIT OR Apache-2.0.
Nothing in `doc/` is compiled into or linked with the crate, and `doc/` is
excluded from its package. See
[`doc/reference/README.md`](doc/reference/README.md).

## License

The crate's code is licensed under the MIT License or the Apache License,
Version 2.0, at your option. The exception is the vendored material in
`doc/reference/`, which keeps its own CDDL 1.0 license (see above).
