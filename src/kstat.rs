// Copyright (c) 2026 Mikko Tanner. All rights reserved.
// Licensed under the MIT License or the Apache License, Version 2.0.
// SPDX-License-Identifier: MIT OR Apache-2.0

/*!
SPL kstats: the counters the ZFS module exports as plain text in procfs
(`/proc/spl/kstat/zfs/…`). No `/dev/zfs` ioctl is involved: the files are
world-readable, so there is no ABI hazard and no privilege requirement. The
procfs files (and the readers here) exist on Linux only; the parsers are
portable.

Host-wide there are the ARC's `arcstats` (the `arc_summary` / `arcstat`
data), the prefetcher's `zfetchstats`, the DMU's `dmu_tx` counters, the pool
loads in progress (`import_progress`, [`ImportProgress`]) and the module's
debug log (`dbgmsg`, [`DbgMsg`], root only). Each
imported pool has a directory of its own, `/proc/spl/kstat/zfs/<pool>/`
([`pool_names`] lists them, the one pool list that needs no ZFS lock):

- `txgs`, the recent txg history with each txg's phase and timings
  ([`TxgInfo`]);
- `dmu_tx_assign`, how long transactions waited for a txg, i.e. the write
  throttle ([`TxAssignHistogram`]);
- `objset-0x<id>`, each open dataset's I/O and ZIL counters
  ([`ObjsetKstat`]);
- `state`, the pool's health word ([`PoolHealth`]).

Reading them does no pool I/O and takes none of the locks a pool ioctl takes;
the kernel keeps `state` lock-free precisely so it can serve as a pool
heartbeat.

Most kstats are *named*: a header line, a `name type data` column header,
then one `<name> <type> <value>` line per field ([`Kstat`]). Values are stored
as `i64` because the kstat type system has a signed variant (type 3,
`KSTAT_DATA_INT64`) used by `memory_available_bytes`, which goes negative
under memory pressure; every other numeric field is type 4 (unsigned) and
positive, and all of them fit in `i64`. A few fields are strings, such as an
objset's `dataset_name`.

Field schemas differ across OpenZFS major versions — 2.2 reworked ARC
accounting (per-state data/metadata split, an `Uncached` state, `iohits`,
predictive/prescient prefetch counters; the single `p` MRU/MFU target became
`pd`/`pm`; `arc_meta_limit` went away), and the objset kstats gained the ZIL
counters in 2.2, with more in 2.3 and 2.4. Rather than branch on version, read
whatever fields exist and derive each metric only from inputs that are present
([`Kstat::has`]); [`hit_ratio`] and [`accesses`] fold in 2.2's `iohits` where
it exists. The `txgs`, `dmu_tx_assign` and `state` formats are unchanged from
ZoL 0.8 to OpenZFS 2.4. Reference dumps live in `doc/kstat/`.

Counters are cumulative (since boot, import or mount): a rate (or a windowed
hit ratio) is the delta between two timed reads, which is left to the caller.
*/

use std::collections::HashMap;
use std::fs;
use std::io;
use std::iter;
#[cfg(target_os = "linux")]
use std::mem;
use std::path::Path;
#[cfg(target_os = "linux")]
use std::path::PathBuf;
use strum::{Display, EnumString};

use crate::enums::{Coded, SpaLoadState};

/// Where the SPL publishes the ZFS kstats; each imported pool has its own
/// directory below it ([`pool_dir`]).
#[cfg(target_os = "linux")]
pub const KSTAT_DIR: &str = "/proc/spl/kstat/zfs";
/// The ARC's counters (`arc_summary`'s source).
#[cfg(target_os = "linux")]
pub const ARCSTATS_PATH: &str = "/proc/spl/kstat/zfs/arcstats";
/// The DMU (file-level) prefetcher's counters.
#[cfg(target_os = "linux")]
pub const ZFETCHSTATS_PATH: &str = "/proc/spl/kstat/zfs/zfetchstats";
/// The DMU's transaction counters, all pools together: `dmu_tx_assigned`
/// and the throttle events (`dmu_tx_dirty_throttle`, `dmu_tx_dirty_delay`, …).
#[cfg(target_os = "linux")]
pub const DMU_TX_PATH: &str = "/proc/spl/kstat/zfs/dmu_tx";
/// The pool loads (imports) in progress ([`ImportProgress`]).
#[cfg(target_os = "linux")]
pub const IMPORT_PROGRESS_PATH: &str = "/proc/spl/kstat/zfs/import_progress";
/// The ZFS debug log ([`DbgMsg`]); readable by root only.
#[cfg(target_os = "linux")]
pub const DBGMSG_PATH: &str = "/proc/spl/kstat/zfs/dbgmsg";

/// A dataset's kstat file in its pool's directory: the prefix, then the
/// objset id in hex.
#[cfg(target_os = "linux")]
const OBJSET_PREFIX: &str = "objset-0x";
/// The width the SPL pads a named kstat's type column to (`%-4d `).
const TYPE_WIDTH: usize = 4;
/// `KSTAT_DATA_CHAR`: a short string, printed padded.
const KSTAT_DATA_CHAR: u8 = 0;
/// `KSTAT_DATA_STRING`: a string, printed as is.
const KSTAT_DATA_STRING: u8 = 7;

/**
A parsed named kstat: `name → value`. See the module docs for the wire format
and the signed-`i64` rationale. Construct with [`Kstat::parse`] /
[`Kstat::read`] (or collect `(name, value)` pairs); query with [`Kstat::get`]
(raw signed), [`Kstat::u`] (unsigned, clamped at 0), [`Kstat::str`] (string
fields) and [`Kstat::has`] (presence, for version-adaptive views).
*/
#[derive(Debug, Clone, Default)]
pub struct Kstat {
    nums: HashMap<String, i64>,
    strs: HashMap<String, String>,
}

impl Kstat {
    /**
    Parse a named kstat's text. The two header lines are skipped; a numeric
    field whose value doesn't parse as an `i64` is ignored (forward-compat).
    String fields are kept apart, for [`Kstat::str`].
    */
    pub fn parse(text: &str) -> Self {
        let mut k = Kstat::default();
        for (name, ty, value) in text.lines().skip(2).filter_map(named_line) {
            match ty {
                KSTAT_DATA_CHAR => {
                    k.strs.insert(name.to_string(), value.trim_end().to_string());
                }
                KSTAT_DATA_STRING => {
                    k.strs.insert(name.to_string(), value.to_string());
                }
                _ => {
                    if let Ok(v) = value.trim().parse::<i64>() {
                        k.nums.insert(name.to_string(), v);
                    }
                }
            }
        }
        k
    }

    /// Read and parse a kstat file from procfs.
    pub fn read(path: impl AsRef<Path>) -> io::Result<Self> {
        Ok(Kstat::parse(&fs::read_to_string(path)?))
    }

    /// Raw signed value (`None` if the field is absent on this kernel).
    pub fn get(&self, name: &str) -> Option<i64> {
        self.nums.get(name).copied()
    }

    /// Unsigned value, 0 if absent or negative (every field but
    /// `memory_available_bytes` is unsigned and non-negative).
    pub fn u(&self, name: &str) -> u64 {
        self.get(name).unwrap_or(0).max(0) as u64
    }

    /// A string field (`None` if absent, or numeric).
    pub fn str(&self, name: &str) -> Option<&str> {
        self.strs.get(name).map(String::as_str)
    }

    /// Whether a field exists - used to pick the version-appropriate view.
    pub fn has(&self, name: &str) -> bool {
        self.nums.contains_key(name) || self.strs.contains_key(name)
    }

    /// All numeric `(name, value)` pairs (unordered) - for a raw-dump view.
    pub fn iter(&self) -> impl Iterator<Item = (&str, i64)> {
        self.nums.iter().map(|(k, v)| (k.as_str(), *v))
    }
}

impl<S: Into<String>> FromIterator<(S, i64)> for Kstat {
    fn from_iter<I: IntoIterator<Item = (S, i64)>>(iter: I) -> Self {
        let nums = iter.into_iter().map(|(k, v)| (k.into(), v)).collect();
        Kstat { nums, strs: HashMap::new() }
    }
}

/**
Split a named-kstat line into `(name, type, value)`. The SPL prints
`%-31s %-4d <value>`, and both a name (`dmu_tx_assign`'s `1024 ns` buckets)
and a string value (a dataset name) may contain spaces, so a plain
whitespace split won't do. The line is split at its type instead: the first
numeric token after the name's first word. A value keeps its exact text
after the SPL's type padding; a compact line (`name 4 17`) works too.
*/
fn named_line(line: &str) -> Option<(&str, u8, &str)> {
    let mut tokens = token_spans(line);
    tokens.next()?;
    let (ty_start, ty_end, ty) =
        tokens.find_map(|(s, e)| line[s..e].parse::<u8>().ok().map(|ty| (s, e, ty)))?;
    let after = &line[ty_end..];
    let pad = TYPE_WIDTH.saturating_sub(ty_end - ty_start) + 1;
    let value = match after.get(..pad) {
        Some(p) if p.bytes().all(|b| b == b' ') => &after[pad..],
        _ => after.trim_start(),
    };
    Some((line[..ty_start].trim_end(), ty, value))
}

/// The byte spans of `line`'s whitespace-separated tokens.
fn token_spans(line: &str) -> impl Iterator<Item = (usize, usize)> + '_ {
    let mut pos = 0;
    iter::from_fn(move || {
        let start = pos + line[pos..].find(|c: char| !c.is_whitespace())?;
        let end = line[start..].find(char::is_whitespace).map_or(line.len(), |i| start + i);
        pos = end;
        Some((start, end))
    })
}

/// The current arcstats.
#[cfg(target_os = "linux")]
pub fn read_arcstats() -> io::Result<Kstat> {
    Kstat::read(ARCSTATS_PATH)
}

/// The current zfetchstats.
#[cfg(target_os = "linux")]
pub fn read_zfetchstats() -> io::Result<Kstat> {
    Kstat::read(ZFETCHSTATS_PATH)
}

/// The current DMU transaction counters (all pools together).
#[cfg(target_os = "linux")]
pub fn read_dmu_tx() -> io::Result<Kstat> {
    Kstat::read(DMU_TX_PATH)
}

/* ========================== derived ARC metrics ========================== */

/// An ARC access class: the counter prefix of its `hits` / `iohits` /
/// `misses` in arcstats (Display), `All` being the unprefixed totals.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Display)]
#[non_exhaustive]
pub enum ArcClass {
    #[strum(serialize = "")]
    All,
    #[strum(serialize = "demand_data_")]
    DemandData,
    #[strum(serialize = "demand_metadata_")]
    DemandMetadata,
    #[strum(serialize = "prefetch_data_")]
    PrefetchData,
    #[strum(serialize = "prefetch_metadata_")]
    PrefetchMetadata,
}

/**
`hits / (hits + iohits + misses)` for an access class, summing only the
fields that exist (2.1 has no `iohits`, so it reduces to `hits/(hits+miss)`).
Returns `None` when there were no accesses at all (avoids 0/0).
*/
pub fn hit_ratio(arc: &Kstat, class: ArcClass) -> Option<f64> {
    let total = accesses(arc, class);
    (total > 0).then(|| arc.u(&format!("{class}hits")) as f64 / total as f64)
}

/// Total accesses for a class (`hits + iohits + misses`).
pub fn accesses(arc: &Kstat, class: ArcClass) -> u64 {
    ["hits", "iohits", "misses"].iter().map(|c| arc.u(&format!("{class}{c}"))).sum()
}

/// DMU (file-level) prefetch stream hit ratio, from zfetchstats
/// (`hits/(hits+misses)`); `None` if the prefetcher has seen no streams.
pub fn dmu_prefetch_ratio(zfetch: &Kstat) -> Option<f64> {
    let (h, m) = (zfetch.u("hits"), zfetch.u("misses"));
    (h + m > 0).then(|| h as f64 / (h + m) as f64)
}

/// ARC health: the kernel sets `arc_no_grow` when it has stopped growing the
/// cache under memory pressure - `arc_summary`'s THROTTLED vs HEALTHY.
pub fn is_throttled(arc: &Kstat) -> bool {
    arc.u("arc_no_grow") != 0
}

/* ============================ per-pool kstats ============================ */

/**
Pool `pool`'s kstat directory, `/proc/spl/kstat/zfs/<pool>`. A name that
could leave that directory is refused: pool names begin with a letter and
contain no `/`.
*/
#[cfg(target_os = "linux")]
pub fn pool_dir(pool: &str) -> io::Result<PathBuf> {
    if !is_pool_name(pool) {
        let msg = format!("not a pool name: {pool:?}");
        return Err(io::Error::new(io::ErrorKind::InvalidInput, msg));
    }
    Ok(Path::new(KSTAT_DIR).join(pool))
}

/// Whether `name` could be a pool's: pool names begin with a letter and hold
/// no `/` (which also rules out the transient `$import` of `zpool import`).
#[cfg(target_os = "linux")]
fn is_pool_name(name: &str) -> bool {
    name.starts_with(|c: char| c.is_ascii_alphabetic()) && !name.contains('/')
}

/**
The imported pools, by name and sorted, from their kstat directories: each
imported pool has one, holding its `state` kstat, for as long as it is
imported. This takes no ZFS lock, where the pool list from `/dev/zfs`
(`ZfsHandle::pool_configs`) waits on the pool namespace lock: when a stuck
pool holds that lock every pool ioctl blocks, and this still answers.
*/
#[cfg(target_os = "linux")]
pub fn pool_names() -> io::Result<Vec<String>> {
    pool_names_in(Path::new(KSTAT_DIR))
}

/// [`pool_names`] over the kstat directory `dir`: the subdirectories with a
/// `state` kstat, under a name a pool can have.
#[cfg(target_os = "linux")]
fn pool_names_in(dir: &Path) -> io::Result<Vec<String>> {
    let mut names = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let Ok(name) = entry.file_name().into_string() else { continue };
        if is_pool_name(&name) && entry.path().join("state").is_file() {
            names.push(name);
        }
    }
    names.sort();
    Ok(names)
}

/**
A pool's health as its `state` kstat reports it (`spa_state_to_name`): the
word `zpool list` shows, plus `SUSPENDED` and `TRANSITIONING`. The kernel
reads it without taking a lock, where pool ioctls go through `spa_open` and
its namespace lock, so it answers even while the pool is wedged.
*/
#[derive(Debug, Clone, PartialEq, Eq, Display, EnumString)]
#[strum(serialize_all = "UPPERCASE")]
#[non_exhaustive]
pub enum PoolHealth {
    Online,
    Degraded,
    Faulted,
    Offline,
    Removed,
    Unavail,
    /// The pool was split off another (`zpool split`) and can't open.
    Split,
    /// I/O is suspended: the pool lost its devices under `failmode=wait`
    /// or `continue`.
    Suspended,
    /// The pool has no root vdev at the moment: mid import or export.
    Transitioning,
    /// The kernel's own fallback for a vdev state it doesn't name.
    Unknown,
    /// A word newer than this crate.
    #[strum(default)]
    Other(String),
}

/// Pool `pool`'s current health, from its `state` kstat.
#[cfg(target_os = "linux")]
pub fn read_pool_health(pool: &str) -> io::Result<PoolHealth> {
    let text = fs::read_to_string(pool_dir(pool)?.join("state"))?;
    let word = text.trim();
    Ok(word.parse().unwrap_or_else(|_| PoolHealth::Other(word.to_string())))
}

/* ------------------------------ txg history ------------------------------ */

/**
A txg's phase in the `txgs` history: the one it is *in*, as the `state`
letter shows it. A txg enters the history open, and the sync thread works on
one txg at a time, so the row in [`TxgState::Syncing`] is the pool's current
sync.
*/
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TxgState {
    /// `B`: born but not open. The kernel has the letter, but a txg enters
    /// the history already open.
    Birth,
    /// `O`: open, taking new transactions.
    Open,
    /// `Q`: closed to new transactions, waiting for the open ones to finish.
    Quiescing,
    /// `W`: quiesced, waiting for the sync thread.
    WaitingForSync,
    /// `S`: being written out by the sync thread.
    Syncing,
    /// `C`: on disk.
    Committed,
    /// A letter newer than this crate, or the kernel's own `?`.
    Unknown(char),
}

impl TxgState {
    /// The state a `state` column letter names.
    pub fn from_letter(c: char) -> Self {
        match c {
            'B' => TxgState::Birth,
            'O' => TxgState::Open,
            'Q' => TxgState::Quiescing,
            'W' => TxgState::WaitingForSync,
            'S' => TxgState::Syncing,
            'C' => TxgState::Committed,
            other => TxgState::Unknown(other),
        }
    }

    /// The letter the kernel prints for this state.
    pub fn letter(self) -> char {
        match self {
            TxgState::Birth => 'B',
            TxgState::Open => 'O',
            TxgState::Quiescing => 'Q',
            TxgState::WaitingForSync => 'W',
            TxgState::Syncing => 'S',
            TxgState::Committed => 'C',
            TxgState::Unknown(c) => c,
        }
    }
}

/**
One row of a pool's txg history. Times are the kernel's `gethrtime()`, ns of
CLOCK_MONOTONIC_RAW, which [`hrtime_now`] reads too. The durations cover the
phases the txg has finished (0 for the rest). The I/O figures are filled in
when its sync completes: they are the pool's I/O during that sync, plus the
dirty data the txg carried into it.
*/
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct TxgInfo {
    pub txg: u64,
    /// When the txg opened (hrtime, ns).
    pub birth: u64,
    pub state: TxgState,
    /// Dirty data the txg carried into its sync, bytes.
    pub ndirty: u64,
    /// Bytes the pool's vdevs read during the sync.
    pub nread: u64,
    /// Bytes the pool's vdevs wrote during the sync.
    pub nwritten: u64,
    /// Read operations during the sync.
    pub reads: u64,
    /// Write operations during the sync.
    pub writes: u64,
    /// Time open (`otime`), ns.
    pub open_ns: u64,
    /// Time quiescing (`qtime`), ns.
    pub quiesce_ns: u64,
    /// Time waiting for the sync thread (`wtime`), ns.
    pub wait_ns: u64,
    /// Time syncing (`stime`), ns.
    pub sync_ns: u64,
}

impl TxgInfo {
    /// When the txg entered its current phase (hrtime, ns): its birth plus
    /// the phases it has finished.
    pub fn phase_start(&self) -> u64 {
        [self.open_ns, self.quiesce_ns, self.wait_ns, self.sync_ns]
            .iter()
            .fold(self.birth, |t, d| t.saturating_add(*d))
    }

    /**
    How long the txg has been in its current phase at hrtime `now`
    ([`hrtime_now`]), or `None` once it is committed. On the syncing row this
    is the age of the pool's current sync: a sync that keeps aging while no
    newer txg completes is the clearest sign of a wedged pool ZFS offers.
    */
    pub fn in_phase_for(&self, now: u64) -> Option<u64> {
        (self.state != TxgState::Committed).then(|| now.saturating_sub(self.phase_start()))
    }
}

/**
Parse a `txgs` history: a header line, then one row per txg, oldest first.
Columns are found by their header names, so a reordered or extended table
still parses; a row missing one of them is skipped. The kernel keeps the last
`zfs_txg_history` txgs (a module parameter, 100 by default); at 0 the file
holds only the header.
*/
pub fn parse_txgs(text: &str) -> Vec<TxgInfo> {
    let mut lines = text.lines();
    let Some(header) = lines.next() else { return Vec::new() };
    let cols: HashMap<&str, usize> =
        header.split_whitespace().enumerate().map(|(i, c)| (c, i)).collect();
    lines
        .filter_map(|line| {
            let row: Vec<&str> = line.split_whitespace().collect();
            let field = |name: &str| row.get(*cols.get(name)?).copied();
            let num = |name: &str| field(name)?.parse::<u64>().ok();
            Some(TxgInfo {
                txg: num("txg")?,
                birth: num("birth")?,
                state: TxgState::from_letter(field("state")?.chars().next()?),
                ndirty: num("ndirty")?,
                nread: num("nread")?,
                nwritten: num("nwritten")?,
                reads: num("reads")?,
                writes: num("writes")?,
                open_ns: num("otime")?,
                quiesce_ns: num("qtime")?,
                wait_ns: num("wtime")?,
                sync_ns: num("stime")?,
            })
        })
        .collect()
}

/// Pool `pool`'s txg history, oldest first ([`parse_txgs`]).
#[cfg(target_os = "linux")]
pub fn read_txgs(pool: &str) -> io::Result<Vec<TxgInfo>> {
    Ok(parse_txgs(&fs::read_to_string(pool_dir(pool)?.join("txgs"))?))
}

/// The clock of the txg history: the kernel's `gethrtime()`, which is
/// CLOCK_MONOTONIC_RAW in ns.
#[cfg(target_os = "linux")]
pub fn hrtime_now() -> u64 {
    // SAFETY: an all-zero timespec is valid, and clock_gettime only writes it
    let ts = unsafe {
        let mut ts: libc::timespec = mem::zeroed();
        libc::clock_gettime(libc::CLOCK_MONOTONIC_RAW, &mut ts);
        ts
    };
    (ts.tv_sec as u64).saturating_mul(1_000_000_000).saturating_add(ts.tv_nsec as u64)
}

/* ---------------------------- objset counters ---------------------------- */

/**
A dataset's I/O counters, from its pool's `objset-0x<id>` kstat: operations
and bytes written and read through the filesystem or volume (`writes`,
`nwritten`, `reads`, `nread`), unlinks, and from 2.2 the ZIL's
`zil_commit_count`, `zil_itx_*` and so on ([`Kstat::has`] tells the eras
apart). A filesystem has one while mounted and a volume while its device
exists; the counters start at zero each time. The dataset name follows
renames from 2.3 on; earlier kernels keep the name it was opened under.
*/
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ObjsetKstat {
    /// The objset id, from the file name.
    pub objset: u64,
    /// The dataset's name (`dataset_name`).
    pub dataset: String,
    /// Every field, by kstat name.
    pub stats: Kstat,
}

impl ObjsetKstat {
    /// Parse objset `objset`'s kstat text; `None` without a `dataset_name`.
    pub fn parse(objset: u64, text: &str) -> Option<Self> {
        let stats = Kstat::parse(text);
        let dataset = stats.str("dataset_name")?.to_string();
        Some(ObjsetKstat { objset, dataset, stats })
    }
}

/// The objset id in an `objset-0x<id>` file name.
#[cfg(target_os = "linux")]
fn objset_file_id(name: &str) -> Option<u64> {
    u64::from_str_radix(name.strip_prefix(OBJSET_PREFIX)?, 16).ok()
}

/**
Objset `objset`'s kstat in pool `pool`: the cheap re-read once
[`find_objset_kstat`] has found a dataset's id. A dataset unmounted since is
`NotFound`; check [`ObjsetKstat::dataset`] if the id may have been reused.
*/
#[cfg(target_os = "linux")]
pub fn read_objset_kstat(pool: &str, objset: u64) -> io::Result<ObjsetKstat> {
    let path = pool_dir(pool)?.join(format!("{OBJSET_PREFIX}{objset:x}"));
    let text = fs::read_to_string(&path)?;
    ObjsetKstat::parse(objset, &text).ok_or_else(|| {
        let msg = format!("{}: no dataset_name", path.display());
        io::Error::new(io::ErrorKind::InvalidData, msg)
    })
}

/// The objset kstats of pool `pool`'s open datasets, by objset id.
#[cfg(target_os = "linux")]
pub fn read_objset_kstats(pool: &str) -> io::Result<Vec<ObjsetKstat>> {
    let mut all = Vec::new();
    for entry in fs::read_dir(pool_dir(pool)?)? {
        let Some(id) = entry?.file_name().to_str().and_then(objset_file_id) else { continue };
        match read_objset_kstat(pool, id) {
            Ok(k) => all.push(k),
            // unmounted between the listing and the read
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    all.sort_by_key(|k| k.objset);
    Ok(all)
}

/**
The objset kstat of dataset `dataset`, found in its pool's directory, or
`None` when it has none (not mounted, not a volume, or no such dataset). This
scans every objset kstat of the pool; to sample a dataset repeatedly, keep the
returned [`ObjsetKstat::objset`] and re-read it with [`read_objset_kstat`].
*/
#[cfg(target_os = "linux")]
pub fn find_objset_kstat(dataset: &str) -> io::Result<Option<ObjsetKstat>> {
    let pool = dataset.split(['/', '@']).next().unwrap_or(dataset);
    Ok(read_objset_kstats(pool)?.into_iter().find(|k| k.dataset == dataset))
}

/* ------------------------- tx-assign delay histogram --------------------- */

/**
A pool's transaction-assign delay histogram (`dmu_tx_assign`): how long
transactions waited for a txg to take them, i.e. the write throttle and the
dirty-data limit at work. Bucket `i` counts waits of `(2^(i-1), 2^i]` ns
(bucket 0, up to 1 ns). Only transactions that had to wait are counted, so a
pool that never throttled has an empty file; the host-wide `dmu_tx` kstat
([`read_dmu_tx`]) has the total `dmu_tx_assigned` and the throttle events.
The counts are cumulative since import (a root write to the file zeroes
them); [`since`](Self::since) gives the waits between two reads.
*/
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TxAssignHistogram {
    counts: Vec<u64>,
}

impl TxAssignHistogram {
    /// Parse the kstat text. Buckets are placed by their `<2^i> ns` names;
    /// the kernel leaves out the empty ones past the last count.
    pub fn parse(text: &str) -> Self {
        let mut counts = Vec::new();
        for (name, _, value) in text.lines().skip(2).filter_map(named_line) {
            let Some(bound) = name.strip_suffix(" ns").and_then(|n| n.parse::<u64>().ok()) else {
                continue;
            };
            let (true, Ok(count)) = (bound.is_power_of_two(), value.trim().parse::<u64>()) else {
                continue;
            };
            let i = bound.trailing_zeros() as usize;
            if counts.len() <= i {
                counts.resize(i + 1, 0);
            }
            counts[i] = count;
        }
        TxAssignHistogram { counts }
    }

    /// The counts by bucket.
    pub fn counts(&self) -> &[u64] {
        &self.counts
    }

    /// Bucket `i`'s upper bound, ns.
    pub fn bucket_limit_ns(i: usize) -> u64 {
        1u64.checked_shl(i as u32).unwrap_or(u64::MAX)
    }

    /// All waits counted (saturating: the counts come from a text file).
    pub fn total(&self) -> u64 {
        self.counts.iter().fold(0u64, |acc, &c| acc.saturating_add(c))
    }

    /// The waits known to have taken longer than `ns`: the buckets whose
    /// lower bound is at least `ns`, leaving out the one that straddles it.
    pub fn longer_than(&self, ns: u64) -> u64 {
        self.counts
            .iter()
            .enumerate()
            .skip(1)
            .filter(|(i, _)| Self::bucket_limit_ns(i - 1) >= ns)
            .fold(0u64, |acc, (_, &c)| acc.saturating_add(c))
    }

    /**
    The waits counted since `earlier`, bucket by bucket. A bucket smaller
    than before means the histogram was zeroed in between; then everything
    counted is new, and `self` comes back whole.
    */
    pub fn since(&self, earlier: &Self) -> Self {
        let at = |h: &Self, i: usize| h.counts.get(i).copied().unwrap_or(0);
        let len = self.counts.len().max(earlier.counts.len());
        if (0..len).any(|i| at(self, i) < at(earlier, i)) {
            return self.clone();
        }
        let counts = (0..self.counts.len()).map(|i| at(self, i) - at(earlier, i)).collect();
        TxAssignHistogram { counts }
    }
}

/// Pool `pool`'s tx-assign delay histogram.
#[cfg(target_os = "linux")]
pub fn read_tx_assign(pool: &str) -> io::Result<TxAssignHistogram> {
    let text = fs::read_to_string(pool_dir(pool)?.join("dmu_tx_assign"))?;
    Ok(TxAssignHistogram::parse(&text))
}

/* ====================== pool loads and the debug log ===================== */

/**
A pool load in progress, from the host-wide `import_progress` table: a
`zpool import` (or `zpool import -F` recovery, or a tryimport scan) while it
runs. An import holds the pool namespace lock for its whole load, so while
one runs every pool ioctl on the host waits for it; this table, which takes
no ZFS lock, is where that shows. The format is unchanged from ZoL 0.8 to
OpenZFS 2.3; 2.4 appends the `notes` column.
*/
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ImportProgress {
    pub pool_guid: u64,
    /// The pool's name, `None` until the load knows it.
    pub pool: Option<String>,
    pub load_state: Coded<SpaLoadState>,
    /// How long the multihost (MMP) activity check waits, seconds: the
    /// import watches that long for another host still writing the pool.
    pub multihost_secs: u64,
    /// The newest txg the load may use: lowered step by step as a recovery
    /// import rewinds, `u64::MAX` when uncapped.
    pub max_txg: u64,
    /// What the load is doing, in the kernel's words (2.4 on).
    pub notes: Option<String>,
}

/**
Parse an `import_progress` table: a header line, then one row per load.
Columns are found by their header names; `notes` is free text and runs to
the end of the line. A `-` name or note is absent.
*/
pub fn parse_import_progress(text: &str) -> Vec<ImportProgress> {
    let mut lines = text.lines();
    let Some(header) = lines.next() else { return Vec::new() };
    let cols: HashMap<&str, usize> =
        header.split_whitespace().enumerate().map(|(i, c)| (c, i)).collect();
    let present = |s: &str| (s != "-").then(|| s.to_string());
    lines
        .filter_map(|line| {
            let row: Vec<&str> = line.split_whitespace().collect();
            let field = |name: &str| row.get(*cols.get(name)?).copied();
            let num = |name: &str| field(name)?.parse::<u64>().ok();
            let notes = cols
                .get("notes")
                .and_then(|&i| token_spans(line).nth(i))
                .map(|(start, _)| line[start..].trim_end());
            Some(ImportProgress {
                pool_guid: num("pool_guid")?,
                pool: present(field("pool_name")?),
                load_state: Coded::new(num("load_state")?),
                multihost_secs: num("multihost_secs")?,
                max_txg: num("max_txg")?,
                notes: notes.and_then(present),
            })
        })
        .collect()
}

/// The pool loads in progress on this host ([`parse_import_progress`]).
#[cfg(target_os = "linux")]
pub fn read_import_progress() -> io::Result<Vec<ImportProgress>> {
    Ok(parse_import_progress(&fs::read_to_string(IMPORT_PROGRESS_PATH)?))
}

/**
One entry of the ZFS debug log (`dbgmsg`): the module's ring of internal
messages (`zfs_dbgmsg()`), such as pool load steps, scan and device-removal
progress, multihost checks, and errors the code chose to record. Messages
are kept while the `zfs_dbgmsg_enable` module parameter is set (the Linux
default), up to `zfs_dbgmsg_maxsize` bytes, oldest dropped first. Reading the
file needs root.
*/
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DbgMsg {
    /// When it was logged, Unix seconds.
    pub time: u64,
    /// The message, usually prefixed `file.c:line:function(): `.
    pub message: String,
}

/**
Parse the debug log, oldest first: a header line, then `<timestamp>
<message>` lines. A message with a newline in it spans lines; a line that
doesn't start with a timestamp continues the message before it.
*/
pub fn parse_dbgmsg(text: &str) -> Vec<DbgMsg> {
    let mut out: Vec<DbgMsg> = Vec::new();
    for line in text.lines().skip(1) {
        let (first, rest) = line.split_once(char::is_whitespace).unwrap_or((line, ""));
        match (first.parse::<u64>(), out.last_mut()) {
            (Ok(time), _) => out.push(DbgMsg { time, message: rest.trim_start().to_string() }),
            (Err(_), Some(last)) => {
                last.message.push('\n');
                last.message.push_str(line);
            }
            (Err(_), None) => {}
        }
    }
    out
}

/// The ZFS debug log, oldest first ([`parse_dbgmsg`]). `PermissionDenied`
/// unless root.
#[cfg(target_os = "linux")]
pub fn read_dbgmsg() -> io::Result<Vec<DbgMsg>> {
    Ok(parse_dbgmsg(&fs::read_to_string(DBGMSG_PATH)?))
}

/* ================================ tests ================================== */

#[cfg(test)]
mod tests {
    use super::*;

    // the committed reference dumps (root-free regression fixtures)
    const ARC_21: &str = include_str!("../doc/kstat/arcstats_v2.1.6.txt");
    const ARC_22: &str = include_str!("../doc/kstat/arcstats_v2.2.2.txt");
    const ZF_21: &str = include_str!("../doc/kstat/zfetchstats_v2.1.6.txt");
    const ZF_22: &str = include_str!("../doc/kstat/zfetchstats_v2.2.2.txt");
    const DMU_TX_22: &str = include_str!("../doc/kstat/dmu_tx_v2.2.2.txt");
    const TXGS_22: &str = include_str!("../doc/kstat/txgs_v2.2.2.txt");
    const TX_ASSIGN_22: &str = include_str!("../doc/kstat/dmu_tx_assign_v2.2.2.txt");
    // a root filesystem's objset kstat, its dataset name anonymised
    const OBJSET_22: &str = include_str!("../doc/kstat/objset_v2.2.2.txt");

    /// Round a fraction to one decimal percent, as `arc_summary` prints it.
    fn pct(f: f64) -> f64 {
        (f * 1000.0).round() / 10.0
    }

    #[test]
    fn parses_both_schemas_and_signed_field() {
        let k21 = Kstat::parse(ARC_21);
        let k22 = Kstat::parse(ARC_22);
        // a shared field decodes the same way in both
        assert_eq!(k21.u("c_max"), 103079215104);
        assert_eq!(k22.u("c_max"), 67431995392);
        // version-only fields: present where expected, absent (→0/false) elsewhere
        assert!(k21.has("p") && k21.has("arc_meta_limit"));
        assert!(!k22.has("p") && !k22.has("arc_meta_limit"));
        assert!(k22.has("iohits") && k22.has("mfu_data") && k22.has("uncached_size"));
        assert!(!k21.has("iohits") && !k21.has("mfu_data"));
        // memory_available_bytes is the signed (type-3) field; both samples positive
        assert_eq!(k21.get("memory_available_bytes"), Some(9058452352));
    }

    #[test]
    fn derived_ratios_match_arc_summary() {
        let (k21, k22) = (Kstat::parse(ARC_21), Kstat::parse(ARC_22));

        // overall cache hit ratio - 2.1 "87.5%", 2.2 "100.0%" (iohits folded in)
        assert_eq!(pct(hit_ratio(&k21, ArcClass::All).unwrap()), 87.5);
        assert_eq!(pct(hit_ratio(&k22, ArcClass::All).unwrap()), 100.0);

        // demand-data efficiency - 2.1 "13.5%"; 2.2 includes iohits in the base
        assert_eq!(pct(hit_ratio(&k21, ArcClass::DemandData).unwrap()), 13.5);
        assert_eq!(pct(hit_ratio(&k22, ArcClass::DemandData).unwrap()), 100.0);

        // DMU prefetch stream hit ratio - both eras "73.6%"
        assert_eq!(pct(dmu_prefetch_ratio(&Kstat::parse(ZF_21)).unwrap()), 73.6);
        assert_eq!(pct(dmu_prefetch_ratio(&Kstat::parse(ZF_22)).unwrap()), 6.4);

        // health: 2.1 was THROTTLED (arc_no_grow=1), 2.2 HEALTHY
        assert!(is_throttled(&k21));
        assert!(!is_throttled(&k22));
    }

    #[test]
    fn empty_classes_dont_divide_by_zero() {
        let empty = Kstat::default();
        assert!(hit_ratio(&empty, ArcClass::All).is_none());
        assert!(dmu_prefetch_ratio(&empty).is_none());
        assert_eq!(accesses(&empty, ArcClass::All), 0);
    }

    #[test]
    fn class_prefixes_name_the_counters() {
        let k: Kstat =
            [("prefetch_metadata_hits", 3), ("prefetch_metadata_misses", 1)].into_iter().collect();
        assert_eq!(accesses(&k, ArcClass::PrefetchMetadata), 4);
        assert_eq!(hit_ratio(&k, ArcClass::PrefetchMetadata), Some(0.75));
        assert_eq!(accesses(&k, ArcClass::All), 0);
    }

    /// A named kstat line as the SPL prints it (`%-31s %-4d <value>`).
    fn spl_line(name: &str, ty: u8, value: &str) -> String {
        format!("{name:<31} {ty:<4} {value}")
    }

    #[test]
    fn named_lines_split_at_the_type() {
        // a name with a space, and a string value with spaces
        let bucket = spl_line("1024 ns", 4, "17");
        assert_eq!(named_line(&bucket), Some(("1024 ns", 4, "17")));
        let name = spl_line("dataset_name", 7, "tank/my data ");
        assert_eq!(named_line(&name), Some(("dataset_name", 7, "tank/my data ")));
        // a name longer than the padded column runs on
        let long = spl_line("zil_itx_metaslab_normal_count_extra", 4, "9");
        assert_eq!(named_line(&long), Some(("zil_itx_metaslab_normal_count_extra", 4, "9")));
        // a compact line, as a hand-written fixture has it
        assert_eq!(named_line("memory_available_bytes 3 -2147483648"),
                   Some(("memory_available_bytes", 3, "-2147483648")));
        assert_eq!(named_line("dataset_name 7 tank/x y"), Some(("dataset_name", 7, "tank/x y")));
        // a CHAR value is padded; parse trims it
        let k = Kstat::parse(&format!("hdr\nname type data\n{}\n", spl_line("c", 0, "abc   ")));
        assert_eq!(k.str("c"), Some("abc"));
        // the column header is no field (parse skips both header lines anyway)
        assert_eq!(named_line("name                            type data"), None);
        assert_eq!(named_line("short"), None);
    }

    #[test]
    fn string_fields_and_the_dmu_tx_counters() {
        let k = Kstat::parse(OBJSET_22);
        assert_eq!(k.str("dataset_name"), Some("tank/home"));
        assert_eq!(k.get("dataset_name"), None);
        assert!(k.has("dataset_name") && k.has("zil_commit_count"));
        assert_eq!(k.u("writes"), 1788530);
        assert_eq!(k.u("nwritten"), 22966074955);
        assert_eq!(k.u("zil_commit_count"), 3263);
        assert!(k.iter().all(|(name, _)| name != "dataset_name"));

        let tx = Kstat::parse(DMU_TX_22);
        assert_eq!(tx.u("dmu_tx_assigned"), 63286040);
        assert!(tx.has("dmu_tx_dirty_throttle") && tx.has("dmu_tx_quota"));
    }

    #[test]
    fn objset_kstat_needs_a_dataset_name() {
        let o = ObjsetKstat::parse(0x31, OBJSET_22).unwrap();
        assert_eq!((o.objset, o.dataset.as_str()), (0x31, "tank/home"));
        assert_eq!(o.stats.u("reads"), 80303576);
        assert!(ObjsetKstat::parse(1, DMU_TX_22).is_none());
    }

    #[test]
    fn txg_history_rows_and_phases() {
        let txgs = parse_txgs(TXGS_22);
        assert_eq!(txgs.len(), 12);
        assert!(txgs.windows(2).all(|w| w[1].txg == w[0].txg + 1), "oldest first");

        let synced = &txgs[8];
        assert_eq!((synced.txg, synced.state), (38933313, TxgState::Committed));
        assert_eq!((synced.ndirty, synced.nwritten, synced.writes), (315760640, 286113792, 3909));
        assert_eq!(synced.sync_ns, 169886025);
        assert_eq!(synced.in_phase_for(u64::MAX), None);

        // the syncing txg: open, quiesce and wait done, its I/O not filled in yet
        let syncing = &txgs[10];
        assert_eq!((syncing.txg, syncing.state), (38933315, TxgState::Syncing));
        assert_eq!((syncing.open_ns, syncing.quiesce_ns, syncing.wait_ns), (5119702792, 15230, 30460));
        assert_eq!((syncing.sync_ns, syncing.ndirty), (0, 0));
        let start = syncing.birth + 5119702792 + 15230 + 30460;
        assert_eq!(syncing.phase_start(), start);
        assert_eq!(syncing.in_phase_for(start + 2_000_000_000), Some(2_000_000_000));
        // a txg's open phase ends when the next one is born
        assert_eq!(syncing.birth + syncing.open_ns, txgs[11].birth);

        let open = &txgs[11];
        assert_eq!((open.state, open.phase_start()), (TxgState::Open, open.birth));
    }

    #[test]
    fn txg_history_is_parsed_by_header() {
        // reordered, with an extra column; a short row is skipped
        let text = "state txg birth otime qtime wtime stime extra ndirty nread nwritten reads writes\n\
                    S 7 100 10 1 2 0 x 5 6 7 8 9\n\
                    C 6 50\n";
        let t = parse_txgs(text);
        assert_eq!(t.len(), 1);
        assert_eq!((t[0].txg, t[0].birth, t[0].state, t[0].writes), (7, 100, TxgState::Syncing, 9));
        assert_eq!(t[0].phase_start(), 113);
        assert!(parse_txgs("").is_empty());
        assert_eq!(TxgState::from_letter('?'), TxgState::Unknown('?'));
        for c in "BOQWSC?".chars() {
            assert_eq!(TxgState::from_letter(c).letter(), c);
        }
    }

    #[test]
    fn tx_assign_buckets_by_their_bounds() {
        let h = TxAssignHistogram::parse(TX_ASSIGN_22);
        assert_eq!(h.counts().len(), 32);
        assert_eq!(h.counts()[14], 1);
        assert_eq!(h.counts()[29], 422);
        assert_eq!(h.counts()[31], 36);
        assert_eq!(h.total(), 1150);
        assert_eq!(TxAssignHistogram::bucket_limit_ns(31), 2147483648);
        // waits over a second: only the (2^30, 2^31] ns bucket qualifies
        assert_eq!(h.longer_than(1_000_000_000), 36);
        assert_eq!(h.longer_than(1 << 29), 286 + 36);
        assert_eq!(h.longer_than(0), 1150);
        // a pool that never throttled has an empty file
        assert_eq!(TxAssignHistogram::parse("").total(), 0);
    }

    #[test]
    fn tx_assign_sums_saturate() {
        // hostile counts: two full buckets must not overflow the sums
        let text = format!(
            "hdr\nname type data\n{}\n{}\n",
            spl_line("1 ns", 4, &u64::MAX.to_string()),
            spl_line("2 ns", 4, &u64::MAX.to_string())
        );
        let h = TxAssignHistogram::parse(&text);
        assert_eq!(h.counts(), [u64::MAX, u64::MAX]);
        assert_eq!(h.total(), u64::MAX);
        assert_eq!(h.longer_than(0), u64::MAX);
    }

    #[test]
    fn tx_assign_windows_and_resets() {
        let h = |counts: &[u64]| TxAssignHistogram { counts: counts.to_vec() };
        assert_eq!(h(&[1, 5, 2]).since(&h(&[1, 3])), h(&[0, 2, 2]));
        // a bucket going down (or one vanishing) means the counts were zeroed
        assert_eq!(h(&[1, 2]).since(&h(&[1, 3])), h(&[1, 2]));
        assert_eq!(h(&[4]).since(&h(&[4, 1])), h(&[4]));
    }

    #[test]
    fn pool_health_words() {
        let p = |w: &str| w.parse::<PoolHealth>().unwrap();
        assert_eq!(p("ONLINE"), PoolHealth::Online);
        assert_eq!(p("UNAVAIL"), PoolHealth::Unavail);
        assert_eq!(p("SUSPENDED"), PoolHealth::Suspended);
        assert_eq!(p("TRANSITIONING"), PoolHealth::Transitioning);
        assert_eq!(p("WOBBLY"), PoolHealth::Other("WOBBLY".into()));
        assert_eq!(PoolHealth::Degraded.to_string(), "DEGRADED");
        assert_eq!(PoolHealth::Other("WOBBLY".into()).to_string(), "WOBBLY");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn objset_ids_from_file_names() {
        assert_eq!(objset_file_id("objset-0x18a3e"), Some(0x18a3e));
        assert_eq!(objset_file_id("objset-0xzz"), None);
        assert_eq!(objset_file_id("txgs"), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn pool_dir_stays_inside_the_kstat_tree() {
        assert_eq!(pool_dir("tank").unwrap(), Path::new("/proc/spl/kstat/zfs/tank"));
        for bad in ["", "..", ".", "a/../b", "9pool", "/etc"] {
            assert!(pool_dir(bad).is_err(), "{bad:?}");
        }
    }

    /**
    Pool names come from the subdirectories holding a `state` kstat: not the
    host-wide kstat files, not a directory without one, and not the
    transient `$import` pool.
    */
    #[cfg(target_os = "linux")]
    #[test]
    fn pool_names_are_the_dirs_with_a_state() {
        let dir = std::env::temp_dir().join(format!("zfsdev-pool-names-{}", std::process::id()));
        for pool in ["tank", "rpool", "$import"] {
            fs::create_dir_all(dir.join(pool)).unwrap();
            fs::write(dir.join(pool).join("state"), "ONLINE\n").unwrap();
        }
        fs::create_dir_all(dir.join("nostate")).unwrap();
        fs::write(dir.join("arcstats"), ARC_22).unwrap();
        let names = pool_names_in(&dir);
        let _ = fs::remove_dir_all(&dir);
        assert_eq!(names.unwrap(), ["rpool", "tank"]);
    }

    /// Both table eras, as spa_import_progress_show prints them: the 2.4 one
    /// adds the free-text `notes` column.
    #[test]
    fn import_progress_parses_both_eras() {
        let v22 = "pool_guid            load_state     multihost_secs max_txg      pool_name\n\
                   12345678901234567890 2              10             18446744073709551615 tank\n\
                   42                   3              0              18446744073709551615 -\n";
        let rows = parse_import_progress(v22);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].pool.as_deref(), Some("tank"));
        assert_eq!(rows[0].load_state.get(), Some(SpaLoadState::Import));
        assert_eq!((rows[0].multihost_secs, rows[0].max_txg, rows[0].notes.as_deref()), (10, u64::MAX, None));
        // a tryimport scan before it knows the name
        assert_eq!((rows[1].pool.as_deref(), rows[1].load_state.to_string().as_str()), (None, "tryimport"));

        let v24 = "pool_guid            load_state     multihost_secs max_txg      pool_name        notes\n\
                   7                    4              0              1234         tank             Loading checkpoint txg\n\
                   8                    9              0              5            data             -\n";
        let rows = parse_import_progress(v24);
        assert_eq!(rows[0].notes.as_deref(), Some("Loading checkpoint txg"));
        assert_eq!(rows[0].load_state.get(), Some(SpaLoadState::Recover));
        // a load state newer than this crate keeps its number
        assert_eq!((rows[1].load_state.to_string().as_str(), rows[1].notes.as_deref()), ("?9", None));
        assert!(parse_import_progress("").is_empty());
    }

    #[test]
    fn dbgmsg_entries_and_continuations() {
        let text = "timestamp    message \n\
                    1696000000   spa.c:6624:spa_import(): spa_import: importing tank\n\
                    1696000001   a message with\n\
                    a second line\n\
                    1696000002   \n";
        let msgs = parse_dbgmsg(text);
        assert_eq!(msgs.len(), 3);
        assert_eq!(msgs[0].time, 1696000000);
        assert_eq!(msgs[0].message, "spa.c:6624:spa_import(): spa_import: importing tank");
        assert_eq!(msgs[1].message, "a message with\na second line");
        assert_eq!(msgs[2].message, "");
        assert!(parse_dbgmsg("timestamp    message \n").is_empty());
    }
}
