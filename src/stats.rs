// Copyright (c) 2026 Mikko Tanner. All rights reserved.
// Licensed under the MIT License or the Apache License, Version 2.0.
// SPDX-License-Identifier: MIT OR Apache-2.0

/*!
Typed decoders for the kernel's vdev and pool statistics — the positional
`u64` arrays (`vdev_stat_t`, `pool_scan_stat_t`, `vdev_rebuild_stat_t`) and the
`vdev_stats_ex` nvlist that POOL_STATS hangs off each vdev of the config tree.

Those arrays are C structs flattened to words, and their layouts changed across
OpenZFS releases: fields appended, `vs_noalloc` *inserted* mid-array in 2.2,
`pool_scan_stat_t` slot 6 repurposed. Every change is told apart by the array
length the kernel hands back, so no version probe is needed — and that
knowledge lives here once: callers get named fields, with `Option` for the
ones the running kernel doesn't report. Each decoder reads its words in the C
struct's field order (`Words`), so it can be checked against the header
line by line: `doc/reference/zfs.h` (2.2) and `doc/reference/{0.8,2.0,2.1,
2.3}/zfs.h`. ZoL 0.6/0.7 layouts are not supported (0.7's `vdev_stat_t` has a
mid-array insert that the length alone can't tell apart).

Derived figures that follow from the kernel fields alone (scan progress, pass
rate, ETA — computed the way `zpool status` does; a histogram's window
between two reads and its quantiles) are methods; presentation is the
caller's.
*/

use crate::enums::{
    CEnum, Coded, DslScanState, PoolScanFunc, VdevAux, VdevInitializeState, VdevRebuildState,
    VdevState, VdevTrimState,
};
use crate::nvlist::{NvData, NvList, NvPair};
use std::collections::HashSet;
use std::str::FromStr;
use strum::{EnumIter, EnumString, IntoEnumIterator, IntoStaticStr};

/* vdev config nvlist keys (ZPOOL_CONFIG_* in zfs.h) */
const VDEV_STATS_KEY: &str = "vdev_stats";
const SCAN_STATS_KEY: &str = "scan_stats";
/// ZPOOL_CONFIG_REBUILD_STATS — note the feature-namespace prefix.
const REBUILD_STATS_KEY: &str = "org.openzfs:rebuild_stats";
const VDEV_STATS_EX_KEY: &str = "vdev_stats_ex";

/*
vdev_stat_t length (u64 words) per layout era. 0.8 ends at vs_trim_action_time;
2.0 appends rebuild_processed + the three ashifts; 2.1 appends vs_pspace (at
45); 2.2 *inserts* vs_noalloc at 45 (pspace moves to 46); 2.3 appends
vs_dio_verify_errors.
*/
const VS_LEN_0_8: usize = 41;
const VS_LEN_2_0: usize = 45;
const VS_LEN_2_2: usize = 47;
const VS_LEN_2_3: usize = 48;

/*
pool_scan_stat_t: 15 words through 2.1 (slot 6 = pss_to_process); 2.2 renamed
slot 6 pss_skipped in the same change that appended the error-scrub fields.
*/
const PSS_LEN_BASE: usize = 15;
const PSS_LEN_2_2: usize = 22;

/// vdev_rebuild_stat_t: 12 words in 2.0/2.1; 2.2 appends pass_bytes_skipped.
const VRS_LEN_BASE: usize = 12;

/// `vs_fragmentation` above this is ZFS_FRAG_INVALID (no figure for this vdev).
const FRAG_MAX_PCT: u64 = 100;

/* vdev_stat_ex histogram bucket counts (zfs.h) */
const VDEV_L_HISTO_BUCKETS: usize = 37;
const VDEV_RQ_HISTO_BUCKETS: usize = 25;

/* ---------------------------- word reader -------------------------------- */

/**
Sequential reader over a flattened kernel struct, consumed in C field order.
Decoders length-check the base layout up front, so [`word`](Words::word)
never runs past it; fields a newer layout appended go through
[`word_opt`](Words::word_opt).
*/
struct Words<'a> {
    words: &'a [u64],
    pos: usize,
}

impl<'a> Words<'a> {
    fn new(words: &'a [u64]) -> Self {
        Words { words, pos: 0 }
    }

    /// The next field of the base layout (0 past the end, which the up-front
    /// length check rules out).
    fn word(&mut self) -> u64 {
        self.word_opt().unwrap_or(0)
    }

    /// The next field, if this kernel's array has it.
    fn word_opt(&mut self) -> Option<u64> {
        let w = self.words.get(self.pos).copied();
        self.pos += 1;
        w
    }

    fn flag(&mut self) -> bool {
        self.word() != 0
    }

    fn coded<E: CEnum>(&mut self) -> Coded<E> {
        Coded::new(self.word())
    }

    fn array<const N: usize>(&mut self) -> [u64; N] {
        std::array::from_fn(|_| self.word())
    }
}

/// `part / whole` as a fraction, 0 when the whole is unknown (0).
fn fraction(part: u64, whole: u64) -> f64 {
    if whole > 0 { part as f64 / whole as f64 } else { 0.0 }
}

/// Seconds to finish `left` bytes at `rate` bytes/s; None at a standstill.
fn eta(left: u64, rate: Option<u64>) -> Option<u64> {
    rate.filter(|&r| r > 0 && left > 0).map(|r| left / r)
}

/* --------------------------- cumulative histograms ------------------------ */

/**
The counts added between two reads of a cumulative histogram, bucket by
bucket, or `None` when a bucket shrank: the histogram was reset in between
(zeroed, or its vdev reopened), so `now` counts only new samples. Buckets
missing from the shorter slice count as 0.
*/
pub(crate) fn bucket_deltas(now: &[u64], earlier: &[u64]) -> Option<Vec<u64>> {
    let at = |h: &[u64], i: usize| h.get(i).copied().unwrap_or(0);
    let len = now.len().max(earlier.len());
    if (0..len).any(|i| at(now, i) < at(earlier, i)) {
        return None;
    }
    Some(now.iter().enumerate().map(|(i, &c)| c - at(earlier, i)).collect())
}

/**
The bucket holding the `q`-quantile (0 ≤ `q` ≤ 1) of the samples counted in
`counts`: the first bucket by which `⌈q · total⌉` samples (at least one) have
been counted. `None` for an empty histogram or a `q` outside 0..=1.
*/
pub(crate) fn quantile_bucket(counts: &[u64], q: f64) -> Option<usize> {
    let total = counts.iter().fold(0u64, |acc, &c| acc.saturating_add(c));
    if total == 0 || !(0.0..=1.0).contains(&q) {
        return None;
    }
    let rank = ((q * total as f64).ceil() as u64).clamp(1, total);
    let mut seen = 0u64;
    counts.iter().position(|&c| {
        seen = seen.saturating_add(c);
        seen >= rank
    })
}

/* ------------------------------ vdev_stat_t ------------------------------ */

/**
Per-ZIO-type counters (`vs_ops` / `vs_bytes`, indexed by `zio_type_t`;
`VS_ZIO_TYPES` = 6, so TRIM has no slot here).
*/
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct ZioCounters {
    pub null: u64,
    pub read: u64,
    pub write: u64,
    pub free: u64,
    pub claim: u64,
    /// ZIO_TYPE_IOCTL, renamed ZIO_TYPE_FLUSH in OpenZFS 2.3.
    pub flush: u64,
}

impl ZioCounters {
    fn from_words(w: [u64; 6]) -> Self {
        let [null, read, write, free, claim, flush] = w;
        ZioCounters { null, read, write, free, claim, flush }
    }
}

/// Progress of a per-leaf `zpool initialize` or `zpool trim`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct LeafOpProgress<S: CEnum> {
    pub state: Coded<S>,
    pub errors: u64,
    pub bytes_done: u64,
    pub bytes_est: u64,
    /// Unix time of the last state change.
    pub action_time: u64,
}

/// The vdev's ashift as configured, and as the device reports it (OpenZFS 2.0+).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct VdevAshift {
    /// The top-level vdev's ashift (`vdev_ashift`).
    pub configured: u64,
    pub logical: u64,
    pub physical: u64,
}

/// `vdev_stat_t`: one vdev's state, capacity, I/O and error counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct VdevStats {
    /// Nanoseconds since the vdev was loaded (`vs_timestamp`).
    pub timestamp_ns: u64,
    pub state: Coded<VdevState>,
    pub aux: Coded<VdevAux>,
    pub alloc: u64,
    pub space: u64,
    pub dspace: u64,
    /// `vs_rsize`: the size a replacing device must have.
    pub replaceable_size: u64,
    /// `vs_esize`: space a `zpool online -e` would add.
    pub expandable_size: u64,
    /// Operations since vdev load.
    pub ops: ZioCounters,
    /// Bytes since vdev load.
    pub bytes: ZioCounters,
    pub read_errors: u64,
    pub write_errors: u64,
    pub checksum_errors: u64,
    pub self_healed: u64,
    /// The vdev is being removed (`zpool remove`).
    pub scan_removing: bool,
    /// Bytes this vdev has resilvered/scrubbed in the current scan.
    pub scan_processed: u64,
    /// Percent; None when the kernel has no figure (ZFS_FRAG_INVALID — e.g.
    /// a leaf or interior vdev).
    pub fragmentation: Option<u64>,
    pub initialize: LeafOpProgress<VdevInitializeState>,
    pub checkpoint_space: u64,
    /// A resilver of this vdev waits for the running one to finish.
    pub resilver_deferred: bool,
    /// I/Os that took longer than `zio_slow_io_ms` — the kernel's hang counter.
    pub slow_ios: u64,
    pub trim: LeafOpProgress<VdevTrimState>,
    /// The device doesn't support TRIM.
    pub trim_unsupported: bool,
    /// Bytes rebuilt by a sequential rebuild (OpenZFS 2.0+).
    pub rebuild_processed: Option<u64>,
    /// OpenZFS 2.0+.
    pub ashift: Option<VdevAshift>,
    /// Allocations halted on this vdev (OpenZFS 2.2+).
    pub noalloc: Option<bool>,
    /// Physical capacity (OpenZFS 2.1+).
    pub pspace: Option<u64>,
    /// Direct-I/O checksum verify errors (OpenZFS 2.3+).
    pub dio_verify_errors: Option<u64>,
}

impl VdevStats {
    /// The stats of a vdev config nvlist (any vdev of a POOL_STATS tree).
    pub fn from_vdev(vdev: &NvList) -> Option<VdevStats> {
        vdev.get_u64_array(VDEV_STATS_KEY).and_then(VdevStats::decode)
    }

    /// Decode a raw `vdev_stats` array; None when shorter than any supported layout.
    pub fn decode(vs: &[u64]) -> Option<VdevStats> {
        if vs.len() < VS_LEN_0_8 {
            return None;
        }
        let mut w = Words::new(vs);
        let timestamp_ns = w.word();
        let state = w.coded();
        let aux = w.coded();
        let (alloc, space, dspace) = (w.word(), w.word(), w.word());
        let (replaceable_size, expandable_size) = (w.word(), w.word());
        let ops = ZioCounters::from_words(w.array());
        let bytes = ZioCounters::from_words(w.array());
        let (read_errors, write_errors, checksum_errors) = (w.word(), w.word(), w.word());
        let initialize_errors = w.word();
        let self_healed = w.word();
        let scan_removing = w.flag();
        let scan_processed = w.word();
        let fragmentation = Some(w.word()).filter(|&f| f <= FRAG_MAX_PCT);
        let initialize = LeafOpProgress {
            errors: initialize_errors,
            bytes_done: w.word(),
            bytes_est: w.word(),
            state: w.coded(),
            action_time: w.word(),
        };
        let checkpoint_space = w.word();
        let resilver_deferred = w.flag();
        let slow_ios = w.word();
        let trim_errors = w.word();
        let trim_unsupported = w.flag();
        let trim = LeafOpProgress {
            errors: trim_errors,
            bytes_done: w.word(),
            bytes_est: w.word(),
            state: w.coded(),
            action_time: w.word(),
        };
        // ---- 2.0 ----
        let rebuild_processed = (vs.len() >= VS_LEN_2_0).then(|| w.word());
        let ashift = (vs.len() >= VS_LEN_2_0).then(|| VdevAshift {
            configured: w.word(),
            logical: w.word(),
            physical: w.word(),
        });
        // ---- 2.1 appended pspace; 2.2 inserted noalloc before it ----
        let noalloc = if vs.len() >= VS_LEN_2_2 { w.word_opt().map(|n| n != 0) } else { None };
        let pspace = if vs.len() >= VS_LEN_2_0 { w.word_opt() } else { None };
        // ---- 2.3 ----
        let dio_verify_errors = if vs.len() >= VS_LEN_2_3 { w.word_opt() } else { None };
        Some(VdevStats {
            timestamp_ns,
            state,
            aux,
            alloc,
            space,
            dspace,
            replaceable_size,
            expandable_size,
            ops,
            bytes,
            read_errors,
            write_errors,
            checksum_errors,
            self_healed,
            scan_removing,
            scan_processed,
            fragmentation,
            initialize,
            checkpoint_space,
            resilver_deferred,
            slow_ios,
            trim,
            trim_unsupported,
            rebuild_processed,
            ashift,
            noalloc,
            pspace,
            dio_verify_errors,
        })
    }
}

/* ---------------------------- pool_scan_stat_t --------------------------- */

/**
`pool_scan_stat_t`: the pool-wide scrub / healing resilver, carried by the root
vdev only. An error scrub (`zpool scrub -e`) has fields of its own
([`error_scrub`](ScanStats::error_scrub)): while it runs, `func`/`state` keep
describing the *previous* regular scan.
*/
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ScanStats {
    pub func: Coded<PoolScanFunc>,
    pub state: Coded<DslScanState>,
    pub start_time: u64,
    pub end_time: u64,
    /// Bytes to scan.
    pub to_examine: u64,
    /// Bytes the metadata traversal (phase 1) has located.
    pub examined: u64,
    /// Bytes deliberately skipped (OpenZFS 2.2+; the slot meant
    /// `pss_to_process` before and isn't exposed for those kernels).
    pub skipped: Option<u64>,
    pub processed: u64,
    pub errors: u64,
    pub pass_examined: u64,
    /// Unix time the current pass started.
    pub pass_start: u64,
    /// Unix time the running scrub was paused, 0 while not paused.
    pub pass_scrub_pause: u64,
    /// Seconds the current pass spent paused (accumulates on resume).
    pub pass_scrub_spent_paused: u64,
    pub pass_issued: u64,
    /// Bytes read and verified (phase 2) — what progress keys off.
    pub issued: u64,
    /// OpenZFS 2.2+.
    pub error_scrub: Option<ErrorScrubStats>,
}

/// The error-scrub half of `pool_scan_stat_t` (OpenZFS 2.2+).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ErrorScrubStats {
    pub func: Coded<PoolScanFunc>,
    pub state: Coded<DslScanState>,
    pub start_time: u64,
    pub end_time: u64,
    /// Error blocks issued I/O so far.
    pub examined: u64,
    /// Error blocks still to be issued.
    pub to_be_examined: u64,
    /// Pause time in milliseconds, 0 while not paused.
    pub pass_pause_ms: u64,
}

impl ScanStats {
    /// The pool-wide scan stats; only the *root* vdev's nvlist carries them.
    pub fn from_vdev(root: &NvList) -> Option<ScanStats> {
        root.get_u64_array(SCAN_STATS_KEY).and_then(ScanStats::decode)
    }

    /// Decode a raw `scan_stats` array; None when shorter than any supported layout.
    pub fn decode(ss: &[u64]) -> Option<ScanStats> {
        if ss.len() < PSS_LEN_BASE {
            return None;
        }
        let modern = ss.len() >= PSS_LEN_2_2;
        let mut w = Words::new(ss);
        let (func, state) = (w.coded(), w.coded());
        let (start_time, end_time) = (w.word(), w.word());
        let (to_examine, examined) = (w.word(), w.word());
        let slot6 = w.word();
        let (processed, errors) = (w.word(), w.word());
        let (pass_examined, pass_start) = (w.word(), w.word());
        let (pass_scrub_pause, pass_scrub_spent_paused) = (w.word(), w.word());
        let (pass_issued, issued) = (w.word(), w.word());
        let error_scrub = modern.then(|| ErrorScrubStats {
            func: w.coded(),
            state: w.coded(),
            start_time: w.word(),
            end_time: w.word(),
            examined: w.word(),
            to_be_examined: w.word(),
            pass_pause_ms: w.word(),
        });
        Some(ScanStats {
            func,
            state,
            start_time,
            end_time,
            to_examine,
            examined,
            skipped: modern.then_some(slot6),
            processed,
            errors,
            pass_examined,
            pass_start,
            pass_scrub_pause,
            pass_scrub_spent_paused,
            pass_issued,
            issued,
            error_scrub,
        })
    }

    /// A regular scan (scrub or resilver) has run at some point.
    pub fn has_run(&self) -> bool {
        !self.func.is(PoolScanFunc::None)
    }

    /// A regular scan is running (possibly paused).
    pub fn is_active(&self) -> bool {
        self.state.is(DslScanState::Scanning)
    }

    pub fn is_paused(&self) -> bool {
        self.is_active() && self.pass_scrub_pause != 0
    }

    /// The bytes the scan will issue — `to_examine` net of skipped, the
    /// denominator `zpool status` uses.
    pub fn total(&self) -> u64 {
        self.to_examine.saturating_sub(self.skipped.unwrap_or(0))
    }

    /// Fraction of [`total`](Self::total) issued (0 while the total is unknown).
    pub fn progress(&self) -> f64 {
        fraction(self.issued, self.total())
    }

    /**
    The current pass's average issue rate, bytes/s: pass-issued over the pass's
    wall-clock time minus time spent paused, like libzfs. While paused the
    clock stops at the pause timestamp (spent-paused only accumulates on
    resume), so the rate holds steady instead of decaying. None until the
    pass has run for a second. `now` is the current unix time.
    */
    pub fn pass_rate(&self, now: u64) -> Option<u64> {
        let clock = if self.pass_scrub_pause > 0 { self.pass_scrub_pause } else { now };
        let elapsed = clock.saturating_sub(self.pass_start).saturating_sub(self.pass_scrub_spent_paused);
        self.pass_issued.checked_div(elapsed)
    }

    /// Seconds left at the pass rate; None at a standstill or when done.
    pub fn eta(&self, now: u64) -> Option<u64> {
        eta(self.total().saturating_sub(self.issued), self.pass_rate(now))
    }
}

impl ErrorScrubStats {
    /// An error scrub has run at some point.
    pub fn has_run(&self) -> bool {
        !self.func.is(PoolScanFunc::None)
    }

    pub fn is_active(&self) -> bool {
        self.state.is(DslScanState::ErrorScrubbing)
    }

    pub fn is_paused(&self) -> bool {
        self.pass_pause_ms != 0
    }

    /// Error blocks in all: issued so far plus still to go.
    pub fn total(&self) -> u64 {
        self.examined.saturating_add(self.to_be_examined)
    }

    pub fn progress(&self) -> f64 {
        fraction(self.examined, self.total())
    }
}

/* -------------------------- vdev_rebuild_stat_t -------------------------- */

/**
`vdev_rebuild_stat_t`: a sequential rebuild (dRAID distributed spare, or
`zpool replace -s` / `attach -s` on a mirror), carried per top-level vdev
(OpenZFS 2.0+).
*/
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct RebuildStats {
    pub state: Coded<VdevRebuildState>,
    pub start_time: u64,
    pub end_time: u64,
    pub scan_time_ms: u64,
    /// Allocated bytes scanned.
    pub bytes_scanned: u64,
    /// Bytes read (issued) — what progress keys off.
    pub bytes_issued: u64,
    pub bytes_rebuilt: u64,
    /// Total bytes to scan.
    pub bytes_est: u64,
    pub errors: u64,
    pub pass_time_ms: u64,
    pub pass_bytes_scanned: u64,
    pub pass_bytes_issued: u64,
    /// OpenZFS 2.2+.
    pub pass_bytes_skipped: Option<u64>,
}

impl RebuildStats {
    /// The rebuild stats of a top-level vdev config nvlist.
    pub fn from_vdev(top: &NvList) -> Option<RebuildStats> {
        top.get_u64_array(REBUILD_STATS_KEY).and_then(RebuildStats::decode)
    }

    /// Decode a raw rebuild-stats array; None when shorter than any supported layout.
    pub fn decode(rs: &[u64]) -> Option<RebuildStats> {
        if rs.len() < VRS_LEN_BASE {
            return None;
        }
        let mut w = Words::new(rs);
        Some(RebuildStats {
            state: w.coded(),
            start_time: w.word(),
            end_time: w.word(),
            scan_time_ms: w.word(),
            bytes_scanned: w.word(),
            bytes_issued: w.word(),
            bytes_rebuilt: w.word(),
            bytes_est: w.word(),
            errors: w.word(),
            pass_time_ms: w.word(),
            pass_bytes_scanned: w.word(),
            pass_bytes_issued: w.word(),
            pass_bytes_skipped: w.word_opt(),
        })
    }

    /// A rebuild has run on this vdev at some point.
    pub fn has_run(&self) -> bool {
        !self.state.is(VdevRebuildState::None)
    }

    pub fn is_active(&self) -> bool {
        self.state.is(VdevRebuildState::Active)
    }

    /// Fraction of the estimate issued (0 while the estimate is unknown).
    pub fn progress(&self) -> f64 {
        fraction(self.bytes_issued, self.bytes_est)
    }

    /// The current pass's average issue rate, bytes/s; None before it has run.
    pub fn pass_rate(&self) -> Option<u64> {
        self.pass_bytes_issued.saturating_mul(1000).checked_div(self.pass_time_ms)
    }

    /// Seconds left at the pass rate; None at a standstill or when done.
    pub fn eta(&self) -> Option<u64> {
        eta(self.bytes_est.saturating_sub(self.bytes_issued), self.pass_rate())
    }
}

/* ----------------------------- vdev_stats_ex ----------------------------- */

/**
The queueable ZIO priority classes (`zio_priority_t`) as `vdev_stats_ex` names
them: `vdev_<stem>_active_queue` / `vdev_<stem>_pend_queue`. Declaration order
is `zpool iostat -q`'s column order.
*/
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, EnumIter, IntoStaticStr)]
#[non_exhaustive]
pub enum IoClass {
    #[strum(serialize = "sync_r")]
    SyncRead,
    #[strum(serialize = "sync_w")]
    SyncWrite,
    #[strum(serialize = "async_r")]
    AsyncRead,
    #[strum(serialize = "async_w")]
    AsyncWrite,
    #[strum(serialize = "async_scrub")]
    Scrub,
    #[strum(serialize = "async_trim")]
    Trim,
    #[strum(serialize = "rebuild")]
    Rebuild,
}

/// One priority class's queue: ZIOs issued to the disk vs waiting in the scheduler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct QueueDepth {
    pub class: IoClass,
    pub active: u64,
    pub pending: u64,
}

/**
The `vdev_stats_ex` histograms (`ZPOOL_CONFIG_VDEV_*_HISTO` in zfs.h), by
nvlist key. Latency histograms are end-to-end (`Total*`), device-only
(`Disk*`) or time waiting in a class's queue; size histograms count the
individual ZIOs (`*Ind*`) or the larger I/Os the scheduler aggregated them
into (`*Agg*`).
*/
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, EnumIter, EnumString, IntoStaticStr)]
#[non_exhaustive]
pub enum HistogramId {
    #[strum(serialize = "vdev_tot_r_lat_histo")]
    TotalReadLatency,
    #[strum(serialize = "vdev_tot_w_lat_histo")]
    TotalWriteLatency,
    #[strum(serialize = "vdev_disk_r_lat_histo")]
    DiskReadLatency,
    #[strum(serialize = "vdev_disk_w_lat_histo")]
    DiskWriteLatency,
    #[strum(serialize = "vdev_sync_r_lat_histo")]
    SyncReadQueueLatency,
    #[strum(serialize = "vdev_sync_w_lat_histo")]
    SyncWriteQueueLatency,
    #[strum(serialize = "vdev_async_r_lat_histo")]
    AsyncReadQueueLatency,
    #[strum(serialize = "vdev_async_w_lat_histo")]
    AsyncWriteQueueLatency,
    #[strum(serialize = "vdev_scrub_histo")]
    ScrubQueueLatency,
    #[strum(serialize = "vdev_trim_histo")]
    TrimQueueLatency,
    #[strum(serialize = "vdev_rebuild_histo")]
    RebuildQueueLatency,
    #[strum(serialize = "vdev_sync_ind_r_histo")]
    SyncReadIndSize,
    #[strum(serialize = "vdev_sync_ind_w_histo")]
    SyncWriteIndSize,
    #[strum(serialize = "vdev_async_ind_r_histo")]
    AsyncReadIndSize,
    #[strum(serialize = "vdev_async_ind_w_histo")]
    AsyncWriteIndSize,
    #[strum(serialize = "vdev_ind_scrub_histo")]
    ScrubIndSize,
    #[strum(serialize = "vdev_ind_trim_histo")]
    TrimIndSize,
    #[strum(serialize = "vdev_ind_rebuild_histo")]
    RebuildIndSize,
    #[strum(serialize = "vdev_sync_agg_r_histo")]
    SyncReadAggSize,
    #[strum(serialize = "vdev_sync_agg_w_histo")]
    SyncWriteAggSize,
    #[strum(serialize = "vdev_async_agg_r_histo")]
    AsyncReadAggSize,
    #[strum(serialize = "vdev_async_agg_w_histo")]
    AsyncWriteAggSize,
    #[strum(serialize = "vdev_agg_scrub_histo")]
    ScrubAggSize,
    #[strum(serialize = "vdev_agg_trim_histo")]
    TrimAggSize,
    #[strum(serialize = "vdev_agg_rebuild_histo")]
    RebuildAggSize,
}

/// What a histogram's buckets measure, told apart by bucket count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistogramKind {
    /// Bucket `i` counts latencies in `[2^i, 2^(i+1))` nanoseconds.
    Latency,
    /// Bucket `i` counts requests of `[2^i, 2^(i+1))` bytes.
    RequestSize,
}

impl HistogramKind {
    fn from_len(n: usize) -> Option<Self> {
        match n {
            VDEV_L_HISTO_BUCKETS => Some(HistogramKind::Latency),
            VDEV_RQ_HISTO_BUCKETS => Some(HistogramKind::RequestSize),
            _ => None,
        }
    }
}

/**
One cumulative (since vdev load) `vdev_stats_ex` histogram. Bucket `i`
counts values in `[2^i, 2^(i+1))` (`HISTO()` in zfs.h), except that bucket 0
also takes 0 and the last bucket everything above its floor. For the
distribution over an interval, take [`since`](Self::since) between two
reads, then [`quantile`](Self::quantile) of that.
*/
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Histogram {
    /// The kernel's nvlist key; a key a newer kernel adds has no [`HistogramId`].
    pub key: String,
    pub kind: HistogramKind,
    pub buckets: Vec<u64>,
}

impl Histogram {
    pub fn id(&self) -> Option<HistogramId> {
        HistogramId::from_str(&self.key).ok()
    }

    /// Lower bound of bucket `i` (ns or bytes, per [`kind`](Self::kind)).
    pub fn bucket_floor(i: usize) -> u64 {
        u32::try_from(i).ok().and_then(|s| 1u64.checked_shl(s)).unwrap_or(u64::MAX)
    }

    /// Samples across all buckets.
    pub fn count(&self) -> u64 {
        self.buckets.iter().fold(0u64, |acc, &c| acc.saturating_add(c))
    }

    /**
    The samples counted since `earlier`, an older read of the same histogram,
    bucket by bucket. A bucket smaller than before means the histogram was
    reset in between (the vdev was reopened); then everything counted is
    new, and `self` comes back whole.
    */
    pub fn since(&self, earlier: &Histogram) -> Histogram {
        match bucket_deltas(&self.buckets, &earlier.buckets) {
            Some(buckets) => Histogram { buckets, ..self.clone() },
            None => self.clone(),
        }
    }

    /**
    The `q`-quantile (0 ≤ `q` ≤ 1; 0.99 for p99) as the upper bound of the
    bucket holding it, ns or bytes: no more than `1 - q` of the samples were
    this large, and the true quantile is at most a factor of two below it.
    In the open-ended last bucket this is that bucket's floor instead, so a
    quantile there reads "at least" (Prometheus's convention for its `+Inf`
    bucket). `None` for an empty histogram or a `q` outside 0..=1.
    */
    pub fn quantile(&self, q: f64) -> Option<u64> {
        let i = quantile_bucket(&self.buckets, q)?;
        let last = i + 1 == self.buckets.len();
        Some(Self::bucket_floor(if last { i } else { i + 1 }))
    }
}

/**
`vdev_stats_ex`: the extended iostat data (`zpool iostat -wqr`) — live queue
depths per priority class plus the latency and request-size histograms. Live
backend only: on-disk configs don't carry it.
*/
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct VdevStatsEx {
    /// Queue depths, in [`IoClass`] order, for the classes the kernel reports.
    pub queues: Vec<QueueDepth>,
    /// The histograms, in the kernel's nvlist order.
    pub histograms: Vec<Histogram>,
}

impl VdevStatsEx {
    /// The extended stats of a vdev config nvlist (any vdev of a POOL_STATS tree).
    pub fn from_vdev(vdev: &NvList) -> Option<VdevStatsEx> {
        vdev.get_list(VDEV_STATS_EX_KEY).map(VdevStatsEx::decode)
    }

    /**
    Decode the `vdev_stats_ex` nvlist itself. Arrays that aren't a known
    histogram length are skipped. A name given twice counts once, as its
    last pair, the way the kernel reads a list ([`NvList::get`]), so each
    key names one histogram.
    */
    pub fn decode(nv: &NvList) -> VdevStatsEx {
        let queues = IoClass::iter()
            .filter_map(|class| {
                let stem: &str = class.into();
                let active = nv.get_u64(&format!("vdev_{stem}_active_queue"))?;
                let pending = nv.get_u64(&format!("vdev_{stem}_pend_queue"))?;
                Some(QueueDepth { class, active, pending })
            })
            .collect();
        let pairs: Vec<&NvPair> = nv.iter().collect();
        let mut seen = HashSet::new();
        let mut last: Vec<&NvPair> = pairs.into_iter().rev().filter(|p| seen.insert(&p.name)).collect();
        last.reverse();
        let histograms = last
            .into_iter()
            .filter_map(|p| match &p.data {
                NvData::Uint64Array(buckets) => Some(Histogram {
                    key: p.name.clone(),
                    kind: HistogramKind::from_len(buckets.len())?,
                    buckets: buckets.clone(),
                }),
                _ => None,
            })
            .collect();
        VdevStatsEx { queues, histograms }
    }

    pub fn queue(&self, class: IoClass) -> Option<QueueDepth> {
        self.queues.iter().find(|q| q.class == class).copied()
    }

    pub fn histogram(&self, id: HistogramId) -> Option<&Histogram> {
        self.histograms.iter().find(|h| h.id() == Some(id))
    }

    /**
    Each histogram's samples since `earlier`, an older read of the same
    vdev's stats ([`Histogram::since`], matched by key; one `earlier` lacks
    comes back whole). The queue depths are gauges, not counters, and stay
    as read.
    */
    pub fn since(&self, earlier: &VdevStatsEx) -> VdevStatsEx {
        let histograms = self
            .histograms
            .iter()
            .map(|h| match earlier.histograms.iter().find(|e| e.key == h.key) {
                Some(e) => h.since(e),
                None => h.clone(),
            })
            .collect();
        VdevStatsEx { queues: self.queues.clone(), histograms }
    }
}

/* ========================================================================= */

#[cfg(test)]
mod tests {
    use super::*;

    /**
    OpenZFS 2.1's 46-word `vdev_stat_t` has `vs_pspace` at 45 and no
    `vs_noalloc`; 2.2 inserted noalloc there (pspace → 46). A 2.1 vdev with
    capacity must decode pspace, not a phantom noalloc.
    */
    #[test]
    fn vdev_stats_noalloc_pspace_by_layout() {
        let mut v21 = vec![0u64; 46];
        v21[45] = 1 << 30;
        let s = VdevStats::decode(&v21).unwrap();
        assert_eq!((s.pspace, s.noalloc), (Some(1 << 30), None));

        let mut v22 = vec![0u64; 47];
        v22[45] = 1; // noalloc
        v22[46] = 2 << 30;
        let s = VdevStats::decode(&v22).unwrap();
        assert_eq!((s.pspace, s.noalloc, s.dio_verify_errors), (Some(2 << 30), Some(true), None));

        // 2.3 appends dio_verify_errors after the 2.2 layout
        let mut v23 = v22.clone();
        v23.push(5);
        let s = VdevStats::decode(&v23).unwrap();
        assert_eq!((s.pspace, s.dio_verify_errors), (Some(2 << 30), Some(5)));

        // 2.0 (45 words): ashift + rebuild, neither pspace nor noalloc
        let s = VdevStats::decode(&[0u64; 45]).unwrap();
        assert_eq!((s.pspace, s.noalloc), (None, None));
        assert!(s.ashift.is_some() && s.rebuild_processed.is_some());

        // 0.8 (41 words): the base layout only; anything shorter is refused
        let s = VdevStats::decode(&[0u64; 41]).unwrap();
        assert_eq!((s.ashift, s.rebuild_processed, s.pspace), (None, None, None));
        assert!(VdevStats::decode(&[0u64; 40]).is_none());
    }

    /// Every base field lands where `vdev_stat_t` puts it (index = value).
    #[test]
    fn vdev_stats_fields_follow_the_struct() {
        let vs: Vec<u64> = (0..47).collect();
        let s = VdevStats::decode(&vs).unwrap();
        assert_eq!((s.state.raw(), s.aux.raw(), s.alloc), (1, 2, 3));
        assert_eq!((s.replaceable_size, s.expandable_size), (6, 7));
        assert_eq!((s.ops.null, s.ops.read, s.ops.write, s.ops.flush), (8, 9, 10, 13));
        assert_eq!((s.bytes.read, s.bytes.write), (15, 16));
        assert_eq!((s.read_errors, s.write_errors, s.checksum_errors), (20, 21, 22));
        assert_eq!((s.initialize.errors, s.self_healed, s.scan_processed), (23, 24, 26));
        assert_eq!(s.fragmentation, Some(27));
        assert_eq!((s.initialize.bytes_done, s.initialize.bytes_est), (28, 29));
        assert_eq!((s.initialize.state.raw(), s.initialize.action_time), (30, 31));
        assert_eq!((s.checkpoint_space, s.slow_ios), (32, 34));
        assert_eq!((s.trim.errors, s.trim.bytes_done, s.trim.bytes_est), (35, 37, 38));
        assert_eq!((s.trim.state.raw(), s.trim.action_time), (39, 40));
        assert_eq!(s.rebuild_processed, Some(41));
        assert_eq!(s.ashift, Some(VdevAshift { configured: 42, logical: 43, physical: 44 }));
        assert_eq!((s.noalloc, s.pspace), (Some(true), Some(46)));
        // ZFS_FRAG_INVALID is "no figure", not a percentage
        let mut vs = vs;
        vs[27] = u64::MAX;
        assert_eq!(VdevStats::decode(&vs).unwrap().fragmentation, None);
    }

    /// Build a 22-word (2.2) `pool_scan_stat_t` from named fields.
    fn scan_words(func: u64, state: u64) -> [u64; 22] {
        let mut s = [0u64; 22];
        s[0] = func;
        s[1] = state;
        s
    }

    #[test]
    fn scan_progress_rate_and_eta() {
        // SCRUB/SCANNING: 1 GiB issued of 4 GiB, pass made 256 MiB in 256 s
        let mut w = scan_words(1, 1);
        w[2] = 1000; // start
        w[4] = 4 << 30; // to_examine
        w[10] = 1000; // pass_start
        w[13] = 256 << 20; // pass_issued
        w[14] = 1 << 30; // issued
        let s = ScanStats::decode(&w).unwrap();
        assert!(s.has_run() && s.is_active() && !s.is_paused());
        assert_eq!(s.progress(), 0.25);
        assert_eq!(s.pass_rate(1256), Some(1 << 20));
        assert_eq!(s.eta(1256), Some(3072)); // 3 GiB at 1 MiB/s
        // no pass time yet: no rate, no ETA
        assert_eq!((s.pass_rate(1000), s.eta(1000)), (None, None));
    }

    #[test]
    fn scan_paused_freezes_the_pass_clock() {
        let mut w = scan_words(1, 1);
        w[4] = 4 << 30;
        w[10] = 1000; // pass_start
        w[11] = 1256; // paused at t=1256
        w[13] = 256 << 20;
        w[14] = 1 << 30;
        let s = ScanStats::decode(&w).unwrap();
        assert!(s.is_paused());
        // inspected long after the pause: the rate holds instead of decaying
        assert_eq!(s.pass_rate(9999), Some(1 << 20));
    }

    /**
    Through 2.1 slot 6 is `pss_to_process` (≈ the whole pool), not
    `pss_skipped` — subtracting it would collapse the denominator. The
    15-word layout must use plain `to_examine` and report no skipped bytes.
    */
    #[test]
    fn scan_slot_6_by_layout() {
        let mut w = scan_words(1, 1);
        w[4] = 4 << 30;
        w[6] = 4 << 30;
        w[14] = 1 << 30;
        let old = ScanStats::decode(&w[..15]).unwrap();
        assert_eq!((old.skipped, old.total(), old.progress()), (None, 4 << 30, 0.25));
        assert!(old.error_scrub.is_none());
        // the same fill in the 2.2 layout is pss_skipped: nothing left to issue
        let new = ScanStats::decode(&w).unwrap();
        assert_eq!((new.skipped, new.total(), new.progress()), (Some(4 << 30), 0, 0.0));
        assert!(ScanStats::decode(&w[..14]).is_none());
    }

    #[test]
    fn error_scrub_is_decoded() {
        // previous scrub FINISHED, an error scrub (func 3) running
        let mut w = scan_words(1, 2);
        w[15] = 3; // ERRORSCRUB
        w[16] = 4; // ERRORSCRUBBING
        w[17] = 5000;
        w[19] = 30; // examined
        w[20] = 10; // to be examined
        let s = ScanStats::decode(&w).unwrap();
        assert!(!s.is_active());
        let es = s.error_scrub.unwrap();
        assert!(es.has_run() && es.is_active() && !es.is_paused());
        assert_eq!((es.start_time, es.total(), es.progress()), (5000, 40, 0.75));
    }

    #[test]
    fn rebuild_progress_rate_and_eta() {
        let mut w = [0u64; 13];
        w[0] = 1; // ACTIVE
        w[5] = 512 << 20; // issued
        w[7] = 2 << 30; // est
        w[9] = 128_000; // pass_time_ms
        w[11] = 128 << 20; // pass_bytes_issued
        w[12] = 7; // pass_bytes_skipped (2.2)
        let r = RebuildStats::decode(&w).unwrap();
        assert!(r.has_run() && r.is_active());
        assert_eq!(r.progress(), 0.25);
        assert_eq!(r.pass_rate(), Some(1 << 20));
        assert_eq!(r.eta(), Some(1536)); // 1.5 GiB at 1 MiB/s
        assert_eq!(r.pass_bytes_skipped, Some(7));
        // the 12-word 2.0/2.1 layout has no skipped counter
        assert_eq!(RebuildStats::decode(&w[..12]).unwrap().pass_bytes_skipped, None);
        assert!(RebuildStats::decode(&w[..11]).is_none());
    }

    #[test]
    fn stats_ex_queues_and_histograms() {
        let mut nv = NvList::new();
        nv.push("vdev_sync_r_active_queue", NvData::Uint64(3));
        nv.push("vdev_sync_r_pend_queue", NvData::Uint64(7));
        nv.push("vdev_async_w_active_queue", NvData::Uint64(0));
        nv.push("vdev_async_w_pend_queue", NvData::Uint64(0));
        // half a pair isn't a reported class
        nv.push("vdev_rebuild_active_queue", NvData::Uint64(1));
        let mut lat = vec![0u64; 37];
        lat[12] = 100;
        nv.push("vdev_tot_r_lat_histo", NvData::Uint64Array(lat));
        nv.push("vdev_sync_ind_r_histo", NvData::Uint64Array(vec![1; 25]));
        nv.push("vdev_future_x_histo", NvData::Uint64Array(vec![0; 37]));
        nv.push("vdev_other_array", NvData::Uint64Array(vec![0; 8])); // not a histogram
        let ex = VdevStatsEx::decode(&nv);

        let classes: Vec<IoClass> = ex.queues.iter().map(|q| q.class).collect();
        assert_eq!(classes, [IoClass::SyncRead, IoClass::AsyncWrite]);
        let q = ex.queue(IoClass::SyncRead).unwrap();
        assert_eq!((q.active, q.pending), (3, 7));
        assert!(ex.queue(IoClass::Rebuild).is_none());

        assert_eq!(ex.histograms.len(), 3);
        let h = ex.histogram(HistogramId::TotalReadLatency).unwrap();
        assert_eq!((h.kind, h.count()), (HistogramKind::Latency, 100));
        let h = ex.histogram(HistogramId::SyncReadIndSize).unwrap();
        assert_eq!((h.kind, h.count()), (HistogramKind::RequestSize, 25));
        // a key a newer kernel adds still decodes, just without an id
        assert_eq!(ex.histograms[2].id(), None);
        assert_eq!((Histogram::bucket_floor(0), Histogram::bucket_floor(12)), (1, 4096));
        assert_eq!(Histogram::bucket_floor(64), u64::MAX);
    }

    fn latency(buckets: &[(usize, u64)]) -> Histogram {
        let mut h = vec![0u64; VDEV_L_HISTO_BUCKETS];
        buckets.iter().for_each(|&(i, c)| h[i] = c);
        Histogram { key: "vdev_tot_w_lat_histo".into(), kind: HistogramKind::Latency, buckets: h }
    }

    #[test]
    fn histogram_windows_and_quantiles() {
        let before = latency(&[(10, 50), (20, 1)]);
        let after = latency(&[(10, 150), (12, 99), (20, 2)]);
        let window = after.since(&before);
        assert_eq!(window, latency(&[(10, 100), (12, 99), (20, 1)]));
        // 200 samples: the median is in [2^10, 2^11), p99 (rank 198) in [2^12, 2^13)
        assert_eq!(window.quantile(0.5), Some(1 << 11));
        assert_eq!(window.quantile(0.99), Some(1 << 13));
        // the slowest one is in [2^20, 2^21)
        assert_eq!(window.quantile(1.0), Some(1 << 21));
        assert_eq!((window.quantile(-0.1), latency(&[]).quantile(0.5)), (None, None));
        // a reopened vdev starts over: the later read is all new
        assert_eq!(before.since(&after), before);
        // the open-ended top bucket reports its floor: "at least 2^36 ns"
        assert_eq!(latency(&[(36, 1)]).quantile(0.99), Some(1 << 36));
    }

    /// Fuzz find: a key given twice made `since` pair a histogram with its
    /// twin. The last pair stands for the name, as in the kernel.
    #[test]
    fn stats_ex_duplicate_keys_count_once() {
        let mut nv = NvList::new();
        nv.push("vdev_tot_w_lat_histo", NvData::Uint64Array(latency(&[(3, 9)]).buckets));
        nv.push("vdev_tot_r_lat_histo", NvData::Uint64Array(latency(&[(4, 1)]).buckets));
        nv.push("vdev_tot_w_lat_histo", NvData::Uint64Array(latency(&[(5, 2)]).buckets));
        // a later pair of another type hides the histogram altogether
        nv.push("vdev_tot_r_lat_histo", NvData::Uint64(0));
        let ex = VdevStatsEx::decode(&nv);
        assert_eq!(ex.histograms, [latency(&[(5, 2)])]);
        assert_eq!(ex.since(&ex).histograms[0].count(), 0);
    }

    #[test]
    fn stats_ex_windows_by_key() {
        let mut ex = VdevStatsEx::default();
        ex.histograms.push(latency(&[(3, 4)]));
        let mut later = ex.clone();
        later.histograms[0].buckets[3] = 10;
        later.histograms.push(Histogram { key: "vdev_new_histo".into(), ..latency(&[(1, 1)]) });
        later.queues.push(QueueDepth { class: IoClass::SyncWrite, active: 1, pending: 2 });
        let window = later.since(&ex);
        assert_eq!(window.histograms[0], latency(&[(3, 6)]));
        // a histogram the earlier read lacks is whole; queue depths stay as read
        assert_eq!(window.histograms[1].count(), 1);
        assert_eq!(window.queues, later.queues);
    }

    /// The config keys, through the nvlist accessors.
    #[test]
    fn decoders_read_their_config_keys() {
        let mut root = NvList::new();
        root.push(VDEV_STATS_KEY, NvData::Uint64Array(vec![0; 47]));
        root.push(SCAN_STATS_KEY, NvData::Uint64Array(scan_words(1, 2).to_vec()));
        root.push(REBUILD_STATS_KEY, NvData::Uint64Array(vec![0; 13]));
        root.push(VDEV_STATS_EX_KEY, NvData::List(NvList::new()));
        assert!(VdevStats::from_vdev(&root).is_some());
        assert!(ScanStats::from_vdev(&root).is_some_and(|s| s.has_run() && !s.is_active()));
        assert!(RebuildStats::from_vdev(&root).is_some_and(|r| !r.has_run()));
        assert!(VdevStatsEx::from_vdev(&root).is_some());
        assert!(VdevStats::from_vdev(&NvList::new()).is_none());
    }
}
