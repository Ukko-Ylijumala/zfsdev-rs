// Copyright (c) 2026 Mikko Tanner. All rights reserved.
// Licensed under the MIT License or the Apache License, Version 2.0.
// SPDX-License-Identifier: MIT OR Apache-2.0

/*!
SPL kstats: the counters the ZFS module exports as plain text in procfs
(`/proc/spl/kstat/zfs/…`) — the `arc_summary` / `arcstat` data among them.
No `/dev/zfs` ioctl is involved: the files are world-readable, so there is no
ABI hazard and no privilege requirement. Linux only.

The text format is a header line, a `name type data` column header, then
`<name> <type> <value>` triples. Values are stored as `i64` because the kstat
type system has a signed variant (type 3, `KSTAT_DATA_INT64`) used by
`memory_available_bytes`, which goes negative under memory pressure; every
other field is type 4 (unsigned) and positive, and all of them fit in `i64`.

Field schemas differ across OpenZFS major versions — 2.2 reworked ARC
accounting (per-state data/metadata split, an `Uncached` state, `iohits`,
predictive/prescient prefetch counters; the single `p` MRU/MFU target became
`pd`/`pm`; `arc_meta_limit` went away). Rather than branch on version, read
whatever fields exist and derive each metric only from inputs that are present
([`Kstat::has`]); [`hit_ratio`] and [`accesses`] fold in 2.2's `iohits` where
it exists. Reference dumps for both eras live in `doc/kstat/`.

Counters are cumulative since boot: a rate (or a windowed hit ratio) is the
delta between two timed reads, which is left to the caller.
*/

use std::collections::HashMap;
use std::fs;
use std::io;
use strum::Display;

/// The ARC's counters (`arc_summary`'s source).
pub const ARCSTATS_PATH: &str = "/proc/spl/kstat/zfs/arcstats";
/// The DMU (file-level) prefetcher's counters.
pub const ZFETCHSTATS_PATH: &str = "/proc/spl/kstat/zfs/zfetchstats";

/**
A parsed kstat file: `name → value`. See the module docs for the wire format
and the signed-`i64` rationale. Construct with [`Kstat::parse`] /
[`Kstat::read`] (or collect `(name, value)` pairs); query with [`Kstat::get`]
(raw signed), [`Kstat::u`] (unsigned, clamped at 0) and [`Kstat::has`]
(presence, for version-adaptive views).
*/
#[derive(Debug, Clone, Default)]
pub struct Kstat(HashMap<String, i64>);

impl Kstat {
    /// Parse the SPL kstat text. The two header lines are skipped; any line
    /// whose value doesn't parse as an integer is ignored (forward-compat).
    pub fn parse(text: &str) -> Self {
        let mut map = HashMap::new();
        for line in text.lines().skip(2) {
            let mut cols = line.split_whitespace();
            // <name> <type> <value> - type column is consumed but unused
            if let (Some(name), Some(_ty), Some(val)) = (cols.next(), cols.next(), cols.next())
                && let Ok(v) = val.parse::<i64>()
            {
                map.insert(name.to_string(), v);
            }
        }
        Kstat(map)
    }

    /// Read and parse a kstat file from procfs.
    pub fn read(path: &str) -> io::Result<Self> {
        Ok(Kstat::parse(&fs::read_to_string(path)?))
    }

    /// Raw signed value (`None` if the field is absent on this kernel).
    pub fn get(&self, name: &str) -> Option<i64> {
        self.0.get(name).copied()
    }

    /// Unsigned value, 0 if absent or negative (every field but
    /// `memory_available_bytes` is unsigned and non-negative).
    pub fn u(&self, name: &str) -> u64 {
        self.get(name).unwrap_or(0).max(0) as u64
    }

    /// Whether a field exists - used to pick the version-appropriate view.
    pub fn has(&self, name: &str) -> bool {
        self.0.contains_key(name)
    }

    /// All `(name, value)` pairs (unordered) - for the raw-dump view.
    pub fn iter(&self) -> impl Iterator<Item = (&str, i64)> {
        self.0.iter().map(|(k, v)| (k.as_str(), *v))
    }
}

impl<S: Into<String>> FromIterator<(S, i64)> for Kstat {
    fn from_iter<I: IntoIterator<Item = (S, i64)>>(iter: I) -> Self {
        Kstat(iter.into_iter().map(|(k, v)| (k.into(), v)).collect())
    }
}

/// The current arcstats.
pub fn read_arcstats() -> io::Result<Kstat> {
    Kstat::read(ARCSTATS_PATH)
}

/// The current zfetchstats.
pub fn read_zfetchstats() -> io::Result<Kstat> {
    Kstat::read(ZFETCHSTATS_PATH)
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

/* ================================ tests ================================== */

#[cfg(test)]
mod tests {
    use super::*;

    // the committed reference dumps (root-free regression fixtures)
    const ARC_21: &str = include_str!("../../doc/kstat/arcstats_v2.1.6.txt");
    const ARC_22: &str = include_str!("../../doc/kstat/arcstats_v2.2.2.txt");
    const ZF_21: &str = include_str!("../../doc/kstat/zfetchstats_v2.1.6.txt");
    const ZF_22: &str = include_str!("../../doc/kstat/zfetchstats_v2.2.2.txt");

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
}
