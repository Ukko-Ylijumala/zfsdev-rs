// Copyright (c) 2026 Mikko Tanner. All rights reserved.
// Licensed under the MIT License or the Apache License, Version 2.0.
// SPDX-License-Identifier: MIT OR Apache-2.0

/*!
`NvList::unpack` (native, and XDR as vdev labels carry it), then every decoder
that reads a decoded list: the property entries and their sources, and the
stat decoders with their derived figures, on each nested list and array
(a histogram against itself is an empty window, and its quantiles never
fall as `q` rises).
Whatever decodes must survive our own encoder: `pack` either refuses cleanly
or produces bytes that decode again and re-pack byte-identically (compared as
bytes, not `PartialEq`, since a NaN double never equals itself).
*/

#![no_main]

use libfuzzer_sys::fuzz_target;
use zfsdev::nvlist::{NvData, NvList};
use zfsdev::props::{decode_prop_value, prop_entries};
use zfsdev::stats::{RebuildStats, ScanStats, VdevStats, VdevStatsEx};

/// The `now`s the time-dependent figures are asked at: the epoch, a
/// plausible present, and the far end.
const NOWS: [u64; 3] = [0, 1_800_000_000, u64::MAX];
/// The quantiles checked for order, ascending.
const QUANTILES: [f64; 5] = [0.0, 0.5, 0.9, 0.99, 1.0];

fn scan(s: &ScanStats) {
    let _ = (s.has_run(), s.is_active(), s.is_paused(), s.total(), s.progress());
    for now in NOWS {
        let _ = (s.pass_rate(now), s.eta(now));
    }
    if let Some(e) = &s.error_scrub {
        let _ = (e.has_run(), e.is_active(), e.is_paused(), e.total(), e.progress());
    }
}

fn rebuild(r: &RebuildStats) {
    let _ = (r.has_run(), r.is_active(), r.progress(), r.pass_rate(), r.eta());
}

fn stats_ex(x: &VdevStatsEx) {
    for q in &x.queues {
        let _ = x.queue(q.class);
    }
    for h in &x.histograms {
        let _ = (h.id(), h.count());
        assert_eq!(h.since(h).count(), 0, "a window against itself");
        let qs: Vec<Option<u64>> = QUANTILES.iter().map(|&q| h.quantile(q)).collect();
        assert!(qs.is_sorted(), "a quantile fell as q rose");
    }
    assert_eq!(x.since(x).histograms.iter().map(|h| h.count()).sum::<u64>(), 0);
}

fn walk(list: &NvList) {
    // any pair may be a property, wrapped or bare
    for e in prop_entries(list) {
        let _ = (e.str(), e.source("pool/dataset"));
        if let Some(v) = e.u64() {
            let _ = decode_prop_value(e.name, v);
        }
    }
    // and any list a vdev
    let _ = VdevStats::from_vdev(list);
    ScanStats::from_vdev(list).iter().for_each(scan);
    RebuildStats::from_vdev(list).iter().for_each(rebuild);
    VdevStatsEx::from_vdev(list).iter().for_each(stats_ex);
    stats_ex(&VdevStatsEx::decode(list));
    for pair in list.iter() {
        match &pair.data {
            NvData::Uint64Array(a) => {
                let _ = VdevStats::decode(a);
                ScanStats::decode(a).iter().for_each(scan);
                RebuildStats::decode(a).iter().for_each(rebuild);
            }
            NvData::List(l) => walk(l),
            NvData::ListArray(ls) => ls.iter().for_each(walk),
            _ => {}
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let Ok(list) = NvList::unpack(data) else { return };
    walk(&list);
    let Ok(packed) = list.pack() else { return };
    let again = NvList::unpack(&packed).expect("our own packing must decode");
    let repacked = again.pack().expect("a decoded packing must re-pack");
    assert!(packed == repacked, "pack is not a fixed point");
});
