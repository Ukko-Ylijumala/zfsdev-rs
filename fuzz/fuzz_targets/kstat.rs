// Copyright (c) 2026 Mikko Tanner. All rights reserved.
// Licensed under the MIT License or the Apache License, Version 2.0.
// SPDX-License-Identifier: MIT OR Apache-2.0

/*!
The kstat text parsers: named kstats (cut by column, so a hostile line must
not split inside a character), the txg history table, the objset counters
and the tx-assign histogram with its window arithmetic. The histogram
properties: a window against itself is empty, against nothing it is whole,
and no count of waits exceeds the total.
*/

#![no_main]

use libfuzzer_sys::fuzz_target;
use zfsdev::kstat::{Kstat, ObjsetKstat, TxAssignHistogram, parse_txgs};

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);

    let k = Kstat::parse(&text);
    for (name, _) in k.iter() {
        let _ = (k.get(name), k.u(name), k.has(name));
    }
    let _ = ObjsetKstat::parse(1, &text);

    for t in parse_txgs(&text) {
        let _ = (t.state.letter(), t.phase_start(), t.in_phase_for(u64::MAX));
    }

    let h = TxAssignHistogram::parse(&text);
    let total = h.total();
    assert_eq!(h.since(&h).total(), 0, "a window against itself");
    assert_eq!(h.since(&TxAssignHistogram::default()), h, "a window from nothing");
    for ns in [0, 1, 1 << 20, u64::MAX] {
        assert!(h.longer_than(ns) <= total, "more long waits than waits");
    }
});
