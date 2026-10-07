// Copyright (c) 2026 Mikko Tanner. All rights reserved.
// Licensed under the MIT License or the Apache License, Version 2.0.
// SPDX-License-Identifier: MIT OR Apache-2.0

/*!
Cuts a seed corpus for the fuzz targets in `fuzz/`: `cargo run --example
fuzz_seeds`. The nvlist seeds are packed vdev trees and property lists in the
shapes the kernel returns, plus this host's own pool configs, stats and
properties where `/dev/zfs` answers; the kstat seeds are the reference dumps
in `doc/kstat/`. The corpus is gitignored: regenerate it, don't commit it.
*/

use std::fs;
use std::io;
use std::path::Path;
use zfsdev::nvlist::{NvData, NvList};

/// Where cargo-fuzz looks for each target's corpus.
const CORPUS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/fuzz/corpus");
/// The committed kstat reference dumps.
const KSTAT_DUMPS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/doc/kstat");

/// A `{value, source}` property pair, its source a dataset name.
fn prop(value: u64, source: &str) -> NvList {
    let mut p = NvList::new();
    p.add_u64("value", value).add_str("source", source);
    p
}

/// A vdev config the way POOL_STATS nests it: the stat arrays at their 2.2
/// lengths, extended stats with a latency and a request-size histogram.
fn vdev(kind: &str, children: Vec<NvList>) -> NvList {
    let mut ex = NvList::new();
    ex.add_u64("vdev_sync_r_active_queue", 1)
        .add_u64("vdev_sync_r_pend_queue", 2)
        .push("vdev_tot_r_lat_histo", NvData::Uint64Array((0..37).collect()))
        .push("vdev_sync_ind_r_histo", NvData::Uint64Array((0..25).collect()));
    let mut v = NvList::new();
    v.add_str("type", kind)
        .add_u64("guid", 0x1234_5678)
        .push("vdev_stats", NvData::Uint64Array((0..47).map(|i| i * 4096).collect()))
        .push("scan_stats", NvData::Uint64Array((0..22).collect()))
        .push("org.openzfs:rebuild_stats", NvData::Uint64Array((0..13).collect()))
        .add_nvlist("vdev_stats_ex", ex);
    if !children.is_empty() {
        v.push("children", NvData::ListArray(children));
    }
    v
}

fn write(target: &str, name: &str, bytes: &[u8]) -> io::Result<()> {
    let dir = Path::new(CORPUS).join(target);
    fs::create_dir_all(&dir)?;
    fs::write(dir.join(name), bytes)
}

fn write_list(name: &str, list: &NvList) -> io::Result<()> {
    write("nvlist", name, &list.pack().map_err(io::Error::other)?)
}

/// This host's pool configs, stats and properties, best-effort.
#[cfg(target_os = "linux")]
fn live_seeds() -> io::Result<usize> {
    use zfsdev::ioctl::ZfsHandle;
    let Ok(zfs) = ZfsHandle::open() else { return Ok(0) };
    let Ok(configs) = zfs.pool_configs() else { return Ok(0) };
    write_list("live-configs", &configs)?;
    let mut n = 1;
    for (i, pool) in configs.iter().enumerate() {
        let lists = [
            ("stats", zfs.pool_stats(&pool.name)),
            ("props", zfs.pool_props(&pool.name)),
            ("dataset", zfs.objset_stats(&pool.name).map(|(_, props)| props)),
        ];
        for (what, list) in lists {
            if let Ok(list) = list {
                write_list(&format!("live-{i}-{what}"), &list)?;
                n += 1;
            }
        }
    }
    Ok(n)
}

#[cfg(not(target_os = "linux"))]
fn live_seeds() -> io::Result<usize> {
    Ok(0)
}

fn main() -> io::Result<()> {
    let leaves = vec![vdev("disk", vec![]), vdev("file", vec![])];
    let mut root = vdev("root", vec![vdev("mirror", leaves)]);
    root.add_str("name", "tank").add_u64("state", 0).add_u64("version", 5000);
    write_list("vdev-tree", &root)?;

    let mut props = NvList::new();
    props
        .add_nvlist("compression", prop(15, "tank"))
        .add_nvlist("atime", prop(0, "tank/parent"))
        .add_nvlist("quota", prop(1 << 30, "$recvd"))
        .add_nvlist("recordsize", prop(131072, ""));
    write_list("dataset-props", &props)?;
    let mut zpl = NvList::new();
    zpl.add_u64("version", 5).add_u64("normalization", 0).add_u64("casesensitivity", 0);
    write_list("zpl-props", &zpl)?;

    let live = live_seeds()?;

    let mut kstats = 0;
    for entry in fs::read_dir(KSTAT_DUMPS)? {
        let path = entry?.path();
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            write("kstat", name, &fs::read(&path)?)?;
            kstats += 1;
        }
    }
    println!("seeded {CORPUS}: {} nvlists ({live} live), {kstats} kstats", 3 + live);
    Ok(())
}
