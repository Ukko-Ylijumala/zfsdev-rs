// Copyright (c) 2026 Mikko Tanner. All rights reserved.
// Licensed under the MIT License or the Apache License, Version 2.0.
// SPDX-License-Identifier: MIT OR Apache-2.0

/*!
Walking a pool's vdev tree: the `vdev_tree` nvlist of a pool config, as
`ZfsHandle::pool_stats` returns it (or a vdev label's tree). [`walk`] yields
every vdev with its depth and its [`VdevRole`]: which allocation class its
top-level vdev serves (data, log, special, dedup), or that it is a cache
device or a hot spare. The role is what tells a SLOG from a data disk; the
config spreads it over `is_log` and `alloc_bias` on the top-level vdev, and
the root's separate `l2cache` and `spares` arrays.

Each [`VdevEntry`] borrows the vdev's own config nvlist, so the stat
decoders ([`crate::stats::VdevStats::from_vdev`] and the rest) apply to it
directly.
*/

use crate::enums::{AllocBias, VdevType};
use crate::nvlist::NvList;
use strum::{Display, EnumString};

/* vdev config nvlist keys (ZPOOL_CONFIG_* in zfs.h) */
const TYPE_KEY: &str = "type";
const ID_KEY: &str = "id";
const GUID_KEY: &str = "guid";
const PATH_KEY: &str = "path";
const CHILDREN_KEY: &str = "children";
const L2CACHE_KEY: &str = "l2cache";
const SPARES_KEY: &str = "spares";
const IS_LOG_KEY: &str = "is_log";
const ALLOC_BIAS_KEY: &str = "alloc_bias";
const NPARITY_KEY: &str = "nparity";
const DRAID_NDATA_KEY: &str = "draid_ndata";
const DRAID_NSPARES_KEY: &str = "draid_nspares";

/// A raidz without `nparity` predates multiple parity levels: raidz1.
const LEGACY_RAIDZ_PARITY: u64 = 1;

/**
What a vdev is for: the allocation class of its top-level vdev, or an
auxiliary role. Each vdev below a top-level vdev has the top-level's role;
a hot spare that has taken over for a disk sits in the tree under a `spare`
vdev, and so serves the role of the vdev it stands in for.
*/
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Display, EnumString)]
#[strum(serialize_all = "lowercase")]
#[non_exhaustive]
pub enum VdevRole {
    /// The normal class: data, and metadata too without a special vdev.
    Data,
    /// A separate intent log (SLOG).
    Log,
    /// The special class: metadata, and small blocks up to `special_small_blocks`.
    Special,
    /// The dedup class: the dedup tables.
    Dedup,
    /// An L2ARC device, from the root's `l2cache`.
    Cache,
    /// A hot spare not in use, from the root's `spares`.
    Spare,
}

impl VdevRole {
    /**
    The role of top-level vdev `top`: `is_log` marks a log (in every
    config), `alloc_bias` a special or dedup vdev. The kernel adds
    `alloc_bias` only to configs generated with stats, so in a config
    without them (`pool_configs`, a vdev label) a special or dedup vdev
    reads as [`Data`](VdevRole::Data), as does a bias this crate doesn't
    know.
    */
    pub fn of_top_level(top: &NvList) -> VdevRole {
        if top.get_u64(IS_LOG_KEY).is_some_and(|v| v != 0) {
            return VdevRole::Log;
        }
        match top.get_str(ALLOC_BIAS_KEY).and_then(|b| b.parse::<AllocBias>().ok()) {
            Some(bias) => bias.into(),
            None => VdevRole::Data,
        }
    }
}

impl From<AllocBias> for VdevRole {
    fn from(bias: AllocBias) -> Self {
        match bias {
            AllocBias::Log => VdevRole::Log,
            AllocBias::Special => VdevRole::Special,
            AllocBias::Dedup => VdevRole::Dedup,
        }
    }
}

/// One vdev of the tree, as [`walk`] yields it.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct VdevEntry<'a> {
    /// The vdev's own config nvlist (its stats, path, guid, …).
    pub config: &'a NvList,
    /// 0 for a top-level vdev, a cache device or a spare; one more per level below.
    pub depth: usize,
    pub role: VdevRole,
}

impl<'a> VdevEntry<'a> {
    /// The `type` string as the config has it (`disk`, `mirror`, `raidz`, …).
    pub fn type_name(&self) -> &'a str {
        self.config.get_str(TYPE_KEY).unwrap_or("")
    }

    /// The type, `None` for one this crate doesn't know.
    pub fn vdev_type(&self) -> Option<VdevType> {
        self.type_name().parse().ok()
    }

    pub fn guid(&self) -> Option<u64> {
        self.config.get_u64(GUID_KEY)
    }

    /// The device path of a leaf (a dRAID distributed spare's is its name).
    pub fn path(&self) -> Option<&'a str> {
        self.config.get_str(PATH_KEY)
    }

    /// Whether the vdev has no children: a device, or a hole or removed vdev.
    pub fn is_leaf(&self) -> bool {
        self.config.get_list_array(CHILDREN_KEY).is_none_or(<[NvList]>::is_empty)
    }

    /**
    The vdev's name as `zpool` commands take it: a leaf's device path, and
    otherwise `<type>-<id>` (`mirror-0`; `raidz2-1` with the parity level;
    dRAID with its whole geometry, `draid2:8d:44c:2s-0`). The path is the
    full one; `zpool status` shortens it for display. A vdev with neither a
    path nor an id is named by its guid.
    */
    pub fn name(&self) -> String {
        if let Some(path) = self.path() {
            return path.to_string();
        }
        let nv = self.config;
        let kind = match self.vdev_type() {
            Some(VdevType::Raidz) => {
                format!("raidz{}", nv.get_u64(NPARITY_KEY).unwrap_or(LEGACY_RAIDZ_PARITY))
            }
            Some(VdevType::Draid) => {
                let num = |key| nv.get_u64(key).unwrap_or(0);
                let children = nv.get_list_array(CHILDREN_KEY).map_or(0, <[NvList]>::len);
                let (parity, data) = (num(NPARITY_KEY), num(DRAID_NDATA_KEY));
                format!("draid{parity}:{data}d:{children}c:{}s", num(DRAID_NSPARES_KEY))
            }
            _ => self.type_name().to_string(),
        };
        match (nv.get_u64(ID_KEY), self.guid()) {
            (Some(id), _) => format!("{kind}-{id}"),
            (None, Some(guid)) => guid.to_string(),
            (None, None) => kind,
        }
    }
}

/**
Every vdev of `tree`, depth first in config order: each top-level vdev
followed by everything beneath it, then the cache devices, then the hot
spares. `tree` is a pool's root vdev (the config's `vdev_tree`), which
itself is not yielded; any other vdev, such as the top-level vdev a label's
`vdev_tree` holds, is walked as a top-level vdev itself.
*/
pub fn walk(tree: &NvList) -> VdevWalk<'_> {
    let mut pending = Vec::new();
    if tree.get_str(TYPE_KEY).and_then(|t| t.parse().ok()) != Some(VdevType::Root) {
        pending.push(VdevEntry { config: tree, depth: 0, role: VdevRole::of_top_level(tree) });
        return VdevWalk { pending };
    }
    // a stack: what comes out first goes in last
    let aux = |key, role| {
        let devs = tree.get_list_array(key).unwrap_or_default();
        devs.iter().rev().map(move |config| VdevEntry { config, depth: 0, role })
    };
    pending.extend(aux(SPARES_KEY, VdevRole::Spare));
    pending.extend(aux(L2CACHE_KEY, VdevRole::Cache));
    let tops = tree.get_list_array(CHILDREN_KEY).unwrap_or_default();
    pending.extend(tops.iter().rev().map(|config| {
        VdevEntry { config, depth: 0, role: VdevRole::of_top_level(config) }
    }));
    VdevWalk { pending }
}

/// The iterator [`walk`] returns.
#[derive(Debug, Clone)]
pub struct VdevWalk<'a> {
    pending: Vec<VdevEntry<'a>>,
}

impl<'a> Iterator for VdevWalk<'a> {
    type Item = VdevEntry<'a>;

    fn next(&mut self) -> Option<VdevEntry<'a>> {
        let entry = self.pending.pop()?;
        if let Some(children) = entry.config.get_list_array(CHILDREN_KEY) {
            let depth = entry.depth + 1;
            let below = children.iter().rev().map(|config| VdevEntry { config, depth, ..entry });
            self.pending.extend(below);
        }
        Some(entry)
    }
}

/* ================================ tests ================================== */

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nvlist::NvData;

    fn vdev(vtype: &str, id: Option<u64>, children: Vec<NvList>) -> NvList {
        let mut nv = NvList::new();
        nv.add_str(TYPE_KEY, vtype);
        if let Some(id) = id {
            nv.add_u64(ID_KEY, id);
        }
        if !children.is_empty() {
            nv.push(CHILDREN_KEY, NvData::ListArray(children));
        }
        nv
    }

    fn disk(path: &str) -> NvList {
        let mut nv = vdev("disk", Some(0), vec![]);
        nv.add_str(PATH_KEY, path);
        nv
    }

    /// A data mirror, a raidz2, a SLOG, a special mirror, an L2ARC and a spare.
    fn pool() -> NvList {
        let mirror = vdev("mirror", Some(0), vec![disk("/dev/a"), disk("/dev/b")]);
        let mut raidz = vdev("raidz", Some(1), vec![disk("/dev/c"), disk("/dev/d"), disk("/dev/e")]);
        raidz.add_u64(NPARITY_KEY, 2).add_u64(IS_LOG_KEY, 0);
        let mut slog = disk("/dev/f");
        slog.add_u64(ID_KEY, 2).add_u64(IS_LOG_KEY, 1).add_str(ALLOC_BIAS_KEY, "log");
        let mut special = vdev("mirror", Some(3), vec![disk("/dev/g"), disk("/dev/h")]);
        special.add_u64(IS_LOG_KEY, 0).add_str(ALLOC_BIAS_KEY, "special");
        let mut root = vdev("root", Some(0), vec![mirror, raidz, slog, special]);
        root.push(L2CACHE_KEY, NvData::ListArray(vec![disk("/dev/i")]));
        root.push(SPARES_KEY, NvData::ListArray(vec![disk("/dev/j")]));
        root
    }

    #[test]
    fn walk_yields_every_vdev_with_depth_and_role() {
        let tree = pool();
        let got: Vec<(String, usize, VdevRole)> =
            walk(&tree).map(|v| (v.name(), v.depth, v.role)).collect();
        let want = [
            ("mirror-0", 0, VdevRole::Data),
            ("/dev/a", 1, VdevRole::Data),
            ("/dev/b", 1, VdevRole::Data),
            ("raidz2-1", 0, VdevRole::Data),
            ("/dev/c", 1, VdevRole::Data),
            ("/dev/d", 1, VdevRole::Data),
            ("/dev/e", 1, VdevRole::Data),
            ("/dev/f", 0, VdevRole::Log),
            ("mirror-3", 0, VdevRole::Special),
            ("/dev/g", 1, VdevRole::Special),
            ("/dev/h", 1, VdevRole::Special),
            ("/dev/i", 0, VdevRole::Cache),
            ("/dev/j", 0, VdevRole::Spare),
        ];
        let want: Vec<(String, usize, VdevRole)> =
            want.iter().map(|&(n, d, r)| (n.into(), d, r)).collect();
        assert_eq!(got, want);
        let leaves = walk(&tree).filter(VdevEntry::is_leaf).count();
        assert_eq!(leaves, 10);
    }

    #[test]
    fn roles_from_the_top_level_flags() {
        let mut top = vdev("mirror", Some(0), vec![]);
        assert_eq!(VdevRole::of_top_level(&top), VdevRole::Data);
        top.add_str(ALLOC_BIAS_KEY, "dedup");
        assert_eq!(VdevRole::of_top_level(&top), VdevRole::Dedup);
        // is_log wins, and a bias from the future is data
        let mut log = vdev("disk", Some(1), vec![]);
        log.add_u64(IS_LOG_KEY, 1);
        assert_eq!(VdevRole::of_top_level(&log), VdevRole::Log);
        let mut odd = vdev("mirror", Some(2), vec![]);
        odd.add_str(ALLOC_BIAS_KEY, "someday");
        assert_eq!(VdevRole::of_top_level(&odd), VdevRole::Data);
        assert_eq!(VdevRole::Special.to_string(), "special");
    }

    #[test]
    fn names_follow_zpool() {
        let name = |nv: &NvList| walk(nv).next().unwrap().name();
        let disks = (0..11).map(|i| disk(&format!("/dev/d{i}"))).collect();
        let mut draid = vdev("draid", Some(0), disks);
        draid.add_u64(NPARITY_KEY, 2).add_u64(DRAID_NDATA_KEY, 8).add_u64(DRAID_NSPARES_KEY, 1);
        assert_eq!(name(&draid), "draid2:8d:11c:1s-0");
        // a raidz from before raidz2 existed has no nparity
        assert_eq!(name(&vdev("raidz", Some(4), vec![])), "raidz1-4");
        assert_eq!(name(&vdev("hole", Some(5), vec![])), "hole-5");
        let mut anon = vdev("missing", None, vec![]);
        anon.add_u64(GUID_KEY, 77);
        assert_eq!(name(&anon), "77");
    }

    /// A label's tree is a top-level vdev, walked as one.
    #[test]
    fn a_non_root_tree_is_its_own_top_level() {
        let mut slog = vdev("mirror", Some(2), vec![disk("/dev/x"), disk("/dev/y")]);
        slog.add_u64(IS_LOG_KEY, 1);
        let got: Vec<(usize, VdevRole)> = walk(&slog).map(|v| (v.depth, v.role)).collect();
        assert_eq!(got, [(0, VdevRole::Log), (1, VdevRole::Log), (1, VdevRole::Log)]);
    }
}
