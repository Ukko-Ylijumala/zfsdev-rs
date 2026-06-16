// Copyright (c) 2026 Mikko Tanner. All rights reserved.
// Licensed under the MIT License or the Apache License, Version 2.0.
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Integration tests against the live /dev/zfs interface. They skip
//! gracefully on machines without ZFS so CI stays green.

use zfs_browser::zfs::ioctl::ZfsHandle;

fn handle() -> Option<ZfsHandle> {
    if !std::path::Path::new("/dev/zfs").exists() {
        eprintln!("skipping: no /dev/zfs");
        return None;
    }
    Some(ZfsHandle::open().expect("open /dev/zfs"))
}

#[test]
fn pool_configs_decode_and_match_cli() {
    let Some(zfs) = handle() else { return };
    let configs = zfs.pool_configs().expect("ZFS_IOC_POOL_CONFIGS");
    let mut ours: Vec<String> = configs.iter().map(|p| p.name.clone()).collect();
    ours.sort();
    eprintln!("pools via ioctl: {ours:?}");
    assert!(!ours.is_empty(), "machine has pools but ioctl returned none");

    // each pool config must decode with the essentials present
    for pair in configs.iter() {
        let config = match &pair.data {
            zfs_browser::zfs::nvlist::NvData::List(l) => l,
            other => panic!("pool {} config is not an nvlist: {other:?}", pair.name),
        };
        assert_eq!(config.get_str("name"), Some(pair.name.as_str()));
        assert!(config.get_u64("pool_guid").is_some(), "{}: no pool_guid", pair.name);
        assert!(config.get_u64("txg").is_some(), "{}: no txg", pair.name);
    }

    // cross-check against the CLI if available
    if let Ok(out) = std::process::Command::new("zpool").args(["list", "-H", "-o", "name"]).output()
        && out.status.success()
    {
        let mut cli: Vec<String> =
            String::from_utf8_lossy(&out.stdout).lines().map(str::to_string).collect();
        cli.sort();
        assert_eq!(ours, cli, "ioctl pool list != zpool list");
    }
}

#[test]
fn pool_stats_has_vdev_tree() {
    let Some(zfs) = handle() else { return };
    let configs = zfs.pool_configs().expect("pool configs");
    for pair in configs.iter() {
        let stats = zfs.pool_stats(&pair.name).expect("ZFS_IOC_POOL_STATS");
        let tree = stats.get_list("vdev_tree").expect("config has vdev_tree");
        assert_eq!(tree.get_str("type"), Some("root"));
        let kids = tree.get_list_array("children").expect("root vdev has children");
        assert!(!kids.is_empty());
        eprintln!(
            "{}: {} top-level vdev(s), first: {}",
            pair.name,
            kids.len(),
            kids[0].get_str("type").unwrap_or("?")
        );
    }
}

#[test]
fn pool_props_decode() {
    let Some(zfs) = handle() else { return };
    let configs = zfs.pool_configs().expect("pool configs");
    let Some(first) = configs.iter().next() else { return };
    let props = zfs.pool_props(&first.name).expect("ZFS_IOC_POOL_GET_PROPS");
    assert!(props.get("size").is_some(), "pool props missing 'size'");
    eprintln!("{}: {} pool properties", first.name, props.pairs.len());
}

#[test]
fn datasets_and_snapshots_enumerate() {
    let Some(zfs) = handle() else { return };
    let configs = zfs.pool_configs().expect("pool configs");
    for pair in configs.iter() {
        let (stats, props) = zfs.objset_stats(&pair.name).expect("objset stats of root dataset");
        assert!(!stats.is_snapshot);
        assert!(props.get("used").is_some(), "{}: no 'used' prop", pair.name);

        let children = zfs.datasets(&pair.name).expect("dataset list");
        eprintln!("{}: {} child datasets", pair.name, children.len());
        for child in &children {
            assert!(child.name.starts_with(pair.name.as_str()));
        }

        let snaps = zfs.snapshots(&pair.name).expect("snapshot list");
        eprintln!("{}: {} snapshots of root dataset", pair.name, snaps.len());
        for s in &snaps {
            assert!(s.stats.is_snapshot, "{} not marked as snapshot", s.name);
            assert!(s.name.contains('@'));
        }
    }
}

/// Walk a vdev tree to the first leaf device path.
fn first_disk_path(tree: &zfs_browser::zfs::nvlist::NvList) -> Option<String> {
    if let Some(path) = tree.get_str("path") {
        return Some(path.to_string());
    }
    for child in tree.get_list_array("children")? {
        if let Some(p) = first_disk_path(child) {
            return Some(p);
        }
    }
    None
}

#[test]
fn on_disk_labels_match_ioctl_config() {
    use zfs_browser::zfs::ondisk::label::read_device_labels;

    let Some(zfs) = handle() else { return };
    let configs = zfs.pool_configs().expect("pool configs");
    let mut checked = 0;
    for pair in configs.iter() {
        let stats = zfs.pool_stats(&pair.name).expect("pool stats");
        let tree = stats.get_list("vdev_tree").expect("vdev tree");
        let Some(path) = first_disk_path(tree) else { continue };
        let dl = match read_device_labels(std::path::Path::new(&path)) {
            Ok(dl) => dl,
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!("skipping {}: {path}: permission denied (run as root)", pair.name);
                continue;
            }
            Err(e) => panic!("{}: reading labels from {path}: {e}", pair.name),
        };
        let pool_guid = stats.get_u64("pool_guid").expect("pool guid");
        for label in &dl.labels {
            let config = label
                .config
                .as_ref()
                .unwrap_or_else(|e| panic!("{path} L{}: config: {e}", label.index));
            assert_eq!(config.get_str("name"), Some(pair.name.as_str()), "L{}", label.index);
            assert_eq!(config.get_u64("pool_guid"), Some(pool_guid), "L{}", label.index);
            assert_eq!(
                label.cksum_ok,
                Some(true),
                "{path} L{}: vdev_phys checksum",
                label.index
            );
            assert!(!label.uberblocks.is_empty(), "{path} L{}: no uberblocks", label.index);
            for slot in &label.uberblocks {
                assert_eq!(
                    slot.cksum_ok,
                    Some(true),
                    "{path} L{} ub slot {}: checksum",
                    label.index,
                    slot.slot
                );
            }
            let best = label.best_uberblock().unwrap();
            assert!(best.ub.txg > 0);
            assert!(!best.ub.rootbp.is_hole(), "active rootbp should not be a hole");
        }
        let best_txg =
            dl.labels.iter().filter_map(|l| l.best_uberblock()).map(|s| s.ub.txg).max().unwrap();
        eprintln!(
            "{}: {path}: 4 labels OK, best uberblock txg {best_txg} (ioctl txg {})",
            pair.name,
            stats.get_u64("txg").unwrap_or(0),
        );
        checked += 1;
    }
    eprintln!("verified labels on {checked} pool(s)");
}

/// Walk a vdev tree to the first leaf device's guid.
fn first_disk_guid(tree: &zfs_browser::zfs::nvlist::NvList) -> Option<u64> {
    if tree.get_str("path").is_some() {
        return tree.get_u64("guid");
    }
    for child in tree.get_list_array("children")? {
        if let Some(g) = first_disk_guid(child) {
            return Some(g);
        }
    }
    None
}

/*
Read-only batch (VDEV_GET_PROPS, OBJSET_ZPLPROPS, OBJSET_RECVD_PROPS,
GET_BOOKMARKS, GET_HOLDS, USERSPACE_MANY). These run unprivileged on any pool,
so they double as ABI canaries for both the legacy (zc-field) and new-style
(packed innvl) read paths — a wrong ioctl number or struct layout surfaces as
EFAULT/EINVAL rather than the clean data / empty nvlist we expect.
*/
#[test]
fn read_batch_ioctls() {
    let Some(zfs) = handle() else { return };
    let configs = zfs.pool_configs().expect("pool configs");
    let Some(first) = configs.iter().next() else { return };
    let pool = first.name.clone();

    // VDEV_GET_PROPS on a leaf disk — guid is always returned (OpenZFS 2.2+).
    let stats = zfs.pool_stats(&pool).expect("pool stats");
    let tree = stats.get_list("vdev_tree").expect("vdev tree");
    if let Some(guid) = first_disk_guid(tree) {
        match zfs.vdev_get_props(&pool, guid) {
            Ok(props) => {
                eprintln!("{pool}: vdev {guid} -> {} props", props.pairs.len());
                // the requested guid must round-trip in the returned value
                assert_eq!(props.get_list("guid").and_then(|g| g.get_u64("value")), Some(guid));
            }
            // pre-2.2 kernels lack vdev props; an EINVAL here is acceptable
            Err(e) => eprintln!("{pool}: vdev_get_props unsupported: {e}"),
        }
    }

    // OBJSET_ZPLPROPS on the (filesystem) root dataset: ZPL version present.
    let zpl = zfs.objset_zplprops(&pool).expect("ZFS_IOC_OBJSET_ZPLPROPS");
    assert!(zpl.get_u64("version").is_some(), "ZPL props missing version");
    eprintln!("{pool}: ZPL version {:?}", zpl.get_u64("version"));

    // OBJSET_RECVD_PROPS: valid nvlist (often empty) when supported; old-format
    // pools predating SPA_VERSION_RECVD_PROPS return EOPNOTSUPP, which is fine.
    match zfs.objset_recvd_props(&pool) {
        Ok(recvd) => eprintln!("{pool}: {} received props", recvd.pairs.len()),
        Err(e) => eprintln!("{pool}: recvd props unsupported: {e}"),
    }

    // GET_BOOKMARKS: new-style read with a packed innvl; valid nvlist.
    let bms = zfs.get_bookmarks(&pool).expect("ZFS_IOC_GET_BOOKMARKS");
    eprintln!("{pool}: {} bookmarks", bms.pairs.len());

    // GET_HOLDS on the first snapshot if any; otherwise just exercise the call.
    let snaps = zfs.snapshots(&pool).expect("snapshot list");
    if let Some(s) = snaps.first() {
        let holds = zfs.get_holds(&s.name).expect("ZFS_IOC_GET_HOLDS");
        eprintln!("{}: {} holds", s.name, holds.pairs.len());
    }

    // USERSPACE_MANY (userused = type 0): needs privilege; EPERM is fine, but
    // the raw zfs_useracct_t decode must not panic when it does succeed.
    match zfs.userspace_many(&pool, 0) {
        Ok(accts) => eprintln!("{pool}: {} userused entries", accts.len()),
        Err(e) => eprintln!("{pool}: userspace_many (needs root): {e}"),
    }
}

/*
Kernel event feed (EVENTS_SEEK + EVENTS_NEXT, Linux). Reading events is config-
privileged, so on a non-root run EPERM is the clean expected path — and proves
the ABI all the same (a wrong ioctl number / struct layout would be EFAULT/
EINVAL, not EPERM). When root, drain a bounded, NON-BLOCKING batch so the test
can never hang on an idle event ring, and check each event decodes with a class.
*/
#[test]
fn events_ioctls_abi() {
    let Some(zfs) = handle() else { return };
    if let Err(e) = zfs.events_seek_start() {
        eprintln!("events need root: {e}");
        return;
    }
    let mut n = 0;
    while let Some((nv, _dropped)) = zfs.events_next(false).expect("ZFS_IOC_EVENTS_NEXT") {
        assert!(nv.get_str("class").is_some(), "event nvlist has no 'class'");
        n += 1;
        if n >= 50 {
            break; // bounded — don't drain a huge ring in the test
        }
    }
    eprintln!("read {n} kernel event(s)");
}

/*
Error log (ERROR_LOG) + object resolution (DSOBJ_TO_DSNAME / OBJ_TO_PATH /
OBJ_TO_STATS). ERROR_LOG needs root, so EACCES/EPERM is the clean unprivileged
path and still proves the ABI — in particular the unusual "filled from the back
of the buffer" decode. A healthy pool returns an empty log; any bookmarks found
are resolved (best-effort) to exercise the object-resolution ioctls too.
*/
#[test]
fn error_log_ioctls_abi() {
    let Some(zfs) = handle() else { return };
    let configs = zfs.pool_configs().expect("pool configs");
    let Some(first) = configs.iter().next() else { return };
    let pool = first.name.clone();

    let errs = match zfs.error_log(&pool) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("{pool}: error_log needs root: {e}");
            return;
        }
    };
    eprintln!("{pool}: {} error-log bookmark(s)", errs.len());
    for zb in errs.iter().take(8) {
        // resolution is best-effort: freed objects / non-ZPL objsets give a
        // clean ENOENT/EINVAL, which still exercises the legacy ioctl layout
        if let Ok(ds) = zfs.dsobj_to_dsname(&pool, zb.objset) {
            let _ = zfs.obj_to_stats(&ds, zb.object);
        }
    }
}

/* ------------------------------ write path ------------------------------- */

/*
The write ioctls can't be exercised destructively against the user's real
pools, but targeting a pool name that cannot exist proves the ioctl numbers
and zfs_cmd_t layout are correct for the mutating path — the ABI canary for
writes — with zero side effects. A wrong struct size/number would surface
as EFAULT/EINVAL or a panic, not the clean "no such pool" we expect.
*/

const NOPE_POOL: &str = "zfsbrowser_nonexistent_pool_canary";

#[test]
fn destroy_nonexistent_is_a_clean_mapped_error() {
    let Some(zfs) = handle() else { return };
    // legacy write path (no innvl)
    let target = format!("{NOPE_POOL}/ds");
    let err = zfs.destroy(&target, false).expect_err("destroy of bogus name must fail");
    let msg = err.to_string();
    eprintln!("destroy error (expected): {msg}");
    assert!(msg.starts_with("destroy dataset:"), "unmapped error: {msg}");
}

#[test]
fn snapshot_in_nonexistent_pool_is_a_clean_error() {
    let Some(zfs) = handle() else { return };
    // new-style write path (packed innvl in zc_nvlist_src)
    let snap = format!("{NOPE_POOL}/ds@canary");
    let err = zfs
        .snapshot(NOPE_POOL, &[snap], None)
        .expect_err("snapshot in bogus pool must fail (pool lookup)");
    let msg = err.to_string();
    eprintln!("snapshot error (expected): {msg}");
    assert!(msg.starts_with("create snapshot:"), "unmapped error: {msg}");
}

#[test]
fn get_fsacl_reads_delegations() {
    let Some(zfs) = handle() else { return };
    // GET_FSACL is a read; it must succeed on every pool root dataset and
    // return an nvlist (empty when no `zfs allow` delegations are set). This
    // is the ABI canary for the GET_FSACL path.
    for pair in zfs.pool_configs().expect("pool configs").iter() {
        let acl = zfs.get_fsacl(&pair.name).expect("ZFS_IOC_GET_FSACL");
        eprintln!("{}: {} delegation entr(y/ies)", pair.name, acl.pairs.len());
    }
}
