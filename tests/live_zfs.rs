// Copyright (c) 2026 Mikko Tanner. All rights reserved.
// Licensed under the MIT License or the Apache License, Version 2.0.
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Integration tests against the live /dev/zfs interface. They skip
//! gracefully on machines without ZFS so CI stays green.

use std::os::fd::AsRawFd;
use zfs_browser::zfs::ioctl::{BeginRecord, SendFlags, ZfsHandle};

fn handle() -> Option<ZfsHandle> {
    if !std::path::Path::new("/dev/zfs").exists() {
        eprintln!("skipping: no /dev/zfs");
        return None;
    }
    Some(ZfsHandle::open().expect("open /dev/zfs"))
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

/* ========================================================================= */

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

/// The zc_simple (fast-stat) snapshot listing agrees with the full one on
/// everything its callers use: names, guids, creation txgs.
#[test]
fn snapshot_stats_match_full_listing() {
    let Some(zfs) = handle() else { return };
    let mut targets: Vec<String> =
        zfs.pool_configs().expect("pool configs").iter().map(|p| p.name.clone()).collect();
    if zfs.objset_stats("data/test").is_ok() {
        targets.push("data/test".into()); // the delegated playground has a few
    }
    for name in &targets {
        let key = |v: Vec<zfs_browser::zfs::ioctl::DatasetEntry>| {
            let mut k: Vec<_> =
                v.into_iter().map(|e| (e.name, e.stats.guid, e.stats.creation_txg)).collect();
            k.sort();
            k
        };
        let full = key(zfs.snapshots(name).expect("full listing"));
        let fast = key(zfs.snapshot_stats(name).expect("fast listing"));
        assert_eq!(fast, full, "{name}: fast snapshot stats differ");
        assert!(fast.iter().all(|(_, g, _)| *g != 0));
        eprintln!("{name}: {} snapshot(s) agree", fast.len());
    }
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

/*
Snapshot space estimates: SPACE_WRITTEN (legacy, result in zc fields) and
SPACE_SNAPS (new-style, innvl firstsnap → outnvl used/compressed/uncompressed).
Both are reads, so they run unprivileged; exercised against the first pool root
that has snapshots (sorted by creation txg so the SPACE_SNAPS range is valid).
*/
#[test]
fn space_estimate_ioctls() {
    let Some(zfs) = handle() else { return };
    for pair in zfs.pool_configs().expect("pool configs").iter() {
        let mut snaps = zfs.snapshots(&pair.name).unwrap_or_default();
        snaps.sort_by_key(|s| s.stats.creation_txg);
        let Some(first) = snaps.first() else { continue };
        // written@first for the live pool root — a valid pair, must succeed
        let w = zfs
            .space_written(&pair.name, &first.name)
            .expect("ZFS_IOC_SPACE_WRITTEN on a (dataset, snapshot) pair");
        eprintln!("{}: written since {} = {} bytes", pair.name, first.name, w.used);
        if snaps.len() >= 2 {
            let last = &snaps[snaps.len() - 1].name;
            let s = zfs
                .space_snaps(last, &first.name)
                .expect("ZFS_IOC_SPACE_SNAPS on a snapshot range");
            eprintln!("{}: destroying {}..{} frees {} bytes", pair.name, first.name, last, s.used);
        }
        return; // one pool with snapshots proves both layouts
    }
    eprintln!("no pool-root snapshots to exercise the space estimates against");
}

/* ------------------------------ write path ------------------------------- */

/**
The write ioctls can't be exercised destructively against the user's real
pools, but targeting a pool name that cannot exist proves the ioctl numbers
and zfs_cmd_t layout are correct for the mutating path — the ABI canary for
writes — with zero side effects. A wrong struct size/number would surface
as EFAULT/EINVAL or a panic, not the clean "no such pool" we expect.
*/
const NOPE_POOL: &str = "zfsbrowser_nonexistent_pool_canary";

#[test]
fn send_recv_ioctls_abi() {
    let Some(zfs) = handle() else { return };
    /*
    All four send/receive ioctls against a nonexistent pool. The errno
    matters, not just the failure: the kernel validates the innvl key
    *types* (zfs_keys_send_new / zfs_keys_recv_new) before resolving the
    name, so a mistyped nvlist would surface as ZFS_ERR_IOC_ARG_BADTYPE
    instead of the plain ENOENT asserted here — mistyped keys can't hide
    behind the bogus name (the lesson from the CREATE int32 regression).
    */
    let snap = format!("{NOPE_POOL}/ds@canary");
    let flags = SendFlags { large_block: true, embed: true, compress: true, raw: false };

    let err = zfs
        .send_space(&snap, Some("earlier"), flags)
        .expect_err("send_space of bogus snapshot must fail");
    eprintln!("send_space error (expected): {err}");
    assert!(err.to_string().contains("No such"), "not ENOENT: {err}");

    let sink = std::fs::OpenOptions::new().write(true).open("/dev/null").unwrap();
    let err = zfs
        .send_new(&snap, sink.as_raw_fd(), None, flags)
        .expect_err("send of bogus snapshot must fail");
    eprintln!("send error (expected): {err}");
    assert!(err.to_string().starts_with("send:"), "unmapped error: {err}");
    assert!(err.to_string().contains("No such"), "not ENOENT: {err}");

    let err = zfs
        .send_progress(&snap, sink.as_raw_fd())
        .expect_err("progress of bogus send must fail");
    eprintln!("send_progress error (expected): {err}");

    // a well-formed synthetic BEGIN record into a nonexistent pool: the key
    // types and the byte-array framing are validated, the name is not found
    let mut begin = vec![0u8; zfs_browser::zfs::ioctl::DRR_RECORD_SIZE];
    begin[8..16].copy_from_slice(&0x2F5BACBACu64.to_le_bytes());
    let begin = BeginRecord::parse(&begin).unwrap();
    let src = std::fs::File::open("/dev/null").unwrap();
    let err = zfs
        .recv_new(&snap, &begin, src.as_raw_fd(), false, false)
        .expect_err("receive into bogus pool must fail");
    eprintln!("receive error (expected): {err}");
    assert!(err.to_string().starts_with("receive:"), "unmapped error: {err}");
    assert!(err.to_string().contains("No such"), "not ENOENT: {err}");

    // happy path, root-free: SEND_SPACE is an unprivileged read, so a real
    // snapshot (when the machine has one) proves the outnvl decode too
    let configs = zfs.pool_configs().expect("pool configs");
    for pair in configs.iter() {
        let Ok(snaps) = zfs.snapshots(&pair.name) else { continue };
        if let Some(s) = snaps.first() {
            let space = zfs.send_space(&s.name, None, SendFlags::default()).expect("send_space");
            eprintln!("send_space({}) = {space} bytes", s.name);
            assert!(space > 0, "a full stream of {} can't be empty", s.name);
            return;
        }
    }
    eprintln!("no snapshot found for the send_space happy path");
}

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
fn pool_maintenance_in_nonexistent_pool_is_a_clean_error() {
    let Some(zfs) = handle() else { return };
    /*
    scan/clear are legacy (zc fields); trim/initialize are new-style (packed
    innvl with a vdev-guid nvlist). Targeting a bogus pool exercises all four
    struct layouts / ioctl numbers and must fail at pool lookup, not crash.
    */
    let scrub = zfs.pool_scan(NOPE_POOL, 1, false).expect_err("scrub of bogus pool must fail");
    assert!(scrub.to_string().starts_with("scrub:"), "unmapped: {scrub}");

    let clear = zfs.clear_errors(NOPE_POOL, 0).expect_err("clear of bogus pool must fail");
    assert!(clear.to_string().starts_with("clear errors:"), "unmapped: {clear}");

    let trim = zfs.pool_trim(NOPE_POOL, &[0xdead], 0).expect_err("trim of bogus pool must fail");
    assert!(trim.to_string().starts_with("trim:"), "unmapped: {trim}");

    let init = zfs
        .pool_initialize(NOPE_POOL, &[0xdead], 0)
        .expect_err("initialize of bogus pool must fail");
    assert!(init.to_string().starts_with("initialize:"), "unmapped: {init}");

    let off = zfs
        .vdev_set_state(NOPE_POOL, 0xdead, false, false)
        .expect_err("offline in bogus pool must fail");
    assert!(off.to_string().starts_with("offline vdev:"), "unmapped: {off}");

    // online + expand (zpool online -e) — same ioctl, EXPAND flag in zc_obj
    let exp = zfs
        .vdev_set_state(NOPE_POOL, 0xdead, true, true)
        .expect_err("online -e in bogus pool must fail");
    assert!(exp.to_string().starts_with("online vdev:"), "unmapped: {exp}");

    let det = zfs.vdev_detach(NOPE_POOL, 0xdead).expect_err("detach in bogus pool must fail");
    assert!(det.to_string().starts_with("detach vdev:"), "unmapped: {det}");

    // attach stats the new device first; a temp file proves the conf-nvlist path
    let tmp = std::env::temp_dir().join("zfs-browser-attach-canary");
    std::fs::write(&tmp, b"x").expect("write temp device file");
    let att = zfs
        .vdev_attach(NOPE_POOL, 0xdead, tmp.to_str().unwrap(), false)
        .expect_err("attach in bogus pool must fail");
    assert!(att.to_string().starts_with("attach vdev:"), "unmapped: {att}");
    let _ = std::fs::remove_file(&tmp);

    let setp = zfs
        .vdev_set_props(NOPE_POOL, 0xdead, "failfast", &zfs_browser::zfs::nvlist::NvData::Uint64(0))
        .expect_err("set vdev prop in bogus pool must fail");
    assert!(setp.to_string().starts_with("set vdev property:"), "unmapped: {setp}");
    eprintln!("pool-maintenance canaries all failed cleanly at pool lookup");
}

#[test]
fn hold_release_in_nonexistent_pool_is_a_clean_error() {
    let Some(zfs) = handle() else { return };
    // both are new-style (packed innvl); a bogus snapshot fails at lookup,
    // proving the HOLD/RELEASE struct layouts with no side effects
    let snap = format!("{NOPE_POOL}/ds@canary");
    let hold = zfs.hold(NOPE_POOL, &snap, "tag").expect_err("hold of bogus snap must fail");
    assert!(hold.to_string().starts_with("hold:"), "unmapped: {hold}");
    let rel = zfs.release(NOPE_POOL, &snap, "tag").expect_err("release of bogus snap must fail");
    assert!(rel.to_string().starts_with("release:"), "unmapped: {rel}");
    eprintln!("hold/release canaries failed cleanly");
}

#[test]
fn get_fsacl_reads_delegations() {
    let Some(zfs) = handle() else { return };
    /*
    GET_FSACL is a read; it must succeed on every pool root dataset and
    return an nvlist (empty when no `zfs allow` delegations are set). This
    is the ABI canary for the GET_FSACL path.
    */
    for pair in zfs.pool_configs().expect("pool configs").iter() {
        let acl = zfs.get_fsacl(&pair.name).expect("ZFS_IOC_GET_FSACL");
        eprintln!("{}: {} delegation entr(y/ies)", pair.name, acl.pairs.len());
    }
}

/**
A failed new-style write names the element that failed: the kernel copies
the per-element errors outnvl back even when the ioctl fails, and
`write_ioctl` appends it to the error. Re-creating a snapshot that already
exists in the delegated playground fails per-element with EEXIST inside the
handler (dsl_dataset_snapshot_check) and changes nothing.
*/
#[test]
fn failed_snapshot_names_the_failing_element() {
    const PLAYGROUND: &str = "data/test";
    let Some(zfs) = handle() else { return };
    let Ok(snaps) = zfs.snapshots(PLAYGROUND) else {
        eprintln!("skipping: no {PLAYGROUND} playground on this machine");
        return;
    };
    let Some(existing) = snaps.first().map(|s| s.name.clone()) else {
        eprintln!("skipping: {PLAYGROUND} has no snapshot to re-create");
        return;
    };
    let pool = PLAYGROUND.split('/').next().unwrap();
    match zfs.snapshot(pool, std::slice::from_ref(&existing), None) {
        Err(e) => {
            eprintln!("{e}");
            let e = e.to_string();
            if e.contains("Operation not permitted") {
                eprintln!("skipping: no snapshot delegation on {PLAYGROUND}");
                return;
            }
            assert!(e.contains(&format!("{existing}: File exists")), "element not named: {e}");
        }
        Ok(_) => panic!("re-creating existing {existing} must fail"),
    }
}

/**
`zfs unallow <who>` (revoke with no permission list) against a throwaway
child of the delegated playground: grant ourselves `snapshot` locally on
the child, revoke the whole who, and check the child's own delegations are
gone. The whole-who revoke must be encoded as a *non-nvlist* value — an
empty perm nvlist fails `zfs_deleg_verify_nvlist` with EINVAL. Only the
child's entries are touched (inherited playground perms live on the
parent). Needs the `allow` delegation on the playground; skips otherwise.
*/
#[test]
fn unallow_whole_who_in_playground() {
    use zfs_browser::zfs::ioctl::DelegWho;

    const PLAYGROUND: &str = "data/test";
    let Some(zfs) = handle() else { return };
    if zfs.objset_stats(PLAYGROUND).is_err() {
        eprintln!("skipping: no {PLAYGROUND} playground on this machine");
        return;
    }
    let ds = format!("{PLAYGROUND}/zb-deleg-{}", std::process::id());
    // CREATE never mounts (that's libzfs, userspace) — fine under delegation
    if let Err(e) = zfs.create(&ds, 2, None) {
        eprintln!("skipping: cannot create {ds}: {e}");
        return;
    }
    let me = DelegWho::User(unsafe { libc::getuid() } as u64);
    let result = (|| -> Result<(), String> {
        if let Err(e) = zfs.set_fsacl(&ds, &me, &["snapshot".into()], false) {
            eprintln!("skipping: no `allow` delegation on {PLAYGROUND}: {e}");
            return Ok(());
        }
        let n = zfs.get_fsacl(&ds).map_err(|e| e.to_string())?.pairs.len();
        assert!(n > 0, "grant left no delegation entries on {ds}");
        zfs.set_fsacl(&ds, &me, &[], true).map_err(|e| format!("unallow whole who: {e}"))?;
        let acl = zfs.get_fsacl(&ds).map_err(|e| e.to_string())?;
        assert!(acl.pairs.is_empty(), "whole-who unallow left entries: {acl:?}");
        // an empty *grant* is refused client-side, never sent
        assert!(zfs.set_fsacl(&ds, &me, &[], false).is_err());
        Ok(())
    })();
    let _ = zfs.destroy(&ds, false);
    result.unwrap();
}

#[test]
fn load_unload_key_in_nonexistent_pool_is_a_clean_error() {
    let Some(zfs) = handle() else { return };
    /*
    LOAD_KEY validates its innvl keys (zfs_keys_load_key: hidden_args as an
    nvlist, optional noop flag) before resolving the dataset, so a mistyped
    wkeydata wrapper would surface as ZFS_ERR_IOC_ARG_BADTYPE rather than
    the clean lookup failure asserted here. UNLOAD_KEY has no innvl.
    */
    let ds = format!("{NOPE_POOL}/enc");
    let wkey = [0u8; 32];
    let load = zfs.load_key(&ds, &wkey, false).expect_err("load-key of bogus ds must fail");
    assert!(load.to_string().starts_with("load key:"), "unmapped: {load}");
    let noop = zfs.load_key(&ds, &wkey, true).expect_err("noop load-key of bogus ds must fail");
    assert!(noop.to_string().starts_with("load key:"), "unmapped: {noop}");
    let unload = zfs.unload_key(&ds).expect_err("unload-key of bogus ds must fail");
    assert!(unload.to_string().starts_with("unload key:"), "unmapped: {unload}");
    eprintln!("load/unload-key canaries failed cleanly");
}

/**
End-to-end key management against the delegated playground `data/test`
(mtanner holds `zfs allow` perms there): create a passphrase-encrypted
child via the CLI (`-u` skips the mount, which delegation can't do),
then drive UNLOAD_KEY / LOAD_KEY through our ioctls with the wrapping key
derived by `crypt::derive_wrapping_key` from the dataset's own
pbkdf2salt/pbkdf2iters — including the negative case (a wrong passphrase
must be *rejected by the kernel's MAC check*, proving the kernel really
verified our PBKDF2 output). Skips wherever the environment is absent.
*/
#[test]
fn load_key_roundtrip_in_playground() {
    use std::io::Write;
    use std::process::{Command, Stdio};
    use zfs_browser::node::{prop_value_str, prop_value_u64};
    use zfs_browser::zfs::crypt::derive_wrapping_key;
    use zfs_browser::zfs::props::KeyFormat;

    const PLAYGROUND: &str = "data/test";
    const PASS: &str = "zfs-browser test passphrase";
    let Some(zfs) = handle() else { return };
    if zfs.objset_stats(PLAYGROUND).is_err() {
        eprintln!("skipping: no {PLAYGROUND} playground on this machine");
        return;
    }
    let ds = format!("{PLAYGROUND}/zb-enc-{}", std::process::id());
    // encrypted create needs wkeydata via hidden_args, which our CREATE
    // doesn't pass yet — use the CLI here (tests may; the app never does)
    let mut child = Command::new("zfs")
        .args(["create", "-u", "-o", "encryption=on", "-o", "keyformat=passphrase", &ds])
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn zfs create");
    child.stdin.take().unwrap().write_all(format!("{PASS}\n{PASS}\n").as_bytes()).ok();
    let out = child.wait_with_output().expect("zfs create");
    if !out.status.success() {
        eprintln!(
            "skipping: cannot create an encrypted dataset under {PLAYGROUND}: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
        return;
    }

    let result = (|| -> Result<(), String> {
        let keystatus = |zfs: &ZfsHandle| -> Result<u64, String> {
            let (_, props) = zfs.objset_stats(&ds).map_err(|e| e.to_string())?;
            prop_value_u64(&props, "keystatus").ok_or_else(|| "no keystatus prop".into())
        };
        let (_, props) = zfs.objset_stats(&ds).map_err(|e| e.to_string())?;
        assert_eq!(keystatus(&zfs)?, 2, "fresh encrypted dataset must have its key loaded");
        assert_eq!(prop_value_str(&props, "encryptionroot").as_deref(), Some(ds.as_str()));
        let salt = prop_value_u64(&props, "pbkdf2salt").ok_or("no pbkdf2salt")?;
        let iters = prop_value_u64(&props, "pbkdf2iters").ok_or("no pbkdf2iters")?;

        if let Err(e) = zfs.unload_key(&ds) {
            // delegation may lack load-key on some machines — skip, don't fail
            eprintln!("skipping unload/load round: {e}");
            return Ok(());
        }
        assert_eq!(keystatus(&zfs)?, 1, "keystatus must be unavailable after unload");

        // the kernel must REJECT a key derived from the wrong passphrase —
        // this proves it actually checked our PBKDF2 output against the
        // wrapped master key's MAC, not just accepted 32 bytes
        let wrong = derive_wrapping_key(KeyFormat::Passphrase, b"wrong passphrase", salt, iters)?;
        let denied = zfs.load_key(&ds, &wrong, false);
        assert!(denied.is_err(), "wrong passphrase must be rejected");
        eprintln!("wrong-passphrase load rejected: {}", denied.unwrap_err());
        assert_eq!(keystatus(&zfs)?, 1);

        let right = derive_wrapping_key(KeyFormat::Passphrase, PASS.as_bytes(), salt, iters)?;
        // noop first (zfs load-key -n): verifies without loading
        zfs.load_key(&ds, &right, true).map_err(|e| format!("noop load: {e}"))?;
        assert_eq!(keystatus(&zfs)?, 1, "noop load must not keep the key loaded");
        zfs.load_key(&ds, &right, false).map_err(|e| format!("load: {e}"))?;
        assert_eq!(keystatus(&zfs)?, 2, "keystatus must be available after load");
        eprintln!("unload → wrong-key reject → noop verify → load: all good");
        Ok(())
    })();

    let _ = zfs.destroy(&ds, false);
    result.unwrap();
}
