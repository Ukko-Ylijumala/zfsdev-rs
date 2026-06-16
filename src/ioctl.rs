// Copyright (c) 2026 Mikko Tanner. All rights reserved.
// Licensed under the MIT License or the Apache License, Version 2.0.
// SPDX-License-Identifier: MIT OR Apache-2.0

/*!
Direct `/dev/zfs` ioctl interface.

Struct layouts mirror OpenZFS 2.2.2 (`doc/reference/zfs_ioctl.h`); the
`zfs_cmd_t` ABI is not a committed stable interface across OpenZFS major
versions, so layout changes must be tracked when supporting newer
releases. Ioctl numbers (`0x5a00 + n`, `doc/reference/zfs.h`) live in the
"legacy" range that has been stable since 2.0.

Reads use the GET/LIST ioctls; the mutating ioctls (SET_PROP, CREATE,
DESTROY, SNAPSHOT, …) are also defined. Write requests pass their
parameters in as a packed nvlist (`NvList::pack`) in `zc_nvlist_src` and
read the kernel's per-element errors nvlist back from `zc_nvlist_dst`.
Whether a given write is permitted for the calling uid is decided by the
kernel (root, or a matching `zfs allow` delegation).
*/

use super::nvlist::{NvError, NvList};
use super::props::VdevProp;
use std::ffi::{CStr, CString};
use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use thiserror::Error;

const ZFS_DEV: &str = "/dev/zfs";

const ZFS_IOC_POOL_CONFIGS: u64 = 0x5a04;
const ZFS_IOC_POOL_STATS: u64 = 0x5a05;
const ZFS_IOC_POOL_GET_HISTORY: u64 = 0x5a0a;
const ZFS_IOC_OBJSET_STATS: u64 = 0x5a12;
const ZFS_IOC_OBJSET_ZPLPROPS: u64 = 0x5a13;
const ZFS_IOC_ERROR_LOG: u64 = 0x5a20;
const ZFS_IOC_DSOBJ_TO_DSNAME: u64 = 0x5a24;
const ZFS_IOC_OBJ_TO_PATH: u64 = 0x5a25;
const ZFS_IOC_OBJ_TO_STATS: u64 = 0x5a38;
const ZFS_IOC_DATASET_LIST_NEXT: u64 = 0x5a14;
const ZFS_IOC_SNAPSHOT_LIST_NEXT: u64 = 0x5a15;
const ZFS_IOC_POOL_GET_PROPS: u64 = 0x5a27;
const ZFS_IOC_GET_FSACL: u64 = 0x5a29;
const ZFS_IOC_USERSPACE_MANY: u64 = 0x5a2e;
const ZFS_IOC_GET_HOLDS: u64 = 0x5a32;
const ZFS_IOC_OBJSET_RECVD_PROPS: u64 = 0x5a33;
const ZFS_IOC_GET_BOOKMARKS: u64 = 0x5a44;
const ZFS_IOC_VDEV_GET_PROPS: u64 = 0x5a55;

/*
Linux event-stream ioctls (`zpool events`): ZFS_IOC_PLATFORM = ZFS_IOC_FIRST +
0x80 = 0x5a80, then EVENTS_NEXT/_CLEAR/_SEEK. The cursor is per-fd (keyed by
`zc_cleanup_fd`), so a dedicated handle reads the whole kernel ring.
*/
const ZFS_IOC_EVENTS_NEXT: u64 = 0x5a81;
const ZFS_IOC_EVENTS_SEEK: u64 = 0x5a83;
/// `zc_guid` flag for EVENTS_NEXT: return ENOENT instead of blocking when the
/// cursor has caught up (doc/reference/zfs_ioctl.h).
const ZEVENT_NONBLOCK: u64 = 0x1;
/// EVENTS_SEEK target: rewind the cursor to the oldest retained event.
const ZEVENT_SEEK_START: u64 = 0;

/*
Mutating ioctls (ordinals from doc/reference/zfs.h). SET_PROP, DESTROY,
RENAME and INHERIT_PROP are "legacy" (parameters in zc_ fields); SNAPSHOT,
DESTROY_SNAPS and CREATE are "new"-style (parameters as a packed nvlist in
zc_nvlist_src).
*/
const ZFS_IOC_POOL_SCAN: u64 = 0x5a07;
const ZFS_IOC_CLEAR: u64 = 0x5a21;
const ZFS_IOC_POOL_INITIALIZE: u64 = 0x5a4f;
const ZFS_IOC_POOL_TRIM: u64 = 0x5a50;
const ZFS_IOC_SET_PROP: u64 = 0x5a16;
const ZFS_IOC_SET_FSACL: u64 = 0x5a28;
const ZFS_IOC_CREATE: u64 = 0x5a17;
const ZFS_IOC_DESTROY: u64 = 0x5a18;
const ZFS_IOC_RENAME: u64 = 0x5a1a;
const ZFS_IOC_SNAPSHOT: u64 = 0x5a23;
const ZFS_IOC_POOL_SET_PROPS: u64 = 0x5a26;
const ZFS_IOC_INHERIT_PROP: u64 = 0x5a2b;
const ZFS_IOC_DESTROY_SNAPS: u64 = 0x5a3b;
const ZFS_IOC_HOLD: u64 = 0x5a30;
const ZFS_IOC_RELEASE: u64 = 0x5a31;
const ZFS_IOC_LOG_HISTORY: u64 = 0x5a3f;

const MAXPATHLEN: usize = 4096;
const MAXNAMELEN: usize = 256;

/// Initial nvlist output buffer; grown on ENOMEM as instructed by the kernel.
const DST_INITIAL: usize = 256 * 1024;

#[derive(Debug, Error)]
pub enum ZfsError {
    #[error("cannot open {ZFS_DEV}: {0}")]
    Open(io::Error),
    #[error("zfs ioctl {ioc:#x} ({name}): {err}")]
    Ioctl { ioc: u64, name: String, err: io::Error },
    #[error("decoding nvlist from kernel: {0}")]
    Nv(#[from] NvError),
    /// A mutating operation failed; message already carries an errno hint.
    #[error("{0}")]
    Op(String),
}

type Result<T> = std::result::Result<T, ZfsError>;

/// A human hint for the errnos write ioctls commonly return.
fn errno_hint(err: &io::Error) -> &'static str {
    match err.raw_os_error() {
        Some(libc::EPERM) | Some(libc::EACCES) => {
            " (need root, or a `zfs allow` delegation for this operation)"
        }
        Some(libc::EEXIST) => " (already exists)",
        Some(libc::ENOENT) => " (no such pool/dataset)",
        Some(libc::EBUSY) => " (busy — mounted, held, or has children)",
        Some(libc::ENAMETOOLONG) => " (name too long)",
        Some(libc::EINVAL) => " (invalid argument — bad name or property value?)",
        _ => "",
    }
}

/// A `zfs allow` subject: a user/group (by numeric id) or everyone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DelegWho {
    User(u64),
    Group(u64),
    Everyone,
}

/**
Resolve a who-spec to a [`DelegWho`]: `everyone`; `group:NAME` / `g:NAME`;
`user:NAME` / `u:NAME` / a bare name (defaults to user); or a bare numeric id.
Names are looked up via the system passwd/group databases.
*/
pub fn resolve_who(spec: &str) -> std::result::Result<DelegWho, String> {
    let spec = spec.trim();
    if spec.eq_ignore_ascii_case("everyone") {
        return Ok(DelegWho::Everyone);
    }
    let (is_group, name) = match spec.split_once(':') {
        Some(("group" | "g", n)) => (true, n.trim()),
        Some(("user" | "u", n)) => (false, n.trim()),
        Some((other, _)) => return Err(format!("unknown who type '{other}' (use user:/group:)")),
        None => (false, spec),
    };
    if let Ok(id) = name.parse::<u64>() {
        return Ok(if is_group { DelegWho::Group(id) } else { DelegWho::User(id) });
    }
    if is_group {
        resolve_id(name, true).map(DelegWho::Group).ok_or_else(|| format!("no such group '{name}'"))
    } else {
        resolve_id(name, false).map(DelegWho::User).ok_or_else(|| format!("no such user '{name}'"))
    }
}

/// Look up a numeric uid (or gid) in the system database, returning its name.
/// The inverse of [`resolve_id`]; used to label userused@/groupused@ rows.
pub fn name_for_id(id: u64, group: bool) -> Option<String> {
    let id = u32::try_from(id).ok()?;
    // SAFETY: getpwuid/getgrgid return a pointer into static storage (or null);
    // we copy the name out immediately and don't retain the pointer.
    unsafe {
        let name = if group {
            let gr = libc::getgrgid(id as libc::gid_t);
            (!gr.is_null()).then(|| (*gr).gr_name)
        } else {
            let pw = libc::getpwuid(id as libc::uid_t);
            (!pw.is_null()).then(|| (*pw).pw_name)
        };
        name.map(|p| CStr::from_ptr(p).to_string_lossy().into_owned())
    }
}

/// Look up a user (or group) name in the system database, returning its id.
fn resolve_id(name: &str, group: bool) -> Option<u64> {
    let cname = CString::new(name).ok()?;
    // SAFETY: getpwnam/getgrnam return a pointer into static storage (or null);
    // we read the id field immediately and don't retain the pointer.
    unsafe {
        if group {
            let gr = libc::getgrnam(cname.as_ptr());
            (!gr.is_null()).then(|| (*gr).gr_gid as u64)
        } else {
            let pw = libc::getpwnam(cname.as_ptr());
            (!pw.is_null()).then(|| (*pw).pw_uid as u64)
        }
    }
}

/**
Build a delegation key: `<type><inherit>$<id>` for a user/group, `e<inherit>$`
for everyone. Mirrors `zfs_deleg_whokey` (doc/reference/zfs_deleg.c); `$` is
ZFS_DELEG_FIELD_SEP_CHR and `inherit` is `l` (ZFS_DELEG_LOCAL) or `d`
(ZFS_DELEG_DESCENDENT), per doc/reference/zfs_deleg.h. A bare `zfs allow`
writes both, which `set_fsacl` does.
*/
fn deleg_whokey(who: &DelegWho, inherit: char) -> String {
    match who {
        DelegWho::User(id) => format!("u{inherit}${id}"),
        DelegWho::Group(id) => format!("g{inherit}${id}"),
        DelegWho::Everyone => format!("e{inherit}$"),
    }
}

/**
Parse concatenated pool-history records — each a little-endian `u64` length
followed by that many bytes of `NV_ENCODE_NATIVE` nvlist (the framing
`spa_history_log_sync` writes, doc/reference/spa_history.c). Whole records
are appended to `out`; returns the bytes consumed, leaving any trailing
partial record for the caller to re-read from an advanced offset.
*/
fn unpack_history(buf: &[u8], out: &mut Vec<NvList>) -> Result<usize> {
    let mut pos = 0;
    while pos + 8 <= buf.len() {
        let reclen = u64::from_le_bytes(buf[pos..pos + 8].try_into().unwrap()) as usize;
        if reclen == 0 || pos + 8 + reclen > buf.len() {
            break; // partial record at the buffer tail
        }
        out.push(NvList::unpack(&buf[pos + 8..pos + 8 + reclen])?);
        pos += 8 + reclen;
    }
    Ok(pos)
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ZfsShare {
    z_exportdata: u64,
    z_sharedata: u64,
    z_sharetype: u64,
    z_sharemax: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct DmuObjsetStatsRaw {
    dds_num_clones: u64,
    dds_creation_txg: u64,
    dds_guid: u64,
    dds_type: u32,
    dds_is_snapshot: u8,
    dds_inconsistent: u8,
    dds_redacted: u8,
    dds_origin: [u8; MAXNAMELEN],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct DrrBegin {
    drr_magic: u64,
    drr_versioninfo: u64,
    drr_creation_time: u64,
    drr_type: u32,
    drr_flags: u32,
    drr_toguid: u64,
    drr_fromguid: u64,
    drr_toname: [u8; MAXNAMELEN],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ZinjectRecord {
    zi_objset: u64,
    zi_object: u64,
    zi_start: u64,
    zi_end: u64,
    zi_guid: u64,
    zi_level: u32,
    zi_error: u32,
    zi_type: u64,
    zi_freq: u32,
    zi_failfast: u32,
    zi_func: [u8; MAXNAMELEN],
    zi_iotype: u32,
    zi_duration: i32,
    zi_timer: u64,
    zi_nlanes: u64,
    zi_cmd: u32,
    zi_dvas: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ZfsStat {
    zs_gen: u64,
    zs_mode: u64,
    zs_links: u64,
    zs_ctime: [u64; 2],
}

#[repr(C)]
struct ZfsCmd {
    zc_name: [u8; MAXPATHLEN],
    zc_nvlist_src: u64,
    zc_nvlist_src_size: u64,
    zc_nvlist_dst: u64,
    zc_nvlist_dst_size: u64,
    zc_nvlist_dst_filled: i32,
    zc_pad2: i32,
    zc_history: u64,
    zc_value: [u8; MAXPATHLEN * 2],
    zc_string: [u8; MAXNAMELEN],
    zc_guid: u64,
    zc_nvlist_conf: u64,
    zc_nvlist_conf_size: u64,
    zc_cookie: u64,
    zc_objset_type: u64,
    zc_perm_action: u64,
    zc_history_len: u64,
    zc_history_offset: u64,
    zc_obj: u64,
    zc_iflags: u64,
    zc_share: ZfsShare,
    zc_objset_stats: DmuObjsetStatsRaw,
    zc_begin_record: DrrBegin,
    zc_inject_record: ZinjectRecord,
    zc_defer_destroy: u32,
    zc_flags: u32,
    zc_action_handle: u64,
    zc_cleanup_fd: i32,
    zc_simple: u8,
    zc_pad: [u8; 3],
    zc_sendobj: u64,
    zc_fromobj: u64,
    zc_createtxg: u64,
    zc_stat: ZfsStat,
    zc_zoneid: u64,
}

// The kernel copies exactly sizeof(zfs_cmd_t) from userspace; a size mismatch
// here would mean reading/writing past our buffer.
const _: () = assert!(size_of::<ZfsCmd>() == 13744);
const _: () = assert!(size_of::<DmuObjsetStatsRaw>() == 288);
const _: () = assert!(size_of::<DrrBegin>() == 304);
const _: () = assert!(size_of::<ZinjectRecord>() == 352);

impl ZfsCmd {
    fn new() -> Box<ZfsCmd> {
        // All-zero is the valid "empty" state for zfs_cmd_t (plain integers
        // and byte arrays only).
        unsafe { Box::new(std::mem::zeroed()) }
    }

    fn set_name(&mut self, name: &str) {
        let bytes = name.as_bytes();
        assert!(bytes.len() < MAXPATHLEN, "dataset name too long");
        self.zc_name[..bytes.len()].copy_from_slice(bytes);
        self.zc_name[bytes.len()] = 0;
    }

    /// Set `zc_value` (the secondary name field: rename target, inherited
    /// property name, …). It is `MAXPATHLEN * 2` bytes wide.
    fn set_value(&mut self, value: &str) {
        let bytes = value.as_bytes();
        assert!(bytes.len() < MAXPATHLEN * 2, "value too long");
        self.zc_value[..bytes.len()].copy_from_slice(bytes);
        self.zc_value[bytes.len()] = 0;
    }

    fn name(&self) -> String {
        cstr_field(&self.zc_name)
    }
}

fn cstr_field(buf: &[u8]) -> String {
    CStr::from_bytes_until_nul(buf)
        .map(|c| c.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// Decoded `dmu_objset_stats_t` as filled in by OBJSET_STATS / LIST_NEXT.
#[derive(Debug, Clone)]
pub struct ObjsetStats {
    pub num_clones: u64,
    pub creation_txg: u64,
    pub guid: u64,
    /// Raw dmu_objset_type_t; render via [`crate::zfs::enums::ObjsetType`].
    pub objset_type: u32,
    pub is_snapshot: bool,
    pub inconsistent: bool,
    pub redacted: bool,
    pub origin: String,
}

impl From<&DmuObjsetStatsRaw> for ObjsetStats {
    fn from(raw: &DmuObjsetStatsRaw) -> Self {
        ObjsetStats {
            num_clones: raw.dds_num_clones,
            creation_txg: raw.dds_creation_txg,
            guid: raw.dds_guid,
            objset_type: raw.dds_type,
            is_snapshot: raw.dds_is_snapshot != 0,
            inconsistent: raw.dds_inconsistent != 0,
            redacted: raw.dds_redacted != 0,
            origin: cstr_field(&raw.dds_origin),
        }
    }
}

/**
One decoded `zfs_useracct_t` from USERSPACE_MANY: the space charged to a
user/group. `domain` is empty on plain POSIX ids (set only for SMB/idmap);
`rid` is the uid/gid.
*/
#[derive(Debug, Clone)]
pub struct UserAcct {
    pub domain: String,
    pub rid: u32,
    pub space: u64,
}

/**
A `zbookmark_phys_t` from the pool error log: the block (objset, object, level,
blkid) of a permanent data error. `objset` is a dataset object id (resolve via
[`ZfsHandle::dsobj_to_dsname`]); `object` is an object within that dataset.
*/
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Zbookmark {
    pub objset: u64,
    pub object: u64,
    pub level: i64,
    pub blkid: u64,
}

/// The `zfs_stat_t` an object resolves to (OBJ_TO_STATS): generation, POSIX
/// mode bits, link count, and ctime (unix seconds).
#[derive(Debug, Clone, Copy)]
pub struct ZStat {
    pub generation: u64,
    pub mode: u64,
    pub links: u64,
    pub ctime: u64,
}

impl From<&ZfsStat> for ZStat {
    fn from(s: &ZfsStat) -> Self {
        ZStat { generation: s.zs_gen, mode: s.zs_mode, links: s.zs_links, ctime: s.zs_ctime[0] }
    }
}

/// A dataset or snapshot returned by the LIST_NEXT iterators.
#[derive(Debug, Clone)]
pub struct DatasetEntry {
    pub name: String,
    pub stats: ObjsetStats,
    pub props: NvList,
}

pub struct ZfsHandle {
    file: File,
}

impl ZfsHandle {
    pub fn open() -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(ZFS_DEV)
            .map_err(ZfsError::Open)?;
        Ok(ZfsHandle { file })
    }

    fn ioctl(&self, ioc: u64, zc: &mut ZfsCmd) -> io::Result<()> {
        /*
        The ioctl request arg is c_ulong on glibc but c_int on musl; the
        0x5a00-range request numbers fit either. `libc::Ioctl` is the
        per-target alias, so this casts to the right width on both.
        */
        let rc = unsafe {
            libc::ioctl(self.file.as_raw_fd(), ioc as libc::Ioctl, zc as *mut ZfsCmd)
        };
        if rc != 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
    }

    /// Run an ioctl whose result is an nvlist in `zc_nvlist_dst`, growing the
    /// destination buffer on ENOMEM as the kernel requests.
    fn ioctl_nv(&self, ioc: u64, zc: &mut ZfsCmd) -> Result<NvList> {
        self.ioctl_nv_in(ioc, zc, None)
    }

    /**
    Like [`Self::ioctl_nv`], but for the "new-style" read ioctls that also take
    an input nvlist (packed into `zc_nvlist_src`) — e.g. VDEV_GET_PROPS and
    GET_BOOKMARKS, which name what to fetch. The packed source is held for the
    duration of the call(s).
    */
    fn ioctl_nv_in(&self, ioc: u64, zc: &mut ZfsCmd, innvl: Option<&NvList>) -> Result<NvList> {
        let src = innvl.map(|nv| nv.pack());
        if let Some(s) = &src {
            zc.zc_nvlist_src = s.as_ptr() as u64;
            zc.zc_nvlist_src_size = s.len() as u64;
        }
        let mut dst: Vec<u8> = vec![0; DST_INITIAL];
        loop {
            zc.zc_nvlist_dst = dst.as_mut_ptr() as u64;
            zc.zc_nvlist_dst_size = dst.len() as u64;
            zc.zc_nvlist_dst_filled = 0;
            match self.ioctl(ioc, zc) {
                Ok(()) => {
                    let len = (zc.zc_nvlist_dst_size as usize).min(dst.len());
                    return Ok(NvList::unpack(&dst[..len])?);
                }
                Err(e) if e.raw_os_error() == Some(libc::ENOMEM) => {
                    // kernel wrote the required size into zc_nvlist_dst_size
                    let need = zc.zc_nvlist_dst_size as usize;
                    dst.resize(need.max(dst.len() * 2), 0);
                }
                Err(err) => {
                    return Err(ZfsError::Ioctl { ioc, name: zc.name(), err });
                }
            }
        }
    }

    /// All imported pools: one nvpair per pool, name → config nvlist
    /// (ZFS_IOC_POOL_CONFIGS).
    pub fn pool_configs(&self) -> Result<NvList> {
        let mut zc = ZfsCmd::new();
        self.ioctl_nv(ZFS_IOC_POOL_CONFIGS, &mut zc)
    }

    /// Detailed config for one pool, including the vdev tree with stats
    /// (ZFS_IOC_POOL_STATS).
    pub fn pool_stats(&self, pool: &str) -> Result<NvList> {
        let mut zc = ZfsCmd::new();
        zc.set_name(pool);
        self.ioctl_nv(ZFS_IOC_POOL_STATS, &mut zc)
    }

    /// Pool properties (ZFS_IOC_POOL_GET_PROPS).
    pub fn pool_props(&self, pool: &str) -> Result<NvList> {
        let mut zc = ZfsCmd::new();
        zc.set_name(pool);
        self.ioctl_nv(ZFS_IOC_POOL_GET_PROPS, &mut zc)
    }

    /**
    A pool's command/event history (ZFS_IOC_POOL_GET_HISTORY), decoded into
    one nvlist per record, oldest first. Reading history requires root (it
    fails with EPERM otherwise). Records carry keys like `history_command`,
    `history_time`, `history_who`; internal events use `history_internal_*`.
    */
    pub fn pool_history(&self, pool: &str) -> Result<Vec<NvList>> {
        let mut records = Vec::new();
        let mut buf = vec![0u8; 256 * 1024];
        /*
        The kernel advances zc_history_offset itself, in its own logical
        (ring-buffer-aware) coordinates — and the first read returns only
        the "pool create" region, with later reads walking the ring where
        the command records live. So we drive it exactly like libzfs: feed
        back the kernel's offset, but backed up over any partial record
        left at the buffer tail so it's re-read whole next round. EOF is a
        zero-length read.
        */
        let mut offset = 0u64;
        loop {
            let mut zc = ZfsCmd::new();
            zc.set_name(pool);
            zc.zc_history = buf.as_mut_ptr() as u64;
            zc.zc_history_len = buf.len() as u64;
            zc.zc_history_offset = offset;
            self.ioctl(ZFS_IOC_POOL_GET_HISTORY, &mut zc).map_err(|err| ZfsError::Ioctl {
                ioc: ZFS_IOC_POOL_GET_HISTORY,
                name: pool.to_string(),
                err,
            })?;
            let bytes_read = (zc.zc_history_len as usize).min(buf.len());
            if bytes_read == 0 {
                break; // EOF
            }
            let consumed = unpack_history(&buf[..bytes_read], &mut records)?;
            if consumed == 0 {
                break; // a record larger than the buffer — avoid spinning
            }
            let leftover = (bytes_read - consumed) as u64;
            offset = zc.zc_history_offset.saturating_sub(leftover);
        }
        Ok(records)
    }

    /**
    Delegated permissions for `dataset` — the `zfs allow` table
    (ZFS_IOC_GET_FSACL). The returned nvlist is keyed by the dataset and each
    ancestor that carries permissions; each maps to an nvlist of encoded
    "who" keys → the granted permission set.
    */
    pub fn get_fsacl(&self, dataset: &str) -> Result<NvList> {
        let mut zc = ZfsCmd::new();
        zc.set_name(dataset);
        self.ioctl_nv(ZFS_IOC_GET_FSACL, &mut zc)
    }

    /**
    ZPL-layer properties of a filesystem (ZFS_IOC_OBJSET_ZPLPROPS): `version`,
    `normalization`, `utf8only`, `casesensitivity`. Unlike the dataset prop
    nvlist, values are stored directly (name → uint64), not wrapped in a
    `{value, source}` sub-nvlist. Only meaningful for ZFS (not zvol) objsets.
    */
    pub fn objset_zplprops(&self, dataset: &str) -> Result<NvList> {
        let mut zc = ZfsCmd::new();
        zc.set_name(dataset);
        self.ioctl_nv(ZFS_IOC_OBJSET_ZPLPROPS, &mut zc)
    }

    /**
    The received (`zfs recv`) property values for a dataset
    (ZFS_IOC_OBJSET_RECVD_PROPS) — the values a property would revert to on
    `zfs inherit -S`, distinct from the locally set/inherited values. Same
    `{value, source}` shape as the live property nvlist; empty if nothing was
    received.
    */
    pub fn objset_recvd_props(&self, dataset: &str) -> Result<NvList> {
        let mut zc = ZfsCmd::new();
        zc.set_name(dataset);
        self.ioctl_nv(ZFS_IOC_OBJSET_RECVD_PROPS, &mut zc)
    }

    /**
    User holds on a snapshot (ZFS_IOC_GET_HOLDS), keyed by hold tag → the
    hold's creation time (unix seconds). A snapshot with holds cannot be
    destroyed until they are released. New-style ioctl with no input nvlist.
    */
    pub fn get_holds(&self, snapshot: &str) -> Result<NvList> {
        let mut zc = ZfsCmd::new();
        zc.set_name(snapshot);
        self.ioctl_nv(ZFS_IOC_GET_HOLDS, &mut zc)
    }

    /**
    Vdev properties (ZFS_IOC_VDEV_GET_PROPS) for the vdev `guid` within `pool`,
    keyed by prop name → `{value, source}`. Vdev props are an OpenZFS 2.2+
    feature; older kernels reject the unknown ioctl with EINVAL.

    The input nvlist names the target vdev by guid (`ZPOOL_VDEV_PROPS_GET_VDEV`)
    and the properties to fetch (`ZPOOL_VDEV_PROPS_GET_PROPS`, an nvlist whose
    *keys* are prop names). Omitting the prop set would return only props
    explicitly stored in the vdev ZAP (none, by default) — the computed
    read-only stats must be requested by name. The curated request set (and the
    reason it omits the kernel-abort-prone props) is [`VdevProp`].
    */
    pub fn vdev_get_props(&self, pool: &str, guid: u64) -> Result<NvList> {
        let mut want = NvList::new();
        for p in VdevProp::request_names() {
            want.add_bool_flag(p);
        }
        let mut innvl = NvList::new();
        innvl.add_u64("vdevprops_get_vdev", guid);
        innvl.add_nvlist("vdevprops_get_props", want);
        let mut zc = ZfsCmd::new();
        zc.set_name(pool);
        self.ioctl_nv_in(ZFS_IOC_VDEV_GET_PROPS, &mut zc, Some(&innvl))
    }

    /**
    Bookmarks of a dataset (ZFS_IOC_GET_BOOKMARKS), keyed by bookmark short
    name (the part after `#`) → an nvlist of the requested props, each a
    `{value: ...}` sub-nvlist. The input nvlist lists which props to return as
    bare booleans; we ask for `guid`, `createtxg`, `creation`.
    */
    pub fn get_bookmarks(&self, dataset: &str) -> Result<NvList> {
        let mut innvl = NvList::new();
        for p in ["guid", "createtxg", "creation"] {
            innvl.add_bool_flag(p);
        }
        let mut zc = ZfsCmd::new();
        zc.set_name(dataset);
        self.ioctl_nv_in(ZFS_IOC_GET_BOOKMARKS, &mut zc, Some(&innvl))
    }

    /**
    Per-user or per-group space accounting (ZFS_IOC_USERSPACE_MANY) for
    `dataset`. `prop_type` is a `zfs_userquota_prop_t` index (0 = userused,
    1 = userquota, 2 = groupused, …; doc/reference/zfs.h). Unlike most read
    ioctls this does *not* return an nvlist: the kernel fills `zc_nvlist_dst`
    with a packed array of `zfs_useracct_t` (`zu_domain[256]`, `zu_rid` u32,
    `zu_spare` u32, `zu_space` u64 = 272 bytes) and advances `zc_cookie` as an
    iteration cursor, so we loop until a read returns no bytes. Reading other
    users' usage needs privilege; non-root gets EPERM (surfaced to the UI).
    */
    pub fn userspace_many(&self, dataset: &str, prop_type: u64) -> Result<Vec<UserAcct>> {
        const REC: usize = 272;
        let mut out = Vec::new();
        let mut buf = vec![0u8; 64 * REC];
        let mut cookie = 0u64;
        loop {
            let mut zc = ZfsCmd::new();
            zc.set_name(dataset);
            zc.zc_objset_type = prop_type;
            zc.zc_cookie = cookie;
            zc.zc_nvlist_dst = buf.as_mut_ptr() as u64;
            zc.zc_nvlist_dst_size = buf.len() as u64;
            self.ioctl(ZFS_IOC_USERSPACE_MANY, &mut zc).map_err(|err| ZfsError::Ioctl {
                ioc: ZFS_IOC_USERSPACE_MANY,
                name: dataset.to_string(),
                err,
            })?;
            let filled = (zc.zc_nvlist_dst_size as usize).min(buf.len());
            for rec in buf[..filled].chunks_exact(REC) {
                out.push(UserAcct {
                    domain: cstr_field(&rec[..MAXNAMELEN]),
                    rid: u32::from_ne_bytes(rec[256..260].try_into().unwrap()),
                    space: u64::from_ne_bytes(rec[264..272].try_into().unwrap()),
                });
            }
            // the kernel signals end-of-iteration by returning no entries (and
            // leaving the cursor unchanged); guard on both
            if filled < REC || zc.zc_cookie == cookie {
                break;
            }
            cookie = zc.zc_cookie;
        }
        Ok(out)
    }

    /* -------------------------------- zevents ---------------------------- */

    /**
    Rewind this handle's zevent cursor to the oldest retained event
    (EVENTS_SEEK → ZEVENT_SEEK_START). The cursor is keyed by `zc_cleanup_fd`
    (here our own fd), so a handle dedicated to event reading then sees the
    whole in-kernel ring from the start. Reading events needs root (EPERM).
    */
    pub fn events_seek_start(&self) -> Result<()> {
        let mut zc = ZfsCmd::new();
        zc.zc_cleanup_fd = self.file.as_raw_fd();
        zc.zc_guid = ZEVENT_SEEK_START;
        self.ioctl(ZFS_IOC_EVENTS_SEEK, &mut zc).map_err(|err| ZfsError::Ioctl {
            ioc: ZFS_IOC_EVENTS_SEEK,
            name: "(zevents)".into(),
            err,
        })
    }

    /**
    Read the next kernel event (EVENTS_NEXT) through this handle's per-fd
    cursor, returning the event nvlist and the kernel's "dropped" count (events
    lost to ring overflow in the gap before this one). `block` waits in-kernel
    until an event is available; otherwise `Ok(None)` once the cursor has caught
    up (ENOENT). Reading events needs root.
    */
    pub fn events_next(&self, block: bool) -> Result<Option<(NvList, u64)>> {
        let mut dst: Vec<u8> = vec![0; DST_INITIAL];
        loop {
            let mut zc = ZfsCmd::new();
            zc.zc_cleanup_fd = self.file.as_raw_fd();
            if !block {
                zc.zc_guid = ZEVENT_NONBLOCK;
            }
            zc.zc_nvlist_dst = dst.as_mut_ptr() as u64;
            zc.zc_nvlist_dst_size = dst.len() as u64;
            match self.ioctl(ZFS_IOC_EVENTS_NEXT, &mut zc) {
                Ok(()) => {
                    let len = (zc.zc_nvlist_dst_size as usize).min(dst.len());
                    return Ok(Some((NvList::unpack(&dst[..len])?, zc.zc_cookie)));
                }
                // cursor caught up (only in non-blocking mode)
                Err(e) if e.raw_os_error() == Some(libc::ENOENT) => return Ok(None),
                // event larger than the buffer: kernel set the needed size; grow
                Err(e) if e.raw_os_error() == Some(libc::ENOMEM) => {
                    let need = zc.zc_nvlist_dst_size as usize;
                    dst.resize(need.max(dst.len() * 2), 0);
                }
                // a signal interrupted the blocking wait — just retry
                Err(e) if e.raw_os_error() == Some(libc::EINTR) => {}
                Err(err) => {
                    return Err(ZfsError::Ioctl {
                        ioc: ZFS_IOC_EVENTS_NEXT,
                        name: "(zevents)".into(),
                        err,
                    });
                }
            }
        }
    }

    /* ------------------------------ error log ---------------------------- */

    /**
    The pool's persistent error log (ZFS_IOC_ERROR_LOG) — the bookmarks of
    blocks with permanent data errors, i.e. the `errors:` list `zpool status
    -v` prints. The kernel fills `zc_nvlist_dst` with an array of
    `zbookmark_phys_t` (32 bytes each), writing them from the *back*: on return
    `zc_nvlist_dst_size` is the count of *unused* trailing slots, so the valid
    entries occupy `[remaining, capacity)`. There is no kernel-provided needed
    size, so we double the buffer and retry on ENOMEM (like libzfs).
    */
    pub fn error_log(&self, pool: &str) -> Result<Vec<Zbookmark>> {
        const ENT: usize = 32; // size_of::<zbookmark_phys_t>()
        let mut cap: u64 = 128;
        loop {
            let mut buf = vec![0u8; cap as usize * ENT];
            let mut zc = ZfsCmd::new();
            zc.set_name(pool);
            zc.zc_nvlist_dst = buf.as_mut_ptr() as u64;
            zc.zc_nvlist_dst_size = cap;
            match self.ioctl(ZFS_IOC_ERROR_LOG, &mut zc) {
                Ok(()) => {
                    // entries occupy [remaining, cap); `remaining` is the unused
                    // leading slots the kernel left after back-filling
                    let remaining = zc.zc_nvlist_dst_size.min(cap) as usize;
                    let rd = |o: usize| u64::from_ne_bytes(buf[o..o + 8].try_into().unwrap());
                    let entries = (remaining..cap as usize)
                        .map(|i| {
                            let b = i * ENT;
                            Zbookmark {
                                objset: rd(b),
                                object: rd(b + 8),
                                level: rd(b + 16) as i64,
                                blkid: rd(b + 24),
                            }
                        })
                        .collect();
                    return Ok(entries);
                }
                Err(e) if e.raw_os_error() == Some(libc::ENOMEM) => cap = cap.saturating_mul(2),
                Err(err) => {
                    return Err(ZfsError::Ioctl { ioc: ZFS_IOC_ERROR_LOG, name: pool.to_string(), err });
                }
            }
        }
    }

    /// Resolve a dataset object id to its dataset name within `pool`
    /// (ZFS_IOC_DSOBJ_TO_DSNAME). Used to name error-log bookmarks.
    pub fn dsobj_to_dsname(&self, pool: &str, dsobj: u64) -> Result<String> {
        let mut zc = ZfsCmd::new();
        zc.set_name(pool);
        zc.zc_obj = dsobj;
        self.ioctl(ZFS_IOC_DSOBJ_TO_DSNAME, &mut zc).map_err(|err| ZfsError::Ioctl {
            ioc: ZFS_IOC_DSOBJ_TO_DSNAME,
            name: pool.to_string(),
            err,
        })?;
        Ok(cstr_field(&zc.zc_value))
    }

    /**
    Resolve an object number to its file path within `dataset`
    (ZFS_IOC_OBJ_TO_PATH). Only ZFS (ZPL) objsets — EINVAL for a zvol or the MOS.
    */
    pub fn obj_to_path(&self, dataset: &str, obj: u64) -> Result<String> {
        let mut zc = ZfsCmd::new();
        zc.set_name(dataset);
        zc.zc_obj = obj;
        self.ioctl(ZFS_IOC_OBJ_TO_PATH, &mut zc).map_err(|err| ZfsError::Ioctl {
            ioc: ZFS_IOC_OBJ_TO_PATH,
            name: dataset.to_string(),
            err,
        })?;
        Ok(cstr_field(&zc.zc_value))
    }

    /// Resolve an object to its path *and* stat (ZFS_IOC_OBJ_TO_STATS); same
    /// ZPL-only restriction as [`Self::obj_to_path`].
    pub fn obj_to_stats(&self, dataset: &str, obj: u64) -> Result<(String, ZStat)> {
        let mut zc = ZfsCmd::new();
        zc.set_name(dataset);
        zc.zc_obj = obj;
        self.ioctl(ZFS_IOC_OBJ_TO_STATS, &mut zc).map_err(|err| ZfsError::Ioctl {
            ioc: ZFS_IOC_OBJ_TO_STATS,
            name: dataset.to_string(),
            err,
        })?;
        Ok((cstr_field(&zc.zc_value), (&zc.zc_stat).into()))
    }

    /// Stats and properties for one dataset (ZFS_IOC_OBJSET_STATS).
    pub fn objset_stats(&self, dataset: &str) -> Result<(ObjsetStats, NvList)> {
        let mut zc = ZfsCmd::new();
        zc.set_name(dataset);
        let props = self.ioctl_nv(ZFS_IOC_OBJSET_STATS, &mut zc)?;
        Ok(((&zc.zc_objset_stats).into(), props))
    }

    /// Direct child datasets of `parent` (ZFS_IOC_DATASET_LIST_NEXT).
    pub fn datasets(&self, parent: &str) -> Result<Vec<DatasetEntry>> {
        self.list_next(ZFS_IOC_DATASET_LIST_NEXT, parent)
    }

    /// Snapshots of `dataset` (ZFS_IOC_SNAPSHOT_LIST_NEXT).
    pub fn snapshots(&self, dataset: &str) -> Result<Vec<DatasetEntry>> {
        self.list_next(ZFS_IOC_SNAPSHOT_LIST_NEXT, dataset)
    }

    fn list_next(&self, ioc: u64, parent: &str) -> Result<Vec<DatasetEntry>> {
        let mut out = Vec::new();
        let mut cookie = 0u64;
        loop {
            let mut zc = ZfsCmd::new();
            zc.set_name(parent);
            zc.zc_cookie = cookie;
            match self.ioctl_nv(ioc, &mut zc) {
                Ok(props) => {
                    cookie = zc.zc_cookie;
                    out.push(DatasetEntry {
                        name: zc.name(),
                        stats: (&zc.zc_objset_stats).into(),
                        props,
                    });
                }
                // ESRCH: end of iteration. ENOENT: parent went away mid-walk.
                Err(ZfsError::Ioctl { err, .. })
                    if matches!(err.raw_os_error(), Some(libc::ESRCH) | Some(libc::ENOENT)) =>
                {
                    return Ok(out);
                }
                Err(e) => return Err(e),
            }
        }
    }

    /* -------------------------------- writes ----------------------------- */

    /**
    Issue a mutating ioctl. `innvl`, if present, is packed into
    `zc_nvlist_src`; the kernel's output/errors nvlist is read back from
    `zc_nvlist_dst` (empty if it filled none). `op` names the operation for
    error messages. Errors are returned as [`ZfsError::Op`] with an errno
    hint already appended.
    */
    fn write_ioctl(
        &self,
        ioc: u64,
        op: &str,
        zc: &mut ZfsCmd,
        innvl: Option<&NvList>,
    ) -> Result<NvList> {
        // The packed source must outlive the ioctl call(s); hold it here.
        let src = innvl.map(|nv| nv.pack());
        if let Some(s) = &src {
            zc.zc_nvlist_src = s.as_ptr() as u64;
            zc.zc_nvlist_src_size = s.len() as u64;
        }
        let mut dst: Vec<u8> = vec![0; DST_INITIAL];
        loop {
            zc.zc_nvlist_dst = dst.as_mut_ptr() as u64;
            zc.zc_nvlist_dst_size = dst.len() as u64;
            zc.zc_nvlist_dst_filled = 0;
            match self.ioctl(ioc, zc) {
                Ok(()) => {
                    // Only some ioctls return an nvlist; honor the filled flag.
                    let len = zc.zc_nvlist_dst_size as usize;
                    if zc.zc_nvlist_dst_filled != 0 && len <= dst.len() {
                        return Ok(NvList::unpack(&dst[..len])?);
                    }
                    return Ok(NvList::default());
                }
                Err(e) if e.raw_os_error() == Some(libc::ENOMEM) => {
                    let need = zc.zc_nvlist_dst_size as usize;
                    dst.resize(need.max(dst.len() * 2), 0);
                }
                Err(err) => {
                    return Err(ZfsError::Op(format!("{op}: {err}{}", errno_hint(&err))));
                }
            }
        }
    }

    /**
    Set one or more properties on a dataset (ZFS_IOC_SET_PROP). `props` maps
    prop name → value (use an `NvList` built with `add_str`/`add_u64`).
    Returns the kernel's errors nvlist, keyed by any prop that failed (empty
    on full success).
    */
    pub fn set_prop(&self, dataset: &str, props: &NvList) -> Result<NvList> {
        let mut zc = ZfsCmd::new();
        zc.set_name(dataset);
        self.write_ioctl(ZFS_IOC_SET_PROP, "set property", &mut zc, Some(props))
    }

    /// Set pool properties (ZFS_IOC_POOL_SET_PROPS).
    pub fn pool_set_props(&self, pool: &str, props: &NvList) -> Result<NvList> {
        let mut zc = ZfsCmd::new();
        zc.set_name(pool);
        self.write_ioctl(ZFS_IOC_POOL_SET_PROPS, "set pool property", &mut zc, Some(props))
    }

    /// Reset a property to its inherited value (ZFS_IOC_INHERIT_PROP).
    /// `received` reverts to the received value rather than clearing it.
    pub fn inherit_prop(&self, dataset: &str, prop: &str, received: bool) -> Result<()> {
        let mut zc = ZfsCmd::new();
        zc.set_name(dataset);
        zc.set_value(prop);
        zc.zc_cookie = received as u64;
        self.write_ioctl(ZFS_IOC_INHERIT_PROP, "inherit property", &mut zc, None)?;
        Ok(())
    }

    /**
    Create snapshots (ZFS_IOC_SNAPSHOT). Every name in `snaps` must be a full
    `dataset@snap` within `pool` and share the same snap suffix. `props` are
    applied to the new snapshots. Returns the per-snapshot errors nvlist
    (empty on success).
    */
    pub fn snapshot(&self, pool: &str, snaps: &[String], props: Option<&NvList>) -> Result<NvList> {
        let mut snap_set = NvList::new();
        for s in snaps {
            snap_set.add_bool_flag(s.clone());
        }
        let mut innvl = NvList::new();
        innvl.add_nvlist("snaps", snap_set);
        if let Some(p) = props {
            innvl.add_nvlist("props", p.clone());
        }
        let mut zc = ZfsCmd::new();
        zc.set_name(pool);
        self.write_ioctl(ZFS_IOC_SNAPSHOT, "create snapshot", &mut zc, Some(&innvl))
    }

    /**
    Destroy snapshots (ZFS_IOC_DESTROY_SNAPS); all names must be in `pool`.
    `defer` marks them for deferred destruction if held or cloned. Returns
    the per-snapshot errors nvlist (empty on success).
    */
    pub fn destroy_snaps(&self, pool: &str, snaps: &[String], defer: bool) -> Result<NvList> {
        let mut snap_set = NvList::new();
        for s in snaps {
            snap_set.add_bool_flag(s.clone());
        }
        let mut innvl = NvList::new();
        innvl.add_nvlist("snaps", snap_set);
        if defer {
            innvl.add_bool_flag("defer");
        }
        let mut zc = ZfsCmd::new();
        zc.set_name(pool);
        self.write_ioctl(ZFS_IOC_DESTROY_SNAPS, "destroy snapshots", &mut zc, Some(&innvl))
    }

    /**
    Create a filesystem or volume (ZFS_IOC_CREATE). `objset_type` is a
    `dmu_objset_type_t` (2 = ZFS filesystem, 3 = zvol; see
    [`crate::zfs::enums::ObjsetType`]). `props` are the creation-time
    properties (a zvol needs at least `volsize`).
    */
    pub fn create(&self, name: &str, objset_type: u64, props: Option<&NvList>) -> Result<()> {
        let mut innvl = NvList::new();
        innvl.add_u64("type", objset_type);
        if let Some(p) = props {
            innvl.add_nvlist("props", p.clone());
        }
        let mut zc = ZfsCmd::new();
        zc.set_name(name);
        self.write_ioctl(ZFS_IOC_CREATE, "create dataset", &mut zc, Some(&innvl))?;
        Ok(())
    }

    /**
    Destroy a dataset or snapshot (ZFS_IOC_DESTROY). `defer` defers the
    destroy if the target is busy. This is not recursive — destroy children
    first (or use `destroy_snaps` for snapshots in bulk).
    */
    pub fn destroy(&self, name: &str, defer: bool) -> Result<()> {
        let mut zc = ZfsCmd::new();
        zc.set_name(name);
        zc.zc_defer_destroy = defer as u32;
        self.write_ioctl(ZFS_IOC_DESTROY, "destroy dataset", &mut zc, None)?;
        Ok(())
    }

    /// Rename a dataset (ZFS_IOC_RENAME). `recursive` also renames the
    /// snapshots of descendants (only meaningful when renaming a snapshot).
    pub fn rename(&self, from: &str, to: &str, recursive: bool) -> Result<()> {
        let mut zc = ZfsCmd::new();
        zc.set_name(from);
        zc.set_value(to);
        zc.zc_cookie = recursive as u64;
        self.write_ioctl(ZFS_IOC_RENAME, "rename dataset", &mut zc, None)?;
        Ok(())
    }

    /**
    Grant (`unset` = false) or revoke (`unset` = true) `perms` for `who` on
    `dataset` (ZFS_IOC_SET_FSACL) — like a bare `zfs allow` / `zfs unallow`,
    i.e. local + descendent. The fsacl nvlist is keyed by the per-inheritance
    "who" key, each mapping to an nvlist of permission-name → boolean flag.
    Permission names are validated by the kernel (a bad one is a clean EINVAL).
    */
    pub fn set_fsacl(
        &self,
        dataset: &str,
        who: &DelegWho,
        perms: &[String],
        unset: bool,
    ) -> Result<()> {
        let mut fsacl = NvList::new();
        for inherit in ['l', 'd'] {
            let mut permnv = NvList::new();
            for p in perms {
                permnv.add_bool_flag(p.clone());
            }
            fsacl.add_nvlist(deleg_whokey(who, inherit), permnv);
        }
        let mut zc = ZfsCmd::new();
        zc.set_name(dataset);
        zc.zc_perm_action = unset as u64; // 0 = allow, 1 = unallow
        let op = if unset { "unallow" } else { "allow" };
        self.write_ioctl(ZFS_IOC_SET_FSACL, op, &mut zc, Some(&fsacl))?;
        Ok(())
    }

    /**
    Log a command string to a pool's history (ZFS_IOC_LOG_HISTORY), so a
    mutation made through this tool shows up in `zpool history` like the
    `zfs`/`zpool` CLIs' own entries. The kernel takes the target pool from
    thread-local state left by the *immediately preceding* loggable ioctl —
    so this must be the very next ioctl after the mutation, on the same
    thread, before any other (`zc_name` is intentionally left empty). Callers
    treat it as best-effort.
    */
    pub fn log_history(&self, message: &str) -> Result<()> {
        let mut innvl = NvList::new();
        innvl.add_str("message", message);
        let mut zc = ZfsCmd::new();
        self.write_ioctl(ZFS_IOC_LOG_HISTORY, "log history", &mut zc, Some(&innvl))?;
        Ok(())
    }

    /**
    Place a permanent user hold `tag` on `snapshot` (ZFS_IOC_HOLD); a held
    snapshot can't be destroyed until released. `pool` is the snapshot's pool.
    The input nvlist is `{holds: {snapshot: tag}}` (no `cleanup_fd`, so the hold
    is permanent rather than tied to a process). Returns the per-element errors
    nvlist (empty on success).
    */
    pub fn hold(&self, pool: &str, snapshot: &str, tag: &str) -> Result<NvList> {
        let mut holds = NvList::new();
        holds.add_str(snapshot, tag);
        let mut args = NvList::new();
        args.add_nvlist("holds", holds);
        let mut zc = ZfsCmd::new();
        zc.set_name(pool);
        self.write_ioctl(ZFS_IOC_HOLD, "hold", &mut zc, Some(&args))
    }

    /**
    Release the user hold `tag` from `snapshot` (ZFS_IOC_RELEASE). The input
    nvlist is keyed by snapshot → a set (boolean flags) of tags to release —
    here just `{snapshot: {tag}}`. Returns the per-element errors nvlist.
    */
    pub fn release(&self, pool: &str, snapshot: &str, tag: &str) -> Result<NvList> {
        let mut tags = NvList::new();
        tags.add_bool_flag(tag);
        let mut holds = NvList::new();
        holds.add_nvlist(snapshot, tags);
        let mut zc = ZfsCmd::new();
        zc.set_name(pool);
        self.write_ioctl(ZFS_IOC_RELEASE, "release", &mut zc, Some(&holds))
    }

    /* ---------------------------- pool maintenance ----------------------- */

    /**
    Control a pool scan (ZFS_IOC_POOL_SCAN). `func` is a `pool_scan_func_t`
    (0 = stop the running scan, 1 = scrub, 2 = resilver); `pause` issues a
    pause of the current scan instead (resume = call again with `func` = scrub,
    `pause` = false). zc_cookie carries the func, zc_flags the
    `POOL_SCRUB_PAUSE` bit.
    */
    pub fn pool_scan(&self, pool: &str, func: u64, pause: bool) -> Result<()> {
        let mut zc = ZfsCmd::new();
        zc.set_name(pool);
        zc.zc_cookie = func;
        zc.zc_flags = u32::from(pause); // POOL_SCRUB_PAUSE = 1, else NORMAL
        self.write_ioctl(ZFS_IOC_POOL_SCAN, "scrub", &mut zc, None)?;
        Ok(())
    }

    /**
    Clear device error counts and the persistent error log (ZFS_IOC_CLEAR),
    pool-wide when `guid` is 0 or for one vdev otherwise. zc_cookie =
    `ZPOOL_NO_REWIND` selects the plain (no rewind-policy nvlist) path, which is
    what clearing an online pool wants.
    */
    pub fn clear_errors(&self, pool: &str, guid: u64) -> Result<()> {
        let mut zc = ZfsCmd::new();
        zc.set_name(pool);
        zc.zc_guid = guid;
        zc.zc_cookie = 1; // ZPOOL_NO_REWIND
        self.write_ioctl(ZFS_IOC_CLEAR, "clear errors", &mut zc, None)?;
        Ok(())
    }

    /**
    Build the `{key: guid}` vdev nvlist the trim/initialize ioctls expect
    (the kernel reads each pair's uint64 *value* as a vdev guid; the key is
    arbitrary, so the guid itself doubles as a unique key).
    */
    fn vdev_guid_nvlist(guids: &[u64]) -> NvList {
        let mut nv = NvList::new();
        for g in guids {
            nv.add_u64(g.to_string(), *g);
        }
        nv
    }

    /**
    Start (`cmd` = 0), cancel (1) or suspend (2) TRIM on the given vdev guids
    (ZFS_IOC_POOL_TRIM) — typically a pool's top-level vdevs. The kernel returns
    EINVAL if any vdev can't be trimmed (e.g. a file vdev), which surfaces as the
    operation error.
    */
    pub fn pool_trim(&self, pool: &str, guids: &[u64], cmd: u64) -> Result<()> {
        let mut innvl = NvList::new();
        innvl.add_u64("trim_command", cmd);
        innvl.add_nvlist("trim_vdevs", Self::vdev_guid_nvlist(guids));
        let mut zc = ZfsCmd::new();
        zc.set_name(pool);
        self.write_ioctl(ZFS_IOC_POOL_TRIM, "trim", &mut zc, Some(&innvl))?;
        Ok(())
    }

    /**
    Start (`cmd` = 0), cancel (1), suspend (2) or uninit (3) INITIALIZE on the
    given vdev guids (ZFS_IOC_POOL_INITIALIZE) — writing a pattern to all
    unallocated space.
    */
    pub fn pool_initialize(&self, pool: &str, guids: &[u64], cmd: u64) -> Result<()> {
        let mut innvl = NvList::new();
        innvl.add_u64("initialize_command", cmd);
        innvl.add_nvlist("initialize_vdevs", Self::vdev_guid_nvlist(guids));
        let mut zc = ZfsCmd::new();
        zc.set_name(pool);
        self.write_ioctl(ZFS_IOC_POOL_INITIALIZE, "initialize", &mut zc, Some(&innvl))?;
        Ok(())
    }
}

/* ========================================================================= */

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whokey_format_matches_kernel() {
        // mirrors zfs_deleg_whokey: <type><inherit>$<id>, everyone has no id
        assert_eq!(deleg_whokey(&DelegWho::User(1000), 'l'), "ul$1000");
        assert_eq!(deleg_whokey(&DelegWho::User(1000), 'd'), "ud$1000");
        assert_eq!(deleg_whokey(&DelegWho::Group(50), 'l'), "gl$50");
        assert_eq!(deleg_whokey(&DelegWho::Everyone, 'l'), "el$");
        assert_eq!(deleg_whokey(&DelegWho::Everyone, 'd'), "ed$");
    }

    #[test]
    fn resolve_who_parses_specs() {
        assert_eq!(resolve_who("everyone").unwrap(), DelegWho::Everyone);
        assert_eq!(resolve_who("EVERYONE").unwrap(), DelegWho::Everyone);
        assert_eq!(resolve_who("1000").unwrap(), DelegWho::User(1000));
        assert_eq!(resolve_who("user:1000").unwrap(), DelegWho::User(1000));
        assert_eq!(resolve_who("group:50").unwrap(), DelegWho::Group(50));
        assert_eq!(resolve_who("g:50").unwrap(), DelegWho::Group(50));
        // root is uid/gid 0 on Linux
        assert_eq!(resolve_who("root").unwrap(), DelegWho::User(0));
        assert_eq!(resolve_who("group:root").unwrap(), DelegWho::Group(0));
        assert!(resolve_who("no_such_user_zzz_qx").is_err());
        assert!(resolve_who("bogus:thing").is_err());
    }

    #[test]
    fn history_records_unpack_with_trailing_partial() {
        // frame = [u64 LE len][native-packed nvlist]
        fn frame(buf: &mut Vec<u8>, nv: &NvList) {
            let packed = nv.pack();
            buf.extend_from_slice(&(packed.len() as u64).to_le_bytes());
            buf.extend_from_slice(&packed);
        }
        // ZPOOL_HIST_* keys are spelled with spaces (doc/reference/zfs.h)
        let mut a = NvList::new();
        a.add_str("history command", "zfs snapshot tank@x").add_u64("history time", 1000);
        let mut b = NvList::new();
        b.add_str("history command", "zfs destroy tank@x");

        let mut buf = Vec::new();
        frame(&mut buf, &a);
        frame(&mut buf, &b);
        let whole = buf.len();
        // a truncated record at the end must be left for the next read
        buf.extend_from_slice(&4096u64.to_le_bytes());
        buf.extend_from_slice(&[0u8; 16]);

        let mut out = Vec::new();
        let consumed = unpack_history(&buf, &mut out).unwrap();
        assert_eq!(consumed, whole);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].get_str("history command"), Some("zfs snapshot tank@x"));
        assert_eq!(out[0].get_u64("history time"), Some(1000));
        assert_eq!(out[1].get_str("history command"), Some("zfs destroy tank@x"));
    }
}
