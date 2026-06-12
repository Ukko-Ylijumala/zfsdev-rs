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

Everything here is read-only for the moment: only GET/LIST ioctls are
implemented and no mutating request numbers are defined yet.
*/

use super::nvlist::{NvError, NvList};
use std::ffi::CStr;
use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use thiserror::Error;

const ZFS_DEV: &str = "/dev/zfs";

const ZFS_IOC_POOL_CONFIGS: u64 = 0x5a04;
const ZFS_IOC_POOL_STATS: u64 = 0x5a05;
const ZFS_IOC_OBJSET_STATS: u64 = 0x5a12;
const ZFS_IOC_DATASET_LIST_NEXT: u64 = 0x5a14;
const ZFS_IOC_SNAPSHOT_LIST_NEXT: u64 = 0x5a15;
const ZFS_IOC_POOL_GET_PROPS: u64 = 0x5a27;

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
}

type Result<T> = std::result::Result<T, ZfsError>;

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
    pub objset_type: ObjsetType,
    pub is_snapshot: bool,
    pub inconsistent: bool,
    pub redacted: bool,
    pub origin: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjsetType {
    None,
    Meta,
    Zfs,
    Zvol,
    Other(u32),
}

impl ObjsetType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ObjsetType::None => "none",
            ObjsetType::Meta => "meta",
            ObjsetType::Zfs => "filesystem",
            ObjsetType::Zvol => "volume",
            ObjsetType::Other(_) => "other",
        }
    }
}

impl From<&DmuObjsetStatsRaw> for ObjsetStats {
    fn from(raw: &DmuObjsetStatsRaw) -> Self {
        ObjsetStats {
            num_clones: raw.dds_num_clones,
            creation_txg: raw.dds_creation_txg,
            guid: raw.dds_guid,
            objset_type: match raw.dds_type {
                0 => ObjsetType::None,
                1 => ObjsetType::Meta,
                2 => ObjsetType::Zfs,
                3 => ObjsetType::Zvol,
                other => ObjsetType::Other(other),
            },
            is_snapshot: raw.dds_is_snapshot != 0,
            inconsistent: raw.dds_inconsistent != 0,
            redacted: raw.dds_redacted != 0,
            origin: cstr_field(&raw.dds_origin),
        }
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
        let rc = unsafe {
            libc::ioctl(self.file.as_raw_fd(), ioc as libc::c_ulong, zc as *mut ZfsCmd)
        };
        if rc != 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
    }

    /// Run an ioctl whose result is an nvlist in `zc_nvlist_dst`, growing the
    /// destination buffer on ENOMEM as the kernel requests.
    fn ioctl_nv(&self, ioc: u64, zc: &mut ZfsCmd) -> Result<NvList> {
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
}
