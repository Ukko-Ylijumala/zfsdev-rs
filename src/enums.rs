// Copyright (c) 2026 Mikko Tanner. All rights reserved.
// Licensed under the MIT License or the Apache License, Version 2.0.
// SPDX-License-Identifier: MIT OR Apache-2.0

/*!
Typed mirrors of the on-disk/ioctl C enums (`doc/reference/zfs.h`, `zio.h`,
`zio_compress.h`, `dmu.h`). `FromRepr` converts the raw numeric values,
`Display` renders the conventional lowercase names; unknown values surface
through the `from_*` helpers as a formatted fallback rather than panicking,
since on-disk data can always be newer (or junk).
*/

use strum::{Display, EnumString, FromRepr};

/// Render an enum value or a `?N` fallback for out-of-range raw values.
macro_rules! name_or_unknown {
    ($ty:ty, $v:expr) => {
        match u8::try_from($v).ok().and_then(<$ty>::from_repr) {
            Some(x) => x.to_string(),
            None => format!("?{}", $v),
        }
    };
}

/// zio_compress (zio_compress.h)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Display, FromRepr)]
#[strum(serialize_all = "lowercase")]
#[repr(u8)]
pub enum ZioCompress {
    Inherit = 0,
    On,
    Off,
    Lzjb,
    Empty,
    #[strum(serialize = "gzip-1")]
    Gzip1,
    #[strum(serialize = "gzip-2")]
    Gzip2,
    #[strum(serialize = "gzip-3")]
    Gzip3,
    #[strum(serialize = "gzip-4")]
    Gzip4,
    #[strum(serialize = "gzip-5")]
    Gzip5,
    #[strum(serialize = "gzip-6")]
    Gzip6,
    #[strum(serialize = "gzip-7")]
    Gzip7,
    #[strum(serialize = "gzip-8")]
    Gzip8,
    #[strum(serialize = "gzip-9")]
    Gzip9,
    Zle,
    Lz4,
    Zstd,
}

impl ZioCompress {
    pub fn name(v: u8) -> String {
        name_or_unknown!(ZioCompress, v)
    }
}

/// zio_checksum (zio.h)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Display, FromRepr)]
#[strum(serialize_all = "lowercase")]
#[repr(u8)]
pub enum ZioChecksum {
    Inherit = 0,
    On,
    Off,
    Label,
    #[strum(serialize = "gang_header")]
    GangHeader,
    Zilog,
    Fletcher2,
    Fletcher4,
    Sha256,
    Zilog2,
    Noparity,
    Sha512,
    Skein,
    Edonr,
    Blake3,
}

impl ZioChecksum {
    pub fn name(v: u8) -> String {
        name_or_unknown!(ZioChecksum, v)
    }
}

/// pool_state_t (zfs.h)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Display, FromRepr)]
#[strum(serialize_all = "UPPERCASE")]
#[repr(u8)]
pub enum PoolState {
    Active = 0,
    Exported,
    Destroyed,
    Spare,
    L2Cache,
    Uninitialized,
    Unavail,
    #[strum(serialize = "POTENTIALLY_ACTIVE")]
    PotentiallyActive,
}

impl PoolState {
    pub fn name(v: u64) -> String {
        name_or_unknown!(PoolState, v)
    }
}

/// vdev_state_t (zfs.h)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Display, FromRepr)]
#[strum(serialize_all = "UPPERCASE")]
#[repr(u8)]
pub enum VdevState {
    Unknown = 0,
    Closed,
    Offline,
    Removed,
    #[strum(serialize = "CANT_OPEN")]
    CantOpen,
    Faulted,
    Degraded,
    Healthy,
}

impl VdevState {
    pub fn name(v: u64) -> String {
        name_or_unknown!(VdevState, v)
    }
}

/// dmu_objset_type_t (dmu.h), shared by the live ioctl stats and the
/// on-disk objset_phys decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Display, FromRepr)]
#[repr(u8)]
pub enum ObjsetType {
    #[strum(serialize = "none")]
    None = 0,
    #[strum(serialize = "meta (MOS)")]
    Meta,
    #[strum(serialize = "filesystem")]
    Zfs,
    #[strum(serialize = "volume")]
    Zvol,
    #[strum(serialize = "other")]
    Other,
}

impl ObjsetType {
    pub fn from_u64(v: u64) -> Option<ObjsetType> {
        u8::try_from(v).ok().and_then(ObjsetType::from_repr)
    }

    pub fn name(v: u64) -> String {
        name_or_unknown!(ObjsetType, v)
    }
}

/// d_type values packed into directory entries (bits 60–63).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Display, FromRepr)]
#[strum(serialize_all = "lowercase")]
#[repr(u8)]
pub enum DirentType {
    Fifo = 1,
    Chardev = 2,
    Dir = 4,
    Blockdev = 6,
    File = 8,
    Symlink = 10,
    Socket = 12,
}

impl DirentType {
    pub fn name(v: u8) -> String {
        name_or_unknown!(DirentType, v)
    }
}

/// dmu_object_type_t (dmu.h). Values with the 0x80 bit set are the
/// self-describing DMU_OTN_* scheme; use [`DmuObjectType::name`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Display, FromRepr, EnumString)]
#[repr(u8)]
pub enum DmuObjectType {
    #[strum(serialize = "none")]
    None = 0,
    #[strum(serialize = "object directory")]
    ObjectDirectory,
    #[strum(serialize = "object array")]
    ObjectArray,
    #[strum(serialize = "packed nvlist")]
    PackedNvlist,
    #[strum(serialize = "packed nvlist size")]
    PackedNvlistSize,
    #[strum(serialize = "bpobj")]
    Bpobj,
    #[strum(serialize = "bpobj header")]
    BpobjHeader,
    #[strum(serialize = "spacemap header")]
    SpaceMapHeader,
    #[strum(serialize = "spacemap")]
    SpaceMap,
    #[strum(serialize = "intent log")]
    IntentLog,
    #[strum(serialize = "dnode")]
    Dnode,
    #[strum(serialize = "objset")]
    Objset,
    #[strum(serialize = "DSL directory")]
    DslDir,
    #[strum(serialize = "DSL directory child map")]
    DslDirChildMap,
    #[strum(serialize = "DSL dataset snap map")]
    DslDsSnapMap,
    #[strum(serialize = "DSL props")]
    DslProps,
    #[strum(serialize = "DSL dataset")]
    DslDataset,
    #[strum(serialize = "znode")]
    Znode,
    #[strum(serialize = "old acl")]
    OldAcl,
    #[strum(serialize = "plain file contents")]
    PlainFileContents,
    #[strum(serialize = "directory contents")]
    DirectoryContents,
    #[strum(serialize = "master node")]
    MasterNode,
    #[strum(serialize = "unlinked set")]
    UnlinkedSet,
    #[strum(serialize = "zvol")]
    Zvol,
    #[strum(serialize = "zvol prop")]
    ZvolProp,
    #[strum(serialize = "plain other")]
    PlainOther,
    #[strum(serialize = "uint64 other")]
    Uint64Other,
    #[strum(serialize = "zap other")]
    ZapOther,
    #[strum(serialize = "error log")]
    ErrorLog,
    #[strum(serialize = "spa history")]
    SpaHistory,
    #[strum(serialize = "spa history offsets")]
    SpaHistoryOffsets,
    #[strum(serialize = "pool props")]
    PoolProps,
    #[strum(serialize = "DSL perms")]
    DslPerms,
    #[strum(serialize = "acl")]
    Acl,
    #[strum(serialize = "sysacl")]
    Sysacl,
    #[strum(serialize = "fuid")]
    Fuid,
    #[strum(serialize = "fuid size")]
    FuidSize,
    #[strum(serialize = "next clones")]
    NextClones,
    #[strum(serialize = "scan queue")]
    ScanQueue,
    #[strum(serialize = "usergroup used")]
    UsergroupUsed,
    #[strum(serialize = "usergroup quota")]
    UsergroupQuota,
    #[strum(serialize = "userrefs")]
    Userrefs,
    #[strum(serialize = "ddt zap")]
    DdtZap,
    #[strum(serialize = "ddt stats")]
    DdtStats,
    #[strum(serialize = "system attributes")]
    Sa,
    #[strum(serialize = "sa master node")]
    SaMasterNode,
    #[strum(serialize = "sa attr registration")]
    SaAttrRegistration,
    #[strum(serialize = "sa attr layouts")]
    SaAttrLayouts,
    #[strum(serialize = "scan xlate")]
    ScanXlate,
    #[strum(serialize = "dedup")]
    Dedup,
    #[strum(serialize = "deadlist")]
    Deadlist,
    #[strum(serialize = "deadlist header")]
    DeadlistHeader,
    #[strum(serialize = "DSL clones")]
    DslClones,
    #[strum(serialize = "bpobj subobjs")]
    BpobjSubobjs,
}

impl DmuObjectType {
    pub fn name(v: u8) -> String {
        if v & 0x80 != 0 {
            return "OTN (self-describing)".into();
        }
        name_or_unknown!(DmuObjectType, v)
    }
}

/* ========================================================================= */

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_match_legacy_tables() {
        assert_eq!(ZioCompress::name(15), "lz4");
        assert_eq!(ZioCompress::name(16), "zstd");
        assert_eq!(ZioCompress::name(5), "gzip-1");
        assert_eq!(ZioCompress::name(99), "?99");
        assert_eq!(ZioChecksum::name(7), "fletcher4");
        assert_eq!(ZioChecksum::name(14), "blake3");
        assert_eq!(ZioChecksum::name(4), "gang_header");
        assert_eq!(PoolState::name(1), "EXPORTED");
        assert_eq!(PoolState::name(7), "POTENTIALLY_ACTIVE");
        assert_eq!(VdevState::name(7), "HEALTHY");
        assert_eq!(ObjsetType::name(1), "meta (MOS)");
        assert_eq!(ObjsetType::name(2), "filesystem");
        assert_eq!(DirentType::name(8), "file");
        assert_eq!(DmuObjectType::name(11), "objset");
        assert_eq!(DmuObjectType::name(16), "DSL dataset");
        assert_eq!(DmuObjectType::name(0x80), "OTN (self-describing)");
    }

    #[test]
    fn from_repr_roundtrip() {
        assert_eq!(ZioCompress::from_repr(15), Some(ZioCompress::Lz4));
        assert_eq!(ZioChecksum::from_repr(11), Some(ZioChecksum::Sha512));
        assert_eq!(DmuObjectType::from_repr(12), Some(DmuObjectType::DslDir));
        assert_eq!(DirentType::from_repr(4), Some(DirentType::Dir));
    }
}
