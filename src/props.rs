// Copyright (c) 2026 Mikko Tanner. All rights reserved.
// Licensed under the MIT License or the Apache License, Version 2.0.
// SPDX-License-Identifier: MIT OR Apache-2.0

/*!
Human-friendly rendering of numeric ZFS property values. Property names
parse into [`ZfsProp`] (strum `EnumString`, lowercase) and the small value
enums mirror the `ZFS_*` value constants from `doc/reference/zfs.h` — so
both the dispatch and the value names are typo-proof enums rather than
string tables. Used by the live ioctl property views and the on-disk DSL
props ZAPs alike; the names are the same in both worlds.
*/

use crate::util::{fmt_unix_time, human_bytes};
use crate::zfs::enums::{ZioChecksum, ZioCompress, ZstdLevel};
use crate::zfs::nvlist::NvData;
use std::str::FromStr;
use strum::{Display, EnumIter, EnumString, FromRepr, IntoEnumIterator};

/// Every property name we know how to render. Lowercase matching; names
/// with underscores are spelled out explicitly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumString)]
#[strum(serialize_all = "lowercase")]
enum ZfsProp {
    // zio enums
    Compression,
    Checksum,
    Dedup,
    // byte quantities
    Quota,
    Reservation,
    Refquota,
    Refreservation,
    Used,
    Available,
    Referenced,
    UsedBySnapshots,
    UsedByDataset,
    UsedByChildren,
    UsedByRefReservation,
    Recordsize,
    Volsize,
    Volblocksize,
    Written,
    LogicalUsed,
    LogicalReferenced,
    #[strum(serialize = "special_small_blocks")]
    SpecialSmallBlocks,
    #[strum(serialize = "filesystem_limit")]
    FilesystemLimit,
    #[strum(serialize = "snapshot_limit")]
    SnapshotLimit,
    Size,
    Free,
    Allocated,
    Freeing,
    Leaked,
    Checkpoint,
    BcloneUsed,
    BcloneSaved,
    // times, ratios, percentages
    Creation,
    CompressRatio,
    RefCompressRatio,
    BcloneRatio,
    Fragmentation,
    // booleans
    Atime,
    Relatime,
    Devices,
    Exec,
    Setuid,
    Readonly,
    Zoned,
    Jailed,
    Vscan,
    Nbmand,
    Utf8Only,
    Overlay,
    #[strum(serialize = "defer_destroy")]
    DeferDestroy,
    AutoExpand,
    AutoReplace,
    Delegation,
    ListSnapshots,
    AutoTrim,
    MultiHost,
    Mounted,
    // small value enums
    Canmount,
    AclMode,
    AclInherit,
    AclType,
    Xattr,
    Sync,
    LogBias,
    PrimaryCache,
    SecondaryCache,
    #[strum(serialize = "redundant_metadata")]
    RedundantMetadata,
    SnapDir,
    SnapDev,
    CaseSensitivity,
    Normalization,
    VolMode,
    DnodeSize,
    FailMode,
    KeyFormat,
    KeyStatus,
    Encryption,
}

/* ----------------------------- vdev properties --------------------------- */

/**
The vdev properties read via `VDEV_GET_PROPS` (`vdev_prop_t`,
`module/zcommon/zpool_prop.c`; OpenZFS 2.2+). Only the computed read-only
stats are modelled here: the kernel returns a property only when it is named
in the request nvlist, and `vdev_prop_get` aborts the *entire* reply on the
first requested property whose handler errors - so the settable/tunable props
whose getters can fail (`comment`, `allocating`, `checksum_n`/`_t`,
`io_n`/`_t`) are deliberately excluded, leaving only the always-available
cases. [`request_names`](VdevProp::request_names) yields the full set for the
input nvlist. Values render via [`format_prop_value`] where the names overlap
pool/dataset props (size/free/allocated/fragmentation), raw otherwise.
*/
#[derive(Debug, Clone, Copy, PartialEq, Eq, Display, EnumIter)]
#[strum(serialize_all = "snake_case")]
pub enum VdevProp {
    Name,
    State,
    Guid,
    Capacity,
    Size,
    Asize,
    Psize,
    Ashift,
    Free,
    Allocated,
    #[strum(serialize = "expandsize")]
    ExpandSize,
    Fragmentation,
    Parity,
    #[strum(serialize = "numchildren")]
    NumChildren,
    ReadErrors,
    WriteErrors,
    ChecksumErrors,
    InitializeErrors,
    NullOps,
    ReadOps,
    WriteOps,
    FreeOps,
    ClaimOps,
    TrimOps,
    NullBytes,
    ReadBytes,
    WriteBytes,
    FreeBytes,
    ClaimBytes,
    TrimBytes,
    Removing,
    #[strum(serialize = "failfast")]
    FailFast,
    Path,
    Devid,
    #[strum(serialize = "physpath")]
    PhysPath,
    #[strum(serialize = "encpath")]
    EncPath,
    Fru,
    Parent,
    Children,
}

impl VdevProp {
    /// The vdev-property names to name in the `VDEV_GET_PROPS` input nvlist
    /// (see the type-level note on why this is a curated subset).
    pub fn request_names() -> Vec<String> {
        Self::iter().map(|p| p.to_string()).collect()
    }
}

/* --------------------- property value enums (zfs.h) ---------------------- */

macro_rules! value_enum {
    ($name:ident { $($body:tt)* }) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Display, FromRepr, EnumString)]
        #[strum(serialize_all = "lowercase")]
        #[repr(u8)]
        pub enum $name { $($body)* }
    };
}

value_enum!(Canmount { Off = 0, On, NoAuto });
/*
aclmode/aclinherit share the ZFS_ACL_* value space (zfs_acl.h: DISCARD 0,
NOALLOW 1, GROUPMASK 2, PASSTHROUGH 3, RESTRICTED 4, PASSTHROUGH_X 5) and each
table uses a sparse subset of it — NOT dense 0..n. The kernel only checks that
an index maps to *some* name, so a wrong discriminant here silently sets a
different ACL policy. Aliases per zfs_prop.c (`secure`, `noacl`, …).
*/
value_enum!(AclMode { Discard = 0, GroupMask = 2, Passthrough = 3, Restricted = 4 });
value_enum!(AclInherit {
    Discard = 0,
    NoAllow = 1,
    Passthrough = 3,
    #[strum(to_string = "restricted", serialize = "secure")]
    Restricted = 4,
    #[strum(serialize = "passthrough-x")]
    PassthroughX = 5,
});
value_enum!(AclType {
    #[strum(to_string = "off", serialize = "disabled", serialize = "noacl")]
    Off = 0,
    #[strum(to_string = "posix", serialize = "posixacl")]
    Posix = 1,
    Nfsv4 = 2,
});
value_enum!(XattrMode {
    Off = 0,
    // displays as "on (dir)"; the kernel accepts (and libzfs prints) both
    // "on" and "dir" for value 1, so both parse
    #[strum(to_string = "on (dir)", serialize = "on", serialize = "dir")]
    Dir,
    Sa,
});
value_enum!(SyncMode { Standard = 0, Always, Disabled });
value_enum!(LogBias { Latency = 0, Throughput });
value_enum!(CacheMode { None = 0, Metadata, All });
value_enum!(RedundantMetadata { All = 0, Most, Some, None });
value_enum!(SnapVisibility { Hidden = 0, Visible });
value_enum!(CaseSensitivity { Sensitive = 0, Insensitive, Mixed });
/*
The normalization values are the u8_textprep(9F) flag combinations the kernel
stores (normalize_table in zfs_prop.c → U8_TEXTPREP_NF*): CANON_DECOMP 0x10,
COMPAT_DECOMP 0x20, CANON_COMP 0x40. NOT a dense 0..n enum.
*/
value_enum!(Normalization {
    None = 0,
    #[strum(serialize = "formD")]
    FormD = 0x10,
    #[strum(serialize = "formKD")]
    FormKD = 0x20,
    #[strum(serialize = "formC")]
    FormC = 0x50,
    #[strum(serialize = "formKC")]
    FormKC = 0x60,
});
// zfs_volmode_t: GEOM and FULL are the same value (1); `zfs get` prints "full"
// (first table match), so Display does too and "geom" is a parse alias.
value_enum!(VolMode {
    Default = 0,
    #[strum(to_string = "full", serialize = "geom")]
    Full = 1,
    Dev = 2,
    None = 3,
});
value_enum!(FailMode { Wait = 0, Continue, Panic });
value_enum!(KeyFormat { None = 0, Raw, Hex, Passphrase });
// zfs_keystatus_t: computed key state of an encrypted dataset (zfs.h).
value_enum!(KeyStatus { None = 0, Unavailable, Available });
// zio_encrypt: INHERIT=0, ON=1, OFF=2, then the suites 3..=8 (zfs.h).
value_enum!(Encryption {
    Inherit = 0,
    On,
    Off,
    #[strum(serialize = "aes-128-ccm")]
    Aes128Ccm,
    #[strum(serialize = "aes-192-ccm")]
    Aes192Ccm,
    #[strum(serialize = "aes-256-ccm")]
    Aes256Ccm,
    #[strum(serialize = "aes-128-gcm")]
    Aes128Gcm,
    #[strum(serialize = "aes-192-gcm")]
    Aes192Gcm,
    #[strum(serialize = "aes-256-gcm")]
    Aes256Gcm,
});

/// `value_enum` lookup: enum display name for an in-range value, else None.
fn ev<E: TryFromU64 + std::fmt::Display>(v: u64) -> Option<String> {
    E::try_from_u64(v).map(|e| e.to_string())
}

/// Bridge trait because strum's `from_repr` is an inherent fn, not a trait.
trait TryFromU64: Sized {
    fn try_from_u64(v: u64) -> Option<Self>;
}

macro_rules! impl_try_from_u64 {
    ($($ty:ty),+ $(,)?) => {
        $(impl TryFromU64 for $ty {
            fn try_from_u64(v: u64) -> Option<Self> {
                u8::try_from(v).ok().and_then(Self::from_repr)
            }
        })+
    };
}

impl_try_from_u64!(
    Canmount,
    AclMode,
    AclInherit,
    AclType,
    XattrMode,
    SyncMode,
    LogBias,
    CacheMode,
    RedundantMetadata,
    SnapVisibility,
    CaseSensitivity,
    Normalization,
    VolMode,
    FailMode,
    KeyFormat,
    KeyStatus,
    Encryption,
);

/* ------------------------------- rendering ------------------------------- */

/// Render a numeric property value by property name. Returns None when the
/// name isn't a known property (caller shows the raw value).
pub fn format_prop_value(name: &str, v: u64) -> Option<String> {
    use ZfsProp as P;
    let s = match P::from_str(name).ok()? {
        /*
        zstd carries its level in the property value above the algorithm
        bits: `ZIO_COMPRESS_ZSTD | (zio_zstd_levels << SPA_COMPRESSBITS(7))`
        — so `zstd-3` is stored as 400, not as an enum ordinal.
        */
        P::Compression => match (v & 0x7f, v >> 7) {
            (_, 0) => match u8::try_from(v) {
                Ok(b) => ZioCompress::name(b),
                Err(_) => format!("?{v}"),
            },
            (base, level) if base == ZioCompress::Zstd as u64 => {
                match u8::try_from(level).ok().and_then(ZstdLevel::from_repr) {
                    Some(l) => format!("zstd-{l}"),
                    None => format!("zstd-?{level}"),
                }
            }
            _ => format!("?{v}"), // level bits on a level-less algorithm
        },
        P::Checksum => match u8::try_from(v) {
            Ok(b) => ZioChecksum::name(b),
            Err(_) => format!("?{v}"),
        },
        /*
        dedup stores a zio_checksum value with the ZIO_CHECKSUM_VERIFY bit
        (1<<8) possibly set (dedup_table in zfs_prop.c): plain "verify" is
        on|verify (257), the named algorithms render "sha256,verify" style.
        */
        P::Dedup => {
            let base = ZioChecksum::name((v & 0xff) as u8);
            match (v & 0x100 != 0, v & 0xff) {
                (false, _) => base,
                (true, 1) => "verify".into(),
                (true, _) => format!("{base},verify"),
            }
        }

        P::Quota
        | P::Reservation
        | P::Refquota
        | P::Refreservation
        | P::Used
        | P::Available
        | P::Referenced
        | P::UsedBySnapshots
        | P::UsedByDataset
        | P::UsedByChildren
        | P::UsedByRefReservation
        | P::Recordsize
        | P::Volsize
        | P::Volblocksize
        | P::Written
        | P::LogicalUsed
        | P::LogicalReferenced
        | P::SpecialSmallBlocks
        | P::FilesystemLimit
        | P::SnapshotLimit
        | P::Size
        | P::Free
        | P::Allocated
        | P::Freeing
        | P::Leaked
        | P::Checkpoint
        | P::BcloneUsed
        | P::BcloneSaved => {
            if v == 0 {
                "none".into()
            } else {
                human_bytes(v)
            }
        }

        P::Creation => fmt_unix_time(v),
        P::CompressRatio | P::RefCompressRatio | P::BcloneRatio => {
            format!("{}.{:02}x", v / 100, v % 100)
        }
        // u64::MAX = ZFS_FRAG_INVALID (no spacemap histogram) — zpool shows "-"
        P::Fragmentation => {
            if v == u64::MAX {
                "-".into()
            } else {
                format!("{v}%")
            }
        }

        P::Atime
        | P::Relatime
        | P::Devices
        | P::Exec
        | P::Setuid
        | P::Readonly
        | P::Zoned
        | P::Jailed
        | P::Vscan
        | P::Nbmand
        | P::Utf8Only
        | P::Overlay
        | P::DeferDestroy
        | P::AutoExpand
        | P::AutoReplace
        | P::Delegation
        | P::ListSnapshots
        | P::AutoTrim
        | P::MultiHost => (if v != 0 { "on" } else { "off" }).into(),
        P::Mounted => (if v != 0 { "yes" } else { "no" }).into(),

        P::Canmount => ev::<Canmount>(v)?,
        P::AclMode => ev::<AclMode>(v)?,
        P::AclInherit => ev::<AclInherit>(v)?,
        P::AclType => ev::<AclType>(v)?,
        P::Xattr => ev::<XattrMode>(v)?,
        P::Sync => ev::<SyncMode>(v)?,
        P::LogBias => ev::<LogBias>(v)?,
        P::PrimaryCache | P::SecondaryCache => ev::<CacheMode>(v)?,
        P::RedundantMetadata => ev::<RedundantMetadata>(v)?,
        P::SnapDir | P::SnapDev => ev::<SnapVisibility>(v)?,
        P::CaseSensitivity => ev::<CaseSensitivity>(v)?,
        P::Normalization => ev::<Normalization>(v)?,
        P::VolMode => ev::<VolMode>(v)?,
        P::FailMode => ev::<FailMode>(v)?,
        P::KeyFormat => ev::<KeyFormat>(v)?,
        P::KeyStatus => ev::<KeyStatus>(v)?,
        P::Encryption => ev::<Encryption>(v)?,
        P::DnodeSize => match v {
            0 => "legacy (512)".into(),
            1 => "auto".into(), // ZFS_DNSIZE_AUTO
            n => human_bytes(n),
        },
    };
    Some(format!("{s} ({v})"))
}

/* ------------------------------- parsing --------------------------------- */

/// Parse a value enum from its name (case-insensitively), wrapping the repr.
macro_rules! enum_val {
    ($ty:ty, $input:expr, $name:expr) => {
        <$ty>::from_str($input)
            .or_else(|_| <$ty>::from_str(&$input.to_lowercase()))
            .map(|e| NvData::Uint64(e as u64))
            .map_err(|_| format!("invalid value '{}' for '{}'", $input, $name))
    };
}

/**
Parse a user-entered property value into the typed [`NvData`] the SET_PROP
nvlist needs. Read-only properties are rejected with a message; unknown or
string-valued properties pass through as strings. The kernel re-validates
every set, so a value that slips through here still fails cleanly rather
than corrupting anything.
*/
pub fn parse_prop_value(name: &str, input: &str) -> Result<NvData, String> {
    let input = input.trim();
    // user properties (module:name) are always free-form strings
    if name.contains(':') {
        return Ok(NvData::Str(input.to_string()));
    }
    let Ok(prop) = ZfsProp::from_str(name) else {
        // not a native property we model → string-valued (mountpoint, comment, …)
        return Ok(NvData::Str(input.to_string()));
    };

    use ZfsProp as P;
    let u64v = |v: u64| Ok(NvData::Uint64(v));

    match prop {
        // computed / read-only
        P::Used
        | P::Available
        | P::Referenced
        | P::UsedBySnapshots
        | P::UsedByDataset
        | P::UsedByChildren
        | P::UsedByRefReservation
        | P::Written
        | P::LogicalUsed
        | P::LogicalReferenced
        | P::Size
        | P::Free
        | P::Allocated
        | P::Freeing
        | P::Leaked
        | P::Checkpoint
        | P::BcloneUsed
        | P::BcloneSaved
        | P::Creation
        | P::CompressRatio
        | P::RefCompressRatio
        | P::BcloneRatio
        | P::Fragmentation
        | P::Mounted
        | P::KeyStatus => Err(format!("'{name}' is a read-only property")),

        // booleans
        P::Atime
        | P::Relatime
        | P::Devices
        | P::Exec
        | P::Setuid
        | P::Readonly
        | P::Zoned
        | P::Jailed
        | P::Vscan
        | P::Nbmand
        | P::Utf8Only
        | P::Overlay
        | P::DeferDestroy
        | P::AutoExpand
        | P::AutoReplace
        | P::Delegation
        | P::ListSnapshots
        | P::AutoTrim
        | P::MultiHost => parse_bool(input).and_then(u64v),

        // byte sizes; 0 == "none"/unset
        P::Quota
        | P::Reservation
        | P::Refquota
        | P::Refreservation
        | P::Recordsize
        | P::Volsize
        | P::Volblocksize
        | P::SpecialSmallBlocks => {
            if none_like(input) {
                u64v(0)
            } else {
                parse_size(input).and_then(u64v)
            }
        }

        // count limits; "none" == UINT64_MAX
        P::FilesystemLimit | P::SnapshotLimit => {
            if none_like(input) {
                u64v(u64::MAX)
            } else {
                input
                    .parse::<u64>()
                    .map_err(|_| format!("invalid count '{input}'"))
                    .and_then(u64v)
            }
        }

        P::Compression => {
            let lower = input.to_lowercase();
            if lower == "gzip" {
                // bare "gzip" is the kernel's alias for gzip-6 (compress_table)
                return u64v(ZioCompress::Gzip6 as u64);
            }
            // zstd-<level>: algorithm | (level << 7), see the display arm
            if let Some(suffix) = lower.strip_prefix("zstd-") {
                let level = ZstdLevel::from_str(suffix)
                    .map_err(|_| format!("unknown zstd level '{suffix}'"))?;
                return u64v(ZioCompress::Zstd as u64 | ((level as u64) << 7));
            }
            ZioCompress::from_str(input)
                .or_else(|_| ZioCompress::from_str(&lower))
                .map(|c| NvData::Uint64(c as u64))
                .map_err(|_| format!("unknown compression '{input}'"))
        }
        P::Checksum => parse_checksum(input).and_then(u64v),
        P::Dedup => parse_dedup(input).and_then(u64v),

        P::Canmount => enum_val!(Canmount, input, name),
        P::AclMode => enum_val!(AclMode, input, name),
        P::AclInherit => enum_val!(AclInherit, input, name),
        P::AclType => enum_val!(AclType, input, name),
        P::Xattr => enum_val!(XattrMode, input, name),
        P::Sync => enum_val!(SyncMode, input, name),
        P::LogBias => enum_val!(LogBias, input, name),
        P::PrimaryCache | P::SecondaryCache => enum_val!(CacheMode, input, name),
        P::RedundantMetadata => enum_val!(RedundantMetadata, input, name),
        P::SnapDir | P::SnapDev => enum_val!(SnapVisibility, input, name),
        P::CaseSensitivity => enum_val!(CaseSensitivity, input, name),
        P::Normalization => enum_val!(Normalization, input, name),
        P::VolMode => enum_val!(VolMode, input, name),
        P::FailMode => enum_val!(FailMode, input, name),
        P::KeyFormat => enum_val!(KeyFormat, input, name),
        P::Encryption => enum_val!(Encryption, input, name),
        P::DnodeSize => {
            if input.eq_ignore_ascii_case("legacy") {
                u64v(0)
            } else if input.eq_ignore_ascii_case("auto") {
                u64v(1) // ZFS_DNSIZE_AUTO
            } else {
                parse_size(input).and_then(u64v)
            }
        }
    }
}

/**
Always-read-only informational properties (pool and dataset) that aren't
modelled as [`ZfsProp`] — purely a membership set for [`is_editable`], so a
plain `EnumString` is enough. The computed props (used/available/…) live in
`ZfsProp`; these are the identity/state fields that would otherwise fall
through to "editable string".
*/
#[derive(EnumString)]
#[strum(serialize_all = "snake_case")]
enum ReadOnlyProp {
    Guid,
    #[strum(serialize = "createtxg")]
    CreateTxg,
    #[strum(serialize = "objsetid")]
    ObjsetId,
    Type,
    Capacity,
    Health,
    #[strum(serialize = "dedupratio")]
    DedupRatio,
    #[strum(serialize = "expandsize")]
    ExpandSize,
    LoadGuid,
    Name,
    Origin,
    Version,
    /*
    the encryption identity/derivation fields: not settable through SET_PROP
    (encryptionroot is computed; the pbkdf2 pair only changes via CHANGE_KEY,
    i.e. `zfs change-key`), so from the property editor's viewpoint they are
    read-only.
    */
    #[strum(serialize = "encryptionroot")]
    EncryptionRoot,
    #[strum(serialize = "pbkdf2salt")]
    Pbkdf2Salt,
    #[strum(serialize = "pbkdf2iters")]
    Pbkdf2Iters,
}

/**
Whether a dataset/pool property can be set (vs. a computed/read-only one).
Unknown names — `mountpoint`, `comment`, `module:user` props — are editable
strings. The read-only set mirrors the rejection arm in [`parse_prop_value`]
(a test cross-checks the two).
*/
pub fn is_editable(name: &str) -> bool {
    use ZfsProp as P;
    /*
    always-read-only informational props that aren't modelled as `ZfsProp`
    (pool and dataset alike); without this they'd fall through to "editable
    string". Genuinely settable string props (mountpoint, sharenfs, user
    props) are deliberately *not* in [`ReadOnlyProp`] — unknown defaults to
    editable.
    */
    if ReadOnlyProp::from_str(name).is_ok() {
        return false;
    }
    match ZfsProp::from_str(name) {
        Ok(p) => !matches!(
            p,
            P::Used
                | P::Available
                | P::Referenced
                | P::UsedBySnapshots
                | P::UsedByDataset
                | P::UsedByChildren
                | P::UsedByRefReservation
                | P::Written
                | P::LogicalUsed
                | P::LogicalReferenced
                | P::Size
                | P::Free
                | P::Allocated
                | P::Freeing
                | P::Leaked
                | P::Checkpoint
                | P::BcloneUsed
                | P::BcloneSaved
                | P::Creation
                | P::CompressRatio
                | P::RefCompressRatio
                | P::BcloneRatio
                | P::Fragmentation
                | P::Mounted
                | P::KeyStatus
        ),
        Err(_) => true,
    }
}

/// Whether a *vdev* property can be set — the small settable subset (the rest
/// are computed stats). See `vdev_prop_init` in module/zcommon/zpool_prop.c.
pub fn vdev_prop_editable(name: &str) -> bool {
    matches!(
        name,
        "comment" | "failfast" | "checksum_n" | "checksum_t" | "io_n" | "io_t" | "slow_io_n"
            | "slow_io_t"
    )
}

/// Parse a user-entered *vdev* property value into typed [`NvData`] for
/// VDEV_SET_PROPS. Read-only vdev props are rejected; the kernel re-validates.
pub fn parse_vdev_prop_value(name: &str, input: &str) -> Result<NvData, String> {
    let input = input.trim();
    match name {
        "comment" => Ok(NvData::Str(input.to_string())),
        "failfast" => parse_bool(input).map(NvData::Uint64),
        "checksum_n" | "checksum_t" | "io_n" | "io_t" | "slow_io_n" | "slow_io_t" => {
            input.parse::<u64>().map(NvData::Uint64).map_err(|_| format!("expected a number for '{name}'"))
        }
        _ => Err(format!("'{name}' is a read-only vdev property")),
    }
}

/// "none"/"unlimited"/empty all mean "unset" for size and limit properties.
fn none_like(s: &str) -> bool {
    matches!(s.to_lowercase().as_str(), "none" | "unlimited" | "")
}

fn parse_bool(s: &str) -> Result<u64, String> {
    match s.to_lowercase().as_str() {
        "on" | "yes" | "true" | "1" => Ok(1),
        "off" | "no" | "false" | "0" => Ok(0),
        _ => Err(format!("expected on/off, got '{s}'")),
    }
}

/// Parse a byte size like `128K`, `1.5G`, `4096` (1024-based, optional 'B').
pub(crate) fn parse_size(s: &str) -> Result<u64, String> {
    let lower = s.trim().to_lowercase();
    let split = lower
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(lower.len());
    let (num, suffix) = lower.split_at(split);
    let base: f64 = num
        .parse()
        .map_err(|_| format!("invalid number in '{s}'"))?;
    let shift = match suffix.trim().trim_end_matches('b').trim() {
        "" => 0,
        "k" => 10,
        "m" => 20,
        "g" => 30,
        "t" => 40,
        "p" => 50,
        "e" => 60,
        _ => return Err(format!("unknown size suffix in '{s}'")),
    };
    Ok((base * (1u64 << shift) as f64) as u64)
}

/// checksum property values (ZIO_CHECKSUM_* in zfs.h), settable subset.
fn parse_checksum(s: &str) -> Result<u64, String> {
    Ok(match s.to_lowercase().as_str() {
        "on" => 1,
        "off" => 2,
        "fletcher2" => 6,
        "fletcher4" => 7,
        "sha256" => 8,
        "sha512" => 11,
        "skein" => 12,
        "edonr" => 13,
        "blake3" => 14,
        _ => return Err(format!("unknown checksum '{s}'")),
    })
}

/**
dedup values carry the `ZIO_CHECKSUM_VERIFY` bit (1<<8) on top of a
zio_checksum: `verify` = on|verify (257), `sha256,verify` = 8|256, …
(dedup_table in zfs_prop.c). `off,verify` isn't a valid combination.
*/
fn parse_dedup(s: &str) -> Result<u64, String> {
    let lower = s.to_lowercase();
    let (base, verify) = match lower.strip_suffix(",verify") {
        Some(b) => (b.trim(), true),
        None if lower == "verify" => ("on", true),
        None => (lower.as_str(), false),
    };
    let v = match base {
        "on" => 1,
        "off" if verify => return Err("dedup=off cannot take ',verify'".into()),
        "off" => 2,
        other => parse_checksum(other)?,
    };
    Ok(v | if verify { 0x100 } else { 0 })
}

/* ========================================================================= */

#[cfg(test)]
mod tests {
    use super::*;

    #[rustfmt::skip]
    #[test]
    fn known_mappings() {
        assert_eq!(format_prop_value("compression", 15).unwrap(), "lz4 (15)");
        assert_eq!(format_prop_value("compression", 16).unwrap(), "zstd (16)");
        assert_eq!(format_prop_value("compression", 16 | (3 << 7)).unwrap(), "zstd-3 (400)");
        assert_eq!(format_prop_value("compression", 16 | (112 << 7)).unwrap(),
                   "zstd-fast-10 (14352)");
        assert_eq!(format_prop_value("checksum", 14).unwrap(), "blake3 (14)");
        assert_eq!(format_prop_value("xattr", 2).unwrap(), "sa (2)");
        assert_eq!(format_prop_value("atime", 0).unwrap(), "off (0)");
        assert_eq!(format_prop_value("recordsize", 131072).unwrap(), "128K (131072)");
        // ZFS_ACL_* values are sparse: restricted = 4 (the aclinherit default)
        assert_eq!(format_prop_value("aclinherit", 4).unwrap(), "restricted (4)");
        assert_eq!(format_prop_value("aclinherit", 5).unwrap(), "passthrough-x (5)");
        assert_eq!(format_prop_value("aclmode", 3).unwrap(), "passthrough (3)");
        assert_eq!(format_prop_value("aclmode", 1), None); // noallow isn't an aclmode
        // normalization stores u8_textprep flags, not a dense enum
        assert_eq!(format_prop_value("normalization", 0x10).unwrap(), "formD (16)");
        assert_eq!(format_prop_value("normalization", 0x50).unwrap(), "formC (80)");
        assert_eq!(format_prop_value("normalization", 0x60).unwrap(), "formKC (96)");
        assert_eq!(format_prop_value("special_small_blocks", 0).unwrap(), "none (0)");
        assert_eq!(format_prop_value("no_such_prop", 7), None);
        // out-of-range enum value falls back to raw display
        assert_eq!(format_prop_value("canmount", 9), None);
        // volmode: GEOM==FULL==1 displays "full" like `zfs get`
        assert_eq!(format_prop_value("volmode", 1).unwrap(), "full (1)");
        assert_eq!(format_prop_value("volmode", 2).unwrap(), "dev (2)");
        assert_eq!(format_prop_value("volmode", 3).unwrap(), "none (3)");
        // encryption: zio_encrypt has INHERIT=0/ON/OFF then the suites 3..=8
        assert_eq!(format_prop_value("encryption", 2).unwrap(), "off (2)");
        assert_eq!(format_prop_value("encryption", 6).unwrap(), "aes-128-gcm (6)");
        assert_eq!(format_prop_value("encryption", 8).unwrap(), "aes-256-gcm (8)");
        // dedup carries the verify bit; checksum 3 is LABEL, not "verify"
        assert_eq!(format_prop_value("dedup", 257).unwrap(), "verify (257)");
        assert_eq!(format_prop_value("dedup", 8 | 256).unwrap(), "sha256,verify (264)");
        assert_eq!(format_prop_value("dedup", 2).unwrap(), "off (2)");
        assert_eq!(format_prop_value("checksum", 3).unwrap(), "label (3)");
        // dnodesize auto and the fragmentation invalid sentinel
        assert_eq!(format_prop_value("dnodesize", 1).unwrap(), "auto (1)");
        assert_eq!(format_prop_value("fragmentation", u64::MAX).unwrap(),
                   format!("- ({})", u64::MAX));
    }

    #[test]
    fn vdev_prop_names() {
        let names = VdevProp::request_names();
        // the snake_case overrides for one-word kernel prop names
        assert!(names.contains(&"expandsize".to_string()));
        assert!(names.contains(&"numchildren".to_string()));
        assert!(names.contains(&"physpath".to_string()));
        assert!(names.contains(&"encpath".to_string()));
        assert!(names.contains(&"failfast".to_string()));
        // underscored names keep their underscores
        assert!(names.contains(&"read_errors".to_string()));
        assert!(names.contains(&"trim_bytes".to_string()));
        // and the abort-prone props are deliberately absent
        for omit in ["comment", "allocating", "checksum_n", "checksum_t", "io_n", "io_t"] {
            assert!(!names.contains(&omit.to_string()), "{omit} must not be requested");
        }
    }

    #[test]
    fn editability_matches_parse() {
        // read-only dataset props: not editable, and parse_prop_value rejects them
        for ro in ["used", "available", "creation", "compressratio", "fragmentation", "mounted"] {
            assert!(!is_editable(ro), "{ro} should be read-only");
            assert!(parse_prop_value(ro, "0").is_err(), "{ro} should reject a set");
        }
        // informational props modelled as ReadOnlyProp (not ZfsProp)
        for ro in ["guid", "createtxg", "objsetid", "capacity", "health", "load_guid"] {
            assert!(!is_editable(ro), "{ro} should be read-only");
        }
        // editable ones, incl. unknown/user props (free-form strings)
        for ed in ["compression", "atime", "quota", "mountpoint", "com.example:tag"] {
            assert!(is_editable(ed), "{ed} should be editable");
        }
        // vdev props: only the settable subset
        assert!(vdev_prop_editable("failfast"));
        assert!(vdev_prop_editable("comment"));
        assert!(!vdev_prop_editable("read_errors"));
        assert!(!vdev_prop_editable("state"));
        assert_eq!(parse_vdev_prop_value("failfast", "off").unwrap(), NvData::Uint64(0));
        assert_eq!(parse_vdev_prop_value("io_n", "5").unwrap(), NvData::Uint64(5));
        assert_eq!(parse_vdev_prop_value("comment", "spare").unwrap(), NvData::Str("spare".into()));
        assert!(parse_vdev_prop_value("state", "x").is_err());
    }

    #[rustfmt::skip]
    #[test]
    fn parse_typed_values() {
        use NvData::{Str, Uint64};
        // booleans
        assert_eq!(parse_prop_value("atime", "off").unwrap(), Uint64(0));
        assert_eq!(parse_prop_value("readonly", "yes").unwrap(), Uint64(1));
        // compression via the zio enum, incl. "off"
        assert_eq!(parse_prop_value("compression", "lz4").unwrap(), Uint64(15));
        assert_eq!(parse_prop_value("compression", "zstd").unwrap(), Uint64(16));
        assert_eq!(parse_prop_value("compression", "off").unwrap(), Uint64(2));
        // checksum / dedup explicit maps (dedup verify = the 1<<8 bit)
        assert_eq!(parse_prop_value("checksum", "sha256").unwrap(), Uint64(8));
        assert_eq!(parse_prop_value("checksum", "blake3").unwrap(), Uint64(14));
        assert_eq!(parse_prop_value("dedup", "verify").unwrap(), Uint64(257));
        assert_eq!(parse_prop_value("dedup", "sha256,verify").unwrap(), Uint64(8 | 256));
        assert_eq!(parse_prop_value("dedup", "edonr,verify").unwrap(), Uint64(13 | 256));
        assert!(parse_prop_value("dedup", "off,verify").is_err());
        // bare "gzip" is the gzip-6 alias
        assert_eq!(parse_prop_value("compression", "gzip").unwrap(), Uint64(10));
        // zstd levels ride above the algorithm bits: 16 | (level << 7)
        assert_eq!(parse_prop_value("compression", "zstd-3").unwrap(), Uint64(16 | (3 << 7)));
        assert_eq!(parse_prop_value("compression", "zstd-19").unwrap(), Uint64(16 | (19 << 7)));
        assert_eq!(parse_prop_value("compression", "zstd-fast-10").unwrap(), Uint64(16 | (112 << 7)));
        assert_eq!(parse_prop_value("compression", "zstd-fast").unwrap(), Uint64(16 | (103 << 7)));
        assert!(parse_prop_value("compression", "zstd-99").is_err());
        // sizes & limits
        assert_eq!(parse_prop_value("recordsize", "128K").unwrap(), Uint64(131072));
        assert_eq!(parse_prop_value("quota", "1G").unwrap(), Uint64(1 << 30));
        assert_eq!(parse_prop_value("quota", "none").unwrap(), Uint64(0));
        assert_eq!(parse_prop_value("snapshot_limit", "none").unwrap(), Uint64(u64::MAX));
        // value enums, including a mixed-case custom serialize
        assert_eq!(parse_prop_value("canmount", "noauto").unwrap(), Uint64(2));
        assert_eq!(parse_prop_value("sync", "always").unwrap(), Uint64(1));
        assert_eq!(parse_prop_value("normalization", "formC").unwrap(), Uint64(0x50));
        assert_eq!(parse_prop_value("normalization", "formD").unwrap(), Uint64(0x10));
        // volmode aliases: full and geom are the same kernel value
        assert_eq!(parse_prop_value("volmode", "full").unwrap(), Uint64(1));
        assert_eq!(parse_prop_value("volmode", "geom").unwrap(), Uint64(1));
        assert_eq!(parse_prop_value("volmode", "dev").unwrap(), Uint64(2));
        assert_eq!(parse_prop_value("volmode", "none").unwrap(), Uint64(3));
        // xattr: "on" and "dir" both mean the directory implementation
        assert_eq!(parse_prop_value("xattr", "on").unwrap(), Uint64(1));
        assert_eq!(parse_prop_value("xattr", "dir").unwrap(), Uint64(1));
        assert_eq!(parse_prop_value("xattr", "sa").unwrap(), Uint64(2));
        // ACL policies land on the sparse ZFS_ACL_* values, aliases included
        assert_eq!(parse_prop_value("aclinherit", "passthrough-x").unwrap(), Uint64(5));
        assert_eq!(parse_prop_value("aclinherit", "secure").unwrap(), Uint64(4));
        assert_eq!(parse_prop_value("aclmode", "passthrough").unwrap(), Uint64(3));
        assert_eq!(parse_prop_value("aclmode", "restricted").unwrap(), Uint64(4));
        assert_eq!(parse_prop_value("aclmode", "groupmask").unwrap(), Uint64(2));
        assert_eq!(parse_prop_value("acltype", "posixacl").unwrap(), Uint64(1));
        assert_eq!(parse_prop_value("acltype", "noacl").unwrap(), Uint64(0));
        // encryption suites at their zio_encrypt values
        assert_eq!(parse_prop_value("encryption", "aes-256-gcm").unwrap(), Uint64(8));
        assert_eq!(parse_prop_value("encryption", "off").unwrap(), Uint64(2));
        // dnodesize auto
        assert_eq!(parse_prop_value("dnodesize", "auto").unwrap(), Uint64(1));
        assert_eq!(parse_prop_value("dnodesize", "legacy").unwrap(), Uint64(0));
        // string-valued and user properties
        assert_eq!(parse_prop_value("mountpoint", "/mnt/x").unwrap(), Str("/mnt/x".into()));
        assert_eq!(parse_prop_value("com.example:tag", "hi").unwrap(), Str("hi".into()));
        // read-only rejected
        assert!(parse_prop_value("used", "5").is_err());
        assert!(parse_prop_value("creation", "0").is_err());
        // bad values rejected
        assert!(parse_prop_value("compression", "b00gus").is_err());
        assert!(parse_prop_value("atime", "anytimenow").is_err());
    }
}
