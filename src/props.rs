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
use crate::zfs::enums::{ZioChecksum, ZioCompress};
use std::str::FromStr;
use strum::{Display, EnumString, FromRepr};

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
    Encryption,
}

/* --------------------- property value enums (zfs.h) ---------------------- */

macro_rules! value_enum {
    ($name:ident { $($body:tt)* }) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Display, FromRepr)]
        #[strum(serialize_all = "lowercase")]
        #[repr(u8)]
        pub enum $name { $($body)* }
    };
}

value_enum!(Canmount { Off = 0, On, NoAuto });
value_enum!(AclMode { Discard = 0, GroupMask, Passthrough, Restricted });
value_enum!(AclInherit {
    Discard = 0,
    NoAllow,
    Restricted,
    Passthrough,
    #[strum(serialize = "passthrough-x")]
    PassthroughX,
});
value_enum!(AclType { Off = 0, Posix, Nfsv4 });
value_enum!(XattrMode {
    Off = 0,
    #[strum(serialize = "on (dir)")]
    Dir,
    Sa,
});
value_enum!(SyncMode { Standard = 0, Always, Disabled });
value_enum!(LogBias { Latency = 0, Throughput });
value_enum!(CacheMode { None = 0, Metadata, All });
value_enum!(RedundantMetadata { All = 0, Most, Some, None });
value_enum!(SnapVisibility { Hidden = 0, Visible });
value_enum!(CaseSensitivity { Sensitive = 0, Insensitive, Mixed });
value_enum!(Normalization {
    None = 0,
    #[strum(serialize = "formC")]
    FormC,
    #[strum(serialize = "formD")]
    FormD,
    #[strum(serialize = "formKC")]
    FormKC,
    #[strum(serialize = "formKD")]
    FormKD,
});
value_enum!(VolMode { Default = 0, Full, Geom, Dev, None });
value_enum!(FailMode { Wait = 0, Continue, Panic });
value_enum!(KeyFormat { None = 0, Raw, Hex, Passphrase });
value_enum!(Encryption {
    Off = 0,
    On,
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
    Canmount, AclMode, AclInherit, AclType, XattrMode, SyncMode, LogBias, CacheMode,
    RedundantMetadata, SnapVisibility, CaseSensitivity, Normalization, VolMode, FailMode,
    KeyFormat, Encryption,
);

/* ------------------------------- rendering ------------------------------- */

/// Render a numeric property value by property name. Returns None when the
/// name isn't a known property (caller shows the raw value).
pub fn format_prop_value(name: &str, v: u64) -> Option<String> {
    use ZfsProp as P;
    let s = match P::from_str(name).ok()? {
        P::Compression => ZioCompress::name(u8::try_from(v).unwrap_or(u8::MAX)),
        P::Checksum | P::Dedup => match v {
            0 => "inherit".into(),
            1 => "on".into(),
            2 => "off".into(),
            3 => "verify".into(), // dedup=verify
            _ => ZioChecksum::name(u8::try_from(v).unwrap_or(u8::MAX)),
        },

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
            if v == 0 { "none".into() } else { human_bytes(v) }
        }

        P::Creation => fmt_unix_time(v),
        P::CompressRatio | P::RefCompressRatio | P::BcloneRatio => {
            format!("{}.{:02}x", v / 100, v % 100)
        }
        P::Fragmentation => format!("{v}%"),

        P::Atime | P::Relatime | P::Devices | P::Exec | P::Setuid | P::Readonly | P::Zoned
        | P::Jailed | P::Vscan | P::Nbmand | P::Utf8Only | P::Overlay | P::DeferDestroy
        | P::AutoExpand | P::AutoReplace | P::Delegation | P::ListSnapshots | P::AutoTrim
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
        P::Encryption => ev::<Encryption>(v)?,
        P::DnodeSize => match v {
            0 => "legacy (512)".into(),
            n => human_bytes(n),
        },
    };
    Some(format!("{s} ({v})"))
}

/* ========================================================================= */

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_mappings() {
        assert_eq!(format_prop_value("compression", 15).unwrap(), "lz4 (15)");
        assert_eq!(format_prop_value("compression", 16).unwrap(), "zstd (16)");
        assert_eq!(format_prop_value("checksum", 14).unwrap(), "blake3 (14)");
        assert_eq!(format_prop_value("xattr", 2).unwrap(), "sa (2)");
        assert_eq!(format_prop_value("atime", 0).unwrap(), "off (0)");
        assert_eq!(format_prop_value("recordsize", 131072).unwrap(), "128K (131072)");
        assert_eq!(format_prop_value("aclinherit", 4).unwrap(), "passthrough-x (4)");
        assert_eq!(format_prop_value("normalization", 1).unwrap(), "formC (1)");
        assert_eq!(format_prop_value("special_small_blocks", 0).unwrap(), "none (0)");
        assert_eq!(format_prop_value("no_such_prop", 7), None);
        // out-of-range enum value falls back to raw display
        assert_eq!(format_prop_value("canmount", 9), None);
    }
}
