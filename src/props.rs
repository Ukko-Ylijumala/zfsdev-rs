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
use crate::zfs::nvlist::NvData;
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
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Display, FromRepr, EnumString)]
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
    Encryption,
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
        P::Fragmentation => format!("{v}%"),

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
        P::Encryption => ev::<Encryption>(v)?,
        P::DnodeSize => match v {
            0 => "legacy (512)".into(),
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
        | P::Mounted => Err(format!("'{name}' is a read-only property")),

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

        P::Compression => ZioCompress::from_str(input)
            .or_else(|_| ZioCompress::from_str(&input.to_lowercase()))
            .map(|c| NvData::Uint64(c as u64))
            .map_err(|_| format!("unknown compression '{input}'")),
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
            } else {
                parse_size(input).and_then(u64v)
            }
        }
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
fn parse_size(s: &str) -> Result<u64, String> {
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

fn parse_dedup(s: &str) -> Result<u64, String> {
    match s.to_lowercase().as_str() {
        "on" => Ok(1),
        "off" => Ok(2),
        "verify" => Ok(3),
        _ => parse_checksum(s),
    }
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
        // checksum / dedup explicit maps
        assert_eq!(parse_prop_value("checksum", "sha256").unwrap(), Uint64(8));
        assert_eq!(parse_prop_value("checksum", "blake3").unwrap(), Uint64(14));
        assert_eq!(parse_prop_value("dedup", "verify").unwrap(), Uint64(3));
        // sizes & limits
        assert_eq!(parse_prop_value("recordsize", "128K").unwrap(), Uint64(131072));
        assert_eq!(parse_prop_value("quota", "1G").unwrap(), Uint64(1 << 30));
        assert_eq!(parse_prop_value("quota", "none").unwrap(), Uint64(0));
        assert_eq!(parse_prop_value("snapshot_limit", "none").unwrap(), Uint64(u64::MAX));
        // value enums, including a mixed-case custom serialize
        assert_eq!(parse_prop_value("canmount", "noauto").unwrap(), Uint64(2));
        assert_eq!(parse_prop_value("sync", "always").unwrap(), Uint64(1));
        assert_eq!(parse_prop_value("normalization", "formC").unwrap(), Uint64(1));
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
