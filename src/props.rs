// Copyright (c) 2026 Mikko Tanner. All rights reserved.
// Licensed under the MIT License or the Apache License, Version 2.0.
// SPDX-License-Identifier: MIT OR Apache-2.0

/*!
Typed ZFS property values. [`decode_prop_value`] says what a numeric value
*means* ([`PropValue`]: a name, bytes, a time, a ratio, …), and
[`parse_prop_value`] turns user input into the typed [`NvData`] SET_PROP
wants; presentation is left to the caller. Property names parse into
`ZfsProp` (strum `EnumString`, lowercase) and the small value enums mirror
the `ZFS_*` value constants from `doc/reference/zfs.h` — so both the dispatch
and the value names are typo-proof enums rather than string tables. Applies to
the live ioctl properties and the on-disk DSL props ZAPs alike; the names are
the same in both worlds.

The property nvlists the ioctls return are read through [`PropEntry`]
([`prop_entry`], [`prop_entries`], [`prop_u64`], [`prop_str`]): it unwraps the
`{value, source}` pairs most of them use and decodes the source
([`PropSource`]), `zfs get`'s SOURCE column.
*/

use crate::enums::{CEnum, Coded, ZioChecksum, ZioCompress, ZpropSource, ZstdLevel, impl_cenum};
use crate::nvlist::{NvData, NvList, NvPair};
use std::fmt;
use std::str::FromStr;
use strum::{Display, EnumIter, EnumString, FromRepr, IntoEnumIterator, IntoStaticStr};

/// The value key of a `{value, source}` property pair (`ZPROP_VALUE`).
const ZPROP_VALUE: &str = "value";
/// The source key of a `{value, source}` property pair (`ZPROP_SOURCE`).
const ZPROP_SOURCE: &str = "source";
/// The source string of a received dataset property (`ZPROP_SOURCE_VAL_RECVD`).
const ZPROP_SOURCE_VAL_RECVD: &str = "$recvd";

/// Every property name we know how to render. Lowercase matching; names
/// with underscores are spelled out explicitly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumString)]
#[cfg_attr(test, derive(EnumIter, IntoStaticStr))]
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
    // small numbers the kernel wants as uint64 (a string is EINVAL)
    Copies,
    Ashift,
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
    // the wrapping key's derivation parameters (keyformat=passphrase)
    Pbkdf2Iters,
    Pbkdf2Salt,
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
input nvlist. Values decode via [`decode_prop_value`] where the names overlap
pool/dataset props (size/free/allocated/fragmentation), raw otherwise.
*/
#[derive(Debug, Clone, Copy, PartialEq, Eq, Display, EnumIter, IntoStaticStr)]
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
    #[strum(serialize = "dir")]
    Dir = 1,
    #[strum(serialize = "sa")]
    Sa = 2,
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

/// `value_enum` lookup: the variant's name for an in-range value, else None.
fn ev<E: CEnum + fmt::Display>(v: u64) -> Option<PropValue> {
    E::from_raw(v).map(|e| PropValue::Name(e.to_string()))
}

impl_cenum!(
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

/* ------------------------------- decoding -------------------------------- */

/**
What a numeric property value *means*: the raw `uint64` the kernel (or an
on-disk DSL props ZAP) stores, decoded by its property. Presentation - units,
precision, wording - is the caller's.
*/
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PropValue {
    /**
    A named value, spelled the way `zfs get` prints it: `lz4`, `zstd-3`,
    `on`, `restricted`, `sha256,verify`, … An out-of-range algorithm value
    comes through as `?N`.
    */
    Name(String),
    /// A byte quantity.
    Bytes(u64),
    /// A plain number: copies, ashift, filesystem/snapshot limits.
    Count(u64),
    /// A unix timestamp (seconds).
    Time(u64),
    /// A ratio in hundredths (`compressratio` 150 = 1.50x).
    Ratio(u64),
    /// A percentage.
    Percent(u64),
    /// Explicitly unset, `none` in `zfs get` (quota 0, a limit of UINT64_MAX).
    Unset,
    /// Not computed (`fragmentation` without a spacemap histogram).
    Unavailable,
}

/// Decode a numeric property value by property name. Returns None when the
/// name isn't a property we model, or the value is out of its range.
pub fn decode_prop_value(name: &str, v: u64) -> Option<PropValue> {
    use PropValue as V;
    use ZfsProp as P;
    let name_of = |s: &str| V::Name(s.into());
    Some(match P::from_str(name).ok()? {
        /*
        zstd carries its level in the property value above the algorithm
        bits: `ZIO_COMPRESS_ZSTD | (zio_zstd_levels << SPA_COMPRESSBITS(7))`
        — so `zstd-3` is stored as 400, not as an enum ordinal.
        */
        P::Compression => V::Name(match (v & 0x7f, v >> 7) {
            (_, 0) => Coded::<ZioCompress>::new(v).to_string(),
            (base, level) if base == ZioCompress::Zstd as u64 => {
                match ZstdLevel::from_raw(level) {
                    Some(l) => format!("zstd-{l}"),
                    None => format!("zstd-?{level}"),
                }
            }
            _ => format!("?{v}"), // level bits on a level-less algorithm
        }),
        P::Checksum => V::Name(Coded::<ZioChecksum>::new(v).to_string()),
        /*
        dedup stores a zio_checksum value with the ZIO_CHECKSUM_VERIFY bit
        (1<<8) possibly set (dedup_table in zfs_prop.c): plain "verify" is
        on|verify (257), the named algorithms render "sha256,verify" style.
        */
        P::Dedup => {
            let base = Coded::<ZioChecksum>::new(v & 0xff).to_string();
            V::Name(match (v & 0x100 != 0, v & 0xff) {
                (false, _) => base,
                (true, 1) => "verify".into(),
                (true, _) => format!("{base},verify"),
            })
        }

        // plain small numbers (ashift 0 = auto)
        P::Copies | P::Pbkdf2Iters | P::Pbkdf2Salt => V::Count(v),
        P::Ashift => match v {
            0 => name_of("auto"),
            _ => V::Count(v),
        },
        // 0 = unset for the quota/reservation family only (zfs get: "none")
        P::Quota | P::Reservation | P::Refquota | P::Refreservation => match v {
            0 => V::Unset,
            _ => V::Bytes(v),
        },
        // counts, not sizes; UINT64_MAX is the "none" default
        P::FilesystemLimit | P::SnapshotLimit => match v {
            u64::MAX => V::Unset,
            _ => V::Count(v),
        },
        // 0 is a real value here (no small blocks go special), `zfs get` says "0"
        P::SpecialSmallBlocks => match v {
            0 => V::Count(0),
            _ => V::Bytes(v),
        },
        P::Used
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
        | P::Size
        | P::Free
        | P::Allocated
        | P::Freeing
        | P::Leaked
        | P::Checkpoint
        | P::BcloneUsed
        | P::BcloneSaved => V::Bytes(v), // a real 0B, as zfs get shows it

        P::Creation => V::Time(v),
        P::CompressRatio | P::RefCompressRatio | P::BcloneRatio => V::Ratio(v),
        // u64::MAX = ZFS_FRAG_INVALID (no spacemap histogram) — zpool shows "-"
        P::Fragmentation => match v {
            u64::MAX => V::Unavailable,
            _ => V::Percent(v),
        },

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
        | P::MultiHost => name_of(if v != 0 { "on" } else { "off" }),
        P::Mounted => name_of(if v != 0 { "yes" } else { "no" }),

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
        // legacy = fixed 512-byte dnodes; auto = ZFS_DNSIZE_AUTO
        P::DnodeSize => match v {
            0 => name_of("legacy"),
            1 => name_of("auto"),
            n => V::Bytes(n),
        },
    })
}

/* ---------------------------- property nvlists --------------------------- */

/**
Where a property's value comes from: `zfs get`'s SOURCE column. Dataset
properties name it as a string (the dataset the value is set on, `$recvd`
for a received value, empty for the default), while pool and vdev properties
carry a `zprop_source_t` flag ([`ZpropSource`]). A value with no source at
all is a statistic (`used`, `creation`, …), shown as `-` by `zfs get`.
*/
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PropSource {
    /// No source: a statistic or another computed value.
    None,
    /// The built-in default.
    Default,
    /// Set on the dataset, pool or vdev itself.
    Local,
    /// Inherited: from the named ancestor dataset, or unnamed for a pool or
    /// vdev property.
    Inherited(Option<String>),
    /// From a `zfs receive`.
    Received,
    /// A temporary override, such as a mount option.
    Temporary,
    /// A `zprop_source_t` value newer than this crate.
    Unknown(u64),
}

/**
One property of a property nvlist, in either shape the kernel uses. Most
property ioctls wrap each value as `{value, source}` (OBJSET_STATS,
POOL_GET_PROPS, VDEV_GET_PROPS, OBJSET_RECVD_PROPS, a bookmark's props),
while OBJSET_ZPLPROPS stores the bare value. A property at its default is
often absent altogether, and the default is then the caller's to supply.
*/
#[derive(Debug, Clone, Copy)]
pub struct PropEntry<'a> {
    /// The property's name.
    pub name: &'a str,
    /// Its value, unwrapped from a `{value, source}` pair.
    pub value: &'a NvData,
    source: Option<&'a NvData>,
}

impl<'a> PropEntry<'a> {
    /// The entry for one pair of a property nvlist.
    pub fn new(pair: &'a NvPair) -> Self {
        let (value, source) = match &pair.data {
            NvData::List(l) => match l.get(ZPROP_VALUE) {
                Some(v) => (v, l.get(ZPROP_SOURCE)),
                None => (&pair.data, None),
            },
            bare => (bare, None),
        };
        PropEntry { name: &pair.name, value, source }
    }

    /// The value, if it is a number.
    pub fn u64(&self) -> Option<u64> {
        match self.value {
            NvData::Uint64(v) => Some(*v),
            _ => None,
        }
    }

    /// The value, if it is a string.
    pub fn str(&self) -> Option<&'a str> {
        match self.value {
            NvData::Str(s) => Some(s),
            _ => None,
        }
    }

    /**
    Where the value comes from, decoded as libzfs's `get_source` does.
    `owner` is the dataset the properties belong to, which tells a local
    value from an inherited one; pool and vdev properties carry their source
    as a flag and don't need it.
    */
    pub fn source(&self, owner: &str) -> PropSource {
        match self.source {
            Some(NvData::Str(s)) if s.is_empty() => PropSource::Default,
            Some(NvData::Str(s)) if s.contains(ZPROP_SOURCE_VAL_RECVD) => PropSource::Received,
            Some(NvData::Str(s)) if s == owner => PropSource::Local,
            Some(NvData::Str(s))
                if !s.starts_with('$')
                    && owner.starts_with(s.as_str())
                    && matches!(owner.as_bytes().get(s.len()), Some(b'/' | b'@')) =>
            {
                PropSource::Inherited(Some(s.clone()))
            }
            Some(NvData::Str(_)) => PropSource::None,
            Some(NvData::Uint64(v)) => match ZpropSource::from_raw(*v) {
                Some(ZpropSource::None) => PropSource::None,
                Some(ZpropSource::Default) => PropSource::Default,
                Some(ZpropSource::Temporary) => PropSource::Temporary,
                Some(ZpropSource::Local) => PropSource::Local,
                Some(ZpropSource::Inherited) => PropSource::Inherited(None),
                Some(ZpropSource::Received) => PropSource::Received,
                None => PropSource::Unknown(*v),
            },
            // no source, or one of a type no kernel sends
            _ => PropSource::None,
        }
    }
}

/// Property `name` of a property nvlist (the last pair of that name, as the
/// kernel resolves duplicates).
pub fn prop_entry<'a>(props: &'a NvList, name: &str) -> Option<PropEntry<'a>> {
    props.pairs.iter().rfind(|p| p.name == name).map(PropEntry::new)
}

/// Every property of a property nvlist, in the kernel's order.
pub fn prop_entries(props: &NvList) -> impl Iterator<Item = PropEntry<'_>> {
    props.iter().map(PropEntry::new)
}

/// Property `name`'s value, if it is a number.
pub fn prop_u64(props: &NvList, name: &str) -> Option<u64> {
    prop_entry(props, name)?.u64()
}

/// Property `name`'s value, if it is a string.
pub fn prop_str<'a>(props: &'a NvList, name: &str) -> Option<&'a str> {
    prop_entry(props, name)?.str()
}

/* ------------------------------- parsing --------------------------------- */

/**
Whether, and when, a dataset or pool property can be set: the `zprop_attr_t`
of its registration in zfs_prop.c / zpool_prop.c. Only libzfs enforces this
(`zfs_valid_proplist`). The kernel's SET_PROP checks a value's *type* and
nothing else, and stores a read-only or create-only property it is handed in
the dataset's props ZAP as a local setting. A stored `encryption` then
shows on a dataset that isn't encrypted, and `zfs inherit` refuses to clear
a property of either kind. So this classification is the only gate there is.
*/
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PropSettable {
    /// Computed or informational (`PROP_READONLY`): never settable.
    ReadOnly,
    /// Fixed when the dataset is created (`PROP_ONETIME`, `PROP_ONETIME_DEFAULT`):
    /// `encryption`, `keyformat`, `casesensitivity`, `normalization`, `utf8only`,
    /// `volblocksize`, and the `pbkdf2iters`/`pbkdf2salt` of a passphrase key
    /// (later changed only by CHANGE_KEY). Also a pool's `tname`, given at
    /// creation or import.
    CreateOnly,
    /// Settable at any time.
    Always,
}

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
nvlist needs, for a dataset or pool that exists. Read-only and create-only
properties ([`prop_settable`]) are rejected with a message; unknown or
string-valued properties pass through as strings. The kernel re-validates a
value's type and range, so a bad *value* that slips through here fails
cleanly. It does not check whether the property may be set at all: that
gate is here ([`PropSettable`]).

`xattr=on` follows the loaded Linux kernel's version. If that version cannot
be determined (including on other platforms), use the explicit `dir` or `sa`.
*/
pub fn parse_prop_value(name: &str, input: &str) -> Result<NvData, String> {
    match prop_settable(name) {
        PropSettable::ReadOnly => Err(read_only(name)),
        PropSettable::CreateOnly => {
            Err(format!("'{name}' can only be set at creation"))
        }
        PropSettable::Always => typed_prop_value(name, input),
    }
}

/**
[`parse_prop_value`] for the creation properties of a new dataset (CREATE's
`props`), which may also carry the create-only ones: `encryption`,
`casesensitivity`, `volblocksize`, … Read-only properties are still rejected.
*/
pub fn parse_create_prop_value(name: &str, input: &str) -> Result<NvData, String> {
    match prop_settable(name) {
        PropSettable::ReadOnly => Err(read_only(name)),
        PropSettable::CreateOnly | PropSettable::Always => typed_prop_value(name, input),
    }
}

/// The message a read-only property's set is refused with.
fn read_only(name: &str) -> String {
    format!("'{name}' is a read-only property")
}

/// The typed value of `input` for property `name`, whenever it may be set
/// (the callers gate that). Read-only properties have no value to parse.
fn typed_prop_value(name: &str, input: &str) -> Result<NvData, String> {
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
        | P::DeferDestroy
        | P::KeyStatus => Err(read_only(name)),

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

        // the kernel checks the iteration minimum itself (dsl_crypt.c)
        P::Pbkdf2Iters | P::Pbkdf2Salt => {
            input.parse::<u64>().map_err(|_| format!("invalid number '{input}'")).and_then(u64v)
        }

        // index prop, copies_table "1".."3" (zfs_prop.c)
        P::Copies => match input.parse::<u64>() {
            Ok(n @ 1..=3) => u64v(n),
            _ => Err(format!("invalid copies '{input}' (1, 2 or 3)")),
        },
        // pool: 0 = auto, else ASHIFT_MIN..=ASHIFT_MAX (spa_prop_validate)
        P::Ashift => match input.parse::<u64>() {
            Ok(n @ (0 | 9..=16)) => u64v(n),
            _ => Err(format!("invalid ashift '{input}' (0 = auto, or 9..16)")),
        },

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
        P::Xattr => {
            if input == "on" {
                // Since 2.3.0, "on" defaults to SA (2); up to 2.2.x, it mapped to DIR (1).
                #[cfg(target_os = "linux")]
                if let Some(v) = crate::ioctl::kernel_version() {
                    let mode = if v < (crate::ioctl::KernelVersion { major: 2, minor: 3 }) {
                        XattrMode::Dir
                    } else {
                        XattrMode::Sa
                    };
                    return u64v(mode as u64);
                }
                Err("cannot resolve 'xattr=on' without a kernel version; use 'dir' or 'sa'".into())
            } else {
                enum_val!(XattrMode, input, name)
            }
        }
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
modelled as [`ZfsProp`] — purely a membership set for [`prop_settable`], so
a plain `EnumString` is enough. The computed props (used/available/…) live in
`ZfsProp`; these are the identity/state fields that would otherwise fall
through to "editable string". With the read-only arm of
[`ZfsProp::settable`] this is every `PROP_READONLY` registration of
zfs_prop.c and zpool_prop.c from ZoL 0.8 to OpenZFS 2.4, hidden ones included
(pinned against the vendored tables by a test).
The string-typed ones matter most: the kernel takes a string for them (see
[`PropSettable`]), while a string for a numeric one is a clean EINVAL.
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
    // computed from the dataset's place in the encryption hierarchy
    #[strum(serialize = "encryptionroot")]
    EncryptionRoot,
    // dataset: string-typed
    Clones,
    ReceiveResumeToken,
    RedactSnaps,
    #[strum(serialize = "prevsnap")]
    PrevSnap,
    // dataset: counters and state
    FilesystemCount,
    SnapshotCount,
    SnapshotsChanged,
    #[strum(serialize = "userrefs")]
    UserRefs,
    #[strum(serialize = "numclones")]
    NumClones,
    Unique,
    Inconsistent,
    Redacted,
    #[strum(serialize = "ivsetguid")]
    IvsetGuid,
    #[strum(serialize = "keyguid")]
    KeyGuid,
    #[strum(serialize = "remaptxg")]
    RemapTxg,
    #[strum(serialize = "useraccounting")]
    UserAccounting,
    // pool
    #[strum(serialize = "dedupcached")]
    DedupCached,
    DedupTableSize,
    LastScrubbedTxg,
    #[strum(serialize = "maxblocksize")]
    MaxBlockSize,
    #[strum(serialize = "maxdnodesize")]
    MaxDnodeSize,
    // ZoL 0.8 only
    PrivProp,
}

/// The create-only (`PROP_ONETIME`) properties that aren't modelled as
/// [`ZfsProp`], likewise a membership set: a pool's temporary name.
#[derive(EnumString)]
#[strum(serialize_all = "snake_case")]
enum CreateOnlyProp {
    Tname,
}

impl ZfsProp {
    /// When this property can be set. The read-only arm is the one
    /// `typed_prop_value` has no value for (a test cross-checks the two).
    fn settable(self) -> PropSettable {
        use ZfsProp as P;
        match self {
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
            | P::DeferDestroy
            | P::KeyStatus => PropSettable::ReadOnly,
            P::Encryption
            | P::KeyFormat
            | P::CaseSensitivity
            | P::Normalization
            | P::Utf8Only
            | P::Volblocksize
            | P::Pbkdf2Iters
            | P::Pbkdf2Salt => PropSettable::CreateOnly,
            _ => PropSettable::Always,
        }
    }
}

/**
When a dataset or pool property can be set ([`PropSettable`]). User
properties (`module:name`) always can. A name this crate doesn't know —
`mountpoint`, `sharenfs`, `comment`, a property of a newer OpenZFS — counts as
settable, since the genuinely settable string properties aren't modelled;
the known read-only ones are (`ReadOnlyProp`, and the read-only arm of
`ZfsProp::settable`).
*/
pub fn prop_settable(name: &str) -> PropSettable {
    if name.contains(':') {
        return PropSettable::Always;
    }
    if ReadOnlyProp::from_str(name).is_ok() {
        return PropSettable::ReadOnly;
    }
    if CreateOnlyProp::from_str(name).is_ok() {
        return PropSettable::CreateOnly;
    }
    ZfsProp::from_str(name).map_or(PropSettable::Always, ZfsProp::settable)
}

/**
Whether a property of an existing dataset or pool can be set: neither
read-only nor create-only ([`prop_settable`]). Unknown names — `mountpoint`,
`comment`, `module:user` props — are editable strings.
*/
pub fn is_editable(name: &str) -> bool {
    prop_settable(name) == PropSettable::Always
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
pub fn parse_size(s: &str) -> Result<u64, String> {
    let lower = s.trim().to_lowercase();
    let split = lower
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(lower.len());
    let (num, suffix) = lower.split_at(split);
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
    let too_big = || format!("size '{s}' is too large");
    // an integer stays exact (f64 loses bytes past 2^53); overflow is an error
    if let Ok(n) = num.parse::<u64>() {
        return n.checked_mul(1u64 << shift).ok_or_else(too_big);
    }
    let base: f64 = num.parse().map_err(|_| format!("invalid number in '{s}'"))?;
    let v = base * (1u64 << shift) as f64;
    // `as u64` would silently saturate an overflow to u64::MAX
    if !(0.0..u64::MAX as f64).contains(&v) {
        return Err(too_big());
    }
    Ok(v as u64)
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
    use std::fs;
    use std::path::Path;

    #[rustfmt::skip]
    #[test]
    fn known_mappings() {
        use PropValue::*;
        let d = decode_prop_value;
        let name = |s: &str| Some(Name(s.into()));
        assert_eq!(d("compression", 15), name("lz4"));
        assert_eq!(d("compression", 16), name("zstd"));
        assert_eq!(d("compression", 16 | (3 << 7)), name("zstd-3"));
        assert_eq!(d("compression", 16 | (112 << 7)), name("zstd-fast-10"));
        assert_eq!(d("compression", 15 | (3 << 7)), name(&format!("?{}", 15 | (3 << 7))));
        assert_eq!(d("compression", 99), name("?99"));
        assert_eq!(d("checksum", 14), name("blake3"));
        assert_eq!(d("xattr", 1), name("dir"));
        assert_eq!(d("xattr", 2), name("sa"));
        assert_eq!(d("atime", 0), name("off"));
        assert_eq!(d("mounted", 1), name("yes"));
        assert_eq!(d("recordsize", 131072), Some(Bytes(131072)));
        // ZFS_ACL_* values are sparse: restricted = 4 (the aclinherit default)
        assert_eq!(d("aclinherit", 4), name("restricted"));
        assert_eq!(d("aclinherit", 5), name("passthrough-x"));
        assert_eq!(d("aclmode", 3), name("passthrough"));
        assert_eq!(d("aclmode", 1), None); // noallow isn't an aclmode
        // normalization stores u8_textprep flags, not a dense enum
        assert_eq!(d("normalization", 0x10), name("formD"));
        assert_eq!(d("normalization", 0x50), name("formC"));
        assert_eq!(d("normalization", 0x60), name("formKC"));
        assert_eq!(d("special_small_blocks", 0), Some(Count(0)));
        assert_eq!(d("special_small_blocks", 4096), Some(Bytes(4096)));
        // sizes: integers exact past 2^53, fractions fine, overflow refused
        assert_eq!(parse_size("9007199254740993").unwrap(), 9_007_199_254_740_993);
        assert_eq!(parse_size("1.5G").unwrap(), 3 << 29);
        assert_eq!(parse_size("8K").unwrap(), 8192);
        assert!(parse_size("20E").is_err() && parse_size("1e30").is_err());
        assert_eq!(d("quota", 0), Some(Unset));
        assert_eq!(d("quota", 1 << 30), Some(Bytes(1 << 30)));
        assert_eq!(d("written", 0), Some(Bytes(0)));
        assert_eq!(d("snapshot_limit", u64::MAX), Some(Unset));
        assert_eq!(d("filesystem_limit", 12), Some(Count(12)));
        assert_eq!(d("copies", 2), Some(Count(2)));
        assert_eq!((d("ashift", 0), d("ashift", 12)), (name("auto"), Some(Count(12))));
        assert_eq!(d("no_such_prop", 7), None);
        // out-of-range enum value: nothing to decode
        assert_eq!(d("canmount", 9), None);
        // volmode: GEOM==FULL==1 decodes "full" like `zfs get`
        assert_eq!(d("volmode", 1), name("full"));
        assert_eq!(d("volmode", 2), name("dev"));
        assert_eq!(d("volmode", 3), name("none"));
        // encryption: zio_encrypt has INHERIT=0/ON/OFF then the suites 3..=8
        assert_eq!(d("encryption", 2), name("off"));
        assert_eq!(d("encryption", 6), name("aes-128-gcm"));
        assert_eq!(d("encryption", 8), name("aes-256-gcm"));
        // dedup carries the verify bit; checksum 3 is LABEL, not "verify"
        assert_eq!(d("dedup", 257), name("verify"));
        assert_eq!(d("dedup", 8 | 256), name("sha256,verify"));
        assert_eq!(d("dedup", 2), name("off"));
        assert_eq!(d("checksum", 3), name("label"));
        // times, ratios, dnodesize, and the fragmentation invalid sentinel
        assert_eq!(d("creation", 1_700_000_000), Some(Time(1_700_000_000)));
        assert_eq!(d("compressratio", 150), Some(Ratio(150)));
        assert_eq!((d("dnodesize", 0), d("dnodesize", 1)), (name("legacy"), name("auto")));
        assert_eq!(d("dnodesize", 2048), Some(Bytes(2048)));
        assert_eq!(d("fragmentation", 17), Some(Percent(17)));
        assert_eq!(d("fragmentation", u64::MAX), Some(Unavailable));
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

    /**
    The kernel's SET_PROP stores whatever property it is handed, so the
    read-only and create-only ones must stop here: every `PROP_READONLY` /
    `PROP_ONETIME` dataset property of zfs_prop.c (2.2 through 2.4) that
    isn't a user-visible statistic already covered above.
    */
    #[test]
    fn read_only_and_create_only_props_are_refused() {
        let never = [
            // string-typed: the kernel would take these as given
            "name", "origin", "clones", "prevsnap", "receive_resume_token", "encryptionroot",
            "redact_snaps", "type",
            // numbers and indexes
            "defer_destroy", "userrefs", "filesystem_count", "snapshot_count", "snapshots_changed",
            "numclones", "unique", "inconsistent", "redacted", "ivsetguid", "keyguid", "remaptxg",
            "useraccounting", "keystatus", "mounted", "objsetid", "createtxg", "guid",
            // pool
            "dedupcached", "dedup_table_size", "last_scrubbed_txg", "maxblocksize", "maxdnodesize",
        ];
        for ro in never {
            assert_eq!(prop_settable(ro), PropSettable::ReadOnly, "{ro}");
            assert!(!is_editable(ro), "{ro}");
            assert_eq!(parse_prop_value(ro, "1"), Err(read_only(ro)), "{ro}");
            assert_eq!(parse_create_prop_value(ro, "1"), Err(read_only(ro)), "{ro}");
        }
        let create_only = [
            ("encryption", "aes-256-gcm"),
            ("keyformat", "passphrase"),
            ("casesensitivity", "mixed"),
            ("normalization", "formKC"),
            ("utf8only", "on"),
            ("volblocksize", "16K"),
            ("pbkdf2iters", "350000"),
            ("pbkdf2salt", "1234567890123456789"),
        ];
        for (prop, value) in create_only {
            assert_eq!(prop_settable(prop), PropSettable::CreateOnly, "{prop}");
            assert!(!is_editable(prop), "{prop}");
            let refused = parse_prop_value(prop, value).unwrap_err();
            assert!(refused.contains("at creation"), "{prop}: {refused}");
            assert!(matches!(parse_create_prop_value(prop, value), Ok(NvData::Uint64(_))), "{prop}");
        }
        for ok in ["compression", "readonly", "keylocation", "mountpoint", "com.example:name"] {
            assert_eq!(prop_settable(ok), PropSettable::Always, "{ok}");
        }
    }

    /// `ZfsProp::settable` and the value parser agree on which modelled
    /// properties are read-only: exactly those have no value to parse.
    #[test]
    fn settability_matches_the_value_parser() {
        for prop in ZfsProp::iter() {
            let name: &'static str = prop.into();
            let refused = typed_prop_value(name, "1") == Err(read_only(name));
            assert_eq!(refused, prop.settable() == PropSettable::ReadOnly, "{name}");
            assert_eq!(prop_settable(name), prop.settable(), "{name}");
        }
    }

    /**
    The `(name, attribute)` of every `zprop_register_*` call in a vendored
    property table: the first string literal and the `zprop_attr_t` token.
    */
    fn registrations(src: &str) -> Vec<(&str, &str)> {
        const ATTRS: [&str; 5] =
            ["PROP_DEFAULT", "PROP_READONLY", "PROP_INHERIT", "PROP_ONETIME", "PROP_ONETIME_DEFAULT"];
        // zpool_prop.c also holds the vdev properties (2.2+), a separate namespace
        let src = src.split_once("\nvdev_prop_init(").map_or(src, |(pool, _)| pool);
        src.split("zprop_register_")
            .skip(1)
            .map(|call| {
                let call = call.split_once(';').expect("unterminated registration").0;
                let name = match call.split(',').nth(1).map(str::trim) {
                    Some("ZPOOL_DEDUPCACHED_PROP_NAME") => "dedupcached",
                    Some(lit) => lit.strip_prefix('"').and_then(|l| l.strip_suffix('"')).expect(lit),
                    None => panic!("registration without a name"),
                };
                let attr = call
                    .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                    .find(|tok| ATTRS.contains(tok))
                    .unwrap_or_else(|| panic!("no attribute on {name}"));
                (name, attr)
            })
            .collect()
    }

    /**
    `prop_settable` agrees with the property tables of every verified release
    (`zfs_prop.c` and `zpool_prop.c`, 2.2 at the reference root), by the rule
    libzfs applies: `PROP_READONLY` is never settable, `PROP_ONETIME` and
    `PROP_ONETIME_DEFAULT` only at creation. `version` alone is held
    read-only on purpose (`STRICTER`): an upgrade is one-way.
    */
    #[test]
    fn settability_matches_vendored_property_tables() {
        const STRICTER: [&str; 1] = ["version"];
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("doc/reference");
        let mut seen = 0;
        for dir in ["0.8", "2.0", "2.1", "", "2.3", "2.4"] {
            for file in ["zfs_prop.c", "zpool_prop.c"] {
                let src = fs::read_to_string(root.join(dir).join(file)).unwrap();
                for (name, attr) in registrations(&src) {
                    let want = match attr {
                        "PROP_READONLY" => PropSettable::ReadOnly,
                        "PROP_ONETIME" | "PROP_ONETIME_DEFAULT" => PropSettable::CreateOnly,
                        _ => PropSettable::Always,
                    };
                    let want = if STRICTER.contains(&name) { PropSettable::ReadOnly } else { want };
                    assert_eq!(prop_settable(name), want, "{name} ({attr}) in {dir:?}/{file}");
                    seen += 1;
                }
            }
        }
        assert!(seen > 700, "only {seen} registrations parsed");
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
        assert_eq!(parse_create_prop_value("normalization", "formC").unwrap(), Uint64(0x50));
        assert_eq!(parse_create_prop_value("normalization", "formD").unwrap(), Uint64(0x10));
        // volmode aliases: full and geom are the same kernel value
        assert_eq!(parse_prop_value("volmode", "full").unwrap(), Uint64(1));
        assert_eq!(parse_prop_value("volmode", "geom").unwrap(), Uint64(1));
        assert_eq!(parse_prop_value("volmode", "dev").unwrap(), Uint64(2));
        assert_eq!(parse_prop_value("volmode", "none").unwrap(), Uint64(3));
        // xattr: "on" defaults to SA on 2.3+ (Dir on <2.3), "dir" and "sa" are explicit
        #[cfg(target_os = "linux")]
        match crate::ioctl::kernel_version() {
            Some(v) => {
                let on = if v < (crate::ioctl::KernelVersion { major: 2, minor: 3 }) { 1 } else { 2 };
                assert_eq!(parse_prop_value("xattr", "on").unwrap(), Uint64(on));
            }
            None => assert!(parse_prop_value("xattr", "on").is_err()),
        }
        #[cfg(not(target_os = "linux"))]
        assert!(parse_prop_value("xattr", "on").is_err());
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
        // index/number props must go out as uint64 — a string is EINVAL
        assert_eq!(parse_prop_value("copies", "2").unwrap(), Uint64(2));
        assert!(parse_prop_value("copies", "4").is_err());
        assert_eq!(parse_prop_value("ashift", "12").unwrap(), Uint64(12));
        assert_eq!(parse_prop_value("ashift", "0").unwrap(), Uint64(0));
        assert!(parse_prop_value("ashift", "8").is_err());
        // encryption suites at their zio_encrypt values
        assert_eq!(parse_create_prop_value("encryption", "aes-256-gcm").unwrap(), Uint64(8));
        assert_eq!(parse_create_prop_value("encryption", "off").unwrap(), Uint64(2));
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

    /// A `{value, source}` pair as the property ioctls return it.
    fn wrapped(value: NvData, source: Option<NvData>) -> NvList {
        let mut l = NvList::new();
        l.pairs.push(NvPair { name: ZPROP_VALUE.into(), data: value });
        if let Some(s) = source {
            l.pairs.push(NvPair { name: ZPROP_SOURCE.into(), data: s });
        }
        l
    }

    #[test]
    fn dataset_prop_sources_decode_like_libzfs() {
        use NvData::{Str, Uint64};
        let src = |s: &str| Some(Str(s.into()));
        let mut props = NvList::new();
        props
            .add_nvlist("compression", wrapped(Uint64(15), src("tank/a")))
            .add_nvlist("atime", wrapped(Uint64(0), src("tank")))
            .add_nvlist("recordsize", wrapped(Uint64(131072), src("")))
            .add_nvlist("quota", wrapped(Uint64(1 << 30), src("$recvd")))
            .add_nvlist("used", wrapped(Uint64(42), None))
            .add_nvlist("mountpoint", wrapped(Str("/a".into()), src("tank/a")));
        let source = |name: &str| prop_entry(&props, name).unwrap().source("tank/a");
        assert_eq!(source("compression"), PropSource::Local);
        assert_eq!(source("atime"), PropSource::Inherited(Some("tank".into())));
        assert_eq!(source("recordsize"), PropSource::Default);
        assert_eq!(source("quota"), PropSource::Received);
        assert_eq!(source("used"), PropSource::None);
        // Non-ancestor or sentinel "$" string sources report PropSource::None
        let mut bogus = NvList::new();
        bogus
            .add_nvlist("sentinel", wrapped(Uint64(1), src("$")))
            .add_nvlist("unrelated", wrapped(Uint64(1), src("otherpool")))
            .add_nvlist("prefix_not_parent", wrapped(Uint64(1), src("tan")));
        for k in ["sentinel", "unrelated", "prefix_not_parent"] {
            assert_eq!(prop_entry(&bogus, k).unwrap().source("tank/a"), PropSource::None);
        }
        assert_eq!(prop_u64(&props, "compression"), Some(15));
        assert_eq!(prop_str(&props, "mountpoint"), Some("/a"));
        assert_eq!(prop_u64(&props, "mountpoint"), None);
        assert_eq!(prop_u64(&props, "absent"), None);
        let names: Vec<&str> = prop_entries(&props).map(|e| e.name).collect();
        assert_eq!(names, ["compression", "atime", "recordsize", "quota", "used", "mountpoint"]);
    }

    #[test]
    fn pool_sources_are_flags_and_zpl_values_bare() {
        let mut props = NvList::new();
        props
            .add_nvlist("size", wrapped(NvData::Uint64(1 << 40), Some(NvData::Uint64(0x1))))
            .add_nvlist("autotrim", wrapped(NvData::Uint64(1), Some(NvData::Uint64(0x8))))
            .add_nvlist("failmode", wrapped(NvData::Uint64(0), Some(NvData::Uint64(0x40))))
            .add_u64("version", 5)
            // a duplicate resolves to the last pair, as in the kernel
            .add_u64("version", 6);
        let source = |name: &str| prop_entry(&props, name).unwrap().source("tank");
        assert_eq!(source("size"), PropSource::None);
        assert_eq!(source("autotrim"), PropSource::Local);
        assert_eq!(source("failmode"), PropSource::Unknown(0x40));
        // OBJSET_ZPLPROPS stores bare values: no unwrapping, no source
        assert_eq!(prop_u64(&props, "version"), Some(6));
        assert_eq!(source("version"), PropSource::None);
        // a list without a "value" key is the value itself
        let mut odd = NvList::new();
        odd.add_nvlist("weird", NvList::new());
        assert!(matches!(prop_entry(&odd, "weird").unwrap().value, NvData::List(_)));
    }
}
