// Copyright (c) 2026 Mikko Tanner. All rights reserved.
// Licensed under the MIT License or the Apache License, Version 2.0.
// SPDX-License-Identifier: MIT OR Apache-2.0

/*!
Human-friendly rendering of numeric ZFS property values, keyed by property
name (enum index values per `doc/reference/zfs.h`). Used by both the live
ioctl property views and the on-disk DSL props ZAPs — the names are the
same in both worlds.
*/

use crate::util::{fmt_unix_time, human_bytes};
use crate::zfs::ondisk::blkptr::{checksum_name, compression_name};

/// Render a numeric property value by property name. Returns None when the
/// name isn't a known enum/size/time property (caller shows the raw value).
pub fn format_prop_value(name: &str, v: u64) -> Option<String> {
    let s = match name {
        // zio enums (shared with blkptr display)
        "compression" => compression_name(v.min(255) as u8).to_string(),
        "checksum" | "dedup" => match v {
            0 => "inherit".into(),
            1 => "on".into(),
            2 => "off".into(),
            3 => "verify".into(), // dedup=verify
            _ => checksum_name(v.min(255) as u8).to_string(),
        },

        // byte quantities
        "quota" | "reservation" | "refquota" | "refreservation" | "used" | "available"
        | "referenced" | "usedbysnapshots" | "usedbydataset" | "usedbychildren"
        | "usedbyrefreservation" | "recordsize" | "volsize" | "volblocksize" | "written"
        | "logicalused" | "logicalreferenced" | "special_small_blocks" | "filesystem_limit"
        | "snapshot_limit" | "size" | "free" | "allocated" | "freeing" | "leaked"
        | "checkpoint" | "bcloneused" | "bclonesaved" => {
            if v == 0 { "none".into() } else { human_bytes(v) }
        }

        // times and ratios
        "creation" => fmt_unix_time(v),
        "compressratio" | "refcompressratio" | "bcloneratio" | "fragmentation" => {
            if name == "fragmentation" {
                format!("{v}%")
            } else {
                format!("{}.{:02}x", v / 100, v % 100)
            }
        }

        // on/off style booleans
        "atime" | "relatime" | "devices" | "exec" | "setuid" | "readonly" | "zoned"
        | "jailed" | "vscan" | "nbmand" | "utf8only" | "overlay" | "defer_destroy"
        | "autoexpand" | "autoreplace" | "delegation" | "listsnapshots" | "autotrim"
        | "multihost" => bool_str(v).into(),

        "mounted" => (if v != 0 { "yes" } else { "no" }).into(),

        // small enums (zfs.h property value enums)
        "canmount" => enum_str(v, &["off", "on", "noauto"])?,
        "aclmode" => enum_str(v, &["discard", "groupmask", "passthrough", "restricted"])?,
        "aclinherit" => {
            enum_str(v, &["discard", "noallow", "restricted", "passthrough", "passthrough-x"])?
        }
        "acltype" => enum_str(v, &["off", "posix", "nfsv4"])?,
        "xattr" => enum_str(v, &["off", "on (dir)", "sa"])?,
        "sync" => enum_str(v, &["standard", "always", "disabled"])?,
        "logbias" => enum_str(v, &["latency", "throughput"])?,
        "primarycache" | "secondarycache" => enum_str(v, &["none", "metadata", "all"])?,
        "redundant_metadata" => enum_str(v, &["all", "most", "some", "none"])?,
        "snapdir" => enum_str(v, &["hidden", "visible"])?,
        "snapdev" => enum_str(v, &["hidden", "visible"])?,
        "casesensitivity" => enum_str(v, &["sensitive", "insensitive", "mixed"])?,
        "normalization" => enum_str(v, &["none", "formC", "formD", "formKC", "formKD"])?,
        "volmode" => enum_str(v, &["default", "full", "geom", "dev", "none"])?,
        "dnodesize" => match v {
            0 => "legacy (512)".into(),
            n => human_bytes(n),
        },
        "failmode" => enum_str(v, &["wait", "continue", "panic"])?,
        "keyformat" => enum_str(v, &["none", "raw", "hex", "passphrase"])?,
        "encryption" => match v {
            0 => "off".into(),
            1 => "on".into(),
            2 => "aes-128-ccm".into(),
            3 => "aes-192-ccm".into(),
            4 => "aes-256-ccm".into(),
            5 => "aes-128-gcm".into(),
            6 => "aes-192-gcm".into(),
            7 => "aes-256-gcm".into(),
            _ => return None,
        },

        _ => return None,
    };
    Some(format!("{s} ({v})"))
}

fn bool_str(v: u64) -> &'static str {
    if v != 0 { "on" } else { "off" }
}

fn enum_str(v: u64, names: &[&str]) -> Option<String> {
    names.get(v as usize).map(|s| s.to_string())
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
        assert_eq!(format_prop_value("no_such_prop", 7), None);
    }
}
