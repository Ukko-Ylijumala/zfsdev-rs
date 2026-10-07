// Copyright (c) 2026 Mikko Tanner. All rights reserved.
// Licensed under the MIT License or the Apache License, Version 2.0.
// SPDX-License-Identifier: MIT OR Apache-2.0

/*!
Which ZFS dataset a path lives on ([`dataset_of`]). `statfs` tells a ZFS
filesystem apart by its magic number; the caller's mount table
(`/proc/self/mountinfo`) then names the dataset, since a ZFS mount's source
is the dataset's name. The mount is the one whose device (`st_dev`) the
path has, so a bind mount resolves too. No `/dev/zfs` call is made. Linux
only, like the procfs it reads.
*/

use std::ffi::{CString, OsString};
use std::fs;
use std::io;
use std::mem::MaybeUninit;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// ZFS_SUPER_MAGIC (zfs.h): the `f_type` `statfs` reports for ZFS.
const ZFS_SUPER_MAGIC: u64 = 0x2fc12fc1;
/// The caller's mount table, in its own mount namespace.
const MOUNTINFO_PATH: &str = "/proc/self/mountinfo";
/// The filesystem type of a ZFS mount in the mount table.
const ZFS_FSTYPE: &str = "zfs";
/// Ends a mount table line's optional fields; the filesystem type follows.
const OPTIONAL_FIELDS_END: &str = "-";
/// A mount table escape: a backslash and three octal digits.
const ESCAPE_LEN: usize = 4;

/// The ZFS mount a path lives on.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ZfsMount {
    /// The dataset mounted there: `pool/fs`, or `pool/fs@snap` for a
    /// snapshot mounted under `.zfs/snapshot`.
    pub dataset: String,
    /// Where it is mounted.
    pub mount_point: PathBuf,
    /// The dataset's directory mounted there: `/`, except for a bind mount
    /// of a subdirectory.
    pub root: PathBuf,
}

impl ZfsMount {
    /// The pool: the dataset name up to its first `/` or `@`.
    pub fn pool(&self) -> &str {
        self.dataset.split(['/', '@']).next().unwrap_or(&self.dataset)
    }

    pub fn is_snapshot(&self) -> bool {
        self.dataset.contains('@')
    }
}

/**
The ZFS mount `path` lives on, or `None` when its filesystem isn't ZFS. An
error when `path` can't be examined, or (unlikely) when it is on ZFS but in
no mount of the caller's mount table. `path` must exist; symlinks are
followed.
*/
pub fn dataset_of(path: impl AsRef<Path>) -> io::Result<Option<ZfsMount>> {
    let path = path.as_ref();
    if !is_zfs(path)? {
        return Ok(None);
    }
    let dev = fs::metadata(path)?.dev();
    let real = fs::canonicalize(path)?;
    let mountinfo = fs::read_to_string(MOUNTINFO_PATH)?;
    match find_mount(&mountinfo, (libc::major(dev), libc::minor(dev)), &real) {
        Some(mount) => Ok(Some(mount)),
        None => {
            let msg = format!("{}: on ZFS, but in no mount of {MOUNTINFO_PATH}", path.display());
            Err(io::Error::new(io::ErrorKind::NotFound, msg))
        }
    }
}

/// Whether `path` is on a ZFS filesystem, by `statfs`'s magic number.
fn is_zfs(path: &Path) -> io::Result<bool> {
    let cpath = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains a NUL byte"))?;
    let mut sfs = MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: a NUL-terminated path and a buffer of the struct's size.
    if unsafe { libc::statfs(cpath.as_ptr(), sfs.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: statfs succeeded, so it filled the struct.
    let sfs = unsafe { sfs.assume_init() };
    Ok(sfs.f_type as u64 == ZFS_SUPER_MAGIC)
}

/* ---------------------------- the mount table ---------------------------- */

/// The fields of a mount table line that [`find_mount`] needs.
struct MountLine<'a> {
    /// `major:minor`, the `st_dev` of files on the mount.
    dev: &'a str,
    root: &'a str,
    mount_point: PathBuf,
    fstype: &'a str,
    source: &'a str,
}

/**
A `mountinfo` line: `id parent major:minor root mount-point options
[optional fields…] - fstype source super-options`, space-separated, with
spaces and the like inside a field escaped in octal.
*/
fn parse_line(line: &str) -> Option<MountLine<'_>> {
    let mut fields = line.split(' ');
    let (_id, _parent) = (fields.next()?, fields.next()?);
    let (dev, root, mount_point) = (fields.next()?, fields.next()?, fields.next()?);
    let mut tail = fields.skip_while(|&f| f != OPTIONAL_FIELDS_END).skip(1);
    let (fstype, source) = (tail.next()?, tail.next()?);
    Some(MountLine { dev, root, mount_point: unescape_path(mount_point), fstype, source })
}

/**
The ZFS mount in `mountinfo` (`/proc/<pid>/mountinfo`'s format) of the
filesystem on device `dev`. When it is mounted more than once (bind mounts),
the mount whose mount point holds `path` wins, the deepest such one, and of
two at the same point the later, which covers the earlier.
*/
fn find_mount(mountinfo: &str, dev: (u32, u32), path: &Path) -> Option<ZfsMount> {
    let dev = format!("{}:{}", dev.0, dev.1);
    let line = mountinfo
        .lines()
        .filter_map(parse_line)
        .filter(|m| m.dev == dev && m.fstype == ZFS_FSTYPE)
        .max_by_key(|m| (path.starts_with(&m.mount_point), m.mount_point.as_os_str().len()))?;
    Some(ZfsMount {
        dataset: String::from_utf8_lossy(&unescape(line.source)).into_owned(),
        mount_point: line.mount_point,
        root: unescape_path(line.root),
    })
}

fn unescape_path(field: &str) -> PathBuf {
    PathBuf::from(OsString::from_vec(unescape(field)))
}

/// A mount table field with its octal escapes (`\040` for a space, `\134`
/// for a backslash) undone.
fn unescape(field: &str) -> Vec<u8> {
    let bytes = field.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let octal = bytes
            .get(i + 1..i + ESCAPE_LEN)
            .filter(|d| bytes[i] == b'\\' && d.iter().all(|c| (b'0'..=b'7').contains(c)));
        let escaped = octal.and_then(|d| {
            u8::try_from(d.iter().fold(0u16, |v, &c| v * 8 + u16::from(c - b'0'))).ok()
        });
        match escaped {
            Some(b) => {
                out.push(b);
                i += ESCAPE_LEN;
            }
            None => {
                out.push(bytes[i]);
                i += 1;
            }
        }
    }
    out
}

/* ================================ tests ================================== */

#[cfg(test)]
mod tests {
    use super::*;

    /**
    The root on ext4, `tank/data` mounted twice (and a subdirectory of it
    bind-mounted at /srv/www), an automounted snapshot, and a dataset whose
    name and mount point hold a space.
    */
    const MOUNTINFO: &str = "\
22 1 259:2 / / rw,relatime shared:1 - ext4 /dev/nvme0n1p2 rw
40 22 0:51 / /tank/data rw,noatime shared:20 - zfs tank/data rw,xattr,posixacl
41 22 0:51 /www /srv/www rw,noatime shared:20 - zfs tank/data rw,xattr,posixacl
42 40 0:60 / /tank/data/.zfs/snapshot/daily rw,relatime shared:30 - zfs tank/data@daily rw
43 22 0:61 / /media/my\\040disk rw master:5 - zfs tank/my\\040files rw
44 22 0:51 / /ext rw - ext4 /dev/sdz1 rw
";

    #[test]
    fn mounts_found_by_device() {
        let find = |dev, path: &str| find_mount(MOUNTINFO, dev, Path::new(path)).unwrap();
        let m = find((0, 51), "/tank/data/file");
        assert_eq!((m.dataset.as_str(), m.pool(), m.is_snapshot()), ("tank/data", "tank", false));
        assert_eq!((m.mount_point, m.root), ("/tank/data".into(), "/".into()));
        // the same filesystem through its bind mount: the mount holding the path
        let m = find((0, 51), "/srv/www/index.html");
        assert_eq!((m.mount_point, m.root), ("/srv/www".into(), "/www".into()));
        let m = find((0, 60), "/tank/data/.zfs/snapshot/daily/x");
        assert_eq!((m.dataset.as_str(), m.pool(), m.is_snapshot()), ("tank/data@daily", "tank", true));
        let m = find((0, 61), "/media/my disk");
        assert_eq!((m.dataset, m.mount_point), ("tank/my files".into(), "/media/my disk".into()));
        // a device no ZFS mount has (ext4 lines don't count) is no mount
        assert_eq!(find_mount(MOUNTINFO, (259, 2), Path::new("/")), None);
    }

    #[test]
    fn escapes_and_short_lines() {
        assert_eq!(unescape(r"a\040b\134c"), b"a b\\c");
        // not an escape: too short, not octal, or past a byte
        assert_eq!(unescape(r"x\04"), br"x\04");
        assert_eq!(unescape(r"\08x"), br"\08x");
        assert_eq!(unescape(r"\+12"), br"\+12");
        assert_eq!(unescape(r"\777"), br"\777");
        assert!(parse_line("1 2 0:1 / /x rw shared:1").is_none());
        assert!(parse_line("").is_none());
    }

    #[test]
    fn non_zfs_paths_are_none() {
        assert_eq!(dataset_of("/proc").unwrap(), None);
        assert!(dataset_of("/no/such/path").is_err());
    }
}
