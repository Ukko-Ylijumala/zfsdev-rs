# OpenZFS reference material

Headers and sources vendored from [OpenZFS](https://github.com/openzfs/zfs) as
the ground truth for what `zfsdev` mirrors in Rust: the `zfs_cmd_t` layout,
the ioctl numbers, the nvlist wire format, the stat-array layouts, the C enums
and the innvl/outnvl contracts of the new-style ioctls.

They are **reference only**. Nothing here is compiled into or linked with the
crate, and `doc/` is excluded from its package. The one programmatic use is
the test `ioc_ordinals_match_vendored_headers`, which reads the `zfs.h` copies
when the tests run.

## License

These files are © their respective authors and licensed under the **Common
Development and Distribution License (CDDL) 1.0**, *not* under the crate's
MIT OR Apache-2.0. [`LICENSE`](LICENSE) is OpenZFS's own license file, copied
verbatim from the 2.2.2 release. Every vendored file keeps its original CDDL
header unmodified. The `README.md` files are this project's own analyses.

## Layout

- The top level is **OpenZFS 2.2.2**, the layout the Rust mirrors follow:
  - ioctl ABI: `zfs_ioctl.h`, `zfs.h`, `dmu.h`, `zfs_stat.h`
  - kernel ioctl handlers and their innvl key tables: `zfs_ioctl.c`
  - libzfs_core's request shapes: `libzfs_core.c`
  - the nvlist codec: `nvpair.h`, `nvpair.c`
  - the delegation (`zfs allow`) wire format: `zfs_deleg.{c,h}`, `dsl_deleg.c`
  - pool history record framing: `spa_history.c`
  - on-disk enums mirrored in `enums.rs`: `spa.h`, `zio.h`, `zio_compress.h`
- `0.6/`, `0.7/`, `0.8/`, `2.0/`, `2.1/`, `2.3/` and `2.4/` hold the ioctl-ABI
  headers of each release line: `zfs_ioctl.h`, `zfs.h`, `dmu.h` and
  `zfs_stat.h`, from zfs-0.6.5.11, 0.7.13, 0.8.6, 2.0.7, 2.1.15, 2.3.9 and
  2.4.4. Each directory's `README.md` compares that release's ABI with the
  2.2 layout and says what support for it takes.

The per-version READMEs were written in
[zfs-browser](https://github.com/Ukko-Ylijumala/zfs-browser), where this layer
started. They also mention on-disk-format sources that stayed there, such as
0.8's `zfs_sa.h`/`zfs_acl.h`/`zfs_znode.h` and 2.3's RAIDZ-expansion files.
