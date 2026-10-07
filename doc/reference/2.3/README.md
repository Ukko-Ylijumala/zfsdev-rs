# OpenZFS 2.3 reference sources

Kept separate from the 2.2.2 sources in the parent directory, from two tags:

- the RAIDZ-expansion sources (`vdev_raidz.c`, `vdev_raidz.h`,
  `vdev_raidz_impl.h`, `uberblock_impl.h`) from `zfs-2.3.0` — **future work**,
  the on-disk reader targets 2.2.2 layouts;
- the ioctl-ABI headers (`zfs_ioctl.h`, `zfs.h`, `dmu.h`, `zfs_stat.h`) from
  `zfs-2.3.9` (commit `42f2a2fc`, the last 2.3.x release), answering the same
  question as `../2.1`: **does the live backend work on 2.3.x?** (`zfs.h` was
  first vendored from 2.3.0 for its `SPA_FEATURE_*` table; the 2.3.9 copy
  only adds to it.)

## Why these files

- `vdev_raidz.c` — RAIDZ expansion read path. The function of interest is
  `vdev_raidz_map_alloc_expanded()`; see the memory note
  `raidz-expansion-howto` for the implementation plan. The bulk of this
  file's expansion code is in-progress-reflow bookkeeping we don't need for
  a read-only browser of a *completed* expansion.
- `vdev_raidz.h`, `vdev_raidz_impl.h` — `vdev_raidz_t` / `reflow_node_t`
  (the `raidz_expand_txgs` → logical-width mapping) and expansion state.
- `uberblock_impl.h` — adds `ub_raidz_reflow_info` (appended at the end of
  `struct uberblock`, offset 208; does not shift existing fields, so the
  2.2-based `Uberblock::parse` still reads 2.3 uberblocks correctly).
- `zfs.h` — for the new `SPA_FEATURE_*` enums / feature GUID strings.

## New on-disk features in 2.3 (impact on this browser)

| Feature | GUID | Impact |
|---|---|---|
| `raidz_expansion` | `org.openzfs:raidz_expansion` | Read geometry — currently refused (`TopVdev::Unsupported`). See the how-to note. |
| `fast_dedup` | `com.klarasystems:fast_dedup` | New DDT on-disk format (DDT log + flat entries). Only matters if/when we decode the DDT; DDT objects otherwise appear as generic ZAPs. |
| `longname` | `org.zfsonlinux:longname` | File names up to 1023 bytes → forced fat-ZAP, which `zap.rs` already decodes via array-chunk chains. Microzap name cap (50B) is unaffected. Verify dirent handling on a real longname dir. |
| `large_microzap` | `com.klarasystems:large_microzap` | Microzap blocks may exceed the old 128K cap (still a single object block). `read_mzap` reads the full block 0 (`datablksz`), so it should be handled — verify the single-block assumption holds. |

None of these shift existing struct offsets or break 2.2.2 parsing.

## Ioctl ABI (2.3.9 vs 2.2.2): compatible, no code change

**`zfs_cmd_t` is unchanged** — 13744 bytes, every member at the same offset.
Its layout closure differs in one place only:

| struct | 2.2.2 | 2.3.9 |
|---|---|---|
| `zfs_cmd_t` | 13744 | identical |
| `dmu_objset_stats_t` | 288 | `dds_flags` (`uint8_t`) appended after `dds_origin` |
| `struct drr_begin` | 304 | identical |
| `zinject_record_t` | 352 | identical |
| `zfs_stat_t`, `zfs_share_t` | — | identical |

`dds_flags` lands at offset 287, in what was the struct's tail padding: the
size stays 288 and `dds_origin` doesn't move, so our `DmuObjsetStatsRaw`
mirror decodes 2.3 fills unchanged (the flag byte itself isn't read).

**Ioctl ordinals:** 2.3 appends `POOL_PREFETCH` (0x5a58) and `DDT_PRUNE`
(0x5a59) after the 2.2 range; the 48 ioctls `ioctl.rs` calls are at
identical ordinals (checked against the header's own hex annotations).

**Stats arrays:** `vdev_stat_t` appends `vs_dio_verify_errors` (48 words,
decoded as `VdevStats::dio_verify_errors`); `pool_scan_stat_t` and
`vdev_rebuild_stat_t` are unchanged from 2.2.
