# OpenZFS 2.0 reference sources

Vendored from the `zfs-2.0.7` tag (the last 2.0.x release). Same question as
the `../2.1` folder: **what would 2.0.x support cost at the ioctl ABI layer?**

## Headers

Same set as `../2.1`: `zfs_ioctl.h`, `dmu.h`, `zfs_stat.h`, `zfs.h`.

## Result: byte-identical to 2.1.15 — zero code needed

Every struct in the `zfs_cmd_t` layout closure is **textually identical**
between 2.0.7 and 2.1.15 (which is itself byte-identical to 2.2.2, see
`../2.1/README.md`): `zfs_cmd_t` (13744), `dmu_objset_stats_t` (288),
`struct drr_begin` (304), `zinject_record_t` (352), `zfs_stat_t`,
`zfs_share_t`, `zfs_useracct_t`. The `ioctl.rs` size asserts hold unchanged.

## Ioctl ordinals

All 46 ioctls the app can issue sit at **identical positions**, except the
two that don't exist yet:

- `VDEV_GET_PROPS` (0x5a55) / `VDEV_SET_PROPS` (0x5a56) — 2.2.0 additions.
  Both ordinals fall past `ZFS_IOC_LAST` into unassigned space, so the
  kernel rejects them cleanly; the vdev-properties node already documents
  the pre-2.2 EINVAL degrade.

## Feature-level gaps (all degrade already)

- `pool_scan_stat_t` ends at field 14 (`pss_issued`) — the error-scrub
  fields (15..=21, `zpool scrub -e`) don't exist. `scan_stat_rows` reads
  via `.get()` with zero defaults and skips the error-scrub block.
- `vdev_stat_t` ends at `vs_physical_ashift` (45 words): `vs_pspace` is a
  2.1 append (at 45) and 2.2 inserted `vs_noalloc` before it (pspace → 46);
  both are decoded by array length, so a 2.0 kernel simply has neither.
- `head_errlog` pools can't exist on 2.0 — the error-log viewer's legacy
  format is what a 2.0 kernel serves.
- Props/enums newer than 2.0 return `EINVAL`/render `?N`, as designed.

## Verdict

**Supported as-is.** Paper-verified against the 2.0.7 headers; a smoke run
against a live 2.0 host is the only remaining box to tick.
