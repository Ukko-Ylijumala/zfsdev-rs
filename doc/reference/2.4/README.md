# OpenZFS 2.4 reference sources

Vendored from the `zfs-2.4.4` tag (commit `f75f3256`, the latest 2.4.x
release as of 2026-10-07), kept separate from the 2.2.2 sources in the parent
directory. Same question as `../2.1` and `../2.3`: **does the live backend
work on 2.4.x?**

## Headers

- `zfs_ioctl.h` — `zfs_cmd_t`, `zinject_record_t`, `zfs_share_t`,
  `struct drr_begin` (mirrors in `src/zfs/ioctl.rs`).
- `dmu.h` — `dmu_objset_stats_t`.
- `zfs_stat.h` — `zfs_stat_t`.
- `zfs.h` — the `zfs_ioc_t` enum, `vdev_stat_t`, `pool_scan_stat_t`,
  `vdev_rebuild_stat_t` (decoders in `src/zfs/stats.rs`).

## `zfs_cmd_t`: same size, same offsets — and now pinned upstream

`zinject_record_t` grew from 352 to 368 bytes (`zi_match_count`,
`zi_inject_count` appended). Rather than push `zfs_cmd_t` out, 2.4 wraps it
in a union with the members that follow it:

```c
union {
	zinject_record_t zc_inject_record;
	struct {
		char		zc_pad1[sizeof (zinject_record_t) - 16];
		uint32_t	zc_defer_destroy;
		uint32_t	zc_flags;
		uint64_t	zc_action_handle;
	};
};
```

`zc_defer_destroy`/`zc_flags`/`zc_action_handle` keep their 2.2 offsets
(352 bytes past the start of the inject record), and every later member
follows unchanged — those three just overlap the inject record's new tail,
which only ZFS_IOC_INJECT uses. Upstream also added

```c
#define	_expected_zfs_cmd_size ((MAXPATHLEN*3)+MAXNAMELEN+1200)
_Static_assert(sizeof (zfs_cmd_t) == _expected_zfs_cmd_size, ...);
```

i.e. 3·4096 + 256 + 1200 = **13744**, exactly our `ZfsCmd` const-assert. The
struct size is now an upstream-enforced invariant, which makes a future
silent grow far less likely. Our 352-byte `ZinjectRecord` mirror + the three
following fields lay out the same bytes; we never issue ZFS_IOC_INJECT.

`dmu_objset_stats_t` carries the 2.3 `dds_flags` tail byte (see `../2.3`);
`struct drr_begin`, `zfs_stat_t`, `zfs_share_t` are unchanged.

## Ordinals and stats arrays

- `zfs_ioc_t`: no change from 2.3 (`POOL_PREFETCH` 0x5a58 / `DDT_PRUNE`
  0x5a59 remain the last core entries). All 48 ioctls `ioctl.rs` calls keep
  their ordinals.
- `vdev_stat_t` (48 words, ending `vs_dio_verify_errors`),
  `pool_scan_stat_t` (22 words) and `vdev_rebuild_stat_t` (13 words): unchanged
  from 2.3.

## Seen on master (not vendored)

Checked at `master` commit `fc15a2fb` (2026-10-07), the 2.5 development line:
`zfs_cmd_t` and its closure as in 2.4; `ZFS_IOC_POOL_CONDENSE` (0x5a5a)
appended; `pool_scan_stat_t` appends `pss_pass_scrub_flags` (23 words) —
trailing, so `ScanStats::decode` reads the 22-word 2.2 layout from it
unchanged.
