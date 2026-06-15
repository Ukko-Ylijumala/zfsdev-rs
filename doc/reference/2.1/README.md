# OpenZFS 2.1 reference sources

Vendored from the `zfs-2.1.15` tag (the last 2.1.x release), kept separate
from the 2.2.2 sources in the parent directory. These are here to answer one
question: **what would 2.1.x support cost at the ioctl ABI layer?**

## Headers

- `zfs_ioctl.h` — `zfs_cmd_t`, `zinject_record_t`, `zfs_share_t`, and the
  `zfs_ioc_t` enum (mirror in `src/zfs/ioctl.rs`).
- `dmu.h` — `dmu_objset_stats_t`, `struct drr_begin`.
- `zfs_stat.h` — `zfs_stat_t`.
- `zfs.h` — the platform-independent `ZFS_IOC_*` enum and `SPA_FEATURE_*`.

## Result of the struct-size diff (2.1.15 vs 2.2.2)

**`zfs_cmd_t` is byte-identical between 2.1.15 and 2.2.2.** Every struct in
its layout closure is textually identical across the two tags:

| struct | size (2.2.2 assert) | 2.1.15 |
|---|---|---|
| `zfs_cmd_t` | 13744 | identical |
| `dmu_objset_stats_t` | 288 | identical |
| `struct drr_begin` | 304 | identical |
| `zinject_record_t` | 352 | identical |
| `zfs_stat_t` | — | identical |
| `zfs_share_t` | — | identical |

So the `const _: () = assert!(size_of::<ZfsCmd>() == 13744)` canary in
`ioctl.rs` holds unchanged on 2.1.x. **No versioned struct layout is needed.**
There is no `kcopy(sizeof zfs_cmd_t)` mismatch hazard between these two
releases — the ABI surface we use is the same.

## Ioctl ordinals are stable for everything we call

2.2 only *appends* to `zfs_ioc_t`: the new entries (`VDEV_GET_PROPS`,
`VDEV_SET_PROPS`, `POOL_SCRUB`, and the FreeBSD `USERNS_ATTACH`/`JAIL`/
`UNJAIL`/`USERNS_DETACH`) all land at enum positions ≥ 90. The 18 ioctls
this app uses all sit at positions ≤ 68 and are at **identical positions**
in both enums, so the hardcoded `0x5a00 + n` numbers are valid on 2.1.x.

## What 2.1 support actually requires

Nothing at the ABI layer. The only 2.1 gaps are feature-level and already
degrade gracefully:

- Properties / enum values that don't exist in 2.1 (anything tied to 2.2
  features such as block cloning / BRT). A `get`/`set` of an unknown
  property just returns `EINVAL`/`ENOENT`, which the UI already surfaces.
- On-disk reading is governed by pool feature flags / SPA version, not the
  OpenZFS release — a 2.1-created pool is a subset of what the on-disk
  reader already handles, and unknown enums render as `?N`.

Verify against a real 2.1 host before claiming support, but no code change
is anticipated.
