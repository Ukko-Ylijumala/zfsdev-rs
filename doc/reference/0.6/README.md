# ZoL 0.6 reference sources — NOT SUPPORTED (potential future addition)

Vendored from the `zfs-0.6.5.11` tag (the last 0.6.x release — Ubuntu
16.04, Debian jessie-backports era). 0.6 support is **not implemented**;
this documents where the ABI genuinely breaks, so nobody has to rediscover
it.

## Headers

Same set as `../2.1`: `zfs_ioctl.h`, `dmu.h`, `zfs_stat.h`, `zfs.h`.

## The real ABI break: `zinject_record_t` is 8 bytes shorter *mid-struct*

0.6.5 predates `zi_nlanes` (u64, added 0.7.0), and `zc_inject_record` sits
in the middle of `zfs_cmd_t` — so **every field after it shifts down by
8**: `zc_defer_destroy`, `zc_flags` (scrub pause!), `zc_action_handle`,
`zc_cleanup_fd` (events!), `zc_simple`, `zc_sendobj`, `zc_fromobj`,
`zc_createtxg`, `zc_stat`. Unlike 0.7/0.8 (trailing-only delta), 0.6.5
needs the first genuinely **versioned `ZfsCmd` layout** (13728 bytes) —
the exact hazard the `ioctl.rs` const asserts exist to catch.

## Everything else

- **Ordinals**: identical for everything that exists. The
  `ZFS_IOC_LINUX = +0x80` platform range (events at 0x5a81+) goes back to
  at least **0.6.3 (2014)** — verified on the 0.6.3/0.6.4.2/0.6.5 tags —
  so the "stable since 2.0" folklore is off by six years. Missing:
  `RECV_NEW` (0x46) plus everything 0.7+ (`POOL_SYNC`, key ops, trim/init,
  vdev props); all unassigned slots → clean rejection.
- **No `RECV_NEW`** means local receive can't work without implementing
  the legacy `ZFS_IOC_RECV` (0x1b, zc-field contract — real work). Remote
  push over ssh is unaffected (the far CLI does the receiving); *sending*
  works (`SEND_NEW`/`SEND_SPACE` are 0.6.3+, `embedok` 0.6.5; `compressok`
  ignored — no compressed send yet).
- `dmu_objset_stats_t`: same pre-2.0 origin shift (shared shim).
- `pool_scan_stat_t`: 11 fields (no pause fields, no issued) — same
  examined-based fallback as 0.7, minus pause display.
- `vdev_stat_t`: same ≤ 0.7 index remap (see `../0.7/README.md`).
- `zfs_useracct_t`/`drr_begin`/`zfs_stat_t`: identical.

## Verdict

Browse-only support would additionally hinge on the versioned `zfs_cmd_t`
layout; receive is out without legacy-RECV work. Not planned — documented
for completeness. (Point releases before 0.6.3 and non-Linux ports of that
era are explicitly out of scope.)
