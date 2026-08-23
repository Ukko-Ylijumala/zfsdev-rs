# ZoL 0.8 reference sources

Vendored from the `zfs-0.8.6` tag (the last 0.8.x release — the ZFS shipped
by Ubuntu 20.04, CentOS/EL7 zfsonlinux repos, etc.). Question: **what does
0.8.x support cost?** Answer: two small decode shims, no versioned struct.

## Headers

The `../2.1` set (`zfs_ioctl.h`, `dmu.h`, `zfs_stat.h`, `zfs.h`) plus
`zfs_znode.h` — the latter for `znode_phys_t`/`zfs_acl_phys_t`, the
**legacy pre-SA on-disk znode format** (ZPL version ≤ 4) that the 2.2
headers no longer carry; it is the reference for the on-disk layer's
legacy-znode decode, unrelated to the ioctl ABI.

## `zfs_cmd_t`: 13736 bytes — safe with the 13744 mirror as-is

The **only** delta vs 2.x is the missing *trailing* `zc_zoneid` (added in
2.0). Every other field offset is identical — `zinject_record_t` (zi_dvas
present since 0.8), `drr_begin`, `zfs_stat_t`, `zfs_share_t`,
`zfs_useracct_t` are all textually identical to 2.1.15. Because the kernel
copies `sizeof(zfs_cmd_t)` using **its own** definition, a 13744-byte
userspace buffer is safe in both directions against a 13736-byte kernel:
copy-in reads 8 bytes less, copy-out writes 8 bytes less and our (unused,
zero-initialized) `zc_zoneid` just stays zero. **No versioned layout.**

## The two real decode deltas (both pre-2.0-wide, shimmed in `ioctl.rs`)

1. **`dmu_objset_stats_t` has no `dds_redacted`** (2.0, redacted send), so
   `dds_origin` starts at byte offset 30 instead of 31 (total size stays
   288 — tail padding absorbs it). Decoding with the 2.x layout reads a
   clone's origin's first character as `redacted` and truncates the origin.
2. **`pool_scan_stat_t` slot 6 is `pss_to_process`**, not `pss_skipped`
   (repurposed in 2.0's scrub accounting). The 2.x denominator
   `to_examine − skipped` collapses to ~0 on 0.8; pre-2.0 the denominator
   is plain `pss_to_examine` (what 0.8's `zpool status` shows). Slots 13/14
   (`pss_pass_issued`/`pss_issued`) exist — 0.8 is the release that
   introduced issued-based scrub progress — so the rest of the math holds.

Both key off one runtime fact (kernel older than 2.0), probed once from
`/sys/module/zfs/version`.

## What was verified unchanged

- **Ioctl ordinals**: every ioctl we issue exists at the identical number.
  The `ZFS_IOC_LINUX = +0x80` platform range (events at 0x5a81/0x5a83)
  predates 0.8 by years — see `../0.6/README.md` (stable since ≥ 0.6.3).
  Only `VDEV_GET_PROPS`/`VDEV_SET_PROPS` are missing; both ordinals are
  unassigned on 0.8 → clean kernel rejection (the documented pre-2.2
  degrade).
- **`vdev_stat_t`**: the 0.8 field list is a strict prefix of 2.2's in
  identical order (2.0/2.2 only *append* — rebuild, ashift trio, noalloc,
  pspace). Trim/initialize state indices (30/39) are valid. Shorter array
  → the `.get()` decodes degrade.
- **Strict innvl validation (`zfs_keys_*`, introduced in 0.8)**: every key
  we pass was checked against 0.8.6's `zfs_ioctl.c` tables — send_new
  (`fd fromsnap largeblockok embedok compressok rawok`), recv_new
  (`snapname begin_record input_fd force resumable`), send_space (`from`),
  space_snaps (`firstsnap`), hold/release, create (`type props`),
  initialize/trim, load/unload_key (`hidden_args.wkeydata`, `noop`) — all
  accepted. No `ZFS_ERR_IOC_ARG_UNAVAIL` risk.
- `zpool history` record framing, `zbookmark_phys_t` error-log fill,
  `zfs_useracct_t` iteration: unchanged.

## Feature-level gaps (degrade already)

No error-scrub fields, no `head_errlog` pools, no vdev properties, 2.x
props → `EINVAL`/`?N`. ARC kstats differ per schema but the views are
field-presence driven.

## Verdict

**Supported** once the two pre-2.0 shims are active (see the kernel-version
probe in `ioctl.rs`). Encryption datasets work — 0.8 is the release that
introduced native encryption, and LOAD_KEY/UNLOAD_KEY sit at their modern
ordinals with the same innvl contract.
