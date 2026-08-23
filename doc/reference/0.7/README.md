# ZoL 0.7 reference sources — NOT SUPPORTED (potential future addition)

Vendored from the `zfs-0.7.13` tag (the last 0.7.x release — EL7's kmod
era, Ubuntu 18.04). 0.7 support is **not implemented**; this documents what
it would cost, so the decision can be made if a real 0.7 host ever matters.

## Headers

Same set as `../2.1`: `zfs_ioctl.h`, `dmu.h`, `zfs_stat.h`, `zfs.h`.

## ABI facts (surprisingly good)

- **`zfs_cmd_t`**: same story as 0.8 — only the trailing `zc_zoneid` is
  missing (13736 bytes), safe with the 13744 mirror as-is.
  `zinject_record_t` has `zi_pad` where 2.x has `zi_dvas` — same size, no
  offset impact. `drr_begin`/`zfs_stat_t`/`zfs_share_t`/`zfs_useracct_t`
  identical.
- **Ordinals**: every ioctl we issue that exists sits at the identical
  number (the platform-range enum predates 0.7). Missing —
  `LOAD_KEY`/`UNLOAD_KEY` (0x49/0x4a), `POOL_INITIALIZE`/`POOL_TRIM`
  (0x4f/0x50), `VDEV_GET/SET_PROPS` (0x55/0x56). All six ordinals fall in
  **unassigned** space between `ZFS_IOC_POOL_SYNC` (0x47, 0.7's last legacy
  entry) and the 0x80 platform base → clean kernel rejection, no aliasing.
- **`dmu_objset_stats_t`**: same pre-2.0 `dds_redacted`/`dds_origin` shift
  as 0.8 — the shared shim covers it.
- No strict innvl validation yet (`zfs_keys` arrived in 0.8): unknown keys
  in our innvls are silently ignored. Semantic note: `compressok` exists
  (0.7 added compressed send) but `rawok` does not — a "raw" send of an
  encrypted dataset can't arise (0.7 has no encryption).

## What actual support would need (beyond the 0.8 shims)

1. **`vdev_stat_t` index remap**: `vs_initialize_errors` was *inserted*
   (not appended) by 0.8 right after the checksum-error counter, so on
   ≤ 0.7 every u64 index ≥ 23 shifts down by one (`vs_self_healed` 24→23,
   `vs_scan_processed` 26→25, `vs_fragmentation` 27→26; the array ends
   there — no queue depths beyond, no init/trim/rebuild state, no slow-IO
   or ashift fields). `vdev_stat_rows` and the trim/init/offline gates in
   `node.rs` would need the pre-0.8 index table.
2. **Scrub progress fallback**: `pool_scan_stat_t` ends at
   `pss_pass_scrub_spent_paused` (13 fields) — no `pss_pass_issued`/
   `pss_issued` (0.8's scrub rewrite). Progress/rate/ETA must key off
   `pss_examined`/`pss_pass_exam` instead of showing zeros.
3. **UX gating**: trim/initialize/load-key keybindings fail with a clean
   kernel error today; a version gate should not offer them at all.

## Verdict

Moderate but bounded — the shims are display-layer only, no versioned
`zfs_cmd_t`. Do it if a real 0.7 host materializes; not before.
