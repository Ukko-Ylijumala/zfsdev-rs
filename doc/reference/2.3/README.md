# OpenZFS 2.3 reference sources

Vendored from the `zfs-2.3.0` tag, kept separate from the 2.2.2 sources in
the parent directory. These are here for **future work** — the project's
ABI/format code currently targets 2.2.2.

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
