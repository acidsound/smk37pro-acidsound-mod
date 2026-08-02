# Official v15 app.bin extension audit

Status: **BLOCK**. No firmware candidate, flashing, OTA, reset, or device access was used.

## Answer

The exact official v15 `app.bin` cannot be safely extended beyond `0x96a34` under the requested constraints. The maximum extension that preserves every stock byte at its official physical address is **0 bytes**.

Positive runtime evidence exists for the current SFC/XIP app image, not for bytes appended after the JLFS `app.bin` logical file. Bytes after `app.bin` are either named stock JLFS content (`cfg_tool.bin`) or protected post-app bytes outside the `app_area_head` CRC envelope. Therefore appended bytes are **not proven readable/executable app bytes** at runtime.

## Exact byte accounting

| Region | Start | End exclusive | Size | Owner/classification |
|---|---:|---:|---:|---|
| official `app.bin` | `0x04120` | `0x9ab54` | `0x96a34` | JLFS `app.bin` |
| naive tail after app | `0x9ab54` | `0x9acd3` | `383` | `cfg_tool.bin` |
| post app-area to flash.bin end | `0x9acd3` | `0x9c000` | `4909` | protected post-app resources/reserved bytes, outside app_area_head CRC envelope |

The first byte after `app.bin` (`0x9ab54`) is also the first byte of `cfg_tool.bin`. The current `app_area_head` ends at `0x9acd3`; the remaining `0x132d` bytes before UFW `flash.bin` end are protected post-app bytes, not part of the app-area JLFS envelope.
The protected post-app range is not empty padding: SHA-256 `53718db6501441b091aeb48e21eedd480faebcae4743add53d1ae36d57b327e7`, byte counts `{'00': 5, 'ff': 1996, 'other': 2908}`, first 32 bytes `3a25ec28260c18117a0d2d7b75c84ebf1d9abe93f8d0802041a2458b364c9933`.

## Header evidence

| Header | Fact |
|---|---|
| UFW `flash.bin` | offset `0x400`, size `0x9c000` |
| app_area_head | entry/offset `0x02000120`, size `0x96cd3`, end `0x9acd3` |
| JLFS `app.bin` | offset `0x00120`, physical `0x04120..0x9ab54`, size `0x96a34`, CRC valid `True` |
| JLFS `cfg_tool.bin` | offset `0x96b54`, physical `0x9ab54..0x9acd3`, size `0x17f`, CRC valid `True` |
| JLFS `VM` | offset `0x9c000`, physical `0xa0000..0xc4000`, size `0x24000`, CRC valid `not in flash.bin` |
| JLFS `PRCT` | offset `0x00000`, physical `0x04000..0xa0000`, size `0x9c000`, CRC valid `not in flash.bin` |
| JLFS `USRFLASH` | offset `0xc2000`, physical `0xc6000..0xef000`, size `0x29000`, CRC valid `not in flash.bin` |
| JLFS `USR` | offset `0xf4000`, physical `0xf8000..0x102000`, size `0xa000`, CRC valid `not in flash.bin` |

## Decision matrix

| Claim | Decision | Max/nominal bytes | Reason |
|---|---|---:|---|
| Extend exact official app.bin while leaving every stock flash byte at its official physical offset | **BLOCK** | `0` | The first byte after app.bin is the first byte of named JLFS file cfg_tool.bin. Any positive extension changes stock flash bytes at or after 0x9ab54. |
| Extend app.bin by only increasing app.bin.size inside current app_area_head envelope | **BLOCK** | `0` | app.bin end 0x9ab54 equals cfg_tool.bin start 0x9ab54; the 383-byte apparent tail is fully occupied by cfg_tool.bin. |
| Preserve cfg_tool.bin logical bytes by relocating it toward flash.bin end and growing app_area_head | **BLOCK** | `4909` | This moves a named stock JLFS file, changes app.bin/cfg_tool/app_area_head CRC/size/offset headers, consumes protected post-app bytes, and lacks boot/loader/runtime consumer proof. |
| Grow UFW flash.bin past 0x9c000 | **BLOCK** | `0` | The next UFW payload entry starts immediately at flash.bin end 0x9c400, and the UFW payload has no trailing gap after tail.bin. |
| Appended bytes beyond official app.bin are positively proven readable/executable at runtime | **BLOCK** | `n/a` | Official and public evidence support SFC/XIP execution for the current app image, but no exact v15 loader/MPU/cache proof promotes cfg_tool.bin or post-app protected bytes as app-owned executable targets. |

## Runtime mapping, loader, and XIP evidence

- Current app runtime model: `0x02000000`, official app range `0x02000000..0x02096a34`.
- If raw-contiguous mapped, `cfg_tool.bin` would be `0x02096a34..0x02096bb3`. This is not promoted because JLFS names it `cfg_tool.bin`, not `app.bin`.
- If raw-contiguous mapped, the post-app gap would be `0x02096bb3..0x02097ee0`. This is not promoted because it is outside `app_area_head` size/CRC.
- Public AC79/WL82 `sdk_ld_sfc.c` at pinned commit `e30b1ee375d1f2993fc23bf92c8b99006a6e5f9d` defines `rom(rx) ORIGIN = 0x02000120, LENGTH = __FLASH_SIZE__`, puts `.text*` and `.rodata*` in `rom`, and defines RAM LMAs after text. This supports the SFC/XIP model for a linked image.
- Public `isd_config_rule.c` at the same commit selects `ENTRY=0x2000120` for SFC mode and includes `FORCE_4K_ALIGN=YES`. This matches the exact v15 `app_area_head` entry, but does not prove bytes outside official `app.bin` are executable app-owned bytes.
- The exact official U-Boot/ISD raw regions are preserved/protected by existing packer evidence. The recovered raw ISD strings include SPI and clock configuration, but no exact v15 loader bound was recovered that authorizes appended post-app code.

## CRC, size, alignment, cache/MPU, branch, resources, rollback

- Fixed-size app patches update only `app.bin` data CRC, `app_area_head` data/header CRC, UFW flash.bin data CRC, UFW entry-list CRC, and UFW header CRC. The official repacker rejects any app size change.
- Any real extension would additionally change `app.bin.size`; preserving `cfg_tool.bin` would change its offset/header CRC; extending beyond `app_area_head` would change `app_area_head.size`; growing UFW `flash.bin` would collide with UFW `USR` at payload offset `0x9c400`.
- Cache/MPU: public SDK uses I-cache/D-cache/MMU/TLB concepts, but no exact v15 cache/MPU bound proves instruction fetch from appended bytes after `app.bin`.
- Entry/branch reach: the entry point is inside current app.bin. Since safe extension size is 0, no tail branch target is promoted. Prior S1-C2 placement evidence requires exact branch/call bytes and ownership proof before reach is accepted.
- Resources: immediate extension overwrites `cfg_tool.bin`; extension to flash end consumes protected post-app resources/reserved bytes; UFW flash.bin growth overlaps the UFW `USR` entry.
- Rollback sectors for a hypothetical tail/post-app mutation: `0x9a000, 0x9b000`. Rollback sector availability does not make the extension safe.

## Validation

- PASS `official-fwsc-sha`: f7f1831cd7c9ad8b4831b6e71ea0bdbcdff9ae4c4077276b3c965511bf4d4fff
- PASS `official-app-sha`: 36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055
- PASS `app-file-equals-jlfs-app-bytes`: 617012 bytes
- PASS `app-size-is-0x96a34`: 0x96a34
- PASS `cfg-tool-starts-at-app-end`: 0x9ab54 == 0x9ab54
- PASS `cfg-tool-consumes-naive-app-tail`: 0x9ab54..0x9acd3
- PASS `flash-bin-has-no-gap-before-next-ufw-entry`: flash.bin aligned end 0x9c400; USR starts 0x9c400
- PASS `checkable-jlfs-data-crcs-valid`: app.bin/cfg_tool.bin checkable in flash.bin; out-of-flash JLFS data entries have 0xffff CRC placeholders
- PASS `app-area-entry-point`: 0x02000120
- PASS `app-area-size`: 0x96cd3

Reproduce:

```sh
python3 baselines/v15/analysis/patch-set-ui/s1c2-unblock/app-extension/analyze_app_extension.py
shasum -a 256 -c baselines/v15/analysis/patch-set-ui/s1c2-unblock/app-extension/SHA256SUMS
```
