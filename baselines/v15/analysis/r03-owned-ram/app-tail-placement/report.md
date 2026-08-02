# Official v15 R03 app-tail placement audit

Scope: official v15 only. This is static/package analysis only. No patch, flash, or device access was performed.

## Verdict

**BLOCK.** The apparent 383-byte app-area tail after `app.bin` is not unused. The official JLFS directory names it `cfg_tool.bin`, and its data range exactly equals the whole `app.bin`-to-`app_area_end` gap. Preserving JLFS/UFW/FWSC constraints leaves **0 available bytes** for appended R03 code there.

App/text is also **BLOCKED** as owned voice RAM. It is SFC/XIP code/read-only data, not a proven writable RAM allocation with R03 ownership, lifetime, valid, and generation semantics.

## Exact byte accounting

| range | start | end exclusive | bytes | disposition |
| --- | ---: | ---: | ---: | --- |
| `app.bin` in flash | `0x04120` | `0x9ab54` | 617012 | official app payload |
| naive app-area tail | `0x9ab54` | `0x9acd3` | 383 | occupied by `cfg_tool.bin` |
| post-app suffix | `0x9acd3` | `0x9c000` | 4909 | protected resources/reserved, outside app area |
| JLFS-preserving append capacity | n/a | n/a | **0** | no free bytes |

If the 383 bytes were contiguous app text, their runtime range would be `0x02096a34`..`0x02096bb3`. This mapping is not promoted because the official JLFS entry for `app.bin` ends before that range.

## JLFS evidence

| JLFS entry | header | data start | data end | size | overlaps naive tail |
| --- | ---: | ---: | ---: | ---: | --- |
| `app.bin` | `0x04020` | `0x04120` | `0x9ab54` | 617012 | no |
| `cfg_tool.bin` | `0x04040` | `0x9ab54` | `0x9acd3` | 383 | yes |
| `VM` | `0x04060` | `0xa0000` | `0xc4000` | 147456 | no |
| `PRCT` | `0x04080` | `0x04000` | `0xa0000` | 638976 | yes |
| `BTIF` | `0x040a0` | `0xc4000` | `0xc5000` | 4096 | no |
| `USRTRIM` | `0x040c0` | `0xc5000` | `0xc6000` | 4096 | no |
| `USRFLASH` | `0x040e0` | `0xc6000` | `0xef000` | 167936 | no |
| `USR` | `0x04100` | `0xf8000` | `0x102000` | 40960 | no |

The `cfg_tool.bin` row starts at `0x9ab54`, ends at `0x9acd3`, and has size `0x17f`/383 bytes. That is exactly the naive app-area tail.

## Loader and packer implications

- The app-area header entry point is `0x02000120`, and the public SDK SFC layout places code/read-only data in the `0x020xxxxx` XIP region.
- The official package contains encrypted bytes through `app_area_end`, so a raw SFC mapping might be contiguous, but the JLFS `app.bin` logical file is only 617012 bytes. Offline evidence does not prove that code past `app.bin` is a safe executable app target.
- `tools/smk37_v15_app_patch.py` intentionally enforces the official `app.bin` size and only replaces bytes inside `app.bin` plus CRC fields. The current stock packer cannot write this tail.
- A modified packer that only increases `app.bin.size` would overlap `cfg_tool.bin`. Preserving JLFS would require moving/removing a named official file and auditing all consumers, which is outside the safety envelope.
- Extending beyond `app_area_end` would change the protected `post_app_resources_and_reserved` suffix and app-area size/CRC assumptions.

## Branch ranges and relocation

6-byte PI32 `call32` sites can numerically reach the tail candidate, but this does not make the target safe or free:

| source | at | target | displacement | fits | encoding if used |
| --- | ---: | ---: | ---: | --- | --- |
| `note_on_memcpy_callsite_to_tail` | `0x0201c67c` | `0x02096a34` | 500658 | True | `80ffb2a30700` |
| `note_off_memcpy_callsite_to_tail` | `0x0201c63e` | `0x02096a34` | 500720 | True | `80fff0a30700` |
| `existing_code_cave_to_tail` | `0x0201e13e` | `0x02096a34` | 493808 | True | `80fff0880700` |
| `tail_to_memcpy_if_call_at_tail_start` | `0x02096a34` | `0x02048cce` | -318828 | True | `80ff9422fbff` |
| `tail_to_factory_loader_if_call_at_tail_start` | `0x02096a34` | `0x02005660` | -594906 | True | `80ff26ecf6ff` |

Local `jne_imm7` branches cover [-256, 255] halfwords, or [-512, 510] bytes from PC+4. A 383-byte local wrapper could fit this branch range if the storage were free.
The 4-byte `bfea` short-call model is window-limited to `131072` bytes. Post-init `0x02005f9c` and tail `0x02096a34` are in the same 0x20000 window: **False**. Direct post-init short-call-to-tail is BLOCKED, and R03 rules prohibit new early/post-init hooks without a separate boot proof.
Prior R01d wrapper code was 150 bytes, which would fit 383 bytes if the tail were free. It is not free. Any relocation must regenerate all call32 displacements, local branches, and `mov_imm32` literals, and must separately audit window-limited short calls.

## Changed sectors and risks

| hypothetical change | sectors | risk |
| --- | --- | --- |
| tail bytes only | `0x9a000` | overwrites `cfg_tool.bin`; same sector also contains protected suffix after `0x9acd3` |
| JLFS header/app entry CRC or size fields | `0x04000` | changes app-area metadata and requires exact CRC/header revalidation |
| app extension to flash end | `0x9a000, 0x9b000` | changes protected post-app resources/reserved bytes |

## PASS/BLOCK matrix

| use | decision | reason |
| --- | --- | --- |
| append R03 executable code to official app.bin by consuming the app-area tail | **BLOCK** | The entire 383-byte app.bin-to-app-area gap is cfg_tool.bin data in the official JLFS directory, not free padding. |
| overwrite cfg_tool.bin tail bytes and branch/call into them | **BLOCK** | This destroys or repurposes a named official JLFS file with no proof that cfg_tool.bin is unused at boot/update/runtime. |
| extend app.bin past the app-area end toward flash.bin end | **BLOCK** | Bytes after app_area_end are protected post-app resources/reserved data and are outside the app_area_head size/CRC envelope. |
| modified packer that only updates app.bin size/CRC | **BLOCK** | Changing only app.bin size overlaps cfg_tool.bin. Preserving JLFS would also require moving/removing cfg_tool.bin and auditing its consumers. |
| current stock v15 application-only packer for tail placement | **BLOCK** | tools/smk37_v15_app_patch.py enforces fixed app.bin size 617012 and replace_app_bytes() can change only app.bin bytes plus JLFS CRC fields. |
| app/text or tail as owned, data-writable voice RAM | **BLOCK** | The 0x02000000 app/text range is SFC/XIP code/read-only data, not a proven writable RAM allocation with owner, lifetime, valid, and generation semantics. |

## Validation

| check | status | detail |
| --- | --- | --- |
| official-package-sha256 | PASS | `f7f1831cd7c9ad8b4831b6e71ea0bdbcdff9ae4c4077276b3c965511bf4d4fff` |
| official-app-sha256 | PASS | `36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055` |
| manifest-package-binding | PASS | `f7f1831cd7c9ad8b4831b6e71ea0bdbcdff9ae4c4077276b3c965511bf4d4fff` |
| manifest-app-binding | PASS | `36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055` |
| app-area-tail-arithmetic | PASS | `{"bytes": 383, "end_exclusive": "0x9acd3", "start": "0x9ab54"}` |
| cfg-tool-occupies-entire-app-area-tail | PASS | `{"data_crc16": "0x2e75", "data_flash_end_exclusive": "0x9acd3", "data_flash_start": "0x9ab54", "data_offset_relative_to_app_area": "0x96b54", "flags": "0x82", "header_flash_offset": "0x04040", "index": 0, "name": "cfg_tool.bin", "overlaps_app_tail_candidate": true, "reserved": "0xff", "size": 383}` |
| jlfs-preserving-available-bytes | PASS | `0` |
| all-decisions-block | PASS | `{"app/text or tail as owned, data-writable voice RAM": "BLOCK", "append R03 executable code to official app.bin by consuming the app-area tail": "BLOCK", "current stock v15 application-only packer for tail placement": "BLOCK", "extend app.bin past the app-area end toward flash.bin end": "BLOCK", "modified packer that only updates app.bin size/CRC": "BLOCK", "overwrite cfg_tool.bin tail bytes and branch/call into them": "BLOCK"}` |

## Reproduce

```sh
python3 baselines/v15/analysis/r03-owned-ram/app-tail-placement/analyze_app_tail_placement.py
cd baselines/v15/analysis/r03-owned-ram/app-tail-placement
shasum -a 256 -c SHA256SUMS
```

Generated files: `analyze_app_tail_placement.py`, `evidence.json`, `validation.txt`, `report.md`, `SHA256SUMS`.
