# R03 owned RAM candidate audit for official v15

Scope: exact official v15 only. This analysis reads the official app/package,
Quarkslab/Kagaimiq listings, and existing v15-only runtime-source, SysEx-staging,
and UI-state evidence. It performs no patching, flashing, device access, or v12-derived reasoning.

## Verdict

**R03 RAM Gate A remains BLOCKED.** No evaluated RAM candidate PASSes. The only
shape that satisfies the desired R03 policy is a hypothetical owned copy buffer,
but this pass did not find a defensible official-v15 address, allocation owner,
lifetime, and writer-overlap proof for it.

This is intentional: the requirements explicitly hard-BLOCK claims based only on
absence of decoded xrefs. Apparent gaps in zeroed BSS, UI RAM, or product RAM are
therefore not promoted to free RAM.

## Input hashes

| input | sha256 |
| --- | --- |
| app | `36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055` |
| package | `f7f1831cd7c9ad8b4831b6e71ea0bdbcdff9ae4c4077276b3c965511bf4d4fff` |
| manifest | `21041cf36426923c81e1d5c583af928b74aed43b4661dadb81a26ad9349e00a8` |
| quarkslab_exhaustive | `f51e384f5f0efc415f321bbfbbe15d051301953338191282872807dcf8683347` |
| kagaimiq_patched_exhaustive | `814510c15ba600c7420026204c5f4121bce6a5d074422cc20204755d3280e013` |
| runtime_source_trace | `bc619891389c9f1183b36686b706a67136a8852a0de3e8b0fdd6c21d75022d4c` |
| runtime_source_report | `cafbbf22c4f9751a0134ecb0ab9734d6c62be4e5f06cbcb34448e70d8c308932` |
| runtime_writer_inventory | `4f7d3effa0024f5742b568c4eedf8280707693ba43ee1c23598b6bf32dd690c6` |
| sysex_staging_trace | `9cb78c3149b78c5c56569a6e17ef4f36b6c73f25a2bed018bbc2c0d1c0f6b655` |
| sysex_staging_report | `cfabba55680bbee2f699316547ef28ec496434d886a3b2edf4d7e3a421c8d6f8` |
| ui_final_pass_events | `f1d2b68448ad426e3a4f915efc7b9c9fb446261d7974693a466ced8a68955f78` |
| ui_final_pass_report | `1db782f6cc39b85b109af39999915bb8a4d7cf7233cb0bff77227d8f41b0537d` |
| r03_requirements | `0cce1eccb7803be71c91489ee9ce4e2af2358f656bf0124ab877f6604d02653a` |
| post_r02_roadmap | `2dd1879a6020096804bb21fe538dabb81bf3c1b71cd1a225c69b9cbf34facb12` |

## Candidate decisions

| candidate | decision | range/base | primary blockers |
| --- | --- | --- | --- |
| `stock_current_snapshot_0x01c34c74` | **BLOCK** | 0x01c34c74 | Fails immutability: UI patch selection and supported SysEx intentionally rewrite this range.<br>Fails metadata ownership: +0x9c..+0xa2 belongs to the stock 0xa3 current record/tail.<br>Using it would repeat shared-current behavior instead of surviving Ch1 UI changes. |
| `sysex_staging_0x01c37fd0` | **BLOCK** | 0x01c37fd0 | Later supported SysEx traffic can overwrite the Note Off source.<br>Existing sysex-staging analysis explicitly classifies it as transient and unsafe as permanent voice storage.<br>Metadata placed adjacent to stage has no owner/allocation proof and may collide with larger staging paths. |
| `dispatcher_per_voice_slot_engine_plus_index_times_0xa0_plus_0xa2` | **BLOCK** | dynamic | Not a fixed source address that future Note On/Off can reread.<br>Owned by active voice records and voice stealing, not by an immutable Ch10 buffer.<br>Cannot publish/reject reloads independently from the stock allocator. |
| `ui_alt_block_or_gap_near_0x01c34894` | **BLOCK** | 0x01c34894 | Gate A hard-blocks absence-only free-RAM claims.<br>The alias is proven UI-owned, not free or Ch10-owned.<br>Computed/table UI paths and pointer fields prevent a bounded no-alias proof from static listing alone. |
| `product_ram_stride_workspace_0x01c0de20` | **BLOCK** | 0x01c0de20 | Dynamic index and UI ownership mean it cannot be treated as a session-stable Ch10 buffer.<br>No bounded allocation map identifies a free 0xa0 subrange inside the stride.<br>Stack/heap/DMA/storage aliases are not excluded by the static evidence. |
| `generic_zeroed_bss_gap` | **BLOCK** | 0x01c099d4 | Fails Gate A.4/A.5/A.6 ownership and alias exclusions.<br>Would be an absence-of-xrefs claim, which is a mandatory BLOCK.<br>Stack pointers are visible in the same broad memory span, so blind placement is unsafe. |
| `hypothetical_r03_owned_copy_buffer` | **BLOCK** | dynamic/none | No exact start/end address.<br>No bounded allocation or owner/lifetime proof.<br>No static proof excluding DMA/heap/stack/task/USB/UI/audio/storage aliases. |

## Candidate notes

### `stock_current_snapshot_0x01c34c74`: BLOCK

The stock dispatcher copies `0x9c` bytes from `0x01c34c74` on both Note On and
Note Off, but runtime-source evidence shows the same bytes are the mutable
current Patch snapshot at `0x01c33260+0x1a14`. Known overlapping stock writers
include the selected-record loader, the bulk SysEx path followed by reload,
single-parameter writes, bounded field setters for `+0x86/+0x87`, and a UI-mode
reset of `+0x9a`. Metadata at `+0x9c` would also overlap the stock `0xa3` current
record tail.

### `sysex_staging_0x01c37fd0`: BLOCK

The official handler can materialize the R02-proven `0x9c` single-voice payload
at `0x01c37030+0xfa0`, but sysex-staging evidence classifies it as a transient
assembly workspace. Complete, segmented, and other bulk paths overwrite it. It
has no valid/generation state and cannot be the Note Off source after later
supported product SysEx traffic.

### `dispatcher_per_voice_slot_engine_plus_index_times_0xa0_plus_0xa2`: BLOCK

The per-voice destination already has the right local shape, `0x9c` copied tone
bytes plus four stock metadata bytes in a `0xa0` stride. It is not a stable source
buffer. It is owned by the official voice allocator/audio engine, may be reused
or stolen, and the four metadata bytes are not available for R03 validity.

### `ui_alt_block_or_gap_near_0x01c34894`: BLOCK

The final-pass UI evidence recovers two direct base loads of `0x01c34894` and
handlers that write `[base+0]` and `[base+1]`. A gap after those bytes is not an
allocation. Because this address is UI-owned and static evidence cannot bound all
computed/table UI aliases, claiming `0x01c34896..+0xa0` would be absence-only.

### `product_ram_stride_workspace_0x01c0de20`: BLOCK

The `0x49e3` product RAM stride is large, but it is a UI/product workspace with
dynamic selection and observed handlers at `+0xa7e`, `+0xa7f`, `+0x116`, and row
iteration paths. No Ch10-owned suballocation or no-alias proof exists.

### `generic_zeroed_bss_gap`: BLOCK

Boot rows zero `0x01c099d4` for `0x3cb48` bytes, and stack pointers are also
initialized inside or near this broad span. Zero-on-boot is initialization, not
ownership. Without a linker/allocation map or runtime watch proving heap, stack,
DMA, task, USB, UI, audio, and storage cannot alias a chosen subrange, every
specific gap in this span remains BLOCKED.

### `hypothetical_r03_owned_copy_buffer`: BLOCK pending proof

The desired R03 policy is still valid: start invalid at boot, copy exactly `0x9c`
from staging only after an accepted exact packet, publish valid/generation after
copy, keep immutable, and reject reload while Ch10 is active unless per-active
note generation is proven. This audit did not find the required exact RAM range.

## Validation

| check | status | detail |
| --- | --- | --- |
| official-v15-app-sha256 | PASS | 36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055 |
| official-v15-package-sha256 | PASS | f7f1831cd7c9ad8b4831b6e71ea0bdbcdff9ae4c4077276b3c965511bf4d4fff |
| quarkslab-exhaustive-sha256 | PASS | f51e384f5f0efc415f321bbfbbe15d051301953338191282872807dcf8683347 |
| kagaimiq-patched-exhaustive-sha256 | PASS | 814510c15ba600c7420026204c5f4121bce6a5d074422cc20204755d3280e013 |
| manifest-app-binding | PASS | 36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055 |
| manifest-package-binding | PASS | f7f1831cd7c9ad8b4831b6e71ea0bdbcdff9ae4c4077276b3c965511bf4d4fff |
| current-alias-arithmetic | PASS | 0x01c33260+0x1a14=0x01c34c74 |
| sysex-stage-arithmetic | PASS | 0x01c37030+0x0fa0=0x01c37fd0 |
| r03-requires-metadata | PASS | 0xa0 |
| all-candidates-explicitly-decided | PASS | {"dispatcher_per_voice_slot_engine_plus_index_times_0xa0_plus_0xa2": "BLOCK", "generic_zeroed_bss_gap": "BLOCK", "hypothetical_r03_owned_copy_buffer": "BLOCK", "product_ram_stride_workspace_0x01c0de20": "BLOCK", "stock_current_snapshot_0x01c34c74": "BLOCK", "sysex_staging_0x01c37fd0": "BLOCK", "ui_alt_block_or_gap_near_0x01c34894": "BLOCK"} |
| no-pass-without-owned-allocation | PASS | [] |
| stock-current-direct-xref-known | PASS | {"count": 1, "refs": ["0x0201c604"], "value": "0x01c34c74"} |
| sysex-stage-not-direct-immediate | PASS | {"count": 0, "refs": [], "value": "0x01c37fd0"} |
| ui-alt-base-direct-immediates | PASS | {"count": 2, "refs": ["0x02029a22", "0x02029a58"], "value": "0x01c34894"} |

## Reproduce

```sh
python3 baselines/v15/analysis/r03-owned-ram/ram-ownership/analyze_ram_ownership.py
cd baselines/v15/analysis/r03-owned-ram/ram-ownership
shasum -a 256 -c SHA256SUMS
```

Generated files:

- `analyze_ram_ownership.py`
- `evidence.json`
- `access_windows.tsv`
- `validation.txt`
- `report.md`
- `SHA256SUMS`
