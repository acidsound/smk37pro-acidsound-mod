# v15 final-pass renderer indirect-call graph audit

## Scope
- Official app: `build/v15-official-app.bin`
- SHA-256 gate: `36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055`
- Static only. Firmware patch/flash was not performed.
- Inputs include existing `ui-preflash/renderer` and `ui-preflash/followup` artifacts plus Quarkslab/Kagaimiq recursive/exhaustive listings.

## Result
- **No evidence-backed direct or named indirect path** was recovered from `0x02020376` or `0x0201a67c` to `0x0200f74c` or `0x0201e06c` in any checked listing.
- The known partial chain remains: `0x02020376` computes `0x02058314` (`Keys Channel-` descriptor entry) and calls `0x0201a67c` as a string/object setter.
- `0x0201a67c` can call `0x0201a1bc` after replacing `[object+0x24]`, but this final pass does not find a defensible continuation from that helper to `0x0200f74c` or `0x0201e06c`.
- `0x0200f74c` still looks like an object render traversal candidate because it invokes callbacks loaded from object/context fields and then calls `0x0200f412`/`0x0200f734`; it is not reached from the requested starts by evidence-backed graph traversal.
- Final LCD/pixel write remains **not recovered**. The ST7789-like byte run is not promoted because independent write-path xrefs are absent and the known `0x02058b50` overlap remains contradictory.

## Cross-listing path counts
| listing | rows | paths from starts to targets | computed calls |
| --- | --- | --- | --- |
| quarkslab_recursive | 51089 | 0 | 234 |
| quarkslab_exhaustive | 112211 | 0 | 428 |
| kagaimiq_patched_recursive | 1893 | 0 | 14 |
| kagaimiq_patched_exhaustive | 91248 | 0 | 650 |

## Direct target callers in primary exhaustive listing
| target | caller count | caller functions |
| --- | --- | --- |
| render_traversal_0200f74c | 5 | -<br>FUN_02010038@02010038<br>FUN_0201606c@0201606c |
| redraw_dirty_queue_0201e06c | 50 | -<br>FUN_0201e254@0201e254<br>FUN_02023376@02023376<br>FUN_020233f6@020233f6<br>FUN_02023b2c@02023b2c<br>FUN_0202427e@0202427e<br>FUN_02024368@02024368<br>FUN_0202443e@0202443e |

## Focus computed-call sources
| callsite | function | source | classification |
| --- | --- | --- | --- |
| 0x0200f71e | FUN_0200f710@0200f710 | r0+0xc -> r2 | object/vtable-field callback candidate |
| 0x0200f746 | FUN_0200f73a@0200f73a | r0+0x14 -> r4 | object/vtable-field callback candidate |
| 0x0200f770 | FUN_0200f74c@0200f74c | unresolved | not promoted |
| 0x0201ea90 | FUN_0201ea80@0201ea80 | r4+0x0 -> r2 | object/vtable-field callback candidate |
| 0x0201eaae | FUN_0201ea94@0201ea94 | r5+0x4 -> r2 | object/vtable-field callback candidate |
| 0x020233e6 | FUN_02023376@02023376 | r1 + r0<<2 -> r0 | indexed raw-table callback candidate |

Computed-call source histogram in all primary exhaustive rows:
```json
{
  "0x0": 16,
  "0x10": 14,
  "0x14": 9,
  "0x18": 13,
  "0x1c": 7,
  "0x20": 4,
  "0x24": 5,
  "0x28": 6,
  "0x2c": 4,
  "0x30": 1,
  "0x34": 5,
  "0x38": 2,
  "0x3c": 3,
  "0x4": 36,
  "0x8": 25,
  "0xc": 16,
  "indexed_word_load": 11,
  "unresolved": 251
}
```

## Raw table checks
### `0x02023376` computed-call table candidate at `0x02057e30`
| slot | entry | value | target function | promotion |
| --- | --- | --- | --- | --- |
| 0 | 0x02057e30 | 0x00000000 | - | not-promoted |
| 1 | 0x02057e34 | 0x00000000 | - | not-promoted |
| 2 | 0x02057e38 | 0x02017a50 | - | not-promoted |
| 3 | 0x02057e3c | 0x02017a1c | - | not-promoted |
| 4 | 0x02057e40 | 0x00070024 | - | not-promoted |
| 5 | 0x02057e44 | 0x0004fb00 | - | not-promoted |
| 6 | 0x02057e48 | 0x0204ff40 | - | not-promoted |

Only slots that point into named listing functions are code-pointer candidates. Other slots are not promoted.

### Descriptor entries
| entry | slot0 | slot1 | slot2 | slot3 |
| --- | --- | --- | --- | --- |
| Firmware_descriptor_entry | 0x0205d8f5 Firmware# | 0x0205d8f9 ware# | 0x0205d8fe  | 0x0205d902  |
| Pad_Bank_descriptor_entry | 0x0205d9c5 Pad Bank- | 0x0205d9ce  | 0x0205d9d7 tor- | 0x0205d9e0  Repeat- |
| Keys_Channel_descriptor_entry | 0x0205d9e9 Keys Channel- | 0x0205d9f2 nel- | 0x0205d9f9 ds Channel- | 0x0205da03 - |

## LCD/final draw status
- No raw 32-bit pointer refs to 0x0200f74c, 0x0201e06c, 0x0200f412, or 0x0200f734 exist in the official app bytes.
- The ST7789-like byte run at 0x02058aec remains byte-pattern-only; listing references include the known overlap around 0x02058b50, so it is not promoted to an LCD init table or write path.
- Computed calls are recorded with source offsets, but their runtime targets are not statically resolved to final LCD/draw functions without additional evidence.

## Reproduce
```sh
python3 baselines/v15/analysis/ui-preflash/final-pass/renderer/trace_renderer_paths.py
python3 - <<'PY'
import json
from pathlib import Path
p=Path('baselines/v15/analysis/ui-preflash/final-pass/renderer/renderer-trace.json')
d=json.loads(p.read_text())
print(d['conclusions']['direct_or_named_indirect_path_from_02020376_to_0200f74c_or_0201e06c'])
print(d['conclusions']['lcd_or_final_pixel_write_status'])
PY
```

Machine-readable output: `renderer-trace.json`.
