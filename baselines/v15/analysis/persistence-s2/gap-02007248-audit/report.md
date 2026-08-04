# v15/S1C5 gap 0x02007248 audit: REFUTED

## Decision

**REFUTE PROMOTION.** The exact `0x02007248..0x02007390` region is 328 bytes (`0f91e6223173e3fb01f63f0de60f58fe5cfe251dfedaebb81769c0b3bc580b66`), but it is not proved owned or free. Quarkslab exhaustive has a hole after `0x02007242: call 0x02063260`, yet Quarkslab recursive decodes `133` rows through the target and Kagaimiq decodes `122` rows with internal branch reach. No firmware/FWSC/OTA/device artifact was emitted.

## Exact bytes and signatures

- Runtime range: `0x02007248..0x02007390`
- App offsets: `0x07248..0x07390`
- FWSC app-data flash offsets: `0x0b368..0x0b4b0`
- Byte profile: `17` zero bytes, `7` `ff` bytes, `95` unique byte values, entropy `5.946` bits/byte.
- ASCII runs >=4: `[{'offset': 13, 'address': '0x02007255', 'text': 'AE da'}, {'offset': 24, 'address': '0x02007260', 'text': '%@%RX'}, {'offset': 39, 'address': '0x0200726f', 'text': '`A$B D '}, {'offset': 53, 'address': '0x0200727d', 'text': '`A%B '}, {'offset': 85, 'address': '0x0200729d', 'text': '`A$B D '}, {'offset': 112, 'address': '0x020072b8', 'text': "'pa`"}, {'offset': 181, 'address': '0x020072fd', 'text': '`A B '}, {'offset': 241, 'address': '0x02007339', 'text': '`A#B '}, {'offset': 277, 'address': '0x0200735d', 'text': 'JeUPgP'}, {'offset': 285, 'address': '0x02007365', 'text': '`A#B '}]`
- Pointer-like words inside target: `14` heuristic hits; first five `[{'offset_in_gap': 44, 'source': '0x02007274', 'value': '0x00c32044', 'range': 'flash_mapped_or_mmio'}, {'offset_in_gap': 56, 'source': '0x02007280', 'value': '0x00c32042', 'range': 'flash_mapped_or_mmio'}, {'offset_in_gap': 90, 'source': '0x020072a2', 'value': '0x00c32044', 'range': 'flash_mapped_or_mmio'}, {'offset_in_gap': 122, 'source': '0x020072c2', 'value': '0x00041af6', 'range': 'flash_mapped_or_mmio'}, {'offset_in_gap': 154, 'source': '0x020072e2', 'value': '0x00c32241', 'range': 'flash_mapped_or_mmio'}]`.

The full byte string is in `evidence.json`; reproducible `gap-02007248.bin` and `gap-02007248.hex` artifacts are emitted beside this report.

## Decode, xrefs, branch reach, and boundaries

- Quarkslab exhaustive rows inside target: `0`. This is the only source of the apparent gap.
- Quarkslab recursive rows inside target: `133`. It starts exactly at `0x02007248` and continues to `0x0200738e`.
- Kagaimiq patched exhaustive rows inside target: `122`.
- Quarkslab recursive text xrefs into target: `26` total, `0` external-only.
- Kagaimiq patched text xrefs into target: `19` total, `0` external-only.
- Raw little-endian pointer hits to target in app: `1`; first hits `[{'source': '0x0204a190', 'value': '0x02007301', 'alignment': 0}]`.

Pre-gap boundary:

```text
0x02007242 80ff18c00500 call 0x02063260 CALL_TERMINATOR
```

Continuation/return assessment: No listing provides a positive decoded return proof for call target 0x02063260; this absence is not ownership/free evidence. Promotion still fails because the requested range itself is densely decoded by Quarkslab recursive and Kagaimiq, and no artifact proves it is dead or owned by the patch. The target start is not a function/data boundary: 0x02007248 is immediately after a call at 0x02007242, not a push/function prologue or data boundary. Quarkslab recursive treats it as fall-through continuation. Target end is not a safe terminus: 0x02007390 is where Quarkslab exhaustive resumes with another call, not a proven free-space terminus; recursive target rows end with internal goto 0x0200730a at 0x0200738e.

## Public SDK exact matches

Overlapping SDK exact matches: `[]`. Nearest exact SDK matches are `{'name': '_pow', 'start': '0x02004884', 'end_exclusive': '0x02004896', 'bytes': 18, 'sha256': '3f6c16c36e893d2b70eeacffaf5774f1693782380feae2c047fe18b03a6d75a8', 'distance_bytes': 10674}` and `{'name': 'sdfile_str_to_upper', 'start': '0x0202d7a6', 'end_exclusive': '0x0202d7c0', 'bytes': 26, 'sha256': '4bb7ab9ae94abdb00df6f6b9880bfc7a5c93a522d05f98a96213f8307c4f6313', 'distance_bytes': 156694}`. Result: No public SDK exact match owns or frees this region; SDK evidence does not permit promotion.

## Lifecycle audit

- `0x02005fa4` remains blocked for this body. It must preserve and call stock `0x020057e0`, then return to `0x02005fa8`, but this requested body placement is decoded executable continuation and has no positive ownership/free proof.
- First-note lazy restore remains design-only. Exact S1C5 selector/producer `0x0201e13e..0x0201e254` is preserved with SHA-256 `4293474041bd40b697be88dcdc936eb92a2b6ce6d20fb95dc2e9dcbe9205cae1`; no insertion point is approved.
- Safe lifecycle result: no manifest-gated restore body assembled, no FWSC/OTA emitted, no device/MIDI transport opened.

## Related exhaustive-listing gaps >=300 bytes

| Rank | Range | Bytes | Quarkslab recursive rows | Kagaimiq rows | Preliminary decision |
|---:|---:|---:|---:|---:|---|
| 1 | `0x02016a88..0x02016ce2` | 602 | 0 | 148 | unproved listing hole; requires positive ownership/free proof before promotion |
| 2 | `0x02039be6..0x02039e2a` | 580 | 186 | 139 | unproved listing hole; requires positive ownership/free proof before promotion |
| 3 | `0x0202bc62..0x0202be5a` | 504 | 164 | 126 | unproved listing hole; requires positive ownership/free proof before promotion |
| requested target | `0x02007248..0x02007390` | 328 | 133 | 122 | unproved listing hole; requires positive ownership/free proof before promotion |

## Reproduce

```sh
python3 baselines/v15/analysis/persistence-s2/gap-02007248-audit/analyze_gap_02007248.py --check
python3 baselines/v15/analysis/persistence-s2/gap-02007248-audit/validate.py
(cd baselines/v15/analysis/persistence-s2/gap-02007248-audit && shasum -a 256 -c SHA256SUMS)
```
