# v15/S1C5 gap 0x02016a88 audit: REFUTED

## Decision

**REFUTE PROMOTION.** The exact `0x02016a88..0x02016ce2` region is 602 bytes (`6553ba46b3a949db3774ccc60795500983313f5fa38b66e7bab173aee8b958c7`), but it is not proved owned or free. It is executable/caller continuation after `0x02016a84: call 0x0200ad74`; the callee has normal `pop {pc,...}` returns at `0x0200add8, 0x0200addc, 0x0200ae0a, 0x0200ae18`. No firmware/FWSC/OTA/device artifact was emitted.

## Exact bytes and signatures

- Runtime range: `0x02016a88..0x02016ce2`
- App offsets: `0x16a88..0x16ce2`
- FWSC app-data flash offsets: `0x1aba8..0x1ae02`
- Byte profile: `32` zero bytes, `6` `ff` bytes, `162` unique byte values, entropy `6.654` bits/byte.
- ASCII runs >=4: `[{'offset': 71, 'address': '0x02016acf', 'text': ' A `'}, {'offset': 462, 'address': '0x02016c56', 'text': 'kbic'}]`
- Pointer-like words inside gap: `19` heuristic hits; first five `[{'offset_in_gap': 24, 'source': '0x02016aa0', 'value': '0x0001e8be', 'range': 'flash_mapped_or_mmio'}, {'offset_in_gap': 62, 'source': '0x02016ac6', 'value': '0x00c4e8f8', 'range': 'flash_mapped_or_mmio'}, {'offset_in_gap': 76, 'source': '0x02016ad4', 'value': '0x00c816e3', 'range': 'flash_mapped_or_mmio'}, {'offset_in_gap': 158, 'source': '0x02016b26', 'value': '0x00c4e8f8', 'range': 'flash_mapped_or_mmio'}, {'offset_in_gap': 252, 'source': '0x02016b84', 'value': '0x00151101', 'range': 'flash_mapped_or_mmio'}]`.

The full byte string is in `evidence.json`; the reproducible `gap-02016a88.bin` and `gap-02016a88.hex` artifacts are emitted beside this report.

## Decode, xrefs, and boundaries

- Quarkslab exhaustive rows inside target: `0`. This is the source of the apparent hole.
- Quarkslab recursive rows inside target: `0`.
- Kagaimiq patched exhaustive rows inside target: `148`. It decodes dense PI32-like control flow through the region.
- Quarkslab trusted direct text xrefs into target: `0`.
- Kagaimiq patched text xrefs into target: `19`. These include internal branches and a padding-origin external decode; they are not ownership proof, but they further block treating the hole as erased/free.
- Raw little-endian pointer hits to target in app: `0`.

Pre-gap boundary:

```text
0x02016a84 bfea76a1 call 0x0200ad74 CALL_TERMINATOR
```

Quarkslab resumes at `0x02016ce2`, but that is not a function boundary. The previous call's callee returns, so normal execution resumes at `0x02016a88`.

## Public SDK exact matches

Overlapping SDK exact matches: `[]`. Nearest exact SDK matches are `{'name': '_pow', 'start': '0x02004884', 'end_exclusive': '0x02004896', 'bytes': 18, 'sha256': '3f6c16c36e893d2b70eeacffaf5774f1693782380feae2c047fe18b03a6d75a8', 'distance_bytes': 74226}` and `{'name': 'sdfile_str_to_upper', 'start': '0x0202d7a6', 'end_exclusive': '0x0202d7c0', 'bytes': 26, 'sha256': '4bb7ab9ae94abdb00df6f6b9880bfc7a5c93a522d05f98a96213f8307c4f6313', 'distance_bytes': 92868}`. Result: No public SDK exact match owns or names the gap; SDK evidence neither promotes nor frees it.

## Lifecycle audit

- `0x02005fa4` remains a blocked post-storage wrapper point for this body. It must preserve and call stock `0x020057e0`, then return to `0x02005fa8`, but the proposed body placement is live code and the path still lacks post-USB/live safety proof.
- First-note lazy restore remains design-only. Exact S1C5 selector/producer `0x0201e13e..0x0201e254` is preserved with SHA-256 `4293474041bd40b697be88dcdc936eb92a2b6ce6d20fb95dc2e9dcbe9205cae1`; no insertion point is approved without changing that producer/selector.

## Next exhaustive-listing gaps >=300 bytes

| Follow-up rank | Range | Bytes | Kagaimiq rows inside | Preliminary decision |
|---:|---:|---:|---:|---|
| requested target | `0x02016a88..0x02016ce2` | 602 | 148 | unproved listing hole; requires same return-target/data/xref audit before any promotion |
| 1 | `0x02039be6..0x02039e2a` | 580 | 139 | unproved listing hole; requires same return-target/data/xref audit before any promotion |
| 2 | `0x0202bc62..0x0202be5a` | 504 | 126 | unproved listing hole; requires same return-target/data/xref audit before any promotion |
| 3 | `0x02007248..0x02007390` | 328 | 122 | unproved listing hole; requires same return-target/data/xref audit before any promotion |

## Reproduce

```sh
python3 baselines/v15/analysis/persistence-s2/gap-02016a88-audit/analyze_gap_02016a88.py --check
python3 baselines/v15/analysis/persistence-s2/gap-02016a88-audit/validate.py
(cd baselines/v15/analysis/persistence-s2/gap-02016a88-audit && shasum -a 256 -c SHA256SUMS)
```
