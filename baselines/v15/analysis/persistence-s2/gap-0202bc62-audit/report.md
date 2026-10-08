# v15/S1C5 gap 0x0202bc62 audit: REFUTED

## Decision

**REFUTE PROMOTION.** The exact `0x0202bc62..0x0202be5a` region is 504 bytes (`0c5ce1e1b9c0bb13cec4e5b076a70d73ae3fdf0de5d73833d8cb29015338aa2e`), but it is not owned or free. Quarkslab exhaustive stops at `0x0202bc5c: call 0x02063260`, while Quarkslab recursive decodes the same call as a normal call and continues through all requested bytes inside `FUN_0202bc22@0202bc22` to the `0x0202be5a..0x0202be60` epilogue. The containing function has `3` Quarkslab direct call xrefs. No firmware/FWSC/OTA/device artifact was emitted.

## Exact bytes and signatures

- Runtime range: `0x0202bc62..0x0202be5a`
- App offsets: `0x2bc62..0x2be5a`
- FWSC app-data flash offsets: `0x2fd82..0x2ff7a`
- Byte profile: `56` zero bytes, `20` `ff` bytes, `128` unique byte values, entropy `6.0742` bits/byte.
- ASCII runs >=4: `[{'offset': 0, 'address': '0x0202bc62', 'text': 'i@!Y'}, {'offset': 233, 'address': '0x0202bd4b', 'text': '^@!`'}]`
- Pointer-like words inside gap: `40` heuristic hits; first five `[{'offset_in_gap': 6, 'source': '0x0202bc68', 'value': '0x00f7f880', 'range': 'flash_mapped_or_mmio'}, {'offset_in_gap': 20, 'source': '0x0202bc76', 'value': '0x01c09094', 'range': 'hot_ram'}, {'offset_in_gap': 26, 'source': '0x0202bc7c', 'value': '0x01c0908c', 'range': 'hot_ram'}, {'offset_in_gap': 30, 'source': '0x0202bc80', 'value': '0x0001e04d', 'range': 'flash_mapped_or_mmio'}, {'offset_in_gap': 54, 'source': '0x0202bc98', 'value': '0x0020e061', 'range': 'flash_mapped_or_mmio'}]`.

The full byte string is in `evidence.json`; reproducible `gap-0202bc62.bin` and `gap-0202bc62.hex` artifacts are emitted beside this report.

## Decode, xrefs, and boundaries

- Quarkslab exhaustive rows inside target: `0`. This is the source of the apparent hole.
- Quarkslab recursive rows inside target: `164`. It places the interval inside `FUN_0202bc22@0202bc22`.
- Kagaimiq patched exhaustive rows inside target: `126`.
- Quarkslab recursive text xrefs into target: `24`.
- Kagaimiq patched text xrefs into target: `19`.
- Quarkslab exhaustive direct calls to containing function entry `0x0202bc22`: `[{'address': '0x0202bfd4', 'bytes': 'bfea25fe', 'length': 4, 'mnemonic': 'call', 'text': 'call 0x0202bc22', 'flow_type': 'UNCONDITIONAL_CALL', 'function': 'FUN_0202bf98@0202bf98'}, {'address': '0x02035abc', 'bytes': 'bfeab1b0', 'length': 4, 'mnemonic': 'call', 'text': 'call 0x0202bc22', 'flow_type': 'UNCONDITIONAL_CALL', 'function': 'FUN_020359a0@020359a0'}, {'address': '0x02035b1a', 'bytes': 'bfea82b0', 'length': 4, 'mnemonic': 'call', 'text': 'call 0x0202bc22', 'flow_type': 'UNCONDITIONAL_CALL', 'function': 'FUN_020359a0@020359a0'}]`.
- Raw little-endian pointer hits to target in app: `0`.

Pre-gap boundary:

```text
0x0202bc5c 80fffe750300 call 0x02063260 CALL_TERMINATOR  # exhaustive stops here
0x0202bc5c 80fffe750300 call 0x02063260 UNCONDITIONAL_CALL  # recursive continues
```

Return/epilogue boundary:

```text
0x0202be5a 4016 mov r0,r4 FALL_THROUGH
0x0202be5c 0281 add sp,#0x4 FALL_THROUGH
0x0202be5e 5e04 pop {pc,r14,r13,r12,r11,r10,r9,r8,r7,r6,r5,r4} TERMINATOR
```

`0x0202bc62` is therefore not a data/free boundary, and `0x0202be5a` is the live function epilogue start rather than a safe post-gap landing pad.

## Public SDK exact matches

Overlapping SDK exact matches: `[]`. Nearest exact SDK matches are `{'name': '_pow', 'start': '0x02004884', 'end_exclusive': '0x02004896', 'bytes': 18, 'sha256': '3f6c16c36e893d2b70eeacffaf5774f1693782380feae2c047fe18b03a6d75a8', 'distance_bytes': 160716}` and `{'name': 'sdfile_str_to_upper', 'start': '0x0202d7a6', 'end_exclusive': '0x0202d7c0', 'bytes': 26, 'sha256': '4bb7ab9ae94abdb00df6f6b9880bfc7a5c93a522d05f98a96213f8307c4f6313', 'distance_bytes': 6476}`. Result: No public SDK exact match owns or names the gap; SDK evidence neither promotes nor frees it.

## Lifecycle audit

- `0x02005fa4` remains a blocked post-storage wrapper point for this body. It must preserve and call stock `0x020057e0`, then return to `0x02005fa8`, but the proposed body placement is live `FUN_0202bc22` code and the path still lacks separate post-USB/live safety proof.
- First-note lazy restore remains design-only. Exact S1C5 selector/producer `0x0201e13e..0x0201e254` is preserved with SHA-256 `4293474041bd40b697be88dcdc936eb92a2b6ce6d20fb95dc2e9dcbe9205cae1`; no insertion point is approved without changing that producer/selector.
- Because promotion is refuted, no manifest-gated restore body, app, FWSC, OTA sender, rollback, or device-access step was assembled.

## Exhaustive-listing gaps >=300 bytes snapshot

| Rank | Range | Bytes | Quarkslab recursive rows inside | Kagaimiq rows inside | Preliminary decision |
|---:|---:|---:|---:|---:|---|
| 1 | `0x02016a88..0x02016ce2` | 602 | 0 | 148 | unproved listing hole; requires return-target/data/xref audit before any promotion |
| 2 | `0x02039be6..0x02039e2a` | 580 | 186 | 139 | unproved listing hole; requires return-target/data/xref audit before any promotion |
| requested target | `0x0202bc62..0x0202be5a` | 504 | 164 | 126 | unproved listing hole; requires return-target/data/xref audit before any promotion |
| 4 | `0x02007248..0x02007390` | 328 | 133 | 122 | unproved listing hole; requires return-target/data/xref audit before any promotion |

## Reproduce

```sh
python3 baselines/v15/analysis/persistence-s2/gap-0202bc62-audit/analyze_gap_0202bc62.py --check
python3 baselines/v15/analysis/persistence-s2/gap-0202bc62-audit/validate.py
(cd baselines/v15/analysis/persistence-s2/gap-0202bc62-audit && shasum -a 256 -c SHA256SUMS)
```
