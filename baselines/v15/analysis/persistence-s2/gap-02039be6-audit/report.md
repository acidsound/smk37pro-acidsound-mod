# v15/S1C5 gap 0x02039be6 audit: REFUTED

## Decision

**REFUTE PROMOTION.** The exact `0x02039be6..0x02039e2a` region is 580 bytes (`a1825cf3261b2ce8fd20f820bcd4a843b36e2f290b97be1e0e078b652efe5bfe`), but it is not owned/free. The Quarkslab exhaustive gap is bypassed by `0x02039be4: goto 0x02039fee`, yet Quarkslab recursive decodes `186` rows inside the same range and the `0x020399a2` TBH table has entry 3 resolving exactly to `0x02039be6`. No firmware/FWSC/OTA/device artifact was emitted.

## Exact bytes and signatures

- Runtime range: `0x02039be6..0x02039e2a`
- App offsets: `0x39be6..0x39e2a`
- FWSC app-data flash offsets: `0x3dd06..0x3df4a`
- Byte profile: `24` zero bytes, `7` `ff` bytes, `118` unique byte values, entropy `6.0668` bits/byte.
- ASCII runs >=4: `[{'offset': 28, 'address': '0x02039c02', 'text': '`4A '}, {'offset': 168, 'address': '0x02039c8e', 'text': 'Q$1 '}, {'offset': 203, 'address': '0x02039cb1', 'text': 'AB  '}, {'offset': 234, 'address': '0x02039cd0', 'text': '`5A!'}, {'offset': 283, 'address': '0x02039d01', 'text': 'E@ E '}, {'offset': 428, 'address': '0x02039d92', 'text': 'E0"D'}]`
- Pointer-like words inside gap: `13` heuristic hits; first five `[{'offset_in_gap': 16, 'source': '0x02039bf6', 'value': '0x0000ff00', 'range': 'flash_mapped_or_mmio'}, {'offset_in_gap': 116, 'source': '0x02039c5a', 'value': '0x0000ff00', 'range': 'flash_mapped_or_mmio'}, {'offset_in_gap': 210, 'source': '0x02039cb8', 'value': '0x0015ff03', 'range': 'flash_mapped_or_mmio'}, {'offset_in_gap': 336, 'source': '0x02039d36', 'value': '0x00dfe170', 'range': 'flash_mapped_or_mmio'}, {'offset_in_gap': 350, 'source': '0x02039d44', 'value': '0x0012eed2', 'range': 'flash_mapped_or_mmio'}]`.

The full byte string is in `evidence.json`; the reproducible `gap-02039be6.bin` and `gap-02039be6.hex` artifacts are emitted beside this report.

## Decode, xrefs, branch reach, and boundaries

- Quarkslab exhaustive rows inside target: `0`. This is the source of the apparent hole.
- Quarkslab recursive rows inside target: `186` with `576/580` target bytes covered by overlapping rows.
- Kagaimiq patched exhaustive rows inside target: `139` with `320/580` target bytes covered by overlapping rows.
- Quarkslab exhaustive trusted direct text xrefs into target: `0`.
- Quarkslab recursive text xrefs into target: `21`. First five `[{'address': '0x020399c6', 'bytes': '00ff00008b01', 'length': 6, 'mnemonic': 'je', 'text': 'je r0,#0x0,0x02039ce2', 'flow_type': 'CONDITIONAL_JUMP', 'function': 'FUN_0202c238@0202c238', 'target': '0x02039ce2'}, {'address': '0x020399d0', 'bytes': 'c48f', 'length': 2, 'mnemonic': 'goto', 'text': 'goto 0x02039cf0', 'flow_type': 'UNCONDITIONAL_JUMP', 'function': 'FUN_0202c238@0202c238', 'target': '0x02039cf0'}, {'address': '0x02039a4e', 'bytes': '00ff0000c001', 'length': 6, 'mnemonic': 'je', 'text': 'je r0,#0x0,0x02039dd4', 'flow_type': 'CONDITIONAL_JUMP', 'function': 'FUN_0202c238@0202c238', 'target': '0x02039dd4'}, {'address': '0x02039c0a', 'bytes': '6498', 'length': 2, 'mnemonic': 'goto', 'text': 'goto 0x02039dbc', 'flow_type': 'UNCONDITIONAL_JUMP', 'function': 'FUN_0202c238@0202c238', 'target': '0x02039dbc'}, {'address': '0x02039c18', 'bytes': '0041', 'length': 2, 'mnemonic': 'jz', 'text': 'jz r0,0x02039c1c', 'flow_type': 'CONDITIONAL_JUMP', 'function': 'FUN_0202c238@0202c238', 'target': '0x02039c1c'}]`.
- Kagaimiq patched text xrefs into target: `18`. First five `[{'address': '0x020399d0', 'bytes': 'c48f', 'length': 2, 'mnemonic': 'goto', 'text': 'goto 0x02039cf0', 'flow_type': 'UNCONDITIONAL_JUMP', 'function': '-', 'target': '0x02039cf0'}, {'address': '0x02039c18', 'bytes': '0041', 'length': 2, 'mnemonic': 'jz', 'text': 'jz r0,0x02039c1c', 'flow_type': 'CONDITIONAL_JUMP', 'function': '-', 'target': '0x02039c1c'}, {'address': '0x02039c40', 'bytes': '0480', 'length': 2, 'mnemonic': 'goto', 'text': 'goto 0x02039c42', 'flow_type': 'UNCONDITIONAL_JUMP', 'function': '-', 'target': '0x02039c42'}, {'address': '0x02039c98', 'bytes': '718d', 'length': 2, 'mnemonic': 'call', 'text': 'call 0x02039c74', 'flow_type': 'UNCONDITIONAL_CALL', 'function': '-', 'target': '0x02039c74'}, {'address': '0x02039d00', 'bytes': '8045', 'length': 2, 'mnemonic': 'jnz', 'text': 'jnz r0,0x02039d0c', 'flow_type': 'CONDITIONAL_JUMP', 'function': '-', 'target': '0x02039d0c'}]`.
- Raw little-endian pointer hits to target in app: `0`.

Exhaustive-listing boundary before gap:

```text
0x02039be4 0584 goto 0x02039fee UNCONDITIONAL_JUMP
```

TBH branch-table reach:

```text
0x020399a2 1101 tbh r1 COMPUTED_JUMP
entries: [{'index': 0, 'entry_halfword': '0x0007', 'target': '0x020399b2', 'inside_requested_gap': False}, {'index': 1, 'entry_halfword': '0x0007', 'target': '0x020399b2', 'inside_requested_gap': False}, {'index': 2, 'entry_halfword': '0x00ce', 'target': '0x02039b40', 'inside_requested_gap': False}, {'index': 3, 'entry_halfword': '0x0121', 'target': '0x02039be6', 'inside_requested_gap': True}, {'index': 4, 'entry_halfword': '0x0134', 'target': '0x02039c0c', 'inside_requested_gap': True}, {'index': 5, 'entry_halfword': '0x0150', 'target': '0x02039c44', 'inside_requested_gap': True}, {'index': 6, 'entry_halfword': '0x017d', 'target': '0x02039c9e', 'inside_requested_gap': True}]
```

`0x02039be6` is therefore a switch-arm target, not an allocation boundary. `0x02039e2a` is where exhaustive listing resumes, not proof that the preceding 580 bytes are dead/free.

## Public SDK exact matches

Overlapping SDK exact matches: `[]`. Nearest exact SDK matches are `{'name': 'ecvtbuf', 'start': '0x02039286', 'end_exclusive': '0x0203929e', 'bytes': 24, 'sha256': '6c7e4f1cb7a021f9dda8410c016e4fa902dd94e3569700acdb1a5a024c625afe', 'distance_bytes': 2376}` and `{'name': 'mktime', 'start': '0x0203a590', 'end_exclusive': '0x0203a5f8', 'bytes': 104, 'sha256': 'd462ad6eb761277ad32b3a6b9f85af5ae06022133249466fcac96be1ea06db20', 'distance_bytes': 1894}`. Result: No public SDK exact match owns or names the gap; SDK evidence neither promotes nor frees it.

## Lifecycle audit

- `0x02005fa4` remains a blocked post-storage wrapper point for this body. It must preserve and call stock `0x020057e0`, then return to `0x02005fa8`, but the proposed body placement is live switch-arm code and the path still lacks post-USB/live safety proof.
- First-note lazy restore remains design-only. Exact S1C5 selector/producer `0x0201e13e..0x0201e254` is preserved with SHA-256 `4293474041bd40b697be88dcdc936eb92a2b6ce6d20fb95dc2e9dcbe9205cae1`; no insertion point is approved without changing that producer/selector.
- Helper calls inside the candidate range have ordinary terminators/returns recorded in `evidence.json`, so treating call-containing arms as disposable restore storage would corrupt normal continuation behavior.

## Reproduce

```sh
python3 baselines/v15/analysis/persistence-s2/gap-02039be6-audit/analyze_gap_02039be6.py --check
python3 baselines/v15/analysis/persistence-s2/gap-02039be6-audit/validate.py
(cd baselines/v15/analysis/persistence-s2/gap-02039be6-audit && shasum -a 256 -c SHA256SUMS)
```
