# Playback Note live reanalysis: Ch10 consumer path

Status: **TRACE PASS, no firmware built or flashed**.

## Evidence boundary

Used only official v15 app bytes, current S1-C3/S1-C4 artifacts, and the user-provided live result: Original byte161=trigger 36..51 works for all 16 slots, while all-C4 byte161=60 repeats fail transaction / fall back to Ch1. The live result falsifies the S1-C4 assumption that byte 161 is a neutral playback-note sideband. It does not prove the internal cause of that transaction failure.

## Actual Note On synth consumer

| Address | Bytes | Proven role |
|---:|---|---|
| `0x0201c66a` | `1d42` | r5 = msg[2] velocity |
| `0x0201c66c` | `e1f1a020` | r1 = voice index * 0xa0 |
| `0x0201c670` | `1e41` | r6 = msg[1] trigger/native note |
| `0x0201c672` | `0f1c` | r7 = per-voice slot base |
| `0x0201c674` | `00e1a270` | r0 = per-voice slot base + 0xa2 |
| `0x0201c678` | `623c` | r2 = 0x9c copy length |
| `0x0201c67a` | `8116` | r1 = current patch source 0x01c34c74 |
| `0x0201c67c` | `80ff4cc60200` | stock memcpy(voice+0xa2, source, 0x9c) |
| `0x0201c682` | `00e13e71` | r0 = voice slot + 0x13e = copy destination + 0x9c |
| `0x0201c686` | `8e40` | synth-visible note metadata store consumes r6 |
| `0x0201c68c` | `8d42` | synth-visible velocity metadata store consumes r5 |

Conclusion: the stock/S1-C3 synth-visible Note On note is `r6` stored at `0x0201c686` to `destination+0x9c`. Packet byte 161 is not consumed by this Note On path.

Note Off is symmetric: `0x0201c62e` loads `msg[1]` into `r5`, and `0x0201c648` stores `r5` to the same metadata note position. Any playback map must affect Note On and Note Off together.

## Current S1-C3 selector path

- Note On hook: `0x0201c67c -> 0x0201e142`
- Note Off hook: `0x0201c63e -> 0x0201e13e`
- 0x0201e142 mov r3,r6: normalize Note On trigger note
- 0x0201e144 push {rets,r9..r4}: saves/restores r5 velocity and r6 trigger note
- 0x0201e14a gate r9 == 9: Ch10 only
- 0x0201e14e/0x0201e152 gate 36 <= trigger note < 52
- 0x0201e156 slot = trigger note - 36
- 0x0201e158 base = 0x01c46520
- 0x0201e168 multiply slot by 0xa0; 0x0201e16e source = base + slot*0xa0
- 0x0201e174/0x0201e176 require selected slot valid == 1
- 0x0201e17a r1 = trigger-selected source
- 0x0201e17c r0 = saved destination
- 0x0201e17e call memcpy; 0x0201e184 pop restores r6/r5 before stock stores

Result: stock 0x0201c686 stores restored r6, so S1-C3 delivers Trigger Note as synth note.

## Current S1-C4 path and live contradiction

- Consumer route: same Note On/Off hooks as S1-C3, but stock note stores at 0x0201c644 and 0x0201c682 are neutralized.
- Selector map path:
  - 0x0201e158 slot = trigger note - 36; Trigger still selects source slot
  - 0x0201e17c map base = 0x01c46520 + 0xa00 = 0x01c46f20
  - 0x0201e182 r5 = playback_map[trigger slot]
  - 0x0201e184 r1 = trigger-selected source, not playback-note-selected source
  - 0x0201e188 call memcpy
  - 0x0201e18e r0 = saved destination + 0x9c
  - 0x0201e192 store r5 as local synth note metadata
- Producer byte161 path:
  - 0x0201e1e8 r1 = staging + 0x9b, the payload byte that appears as wire packet byte 161
  - 0x0201e1ec r2 = *(staging+0x9b)
  - 0x0201e1ee playback_map[count_slot] = r2
  - 0x0201e1f0/0x0201e1f2 restore staging+0x9b to 0x3f before resident slot copy

Playback Original works when byte 161 remains trigger 36..51; all-C4 fails when byte 161 is 60 repeated. Therefore byte 161 must be treated as trigger/transaction identity, not a safe playback-note sideband.

## Minimum hook that preserves Trigger slot identity

Hook point: consumer selector path reached from 0x0201c63e/0x0201c67c, after Ch10/range/ARMED/valid gates and before the synth metadata note store.

Must preserve:
- Do not change the incoming MIDI event buffer msg[1].
- Do not change direct-product packet byte 161 away from trigger note 36..51 for resident slot loading.
- Do not use playback note P to select source; source_slot = trigger_note - 36 only.

Apply map:
- Let T = proven native trigger register, r6 for Note On and r5 for Note Off.
- Let slot = T - 36 after the existing selector range gate.
- Let P = playback_map[slot], defaulting to T for Original.
- Copy source = 0x01c46520 + slot*0xa0 to the per-voice destination with r2 = 0x9c.
- For Note On, deliver P to destination+0x9c while preserving r5 velocity for 0x0201c68c.
- For Note Off, deliver the same P to destination+0x9c so release identity matches Note On.

S1-C4's consumer-side map load/store shape is the right hook location, but its producer sideband is not: replace the byte161 map writer with an identity-preserving map source, or use a fixed/static map. Until that writer is proven, this remains analysis/minimal-hook guidance, not a flash candidate.

Blocked until proven:
- A per-slot playback_map writer/transport that leaves byte 161 as trigger identity 36..51.
- A validation case showing duplicate playback notes do not alter transaction slot identity.
- Symmetric Note On and Note Off delivery of P.

## Validation

Run:

```sh
python3 baselines/v15/analysis/playback-note/live-reanalysis/consumer/trace_consumer.py
shasum -a 256 -c baselines/v15/analysis/playback-note/live-reanalysis/consumer/SHA256SUMS
```

Decision: TRACE PASS; S1-C4 byte161 sideband is rejected by live evidence; minimum safe hook is consumer-side per-slot map after trigger-selected slot validation with byte161 identity preserved.
