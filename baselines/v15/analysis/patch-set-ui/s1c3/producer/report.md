# S1-C3 sequential 16-packet producer design

Date: 2026-08-03 UTC  
Status: **PASS as offline producer/sender design, BLOCK for firmware candidate or live send**

## Scope

This checkpoint is offline only. It analyzes the current exact S1-C2 live-PASS producer and sender, then specifies the S1-C3 sequential 16-packet loader contract for slots `0..15` at MIDI notes `36..51`.

No firmware, FWSC package, live sender, MIDI transport, flash, OTA, reset, or device access was created or performed.

## Exact S1-C2 live-PASS basis

The current live-PASS basis is `S1C2-two-slot-selector-live-v2`.

| Item | Exact value |
|---|---|
| S1-C2 report | `baselines/v15/analysis/flash-candidates/S1C2-two-slot-selector-live-v2/report.md` |
| S1-C2 report SHA-256 | `d5702f534ee8ab6e07f76f33bf57bd0800c75cb12f1f7bbaf8cbe263872c1a03` |
| S1-C2 evidence SHA-256 | `97c1cc6ff3bdb3e469fbedf0c577fcee33036a5ea0d685beb5bd71bb177ca81c` |
| S1-C2 app manifest SHA-256 | `15e9626b16820d2ba4b14a5bbb6310d1924af0bd7fe9c09ab77aca705d2c7a43` |
| App SHA-256 | `4afd13d7301c2ae209c11d3fe932d019faa770b551f2d8a38cf4c018c7aafa8a` |
| Producer entry | `0x0201e1a2` |
| Segmented reject stub | `0x0201e232` |
| Producer/stub bytes | `148` bytes, `0x0201e1a2..0x0201e236` |
| Owned executable limit | `0x0201e254`, 178 bytes from entry |
| Direct callsite | `0x0201e468 -> 0x0201e1a2`, bytes `bfea9bfe` |
| Segmented callsite | `0x0201e49c -> 0x0201e232`, bytes `bfeac9fe` |
| Direct/segmented reloads | `0x0201e46c bfeaf838`, `0x0201e4a0 bfeade38` |
| Existing guarded sender | `tools/smk37_v15_s1c2_send.c`, SHA-256 `b0cbdda2428518d0363364268b15cdfa98367c2af98d0d660e60a272e8939e0d` |

The S1-C2 v2 validation already establishes the critical producer ABI: direct accepted product messages enter with `r0 = 0x01c37fd0` staging and `r9 = 0xa3` for exact 163-byte direct packets. Segmented accepted-product traffic is split to a no-mutation return stub. The route identity is the call target, not a speculative LR/rets test.

## S1-C3 host protocol

S1-C3 intentionally keeps the official Yamaha direct product packet shape. It does not introduce a private segmented/enveloped command in this checkpoint.

```text
F0 43 00 00 01 1B + 156-byte runtime product payload + F7
```

Rules:

1. Exactly 16 packets are admitted.
2. Every admitted packet is exactly `163` SysEx bytes.
3. Every admitted packet starts with `f0430000011b` and ends with `f7`.
4. The firmware producer independently gates `r9 == 0xa3` before lock/state/slot mutation.
5. The segmented product callsite remains routed to a no-mutation reject stub.
6. Host order is fixed and sequential:

| Order | Slot | Note |
|---:|---:|---:|
| 1 | 0 | 36 |
| 2 | 1 | 37 |
| 3 | 2 | 38 |
| 4 | 3 | 39 |
| 5 | 4 | 40 |
| 6 | 5 | 41 |
| 7 | 6 | 42 |
| 8 | 7 | 43 |
| 9 | 8 | 44 |
| 10 | 9 | 45 |
| 11 | 10 | 46 |
| 12 | 11 | 47 |
| 13 | 12 | 48 |
| 14 | 13 | 49 |
| 15 | 14 | 50 |
| 16 | 15 | 51 |

A future live-capable sender must be fail-closed like S1-C2: verify all 16 exact packet files, exact file order, exact length/framing, and exact SHA-256 allowlist before opening USB. Dry-run must remain offline. One 163-byte SysEx packet packetizes to 55 USB-MIDI events, 220 USB-MIDI bytes, with final CIN `0x05` carrying the single `F7` byte.

This checkpoint does not supply the 16 packet files or any live sender. That is intentional because only the first two current packet hashes are in the S1-C2 live-PASS sender evidence.

## Producer state machine

The producer is fill-once and immutable after publication.

```text
boot/BSS zero -> EMPTY, loaded_count=0, valid[0..15]=0
packet 1       -> LOADING, slot0 valid-last, loaded_count=1
...
packet 15      -> LOADING, slot14 valid-last, loaded_count=15
packet 16      -> slot15 valid-last, loaded_count=16, ARMED last
packet 17+     -> reject, no mutation
```

Required reject behavior:

- segmented route: immediate no-mutation return;
- direct route with `r9 != 0xa3`: reject before `testset`, state, count, or slot mutation;
- failed nonblocking `testset`: return without clearing another owner;
- `state == ARMED`: unlock and reject;
- `loaded_count == 16`: unlock and reject;
- `state` not `EMPTY` or `LOADING`: unlock and reject;
- `state == EMPTY` with `loaded_count != 0`: unlock and reject.

Required mutation order:

1. On slot 0 only, write `state=LOADING` before the first copy. Consumers must still reject because `state != ARMED`.
2. For slot `i`, clear `valid[i]`, copy exactly `0x9c` bytes from staging to `slot[i].voice`, execute `csync`, then write `valid[i]=1` as that slot's publication byte.
3. After `valid[i]`, write `loaded_count=i+1`.
4. For slot `15`, execute a final `csync` and write `state=ARMED` last.
5. After `ARMED`, every later accepted direct product packet rejects without slot mutation.

## RAM layout and placement arithmetic

The static-note S1-C3 producer does not need the 128-entry map from the broader data-model report. It needs 16 resident runtime payload slots and two global bytes in the slot-0 tail.

| Field | Value |
|---|---:|
| Base | `0x01c46520` |
| Slot count | `16` |
| Slot stride | `0xa0` |
| Voice bytes per slot | `0x9c` |
| Total slot reservation | `0x0a00` bytes |
| End exclusive | `0x01c46f20` |
| Slot valid byte | `slot_base + 0x9c` |
| Global lock | `0x01c465bd`, the exact H2/S1-C2 lock byte |
| Loaded count | `0x01c465be` |
| State | `0x01c465bf` |

Slot ranges are generated by `slot_base = 0x01c46520 + slot * 0xa0`:

| Slot | Note | Voice range | Valid byte |
|---:|---:|---|---|
| 0 | 36 | `0x01c46520..0x01c465bc` | `0x01c465bc` |
| 1 | 37 | `0x01c465c0..0x01c4665c` | `0x01c4665c` |
| 2 | 38 | `0x01c46660..0x01c466fc` | `0x01c466fc` |
| 3 | 39 | `0x01c46700..0x01c4679c` | `0x01c4679c` |
| 4 | 40 | `0x01c467a0..0x01c4683c` | `0x01c4683c` |
| 5 | 41 | `0x01c46840..0x01c468dc` | `0x01c468dc` |
| 6 | 42 | `0x01c468e0..0x01c4697c` | `0x01c4697c` |
| 7 | 43 | `0x01c46980..0x01c46a1c` | `0x01c46a1c` |
| 8 | 44 | `0x01c46a20..0x01c46abc` | `0x01c46abc` |
| 9 | 45 | `0x01c46ac0..0x01c46b5c` | `0x01c46b5c` |
| 10 | 46 | `0x01c46b60..0x01c46bfc` | `0x01c46bfc` |
| 11 | 47 | `0x01c46c00..0x01c46c9c` | `0x01c46c9c` |
| 12 | 48 | `0x01c46ca0..0x01c46d3c` | `0x01c46d3c` |
| 13 | 49 | `0x01c46d40..0x01c46ddc` | `0x01c46ddc` |
| 14 | 50 | `0x01c46de0..0x01c46e7c` | `0x01c46e7c` |
| 15 | 51 | `0x01c46e80..0x01c46f1c` | `0x01c46f1c` |

Arithmetic placement of the slot records is internally consistent and preserves the exact slot0 H2/S1-C2 source, valid byte, and lock byte. Firmware placement is still **BLOCK** until heap-prefix headroom is proven for moving the heap begin through `0x01c46f20`. The existing data-model report already flags heap headroom as an implementation blocker.

## PI32 ABI and code budget

### ABI PASS facts

- Direct product callsite `0x0201e468` can continue to target `0x0201e1a2`.
- Segmented product callsite `0x0201e49c` must continue to target a no-mutation stub.
- Direct entry must preserve the S1-C2 saved-register shape, `push {rets,r9,r8,r7,r6,r5,r4}` and `pop {pc,r9,r8,r7,r6,r5,r4}`.
- The exact direct length gate is still `r9 == 0xa3`, copied to a low register before any lock/state/slot mutation.
- The caller reload calls at `0x0201e46c` and `0x0201e4a0` must remain byte-exact.

### Budget BLOCK facts

- Current S1-C2 live-PASS producer and stub consume 148 bytes inside the 178-byte owned range.
- The remaining margin is only 30 bytes.
- S1-C3 adds requirements not present in S1-C2: `loaded_count`, 16-slot address calculation or table lookup, EMPTY/LOADING/ARMED validation, slot15 commit branch, and reject-later behavior.
- This checkpoint intentionally does not claim a firmware candidate without exact assembled PI32 bytes and an independent decoder proving every branch/call reach.

Therefore the PI32 ABI is **PASS as a design contract**, but exact bytes/code budget/placement are **BLOCK for firmware** until an assembled producer proves it fits `0x0201e1a2..0x0201e254` and the RAM heap shift is independently unblocked.

## Host sender proof obligations for a later candidate

A future S1-C3 sender must:

1. accept `dry-run` with no USB open;
2. require exactly 16 positional packet paths;
3. read each file as exactly 163 bytes with no trailing bytes;
4. verify the direct product header and `F7` terminator;
5. verify a pinned SHA-256 for every slot file;
6. verify host order `slot0-note36` through `slot15-note51`;
7. packetize every SysEx into exactly 220 USB-MIDI bytes;
8. reject any segmented, split, short, long, reordered, duplicate, missing, or unknown packet;
9. perform all verification before claiming or opening the MIDI interface;
10. require an explicit confirmation token if live transport is ever authorized.

## Verdict

**PASS:** The offline S1-C3 direct-product sequential-loader design is internally safe: exact direct packets only, segmented reject, nonblocking lock, valid-last per slot, ARMED-last after slot15, and later-packet rejection are specified and validated.

**BLOCK:** No S1-C3 firmware package or live sender is authorized. Missing gates are exact assembled PI32 bytes within the 178-byte owned range, independent branch/decode validation, heap-prefix headroom for `0x01c46520..0x01c46f20`, exact 16 packet hashes, and a guarded 16-packet sender implementation.

## Reproduction

```sh
python3 baselines/v15/analysis/patch-set-ui/s1c3/producer/validate.py
(cd baselines/v15/analysis/patch-set-ui/s1c3/producer && shasum -a 256 -c SHA256SUMS)
```
