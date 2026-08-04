# S2 persistent-default fit-first result: BLOCK

## Decision

**BLOCK.** No firmware candidate, FWSC, rollback bundle, or exact OTA executable is emitted.

The exact current S1C5 baseline and its known 16-packet Bank D set are pinned and reproduced offline. The target mapping is Bank D patches 1..16 on Trigger Notes 36..51, with all 16 Playback Note values fixed to C4/60. The packet payloads normalize byte `0x9b` back to stock `0x3f` and then match the proven Bank D runtime table for all 16 slots.

A safe power-cycle default cannot be promoted from the present evidence without either an immutable exact source table or sufficient proven code/data placement for a side-effect-free materializer. Neither exists.

## Exact fit-first attempt

| Item | Bytes |
|---|---:|
| S1C5 owned executable window `0x0201e13e..0x0201e254` | 278 |
| Exact inherited S1C5 selector | 88 |
| Exact inherited host producer | 188 |
| Tail | 2 |
| Official factory 128-to-156 conversion core `0x020056b4..0x02005766` | 178 |
| Official source/destination setup plus conversion `0x02005682..0x02005766` | 228 |

Keeping the exact 88-byte S1C5 selector and reusing only the exact 178-byte official conversion core consumes 266 of 278 bytes, leaving 12 bytes. That excludes caller-directed immutable source selection, destination/slot arithmetic, nonblocking serialization/recheck, valid-last publication, and C4 playback metadata. Including the official setup reaches 316 bytes, 38 bytes beyond the window.

This is an exact-stock-code fit failure, not a claim that arbitrary hand-optimized code is mathematically impossible. Promotion is independently blocked by source provenance and zero safe app/JLFS capacity.

## Source decision matrix

| Source | Decision | Reason |
|---|---|---|
| `*(0x01c33260+0x164)` stock packed/current Patch store | BLOCK | Official and loader-proven, but mutable through SAVE/default-load and requires 128-to-156 conversion. It cannot guarantee the exact known default after prior user edits. |
| `0x01c0de20 + bank*0x49e3` product/default-bank workspace | BLOCK | Used by official bank-image save, but it is a dynamic UI/product workspace with no immutable lifetime/no-alias proof. |
| Embedded exact expanded table | BLOCK | 2496 payload bytes are required; JLFS-preserving append capacity is 0 bytes. |
| Embedded packed table | BLOCK | 2048 bytes plus converter are required; append capacity remains 0 bytes. |
| Call global loader `0x02005660` on first use | BLOCK | Hardcoded global selection/destination and UI/helper side effects. It is not a caller-directed materializer and is prohibited in the Note path. |

## Exact table scan

For each of the 16 stock-form 156-byte runtime records, exact-byte scans found no occurrence in:

- the extracted official v15 app;
- the exact S1C5 app;
- the clean baseline device dump.

The repository's `runtime-slots.bin` is a proven offline derivation, not an on-device table address. The target therefore cannot simply copy a resident exact table after boot.

## Why no release artifacts exist

The user required BLOCK evidence only if infeasible. Accordingly this directory intentionally contains no:

- `app.bin`;
- `.fwsc` package;
- rollback sectors;
- OTA uploader or exact OTA confirmation token;
- device/live sender.

Creating any of those would incorrectly imply a flashable candidate. No device, MIDI transport, OTA, reset, or flash operation was performed.

## Reproduce

```sh
python3 baselines/v15/analysis/flash-candidates/S2-persistent-default/analyze.py --check
python3 baselines/v15/analysis/flash-candidates/S2-persistent-default/validate.py
(cd baselines/v15/analysis/flash-candidates/S2-persistent-default && shasum -a 256 -c SHA256SUMS)
```

## Unblock requirements

1. Prove an immutable exact Bank D source table and lifetime, or a safe fixed-size in-app replacement region large enough for exact source data.
2. Produce a caller-directed, side-effect-free 128-to-156 materializer that fits a proven executable region.
3. Prove first-use concurrency/publication and matched Note On/Note Off identity without global loader or storage activity after publication.
4. Only then build an exact S1C5 child with deterministic FWSC, rollback, validator, exact OTA gate, and independent review.
