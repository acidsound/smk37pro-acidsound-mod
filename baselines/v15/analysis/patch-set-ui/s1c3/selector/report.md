# S1-C3 contiguous Ch10 16-slot selector design

Date: 2026-08-03 UTC
Status: **PASS for raw selector design and bytes; BLOCK for firmware/live candidate.**
Scope: offline-only analysis. No app/FWSC image, build/flash, USB, MIDI, OTA, reset, or device access was created or performed.

## Decision

**PASS:** The reviewed raw selector blob fits the exact current S1-C2 selector placement `0x0201e13e..0x0201e19e`. It maps Ch10 notes `36..51` to resident slots `0..15` in O(1) as `slot = note - 36`, for both Note On and Note Off, and falls back through the H2-correct original source for all outside-range or unpublished cases.

**BLOCK:** This is not a flashable firmware candidate. A future child still needs a reviewed 16-slot producer/parser, heap/headroom proof, rollback package, independent review, and separately authorized live stress. This run intentionally emits only `selector.bin` plus proof artifacts.

## Exact current basis

- Official v15 app SHA-256: `36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055`.
- S1-C2 live-PASS app SHA-256: `4afd13d7301c2ae209c11d3fe932d019faa770b551f2d8a38cf4c018c7aafa8a`.
- Current S1-C2 selector SHA-256: `adb8774971811f6dbdce8b7338f2265f18b8bb22544ccab746e74610366d4e35`, 96 bytes at `0x0201e13e..0x0201e19e`.
- Live evidence: `flash-candidates/S1C2-two-slot-selector-live-v2/live-validation-20260803.md` records **LIVE PASS** for Note 36 selected slot0, Note 45 selected slot1, Note 40 fallback, no reboot/stuck-note report.
- Independent byte decode basis: `flash-candidates/S1C2-two-slot-selector-live-v2-final-review/pi32-selector-decode.tsv` verified the two native adapters, fallback copy tail, and `memcpy` target.

## Selector algorithm

```c
/* Note Off entry normalizes r5, Note On entry normalizes r6 into r3. */
if (r9 != 9) goto fallback;
if (note < 36 || note >= 52) goto fallback;
if (*(uint8_t *)0x01c465bf != 2) goto fallback;  /* ARMED */
slot = note - 36;
src = (uint8_t *)0x01c46520 + slot * 0xa0;
if (src[0x9c] != 1) goto fallback;
r1 = src;
fallback_or_selected_copy:
r0 = original_destination;
memcpy(r0, r1, r2);  /* r2 remains official 0x9c */
```

The range checks happen before subtracting `36`, so notes below `36` cannot underflow into an out-of-range slot pointer. `r1` is not changed until after the selected slot valid byte passes, so every reject path keeps the original H2/stock source.

## Exact PI32 bytes

- Live code bytes: `72`.
- Placement window bytes: `96`.
- Padding: `24` bytes, twelve inert `pop {pc,r9..r4}` words (`5904`) after the live return.
- `selector.bin` SHA-256: `ea2c76595a93cf2cf6a39236e09b749781e2721e3575d0c1b40194855cd4e915`.
- `selector-live-code.bin` SHA-256: `894f61ee4eedb942b6653bd36dc72934d3719b54a9a413f6c94f29d0084f8ffc`.

```text
53160481631679040416951685f8171283fd154803fd1368f33cc8ff2065c40105e19c80584380f80a04e3e1a0308516351806e19c50684080f801025116401680ff4aab02005904590459045904590459045904590459045904590459045904
```

Full instruction decode is in `pi32-selector-decode.tsv`.

## ABI proof

- Note Off hook `0x0201c63e`: official/S1-C1 evidence proves `r5 = msg[1]`, `r0` is the per-voice destination, `r1` is the original source, `r2 = 0x9c`, and `r9` is the channel nibble. Entry `0x0201e13e` executes `mov r3,r5; goto core`.
- Note On hook `0x0201c67c`: official/S1-C1 evidence proves `r6 = msg[1]` and `r5 = msg[2]` velocity. Entry `0x0201e142` executes `mov r3,r6` and falls through.
- The shared core pushes `{rets,r9..r4}` before scratch use and pops `{pc,r9..r4}` after the copy. This restores Note On `r6` and velocity `r5`, and Note Off `r5`, before official metadata stores.
- The selector never writes `r2`, so the official `0x9c` copy count is preserved.
- The selector restores `r0` from `r4` immediately before `memcpy` on every selected and fallback path.

## Valid, lock, and publication safety

- Slot records occupy `0x01c46520..0x01c46f20`, 16 records at stride `0xa0`. The selected source is bounded to `0x01c46520..0x01c46e80`; selected voice end is at most `0x01c46f1c`, below the slot-region end `0x01c46f20`.
- The selector consumes only when publication state byte `0x01c465bf == 2` (`ARMED`). `EMPTY`, `LOADING`, corrupt, and absent states fall back.
- The selector then checks the selected slot valid byte at `slot+0x9c == 1`. Invalid selected slots fall back with original `r1` intact.
- Producer lock is a producer-only invariant: future producer code must use the H2-compatible nonblocking `csync; testset` byte at `0x01c465bd`, publish each slot `valid=1` only after its `0x9c` copy and `csync`, and write `ARMED` last after all 16 slots pass bounds/checks. Consumers do not lock because v1 prohibits in-place mutation after `ARMED`.

## Branch reach and placement

All conditional rejects target the single copy tail inside the same live selector body. The longest conditional branch in this selector is well inside the signed 9-bit halfword window used by exact v15 `jne/jl/jge` forms. `call32` at the copy tail targets exact stock `memcpy` `0x02048cce`.

The current 96-byte selector placement remains sufficient:

| Item | Bytes |
|---|---:|
| Note adapters and shared O(1) selector live code | 72 |
| Inert padding to cover exact S1-C2 selector window | 24 |
| Total raw replacement blob | 96 |
| Existing S1-C2 selector window | 96 |

## Validation performed

- Encoder self-checks reproduced exact official v15 `jl`, `jge`, `mul`, and `add` examples: `jl r2,#3, jge r3,#0x3a, jge r1,#1, mul r0,r0,#0xa3, mul r1,r2,#0xa0, add r1,r2, add r0,r6`.
- Decoded all `72` live bytes with no undecoded instruction.
- Exhaustive high-level behavior matrix checked `2048` channel/note cases for ARMED/all-valid behavior plus EMPTY, LOADING, and invalid-slot fallback cases.
- No firmware image was built and no live transport path was run.
