# S1C5 SAVE cave helper feasibility proof

Date: 2026-08-04 UTC  
Scope: exact current S1C5 app and repository static evidence only. No device, flash, reset, MIDI transport, FWSC emission, or app patch emission was performed.

## Decision

**BLOCK for a safe standalone persistence/fallback helper.**

The byte range `0x02026d80..0x02026dd4` has an exact budget of **84 bytes**. It can become a safe code cave only with the UI SAVE branch patch at `0x02026d7a`:

```text
old: 60ffff602a00  ; jmz r6,#0xff,0x02026dd4
new: 80f82b020016  ; jne r0,#1,0x02026dd4; mov r0,r0
```

At that point `r0 == 0` is proven by the preceding `0x02026d74` SAVE-state gate, so the replacement always leaves through the stock local SAVE exit before executing `0x02026d80`.

After this patch, the cave can hold a tiny callable leaf, but it cannot hold the requested safe standalone persistence/fallback helper with segmented/reset plus manifest/readback.

## Reachability and cave safety

- Current S1C5 still reaches `0x02026d80` from UI SAVE when `g[0x1ec] == 0` and `r6 != 0xff`. Therefore using the full range without the `0x02026d7a` patch is unsafe.
- Current S1C5 branches at `0x02026da6` to `0x02026dd4` and neutralizes `0x02026dac`, which only makes `0x02026da8..0x02026dd4` dead. It does not make `0x02026d80..0x02026da6` dead.
- The official exhaustive listing has no direct text reference to `0x02026d80` as a branch/call target. It does name `0x02026dd4` as the stock SAVE skip target. This gates direct/static references, not impossible computed-indirect targets.
- `0x02026dd4..0x02026dde` must remain the stock local SAVE exit and is not part of the cave.

## Call reach from producer/selector

- A 6-byte long `call32` reaches from selector/producer-owned code to `0x02026d80`.
  - Selector example from `0x0201e190`: `80ffea8b0000`.
  - Producer-entry example from `0x0201e228`: `80ff528b0000`.
- The existing 4-byte direct and segmented product callsites cannot be retargeted directly to `0x02026d80`. Their short-call form stays in the `0x0201xxxx` page, and those exact windows are only 4 bytes.
- The current S1C5 selector/producer owned window `0x0201e13e..0x0201e254` is fully occupied: 88-byte selector, 188-byte producer, 2-byte tail, zero free bytes without rewrite.

## Wrapper ABI that any writer must obey

```c
uint32_t write_02004b02(const void *src, uint32_t storage, uint32_t len);
uint32_t read_02004870(void *dst, uint32_t storage, uint32_t len);
```

Both wrappers return the requested length only on complete success and return zero on short/fail. A safe writer must require `return == len` for both calls and must compare readback bytes. Stock SAVE ignores wrapper returns, so stock SAVE is not a safe commit engine.

## Register and frame assumptions

- UI SAVE has `r8 = 0x01c33260`, `r6 = handler state`, and `r15 = 1`, but after the required branch patch the helper is not entered from UI SAVE. A standalone helper must not rely on those UI registers.
- A selector-side helper can only be safe under an explicit rewritten-selector ABI, for example `r3 = slot`, `r4 = destination`, return `r0 = destination + 0x9c`, and store the metadata byte at `[r0]`.
- A producer-side writer needs an explicit rewritten-producer ABI and must preserve direct plus segmented-final route behavior. It also needs return checks, readback, compare, manifest/CRC, commit-last ordering, and failure reporting.

## Exact fit accounting

| Item | Bytes | Fit |
|---|---:|---|
| SAVE cave `0x02026d80..0x02026dd4` | 84 | available only after UI branch patch |
| Minimal raw-prefix fallback leaf, no manifest validation | 54 | fits, 30 bytes spare |
| Manifest-note fallback leaf, no manifest/CRC validation | 66 | fits, 18 bytes spare |
| Single payload write lower bound, no readback or manifest | 42 | fits but insufficient |
| Current selector/producer window | 278 | fully occupied |
| Compact direct-only raw16/no-readback successor | 276 | only fits by dropping segmented/reset/manifest/readback |
| Add segmented-final stub | +4 | overruns current owned window by 2 bytes |
| Add slot0 reset floor | +30 | overruns current owned window by 28 bytes |
| Add readback floor | +20 | overruns current owned window by 18 bytes |

These are lower bounds, not polished implementations. The full writer still needs a 16-record loop or unrolled route, manifest construction, payload CRC/equivalent, commit-last sequencing, and failure reporting.

## Concrete partial layout that is safe but insufficient

```text
0x02026d7a..0x02026d80  patch to always branch UI SAVE to 0x02026dd4
0x02026d80..0x02026db6  possible 54-byte raw-prefix fallback leaf, no manifest validation
0x02026d80..0x02026dc2  possible 66-byte manifest-note fallback leaf, no manifest/CRC validation
0x02026dd4..0x02026dde  keep stock local SAVE exit
```

This partial layout is useful as a collaboration constraint, but it is not a releaseable persistence design. It cannot safely claim persistence/fallback with segmented/reset plus manifest/readback.

## Final answer

No. The full requested helper is not feasible in `0x02026d80..0x02026dd4` with exact S1C5 evidence. The range can be quarantined and used for a small callable leaf after the UI branch patch, but a safe standalone persistence/fallback helper needs more proven executable space and a caller rewrite with verified ABI, readback, manifest/CRC, and commit-last semantics.
