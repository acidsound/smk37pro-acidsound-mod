# v15 R03 first Pad Ch10 reboot: first-consumer analysis

Scope: exact v15 offline evidence only. No device access, patching, flashing, or binary modification was performed by this analysis.

## Bottom line

The most likely first fault is not an obvious PI32 call ABI bug. R02 and R03 both preserve the stock dispatcher ABI: `r9` is the channel register, `r0` is the destination voice object, `r2` is `0x9c`, and non-Ch10 fallback calls the original `memcpy` with untouched arguments.

The highest-ranked fault is that R03 probably **did publish** and the first Pad Ch10 consumer then selected the new owned source at `0x01c46520`, a former heap-prefix range created by shifting `HEAP_BEGIN`. That live-only transition is absent from R02 and coincides with first-note allocator/audio activity.

## Exact live evidence

- R02 PASS report: `baselines/v15/analysis/flash-candidates/R02/live-validation-20260802.md`.
- R03 FAIL report: `baselines/v15/analysis/r03-owned-ram/live-validation-20260802.md`.
- Shared Mooger packet SHA-256: `6a9b4097cce1d28780ef3a507f42999743cc10e09770c17c5c78d185e9abff27`.
- R02 app/package: `eebc5190b2e19dedbba68becb27851e9a26cf35f8356319f75bd9f6c20714948` / `93bdf1a7212738b06be8b78919324902729befce8ea07626b0b7aaf7c91e640b`.
- R03 app/package: `3ff9c46b9686c0cea1348a11bed553ebd2d677e2d3452a0f436ce14f3ba5c788` / `001582c097277d6a4a619ed407cf121d5f30097ef82f312d53a2e45c4a9a5a62`.

R02 live succeeded after the exact packet: Pad Ch10 matched Mooger #1, Note Off worked, and Ch1 UI patch changes did not overwrite Ch10. R03 live installed, sent the exact packet, and rebooted on the first physical Pad Ch10 input.

## R02 live-success consumer wrapper

Layout: `{'entry': '0x0201e13e', 'special': '0x0201e146', 'stock': '0x0201e15a', 'end': '0x0201e162'}`.

| address | bytes | text | semantics |
| --- | --- | --- | --- |
| 0x0201e13e | 7904 | push {rets,r9,r8,r7,r6,r5,r4} | save wrapper callee state |
| 0x0201e140 | 9316 | mov r3,r9 | copy live channel nibble |
| 0x0201e142 | 83f80a12 | jne r3,#0x9,0x0201e15a | non-Ch10 falls back to stock memcpy |
| 0x0201e146 | 0416 | mov r4,r0 | preserve destination object |
| 0x0201e148 | c1ffd07fc301 | mov r1,#0x01c37fd0 | R02 source is official SysEx staging |
| 0x0201e14e | 4016 | mov r0,r4 | restore destination in r0 |
| 0x0201e150 | 623c | mov r2,#0x9c | copy exactly the runtime voice block |
| 0x0201e152 | 80ff76ab0200 | call 0x02048cce | memcpy(dest=slot, src=stage, len=0x9c) |
| 0x0201e158 | 5904 | pop {pc,r9,r8,r7,r6,r5,r4} | return |
| 0x0201e15a | 80ff6eab0200 | call 0x02048cce | stock memcpy with untouched r0/r1/r2 |
| 0x0201e160 | 5904 | pop {pc,r9,r8,r7,r6,r5,r4} | return |

R02 has no new producer. It relies on the official accepted SysEx handler to copy the product payload to `0x01c37fd0`, zeros all three stock packer calls, and has Note On and Note Off share the same wrapper/source path.

## R03 consumer and producer path

Layout: `{'off_entry': '0x0201e13e', 'off_stock': '0x0201e166', 'on_entry': '0x0201e16e', 'on_stock': '0x0201e196', 'producer': '0x0201e19e', 'try_fail_branch': '0x0201e1ac', 'producer_unlock': '0x0201e1d8', 'producer_return': '0x0201e1e6', 'end': '0x0201e1e8'}`.
Owned RAM: `{'voice': '0x01c46520..0x01c465bc', 'valid': '0x01c465bc', 'lock': '0x01c465bd', 'end': '0x01c465c0', 'size': '0xa0'}`.

Selected exact decoder rows, including the documented decoder gap at `0x0201e1ac`: 

| address | bytes | text | function |
| --- | --- | --- | --- |
| 0x0201c630 | e1e1a020 | mul r1,r2,#0xa0 | FUN_0201c5ec@0201c5ec |
| 0x0201c636 | 00e1a260 | add r0,r6,#0xa2 | FUN_0201c5ec@0201c5ec |
| 0x0201c63a | 623c | mov r2,#0x9c | FUN_0201c5ec@0201c5ec |
| 0x0201c63c | 8116 | mov r1,r8 | FUN_0201c5ec@0201c5ec |
| 0x0201c63e | 80fffa1a0000 | call 0x0201e13e | FUN_0201c5ec@0201c5ec |
| 0x0201c666 | 72f1f040 | and r2,r4,#0xffffff0f | FUN_0201c5ec@0201c5ec |
| 0x0201c66c | e1f1a020 | mul r1,r2,#0xa0 | FUN_0201c5ec@0201c5ec |
| 0x0201c674 | 00e1a270 | add r0,r7,#0xa2 | FUN_0201c5ec@0201c5ec |
| 0x0201c678 | 623c | mov r2,#0x9c | FUN_0201c5ec@0201c5ec |
| 0x0201c67a | 8116 | mov r1,r8 | FUN_0201c5ec@0201c5ec |
| 0x0201c67c | 80ffec1a0000 | call 0x0201e16e | FUN_0201c5ec@0201c5ec |
| 0x0201e13e | 7904 | push {rets,r9,r8,r7,r6,r5,r4} | FUN_0201e13e@0201e13e |
| 0x0201e140 | 9316 | mov r3,r9 | FUN_0201e13e@0201e13e |
| 0x0201e142 | 83f81012 | jne r3,#0x9,0x0201e166 | FUN_0201e13e@0201e13e |
| 0x0201e146 | 0516 | mov r5,r0 | FUN_0201e13e@0201e13e |
| 0x0201e148 | c4ffbc65c401 | mov r4,#0x1c465bc | FUN_0201e13e@0201e13e |
| 0x0201e14e | 4840 | lb.z r0,[r4 + 0x0] | FUN_0201e13e@0201e13e |
| 0x0201e150 | 80f80902 | jne r0,#0x1,0x0201e166 | FUN_0201e13e@0201e13e |
| 0x0201e154 | 5016 | mov r0,r5 | FUN_0201e13e@0201e13e |
| 0x0201e156 | c1ff2065c401 | mov r1,#0x1c46520 | FUN_0201e13e@0201e13e |
| 0x0201e15c | 623c | mov r2,#0x9c | FUN_0201e13e@0201e13e |
| 0x0201e15e | 80ff6aab0200 | call 0x02048cce | FUN_0201e13e@0201e13e |
| 0x0201e164 | 5904 | pop {pc,r9,r8,r7,r6,r5,r4} | FUN_0201e13e@0201e13e |
| 0x0201e166 | 80ff62ab0200 | call 0x02048cce | FUN_0201e13e@0201e13e |
| 0x0201e16c | 5904 | pop {pc,r9,r8,r7,r6,r5,r4} | FUN_0201e13e@0201e13e |
| 0x0201e16e | 7904 | push {rets,r9,r8,r7,r6,r5,r4} | FUN_0201e16e@0201e16e |
| 0x0201e170 | 9316 | mov r3,r9 | FUN_0201e16e@0201e16e |
| 0x0201e172 | 83f81012 | jne r3,#0x9,0x0201e196 | FUN_0201e16e@0201e16e |
| 0x0201e176 | 0516 | mov r5,r0 | FUN_0201e16e@0201e16e |
| 0x0201e178 | c4ffbc65c401 | mov r4,#0x1c465bc | FUN_0201e16e@0201e16e |
| 0x0201e17e | 4840 | lb.z r0,[r4 + 0x0] | FUN_0201e16e@0201e16e |
| 0x0201e180 | 80f80902 | jne r0,#0x1,0x0201e196 | FUN_0201e16e@0201e16e |
| 0x0201e184 | 5016 | mov r0,r5 | FUN_0201e16e@0201e16e |
| 0x0201e186 | c1ff2065c401 | mov r1,#0x1c46520 | FUN_0201e16e@0201e16e |
| 0x0201e18c | 623c | mov r2,#0x9c | FUN_0201e16e@0201e16e |
| 0x0201e18e | 80ff3aab0200 | call 0x02048cce | FUN_0201e16e@0201e16e |
| 0x0201e194 | 5904 | pop {pc,r9,r8,r7,r6,r5,r4} | FUN_0201e16e@0201e16e |
| 0x0201e196 | 80ff32ab0200 | call 0x02048cce | FUN_0201e16e@0201e16e |
| 0x0201e19c | 5904 | pop {pc,r9,r8,r7,r6,r5,r4} | FUN_0201e16e@0201e16e |
| 0x0201e19e | 7904 | push {rets,r9,r8,r7,r6,r5,r4} | FUN_0201e19e@0201e19e |
| 0x0201e1a0 | 0416 | mov r4,r0 | FUN_0201e19e@0201e19e |
| 0x0201e1a2 | c0ffbd65c401 | mov r0,#0x1c465bd | FUN_0201e19e@0201e19e |
| 0x0201e1a8 | 2000 | csync | FUN_0201e19e@0201e19e |
| 0x0201e1aa | b000 | testset b[r0] | FUN_0201e19e@0201e19e |
| 0x0201e1ac | 40e81b00 | ifeq goto 0x0201e1e6 | decoder gap documented by decoder-provenance.json and official objdump |
| 0x0201e1b0 | 2000 | csync | - |
| 0x0201e1b2 | c5ffbc65c401 | mov r5,#0x1c465bc | - |
| 0x0201e1b8 | 5840 | lb.z r0,[r5 + 0x0] | - |
| 0x0201e1ba | 80f80d00 | jne r0,#0x0,0x0201e1d8 | - |
| 0x0201e1be | c0ff2065c401 | mov r0,#0x1c46520 | - |
| 0x0201e1c4 | 4116 | mov r1,r4 | - |
| 0x0201e1c6 | 623c | mov r2,#0x9c | - |
| 0x0201e1c8 | 80ff00ab0200 | call 0x02048cce | - |
| 0x0201e1ce | c5ffbc65c401 | mov r5,#0x1c465bc | - |
| 0x0201e1d4 | 4021 | mov r0,#0x1 | - |
| 0x0201e1d6 | d840 | sb r0,[r5 + 0x0] | - |
| 0x0201e1d8 | c0ffbd65c401 | mov r0,#0x1c465bd | - |
| 0x0201e1de | 2000 | csync | - |
| 0x0201e1e0 | 4120 | mov r1,#0x0 | - |
| 0x0201e1e2 | 8940 | sb r1,[r0 + 0x0] | - |
| 0x0201e1e4 | 2000 | csync | - |
| 0x0201e1e6 | 5904 | pop {pc,r9,r8,r7,r6,r5,r4} | - |
| 0x0201e468 | bfea99fe | call 0x0201e19e | FUN_0201e254@0201e254 |
| 0x0201e46c | bfeaf838 | call 0x02005660 | FUN_0201e254@0201e254 |
| 0x0201e49c | bfea7ffe | call 0x0201e19e | FUN_0201e254@0201e254 |
| 0x0201e4a0 | bfeade38 | call 0x02005660 | FUN_0201e254@0201e254 |

### R03 publication assessment

more likely than not published after the exact product packet, because lock and valid boot zero, callsites reach producer after final-F7 gates, source pointer is the same live-proven R02 staging pointer, and failure waited for first consumer rather than packet send in the recorded sequence

Reasons: the product callsites are after the final-`F7` gates, pass `r0 = 0x01c37fd0`, lock and valid are boot-zeroed by the R03 BSS extension, the official PI32 object establishes that `testset` fall-through is the acquired path, and the reported reboot happens on first Pad input rather than during the packet send. This is still inferred because there is no live RAM readback.

## Delta matrix

| topic | r02 | r03 | risk |
| --- | --- | --- | --- |
| consumer callsites | both Note Off and Note On call 0x0201e13e | Note Off calls 0x0201e13e; Note On calls 0x0201e16e | low; ABI is preserved and R03 trace validates both calls |
| channel register | r9 -> r3, compare to 9 | same | low |
| memcpy destination | stock dispatcher r0, preserved/restored | same, preserved in r5 | low |
| memcpy source | 0x01c37fd0 transient staging | 0x01c46520 former heap-prefix owned buffer after valid==1 | high; first live fault appears only when this new owned source is selected |
| copy size | 0x9c | 0x9c | low for direct copy overrun; no R03 copy exceeds the live-proven tone block |
| producer | no new producer; handler copy populates staging and stock packer calls are zeroed | product calls short-call producer, then stock reload remains | medium; publication is new but source pointer and memcpy ABI are simple |
| RAM ownership | uses official staging workspace without claiming ownership | extends BSS and shifts HEAP_BEGIN by 0xa0 | highest; previous exact-v15 heap-boundary analysis warned no complete allocator/task/DMA no-alias proof |
| 0xa0 vs 0x9c tail | consumer reads only first 0x9c from staging | owned object is exactly 0xa0: 0x9c voice + valid + lock + 2 reserved bytes | not a direct memcpy overrun, but it removes the earlier 0xa4/0xc0 metadata/generation margin and puts metadata at the old heap base tail |
| cache/sync | no new data publish | csync around testset/unlock, no explicit csync between voice memcpy and valid store | medium-low; could matter for weak ordering, DMA, or cross-context visibility, but less supported than heap/source fault |

## Hidden `0xa0` versus `0x9c` tail dependency

The immediate dispatcher copy is `0x9c` in both R02 and R03, so there is no direct source overread in the Note On/Off `memcpy`. Stock per-voice destination metadata follows the copied block and is written by the dispatcher at the destination, not copied from the source.

However, exact factory-loader evidence shows the live current snapshot has meaningful tail bytes at `0x9c..0xa2` and loader side effects from `0x9c..0x9f`, with `0xa0/+0xa1` postprocessed from `0x86/+0x87` for the clean Mooger path. That makes tail dependency a real system concern, but it ranks below heap-prefix/source ownership for the first reboot because R02 already proved the first `0x9c` bytes are enough for the constrained Pad Ch10 audible path.

## Ranked hypotheses

### 1. first consumer selects a published owned source at the former heap lower bound and triggers an allocator/audio/hidden-owner fault (high)

Evidence for:
- R02 live success proves the same Pad Ch10 dispatcher, r9 channel test, r0 destination, r2=0x9c length, and Mooger payload can work when source is 0x01c37fd0.
- R03 changes the source to 0x01c46520 only after valid==1 and also changes BSS/HEAP_BEGIN to claim 0x01c46520..0x01c465c0.
- The recorded R03 failure occurs on first Pad Ch10 input after product packet, exactly when the consumer first reads valid and then copies from the new owned source.
- Prior exact-v15 heap-boundary evidence explicitly blocked heap/gap ownership without complete allocator/task/DMA/high-water proof.

Evidence against:
- The R03 app did boot and accepted enough host traffic to send the packet, so not every use of the shifted heap boundary is immediately fatal.
- The sbrk HEAP_BEGIN literal was later identified and patched consistently, reducing but not eliminating hidden consumer risk.

First-fault model: producer publishes valid=1; Note On wrapper copies 0x9c bytes from 0x01c46520; the owned range or reduced heap collides with first-note allocator/audio state or leaves first-note allocation without required headroom, causing reboot shortly after the consumer call.

### 2. R03 publication/order/cache visibility bug exposes malformed or partially visible owned voice to the first consumer (medium-low)

Evidence for:
- R03 has a new cross-context publication protocol and no explicit csync immediately between memcpy completion and valid=1.
- The first post-publish consumer is the first time the voice is used by the event/audio path.

Evidence against:
- memcpy is an ordinary CPU call in exact traces, consumers are CPU memcpy callers too, and R03 does use csync around lock/unlock.
- A visibility race would be timing-sensitive; the report says the first physical pad reliably rebooted rather than intermittent corruption.

First-fault model: valid becomes observable before the complete owned voice is safely observable to the consumer/audio path.

### 3. hidden 0xa0/0xa3 tail dependency not represented by R03's 0x9c-only owned copy (low-medium)

Evidence for:
- Factory-loader evidence shows live current snapshot has meaningful bytes at 0x9c..0xa2 and helper side effects from 0x9c..0x9f.
- Earlier requirements discussed at least 0xa0 of voice plus metadata, and earlier heap-prefix design allowed 0xc0, while final R03 reserves only 0xa0 and copies only 0x9c.

Evidence against:
- The exact Note On/Off consumer memcpy length is 0x9c in both R02 and R03.
- R02's live success proves the first 0x9c runtime Mooger payload is sufficient for the constrained audible Pad Ch10 path.
- Stock per-voice event metadata after the 0x9c destination copy is written by the dispatcher, not sourced from 0x01c46520+0x9c.

First-fault model: some downstream path, not the immediate dispatcher memcpy, dereferences source-adjacent or current-snapshot tail state that R03 did not preserve.

### 4. producer did not publish; consumer fallback or valid probe itself faults (low)

Evidence for:
- No live RAM readback exists, so publication is inferred, not proven.
- If the product packet was not accepted, valid would remain zero.

Evidence against:
- With valid=0, R03 falls back to stock memcpy with untouched stock r0/r1/r2, close to the R02/R01 live-booted primitive.
- The valid byte is in the BSS-extended reserved range, and boot success argues a simple byte load from that RAM is not enough to fault.

First-fault model: valid load or branch/fallback faults before owned memcpy, despite not selecting the owned source.

### 5. PI32 call/ABI/register/stack mismatch in R03 consumer wrappers (low)

Evidence for:
- R03 wrappers are longer and have separate entries, unlike R02.

Evidence against:
- Both wrappers save/restore {rets,r9..r4}; r0 destination is preserved/restored; r1/r2 are set exactly for memcpy; stock fallback preserves original r0/r1/r2.
- Decoder trace and validator bind every relevant call target and instruction byte.

First-fault model: misdecoded branch/call or clobbered register causes bad memcpy arguments, but exact bytes make this less likely.

## Safest next discriminating checkpoint

**offline-prepare, later-live heap-only H0 before any owned-source consumer retry**

Do not patch or flash now. Only build/review offline if requested.

1. Create an exact v15 H0 candidate that applies only the two R03 memory-boundary patches: BSS zero length through the shifted HEAP_BEGIN and HEAP_BEGIN=0x01c465c0. Leave Note On/Off, product/SAVE calls, and the packer stock.
2. If live testing is later authorized with rollback ready, test only normal boot, identity, and one stock Pad Ch10 Note On/Off with no product packet and no SAVE.
3. If H0 reboots on first pad, the former-heap-prefix/allocator/audio-owner hypothesis is strongly confirmed and R03 owned-source work should stop.
4. If H0 passes, the next lower-risk discriminator is H1: R02 live-success consumers from 0x01c37fd0 plus R03 producer present but unconsumed, still without using 0x01c46520 as a Note source.

Why: It removes the new owned-source memcpy and producer from the first live discriminator, testing the highest-ranked heap-prefix hypothesis with the fewest event-path changes.

## Reproduce

```sh
cd /Users/spectrum/Documents/SMK37ProMod
PYTHONPATH=tools python3 baselines/v15/analysis/r03-owned-ram/live-failure/consumer/analyze_consumer_fault.py
cd baselines/v15/analysis/r03-owned-ram/live-failure/consumer
shasum -a 256 -c SHA256SUMS
```
