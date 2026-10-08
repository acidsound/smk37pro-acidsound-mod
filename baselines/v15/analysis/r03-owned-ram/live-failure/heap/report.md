# v15 R03 first-Pad reboot heap/BSS failure analysis

Date: 2026-08-02 UTC

Scope: offline only. Inputs are exact official v15, exact R02, exact R03 app SHA
`3ff9c46b9686c0cea1348a11bed553ebd2d677e2d3452a0f436ce14f3ba5c788`, exact Mooger staging SHA
`6a9b4097cce1d28780ef3a507f42999743cc10e09770c17c5c78d185e9abff27`, and repository-pinned SDK evidence. No device access, patching, flashing, or v12-derived assumptions were used.

## Bottom line

The live failure is **not yet proven to be heap ownership corruption**. The exact R03 heap/BSS patches remain an incomplete safety proof, but the strongest falsifiable root cause is a more direct R03 wrapper bug:

> If `valid != 1` on the first Ch10 pad input, R03 branches to its stock fallback after clobbering `r0` with the valid byte. The fallback then calls stock `memcpy` with `r0 == valid` instead of the per-voice destination. That can copy 156 bytes to address `0x00000000` or `0x00000001` and reboot immediately.

This exactly fits a first physical Pad Ch10 reboot if the producer did not publish `valid=1`, whether because the official SysEx handler did not accept the packet in that state or because the `testset`/`ifeq` lock polarity was wrong. R02 avoided this class because it had no valid gate and no heap/BSS patches.

## Exact heap/BSS facts

| Item | Official v15 | Exact R03 |
| --- | --- | --- |
| app SHA-256 | `36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055` | `3ff9c46b9686c0cea1348a11bed553ebd2d677e2d3452a0f436ce14f3ba5c788` |
| BSS zero start | `0x01c099d4` | unchanged |
| BSS zero size instruction | `0x0200001e: c2ff48cb0300`, size `0x3cb48` | `0x0200001e: c2ffeccb0300`, size `0x3cbec` |
| BSS zero end | `0x01c4651c` | `0x01c465c0` |
| SDK-matched `sbrk` | `0x0205e9da`, 80 fixed bytes exact | same body with patched relocation payload |
| `HEAP_BEGIN` instruction | `0x0205e9f8: c5ff2065c401`, `0x01c46520` | `0x0205e9f8: c5ffc065c401`, `0x01c465c0` |
| `HEAP_END` | `0x01c7fd30` | unchanged |
| claimed R03 range | n/a | `0x01c46520..0x01c465c0`, 160 bytes |

The official app contains exactly one raw little-endian `HEAP_BEGIN` literal and one `HEAP_END` literal:

- `0x01c46520` at file offset `0x0005e9fa`, in `mov r5,#0x01c46520` inside the SDK-matched `sbrk`;
- `0x01c7fd30` at file offset `0x0005ea02`, in `mov r10,#0x01c7fd30` inside the same `sbrk`;
- official mov-payload hits in `0x01c46520..0x01c465c0`: only `0x0205e9f8`.

This supports that patching the one `sbrk` immediate moves the public-SDK heap lower bound. It does **not** by itself prove total runtime safety: it still lacks a complete allocator initialization graph, all dynamic allocation/high-water evidence, and a no-alias proof for stacks, DMA, USB/audio workspaces, cache/MMU/MPU, and computed references.

A prior heap-prefix audit promoted a `0xc0` reservation through `0x01c465e0`. Exact live R03 reserved only `0xa0` through `0x01c465c0`. The broader scan still supports no direct official absolute references in the prefix, but the prior `0xc0` state layout and active-count/generation assumptions are not the exact live-failed R03 design.

## R02 live success versus R03 owned-source failure

| Property | R02 live-success transient staging | R03 live-failed owned source |
| --- | --- | --- |
| Live result | PASS as controlled checkpoint | FAIL on first physical Pad Ch10 |
| Ch10 source | `0x01c37fd0` official transient SysEx staging | `0x01c46520` owned copy if `valid==1`; stock fallback otherwise |
| HEAP/BSS changes | none | BSS zero extended and `HEAP_BEGIN` moved by 160 bytes |
| Valid gate | none | yes, `valid` at `0x01c465bc` |
| Producer | none; official handler populates staging | repointed accepted product-packet calls to R03 producer |
| Fallback risk | no invalid fallback path | invalid fallback clobbers destination register |

R02 proved the event-path primitive: the same Note On/Off copy sites can call a wrapper and consume a 156-byte Mooger runtime source. R03 kept those callsites but added a validity branch and a producer. The live failure happened at the first consumer execution after staging, which is the exact point where a stale `valid==0` becomes fatal in R03.

## Exact invalid-fallback bug

R03 Note Off wrapper:

```text
0201e146  0516            mov r5,r0              ; save destination
0201e148  c4ffbc65c401    mov r4,#0x01c465bc    ; valid address
0201e14e  4840            lb.z r0,[r4 + 0x0]     ; r0 = valid, destination clobbered
0201e150  80f80902        jne r0,#0x1,0x0201e166 ; branch if invalid
0201e154  5016            mov r0,r5              ; restore destination only on valid path
0201e156  c1ff2065c401    mov r1,#0x01c46520
0201e15e  80ff6aab0200    call 0x02048cce
0201e166  80ff62ab0200    call 0x02048cce        ; invalid fallback, r0 still valid byte
```

R03 Note On wrapper has the same shape:

```text
0201e176  0516            mov r5,r0
0201e178  c4ffbc65c401    mov r4,#0x01c465bc
0201e17e  4840            lb.z r0,[r4 + 0x0]
0201e180  80f80902        jne r0,#0x1,0x0201e196
0201e184  5016            mov r0,r5              ; restore destination only on valid path
0201e186  c1ff2065c401    mov r1,#0x01c46520
0201e18e  80ff3aab0200    call 0x02048cce
0201e196  80ff32ab0200    call 0x02048cce        ; invalid fallback, r0 still valid byte
```

Therefore, the safety claim “invalid Ch10 falls back to stock source” is false for exact R03. It falls back to stock `r1/r2`, but not stock `r0`.

## Producer uncertainty

R03 producer has an official-toolchain-derived nonblocking sequence:

```text
0201e1a8  2000            csync
0201e1aa  b000            testset b[r0]
0201e1ac  40e81b00        ifeq -> 0x0201e1e6 producer return
```

Offline artifacts prove these bytes and target. They do not prove the live packet was accepted by the handler or that the `testset` condition flags were interpreted correctly for an initially zero lock. If the producer returned before setting `valid=1`, the first Ch10 input deterministically reaches the invalid-fallback bug above.

## Falsifiable root-cause ranking

1. **Invalid-fallback register clobber, triggered by `valid != 1`.** Strongest exact-code finding. Falsify by proving `0x01c465bc == 1` immediately before the first Pad Ch10 input or that the invalid branch cannot be reached in the live sequence.
2. **Producer did not publish `valid=1`.** Plausible trigger for rank 1. Causes include official handler gate rejection, packet not accepted despite host send success, or wrong `testset`/`ifeq` polarity. Falsify with independent PI32 ISA proof plus a non-live trace or emulator proving exact packet publication sets `valid=1`.
3. **R03 heap-prefix ownership remains incompletely proven.** The matched `sbrk` evidence is strong for the lower-bound immediate, but exact R03 changed allocator capacity and did not carry the prior `0xc0` active-count/generation design. Falsify with complete allocator graph and heap high-water margin under boot, SysEx, and first pad.
4. **Patching only `sbrk` immediate is insufficient.** Weighed down by the official literal scan and SDK `sbrk` match, but still not fully refuted for computed allocator state. Falsify by proving all allocation paths derive from the matched `sbrk` state and no other lower-bound cache exists.
5. **Cache/MMU/MPU/DMA incoherence.** Currently unsupported for this CPU-to-CPU `memcpy` path. The Desktop SDK symlink target was unavailable (`/Volumes/Res/NTE_Data/PatcherSDK` not mounted), so only repo-pinned SDK excerpts/objects were checked. Falsify or promote with mounted pinned-SDK/manual evidence requiring cache or MPU changes for normal RAM writes consumed by synth code.

## Safety decision

Do **not** flash another owned-RAM R03 derivative based on the current evidence.

The exact BSS/HEAP patch is not convicted as the most likely live cause, but it also is not a complete PASS. More importantly, exact R03 has a consumer bug that can reboot even if the heap patch is harmless whenever the producer does not publish.

## Next safe checkpoint

Safe non-live checkpoint, in order:

1. Build an offline-only R03 diagnostic variant that fixes the invalid fallback by restoring `r0=r5` before any stock fallback call. Validate both Note On and Note Off invalid paths byte-for-byte. Do not package or flash it.
2. Independently prove `testset b[r0]` flag polarity from the official PI32 ISA/toolchain, not by inference from R03 intent. The current objdump proves bytes and syntax, not the live truth table.
3. Re-run heap ownership as an exact `0xa0` design, not the older `0xc0` design. Required evidence: allocator initialization graph, all `sbrk` callers, heap high-water margin, and cache/MMU/MPU constraints from the pinned SDK/manual.
4. Only after 1-3 pass, consider a minimal no-owned-RAM live checkpoint that exercises only the fixed invalid fallback with `valid` forced zero and stock source restored. This should be treated as a separate candidate with exact rollback, not as R03 continuation.

## Reproduce

```sh
python3 baselines/v15/analysis/r03-owned-ram/live-failure/heap/analyze_r03_heap_live_failure.py
cd baselines/v15/analysis/r03-owned-ram/live-failure/heap
shasum -a 256 -c SHA256SUMS
```

Generated files:

- `analyze_r03_heap_live_failure.py`
- `evidence.json`
- `validation.txt`
- `report.md`
- `SHA256SUMS`
