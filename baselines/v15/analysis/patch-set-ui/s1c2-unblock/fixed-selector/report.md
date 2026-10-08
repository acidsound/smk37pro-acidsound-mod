# S1-C2 fixed two-patch Channel 10 selector checkpoint

Date: 2026-08-02 UTC  
Status: **BLOCK for flash candidate, PASS as an offline design checkpoint**  
Scope: official v15 plus exact live-PASS H2/S1-C1 evidence only. No device, flash, OTA, reset, app candidate, or FWSC candidate was created.

## Decision

A minimal no-runtime-upload-parser selector is structurally sound only if two immutable `0x9c` runtime voice objects can be placed at positively owned readable addresses.

Current result:

- **Selector logic:** PASS design. It needs only the existing Note On/Off memcpy hooks, compares explicit Channel 10 notes `36` and `45`, and uses the same note-to-object rule for Note On and Note Off.
- **Offline objects:** PASS evidence. Two `156`-byte runtime objects were generated from official v15 factory dump inputs and hash-checked against the existing factory voice catalog.
- **Executable/data placement:** **BLOCK.** No existing evidence proves an owned address range for `58` selector bytes plus `312` object bytes while preserving H2 behavior. Appended app/tail placement remains blocked by `cfg_tool.bin`; app/text is not proven writable owned RAM and its tail is not free.
- **Firmware candidate:** **BLOCK.** Do not build one until both executable and data placement are independently proven.

This intentionally avoids the S1-C1/S1-C2 runtime upload parser path. The checkpoint is a fixed selector design, not a mutating loader.

## Exact evidence basis

| Evidence | Path / value | SHA-256 or status |
|---|---|---|
| Official v15 app | `build/v15-official-app.bin` | `36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055` |
| H2 live-parent app | `build/SMK37Pro-v15-H2-owned-source-corrected-fallback/app.bin` | `d71f6c58b4fade00aebb8a0b7d9d024641c37c41ca4bbf3e525fd28773087f59` |
| S1-C1 boundary app | `build/SMK37Pro-v15-S1C1-boundary-only/app.bin` | `16023c9006f2d4d6467ef2d72d6165c14ffeb6cb758d074f7d8163a68146fb2e` |
| Clean v15 factory dump | `baselines/v15/device-dumps/v15-clean-baseline-a.bin` | `1c202201a81ed6d956ec5398adff75ffcd805594a27370a56caafaf18223383b` |
| Factory voice catalog | `baselines/v15/analysis/patch-set-ui/catalog/factory-voices.json` | source dump hash matches clean dump |
| S1-C1 code report | `baselines/v15/analysis/patch-set-ui/s1c1/code/report.md` | proves Note Off `r5`, Note On `r6`, H2 corrected fallback, 96-byte dynamic selector |
| S1-C2 placement audit | `baselines/v15/analysis/patch-set-ui/s1c2-unblock/executable-placement/report.md` | parser placement BLOCK, app-tail BLOCK |
| App-tail placement audit | `baselines/v15/analysis/r03-owned-ram/app-tail-placement/report.md` | JLFS-preserving append capacity `0` |

## Fixed note and object mapping

These are explicit MIDI note values, not physical Pad ordinals and not a contiguous Pad sequence.

| MIDI channel | Note | Object | Factory source | Runtime object file | SHA-256 |
|---:|---:|---|---|---|---|
| 10 | `36` / `0x24` | slot/object 0 | Bank D patch 12, `HAND DRUM` | `objects/note36-bankD12-HAND_DRUM.runtime156.bin` | `98bc86e7d9625c837ee6c07fa3f01cbd6079960c9d1071017cf51194aa48c1bf` |
| 10 | `45` / `0x2d` | slot/object 1 | Bank D patch 14, `Mooger #1` | `objects/note45-bankD14-Mooger_1.runtime156.bin` | `e0bf5adb328b25de2c64d24cf8f6fe8f8e293e968dd56dbbfbf771ad92fe8275` |

Object derivation used the official-v15 factory-loader expansion model already recorded in `channel-separation-reanalysis/factory-loader/analyze_factory_loader.py`: six 17-byte packed operators expand to six 21-byte runtime operators, global bytes expand through `0x7e..0x9b`, and byte `0x9b` is fixed to `0x3f`. Each generated object is exactly `156` bytes and matches the catalog's `runtime_sha256`.

Important limitation: prior live evidence rejected claims that app-resident static snapshots alone prove the audible stock UI identity for `HAND DRUM`, `BUZZ BASS`, or `Mooger #1`. This checkpoint therefore claims only that these are defensible official factory-loader model outputs and distinct immutable runtime objects. It does not claim live acoustic identity until a safe candidate and live test are separately authorized.

## Hook addresses and ABIs

### Note Off hook

| Field | Value |
|---|---|
| Hook callsite | `0x0201c63e` |
| Existing stock target | `0x02048cce` |
| H2/S1-C1 target | `0x0201e13e` |
| Proven note register | `r5 = msg[1]` from `0x0201c62e` |
| Destination | `r0 = per-voice destination = r6 + 0xa2` |
| Stock source | `r1 = r8 = 0x01c34c74` |
| Copy count | `r2 = 0x9c` |
| Channel nibble | `r9 = status & 0x0f`; Channel 10 is `9` |
| Post-call metadata | `0x0201c648` stores original `r5` note |

### Note On hook

| Field | Value |
|---|---|
| Hook callsite | `0x0201c67c` |
| Existing stock target | `0x02048cce` |
| H2/S1-C1 target | `0x0201e142` in the compact two-adapter layout |
| Proven note register | `r6 = msg[1]` from `0x0201c670` |
| Velocity register | `r5 = msg[2]` from `0x0201c66a` |
| Destination | `r0 = per-voice destination = r7 + 0xa2` |
| Stock source | `r1 = r8 = 0x01c34c74` |
| Copy count | `r2 = 0x9c` |
| Channel nibble | `r9 = status & 0x0f`; Channel 10 is `9` |
| Post-call metadata | `0x0201c686` stores original `r6` note; `0x0201c68c` stores original `r5` velocity |

Both hooks must preserve original destination, note, velocity, `r1` fallback source, `r2` count, and callee-saved registers exactly as the S1-C1 code report requires.

## Exact C pseudocode

`OBJ0_ADDR` and `OBJ1_ADDR` are intentionally unassigned. A future candidate must replace them only with independently proven, immutable, readable placement addresses whose bytes hash to the two object hashes above.

```c
#define CH10_NIBBLE 9u
#define NOTE0       36u
#define NOTE1       45u
#define VOICE_BYTES 0x9cu

extern const uint8_t OBJ0_ADDR[VOICE_BYTES]; /* BLOCK: no proven address yet */
extern const uint8_t OBJ1_ADDR[VOICE_BYTES]; /* BLOCK: no proven address yet */

static inline const uint8_t *fixed_ch10_source(uint8_t channel_nibble,
                                                uint8_t note,
                                                const uint8_t *stock_src)
{
    if (channel_nibble != CH10_NIBBLE)
        return stock_src;

    if (note == NOTE0)
        return OBJ0_ADDR;

    if (note == NOTE1)
        return OBJ1_ADDR;

    return stock_src;
}

/* Adapter entered from 0x0201c63e. Native note register is r5. */
void note_off_adapter(uint8_t *dst_r0, const uint8_t *stock_r1,
                      uint32_t count_r2, uint8_t note_r5,
                      uint8_t channel_r9)
{
    const uint8_t *src = fixed_ch10_source(channel_r9, note_r5, stock_r1);
    memcpy(dst_r0, src, count_r2); /* count_r2 must still be exactly 0x9c */
    /* return with r5 restored so 0x0201c648 stores the same Note Off note */
}

/* Adapter entered from 0x0201c67c. Native note register is r6, velocity is r5. */
void note_on_adapter(uint8_t *dst_r0, const uint8_t *stock_r1,
                     uint32_t count_r2, uint8_t velocity_r5,
                     uint8_t note_r6, uint8_t channel_r9)
{
    const uint8_t *src = fixed_ch10_source(channel_r9, note_r6, stock_r1);
    memcpy(dst_r0, src, count_r2); /* count_r2 must still be exactly 0x9c */
    /* return with r6 and r5 restored for note and velocity metadata stores */
}
```

## Minimal PI32 selector budget

This is a byte budget, not a candidate byte string. It uses only instruction forms already admitted by the S1-C1 code report: two native note-register adapters, `push/pop {rets,r9..r4}`, `mov`, `jne rX,#imm7`, official `xor r0,r3` equality, `mov32 r1,#imm32`, short `goto`, and `call32 0x02048cce`.

| Component | Bytes | Notes |
|---|---:|---|
| Note Off adapter: `mov r3,r5; goto core` | `4` | normalizes Note Off note from proven `r5` |
| Note On adapter: `mov r3,r6` | `2` | normalizes Note On note from proven `r6`, then falls through |
| Shared prologue: push, save destination, copy channel | `6` | `push`, `mov r4,r0`, `mov r5,r9` |
| Non-Ch10 fallback branch | `4` | `jne r5,#9,copy` |
| Note 36 compare | `8` | `mov r0,#36; xor r0,r3; jne r0,#0,note1` |
| Object 0 source select | `8` | `mov32 r1,OBJ0_ADDR; goto copy` |
| Note 45 compare | `8` | `mov r0,#45; xor r0,r3; jne r0,#0,copy` |
| Object 1 source select | `6` | `mov32 r1,OBJ1_ADDR` |
| Common copy tail | `10` | `mov r0,r4; call 0x02048cce; pop {pc,r9..r4}` |
| **Selector code total** | **58** | excludes immutable object bytes |
| Immutable object 0 | `156` | generated offline |
| Immutable object 1 | `156` | generated offline |
| **Selector + objects, no H2 producer** | **370** | still requires owned executable/data placement |
| Unchanged H2 producer if preserved at `0x0201e1a2..0x0201e1ec` | `74` | required to preserve accepted product-packet H2 behavior |
| **Selector + objects + H2 producer** | **444** | exceeds all currently owned contiguous ranges |

If the future placement splits code and data, each split must still prove branch/call reach, XIP readability for object constants, object immutability, and non-overlap with official JLFS files or reachable stock/H2 code.

## Placement investigation

| Mechanism | Capacity / fact | Decision |
|---|---:|---|
| Existing H2/S1-C1 replaced stock packer body `0x0201e13e..0x0201e254` | `278` bytes total | **BLOCK**: `58 + 312 = 370` even before preserving H2 producer |
| Preserve H2 producer in place and use remaining body | `278 - 74 - 58 = 146` bytes for objects | **BLOCK**: needs `312` bytes |
| Residual H2 tail `0x0201e1ec..0x0201e254` | `104` bytes | **BLOCK**: not enough for objects and already insufficient for S1-C2 parser |
| App-area tail `0x02096a34..0x02096bb3` | `383` apparent bytes | **BLOCK**: JLFS names it `cfg_tool.bin`; JLFS-preserving available bytes are `0` |
| App/text as immutable data source | XIP may be readable, but no owned insertion address | **BLOCK** until an address is proven owned and packaged safely |
| Official factory packed/raw records | existing flash bytes | **BLOCK**: not two expanded `156`-byte runtime objects at stable readable addresses |
| S1-C1 owned RAM `0x01c46520..0x01c46660` | enough volatile bytes | **BLOCK for no-parser fixed checkpoint**: no proven boot/static initializer places immutable objects there without new runtime producer code |
| Sequential official product SysEx | live-proven for one H2 slot | **REJECTED**: this is a runtime upload/staging route and lacks exact two-object all-or-none invariants |

Conclusion: no appended app code/data or alternative owned mechanism is currently proven. The only safe output is this checkpoint plus offline objects and validator.

## Runtime behavior if placement later passes

1. Channel 10 Note On `0x99 0x24 vel`: copy object 0 to the stock per-voice destination.
2. Channel 10 Note Off `0x89 0x24 vel`: copy object 0 to the same note's release/off path, preserving the original Note Off note metadata.
3. Channel 10 Note On `0x99 0x2d vel`: copy object 1.
4. Channel 10 Note Off `0x89 0x2d vel`: copy object 1.
5. Channel 10 any other note: call original stock/H2 fallback source `0x01c34c74` with original destination and `r2 = 0x9c`.
6. Channel 1 and every non-Channel-10 event: unchanged fallback. The selector must not change `r1` before the fallback branch reaches the common copy tail.
7. H2 accepted-product behavior: unchanged only if the H2 producer remains byte-for-byte reachable at `0x0201e1a2..0x0201e1ec`. If a candidate removes or moves it, the candidate fails this checkpoint.

## Failure behavior

- **Current state:** fail closed at build/validation time. No app/FWSC candidate exists.
- **Object hash mismatch:** validator fails; no firmware build may proceed.
- **Object length not exactly 156:** validator fails.
- **Notes not exactly distinct `36` and `45`:** validator fails.
- **No proven `OBJ0_ADDR`/`OBJ1_ADDR`:** candidate generation remains blocked.
- **Placement overlaps `cfg_tool.bin`, app tail, H2 producer, official handler, or any reachable stock/H2 code:** candidate generation remains blocked.
- **Runtime non-match path:** fallback copies from the original stock source with original destination and count. There is no partial state and no mutation.

## Required validator assertions

A future validator for a candidate must assert all of the following before any flash artifact is allowed:

1. Parent lineage is exact official v15 plus exact live-PASS H2/S1-C1 parent hashes.
2. Note Off hook remains at `0x0201c63e` and enters adapter with `r5 = msg[1]`.
3. Note On hook remains at `0x0201c67c` and enters adapter with `r6 = msg[1]`, `r5 = msg[2]`.
4. Hook call encodings target the two fixed adapters and are decoded independently by both official-v15 listings.
5. Selector bytes decode to the admitted `58`-byte control flow or to a separately proven smaller/equivalent control flow.
6. Every fallback path reaches memcpy with original `r0` restored from saved destination, original `r1` stock source unchanged, and `r2 = 0x9c` unchanged.
7. Matched note `36` selects only object 0 for both Note On and Note Off.
8. Matched note `45` selects only object 1 for both Note On and Note Off.
9. Notes `36` and `45` are distinct, bounded MIDI bytes, and are not inferred from physical Pad order.
10. Object 0 address contains exactly `156` bytes with SHA-256 `98bc86e7d9625c837ee6c07fa3f01cbd6079960c9d1071017cf51194aa48c1bf`.
11. Object 1 address contains exactly `156` bytes with SHA-256 `e0bf5adb328b25de2c64d24cf8f6fe8f8e293e968dd56dbbfbf771ad92fe8275`.
12. Object addresses are readable by the memcpy source path and immutable for the checkpoint lifetime.
13. Data placement is positively owned: it does not overlap app tail `cfg_tool.bin`, protected suffixes, JLFS metadata, official resources, or reachable code.
14. If H2 accepted-product fallback is claimed preserved, `0x0201e1a2..0x0201e1ec` is byte-for-byte unchanged and both product callsites still reach it.
15. No runtime upload parser, private SysEx parser, sequential official-product publication, device access, flash, OTA, or generated app/FWSC artifact is present in this fixed-selector checkpoint directory.

## Reproduction

```sh
python3 baselines/v15/analysis/patch-set-ui/s1c2-unblock/fixed-selector/validate.py
shasum -a 256 -c baselines/v15/analysis/patch-set-ui/s1c2-unblock/fixed-selector/SHA256SUMS
```

The reproduction validates analysis files and object bytes only. It does not build or modify firmware.
