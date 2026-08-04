# S1-C4 withdrawal and duplicate-safe successor design

Status: **DESIGN ONLY, NO FIRMWARE CANDIDATE**.  
Scope: official v15, current committed S1-C3/S1-C4 evidence, and the user live result only. This pass did not generate an app, FWSC, HEX, sender, OTA wrapper, rollback ZIP, USB/MIDI traffic, reset, flash, or live command.

## Withdrawal decision

S1-C4 must be withdrawn as a product candidate.

User live result:

- `Playback Original`: the 16 direct patch packets with wire byte `161 == trigger note 36..51` staged and played all 16 patches normally.
- `all C4`: the same set with wire byte `161 == 60` repeated for all slots failed the transaction and fell back to Ch1 behavior.

Interpretation for successor work:

1. Wire byte `161` is not a safe per-slot Playback Note carrier for a product packet. In the successful live case it matched the physical Trigger Note / resident slot identity. In the failing live case it was an arbitrary duplicate Playback Note.
2. The S1-C4 v1/v2/v3 producer idea of reading `stage[0x9b]` / wire byte `161` as Playback Note is rejected, even though its offline decode said duplicates were allowed.
3. Any successor must preserve the 16 patch packets' physical Trigger Notes `36..51`, the note-ordered slot publication contract, and the existing 16 resident patch slots.
4. Duplicated Playback Notes, including `60` for every slot, must be metadata accepted by a separate path. They must not participate in slot/order/uniqueness/publication acceptance.
5. Note Off correctness is a release gate, not a static assumption. The successor may only ship after Note On and Note Off use the same per-trigger-slot Playback Note, and duplicate-note overlap tests show no stuck notes or wrong fallback.

## Evidence baseline

| Evidence | Exact fact used |
|---|---|
| `flash-candidates/H2-owned-source-corrected-fallback/live-validation-20260802.md` | H2 live-proved owned source `0x01c46520`, corrected Ch10 Note On and Note Off fallback, no reboot, intended sound, normal Note Off. |
| `flash-candidates/S1C3-16slot-boundary-only/live-validation-20260803.md` | The RAM reservation `0x01c46520..0x01c46fb0` (`0x0a90` bytes) is live-safe. |
| `flash-candidates/S1C3-16slot-functional-v2-r3-reload/report.md` | Current 16-slot patch set uses exactly 16 existing slots, note order slot `0..15` maps to MIDI notes `36..51`, and physical Pad permutation is UI-only. |
| `flash-candidates/S1C3-16slot-functional-v2-r3-reload/inputs/producer/report.md` | S1-C3 producer fits `0x0201e1a2..0x0201e250`, leaves only 4 spare bytes, uses lock `0x01c465bd`, count `0x01c465be`, state `0x01c465bf`, and publishes `ARMED` last. |
| `playback-note/candidate-v3-segmented-final/evidence.json` and `decode.tsv` | S1-C4 occupied `0x0201e13e..0x0201e254`: selector `0x0201e13e..0x0201e196` (88 bytes), producer `0x0201e196..0x0201e252` (188 bytes), tail padding 2 bytes. |
| `playback-note/segmented-abi/report.md` | Segmented-final product path can reconstruct `stage[0x9b]`, but that only proves where byte 161 is. The user live result now proves that byte cannot be repurposed as arbitrary duplicate metadata. |
| `playback-note/v3-segmented-review/review.md` | S1-C4 v3 is already BLOCKED offline by exact OTA wrapper mismatch, and is now also withdrawn on live semantics. |

## Successor invariant

Name for planning: **S1-C5 split Playback Note metadata**.

The successor must separate two identities:

- **Physical Trigger Note / slot publication identity:** immutable `36+i` for slot `i`, preserved in every one of the 16 patch packets and used only as `slot = trigger_note - 36`.
- **Playback Note metadata:** independent seven-bit value `0..127`, allowed to duplicate arbitrarily across slots, including all slots equal to `60`.

The firmware must never use Playback Note to choose a resident patch source. Source selection remains:

```text
if channel == Ch10 and trigger_note in 36..51 and set_state == ARMED and slot_valid[trigger_note - 36] == 1:
    source = 0x01c46520 + (trigger_note - 36) * 0xa0
else:
    stock fallback
```

Playback Note may only be read after the same Ch10/range/ARMED/selected-slot-valid gates pass.

## Minimum patch plan

### Step 0: withdraw S1-C4

- Mark S1-C4 v1/v2/v3 as obsolete in release notes before any future user-facing authorization.
- Do not repair S1-C4 v3's OTA wrapper as a route to flashing. That would produce a candidate with the wrong transport semantics.
- Treat any packet set where wire byte `161` differs from `36+i` as invalid for S1-C4 and as a regression test for S1-C5.

Gate `W0`: report-only change. No binary candidate, FWSC, sender, OTA, reset, flash, or live transport generated.

### Step 1: keep S1-C3 patch publication unchanged

- Start from S1-C3 r3-reload behavior, not from S1-C4 byte-161 mutation.
- All 16 existing patch packets remain direct product packets in slot order:

| Slot | Physical Trigger Note / publication byte 161 |
|---:|---:|
| 0 | 36 |
| 1 | 37 |
| 2 | 38 |
| 3 | 39 |
| 4 | 40 |
| 5 | 41 |
| 6 | 42 |
| 7 | 43 |
| 8 | 44 |
| 9 | 45 |
| 10 | 46 |
| 11 | 47 |
| 12 | 48 |
| 13 | 49 |
| 14 | 50 |
| 15 | 51 |

- The existing S1-C3 publication rule remains valid-last, count-after-valid, `state=ARMED` last.
- No 17th patch slot, heap expansion, or unproven RAM is allowed.

Gate `P1`: byte-level packet manifest proves every patch packet still has wire byte `161 == 36+slot`. Any duplicate or non-trigger value in a patch packet is an immediate fail-closed build error.

### Step 2: add one separated Playback Note metadata transaction

Use one new control transaction, not the patch product byte at offset `0x9b`. The safest planned shape is a 163-byte direct product-gate message whose payload begins with an S1-C5-only magic and contains 16 seven-bit Playback Notes. It is consumed by the replacement producer as metadata and must not be copied into any patch slot.

Planned control payload fields:

```text
payload[0..5]    = ASCII-like seven-bit magic for S1C5PN
payload[6]       = version 1
payload[7]       = flags, zero for v1
payload[8]       = count 16
payload[9..24]   = playback_note[0..15], each 0..127, duplicates allowed
payload[25..27]  = compact CRC/check chunks, or omitted only if code-size proof explicitly blocks CRC
payload[28..0x9b]= zero padding if CRC is present; otherwise must still be exact-zero padding
```

Ordering:

1. Send the Playback Note metadata transaction first, or immediately after a reset transaction, while patch count is still `0`.
2. Firmware stores the 16 notes in the already proven header/map area `0x01c46f20..0x01c46f2f` and marks a small metadata state byte in the same proven `0x01c46f20..0x01c46fb0` window.
3. Send the 16 S1-C3 patch packets unchanged with byte `161 == 36..51`.
4. Patch producer publishes `state=ARMED` only after all 16 patch slots are valid. Metadata readiness must not substitute for patch-set ARMED.

Gate `M2`: metadata parser proof must show arbitrary duplicates are accepted, including all 16 bytes equal `60`, and that no metadata byte participates in patch count, slot index, valid-byte publication, or ARMED publication.

### Step 3: use only live-proven RAM

Admitted RAM remains inside the S1-C3 boundary-only live-safe window:

| Address/range | Use |
|---|---|
| `0x01c46520..0x01c46f20` | unchanged 16 resident patch slots, stride `0xa0` |
| `0x01c465bd` | existing producer lock |
| `0x01c465be` | existing loaded count |
| `0x01c465bf` | existing patch-set state, `2 == ARMED` |
| `0x01c46f20..0x01c46f2f` | 16 Playback Note bytes, one per resident slot |
| `0x01c46f30` | metadata state, e.g. `0 empty`, `1 loaded` |
| `0x01c46f31..0x01c46f3f` | optional Note On active latch/counters if exact Note Off proof requires it |
| `0x01c46f40..0x01c46faf` | reserved, must remain zero unless a later exact proof allocates it |

No use outside `0x01c46520..0x01c46fb0` is admitted.

Gate `R3`: app diff must prove no BSS/heap boundary movement beyond the live-PASS S1-C3 `0x0a90` reservation and no memory access outside the table above.

### Step 4: selector semantics

The selector may reuse the S1-C4 v3 high-level idea only after removing any dependency on patch byte `161`:

1. Note Off adapter reads trigger note from `r5`.
2. Note On adapter reads trigger note from `r6` and preserves velocity `r5`.
3. Shared gates check Ch10, trigger range `36..51`, patch-set `ARMED`, and selected slot valid.
4. Source remains `0x01c46520 + (trigger_note - 36) * 0xa0`.
5. Playback Note is loaded from `0x01c46f20 + slot` only if metadata state is loaded. If metadata is absent, fallback Playback Note is the trigger note `36+slot`.
6. Note On and Note Off return the same effective Playback Note for the same trigger slot. If static proof cannot establish this for duplicate notes, add/use `0x01c46f31..0x01c46f3f` active latches and block shipment until overlap live tests pass.
7. MIDI OUT and incoming message bytes remain unchanged.

Gate `S4`: independent PI32 decode must prove source invariant, metadata load after all gates, velocity preservation, identical Note On/Off lookup, and no stock fallback destination clobber. This is a hard gate before any candidate packaging.

### Step 5: code-cave budget rule

The only executable region admitted for S1-C5 is the already used H2/S1-C3/S1-C4 product/selector cave:

| Region | Budget rule |
|---|---|
| `0x0201e13e..0x0201e254` | total replacement must fit wholly here |
| selector subrange | may be rebalanced, but final decode must provide exact start/end and branch targets |
| producer subrange | may be rebalanced, but must include patch publication, metadata control path, reset semantics, and fail-closed returns |
| outside this range | no new executable code unless a separate official-v15 static and live-safe boundary proof is produced first |

Expected pressure: S1-C4 v3 already used 278 bytes total. Preserving byte 161 in patch packets removes the S1-C4 stage/slot restore logic, but the separated metadata parser consumes new bytes. Therefore S1-C5 has a mandatory **fit-first** gate before package build.

Gate `C5`: exact builder emits selector/producer bytes and independent decode. If the total overflows `0x0201e254`, or if CRC/rejection behavior is dropped without an explicit accepted risk gate, stop. Do not build a firmware candidate.

## Exact gates before any future firmware candidate

| Gate | Name | Required proof | Stop condition |
|---|---|---|---|
| `W0` | S1-C4 withdrawn | design/release notes state byte-161 metadata is rejected | any S1-C4 flash/fix path remains presented as usable |
| `P1` | trigger publication preserved | all 16 patch packets have wire byte `161 == 36+slot`; slot order unchanged | any patch packet carries Playback Note in byte 161 |
| `M2` | duplicate metadata accepted | parser model accepts `[60]*16` and arbitrary duplicate vectors | duplicate notes reject, affect count, or prevent ARMED |
| `R3` | no unproven RAM | all table/control accesses remain in `0x01c46520..0x01c46fb0` | heap boundary moves or access escapes window |
| `S4` | selector/Note Off correctness proof | decode proves same per-slot Playback Note path for Note On and Note Off, source keyed by trigger, velocity preserved | Note On-only substitution, source selected by Playback Note, or fallback clobber |
| `C5` | code-cave fit | full replacement fits `0x0201e13e..0x0201e254` with all branches/calls decoded | overrun, undecoded bytes, or unowned executable region |
| `O6` | offline reproducibility | clean-worktree validator rebuilds byte-identical artifacts and exact OTA wrapper compiles against committed `src/ota.c` API | stale validation like S1-C4 v3 review blocker |
| `B7` | rollback reconstruction | rollback sectors exactly reconstruct official v15 flash | missing or extra sector, SHA mismatch |
| `L8` | live authorization | explicit user authorization for flash/send after all offline gates | any live/device action during design or offline validation |

## Rollback sector scope

Use the already established five-sector rollback scope unless an exact future diff proves fewer sectors changed:

| Sector | Reason |
|---:|---|
| `0x04000` | package/app metadata sector touched by prior v15 candidates |
| `0x20000` | app code sector containing event hooks / product logic |
| `0x22000` | app code sector containing selector/producer/product handler area |
| `0x2a000` | app/support sector observed in prior exact rollback manifests |
| `0x62000` | firmware/package metadata sector observed in prior exact rollback manifests |

Rollback gate:

```text
candidate rollback official-v15 recovery sectors must reconstruct flash SHA-256
f77e9ab3cee79113be78f3efacffb03c6cb9b87b78263010e16e81c472df0f9a
```

If future diff shows an additional flash sector changed, the rollback bundle must include it and the live authorization gate resets to BLOCK pending review.

## Live test matrix for a future authorized candidate

No live test is authorized by this design. The table defines the minimum matrix after all offline gates pass and the user explicitly authorizes flash/send.

| Test | Packet metadata | Trigger publication bytes | User/live action | Required result |
|---|---|---|---|---|
| `L0 identity` | Original/effective notes `36..51` | preserved `36..51` | stage 16 patches, press/release all physical pads | all 16 patches normal, no reboot, no stuck note |
| `L1 all C4 arm` | `[60]*16` | preserved `36..51` | stage metadata then same 16 patches | transaction arms, no Ch1 fallback, all pads produce their assigned patch at C4 pitch |
| `L2 all C4 Note Off` | `[60]*16` | preserved `36..51` | press/release each pad one at a time | every release stops normally, no lingering voice |
| `L3 overlapping duplicates` | at least four slots mapped to `60` | preserved `36..51` | hold two duplicate-mapped pads, release in both orders | no stuck note, no wrong patch release, no fallback |
| `L4 mixed duplicates` | e.g. `[60,60,62,62,64,64,...]` | preserved `36..51` | press/release all 16 | duplicates accepted, unique slots still select correct resident patches |
| `L5 fallback` | metadata loaded | preserved `36..51` | send Ch1 and out-of-range Ch10 notes | stock fallback unchanged, MIDI OUT unchanged |
| `L6 reset/reload` | metadata then patch set | preserved `36..51` | reboot or reset according to exact candidate instructions | no stale ARMED without restaging; documented reset semantics hold |
| `L7 malformed control` | short, long, bad magic, bad CRC if CRC is used, note >127 if representable | preserved patch packets | send malformed metadata before patches | metadata rejected without mutating patch slots or patch ARMED state |
| `L8 rollback` | n/a | n/a | install rollback only if explicitly authorized | official v15 identity restored and candidate behavior absent |

Hard live stop conditions: reboot, USB identity loss not attributable to the known macOS interface reclaim race, Ch1 fallback after a supposedly armed duplicate set, stuck note, Note Off mismatch, any patch packet requiring byte 161 other than `36+slot`, or any need to send ad-hoc unvalidated traffic.

## Current conclusion

The minimum safe successor is not a repaired S1-C4. It is a split-metadata successor that keeps S1-C3 patch publication byte-for-byte compatible with physical Trigger Notes `36..51`, stores Playback Notes in already live-proven header RAM, and proves duplicate-safe Note On/Off behavior before packaging. The first future implementation task is the fit-first selector/producer proof for `0x0201e13e..0x0201e254`; if it does not fit, there must be no firmware candidate.
