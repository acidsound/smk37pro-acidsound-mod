# v15 Ch10 per-note patch-set UI integration design

Date: 2026-08-02 UTC  
Scope: official v15 UI evidence plus live-proven H2 artifacts only  
Status: design and evidence package only. No firmware was patched or built. No package was flashed. No device was accessed.

## Executive decision

A Ch10 per-note patch-set editor/selector is architecturally compatible with the behavior proven by H2, but it is **not yet safe to implement** from the available static UI evidence.

The evidence supports this phased direction:

1. Preserve H2's corrected Ch10 and stock fallback behavior.
2. Reuse an existing official 16-slot grid and widget graph.
3. Keep the first UI state volatile and visual-only.
4. Add per-note audio selection only after the MIDI note identity is proven at both H2 Note On and Note Off callsites.
5. Add persistence last. H2 must continue to block SAVE until a separate versioned record, bounds, failure propagation, and recovery contract are live-proven.

The safest first mutating UI checkpoint is **U1, a visual-only volatile 16-slot selector**, and it is gated by a preceding **U0 read-only runtime mapping checkpoint**. U1 must not change H2's source, consumers, LED state, LCD path, or persistence.

Machine-readable evidence is in [`evidence.json`](evidence.json). Finding IDs below refer to that file.

## Evidence and address model

Official v15 identity:

- App: `build/v15-official-app.bin`
- SHA-256: `36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055`
- Runtime VA: `0x02000000 + file_offset`
- Package flash offset: `file_offset + 0x4120`

H2 live-proven identity:

- H2 app SHA-256: `d71f6c58b4fade00aebb8a0b7d9d024641c37c41ca4bbf3e525fd28773087f59`
- H2 package SHA-256: `c1752a69ed8f905af58db0de7c3def29c416b71e832e2834e664cd5d17b85011`
- H2 implementation commit: `75e71805f28f46ff3afd69d34df43ebd81fa64a0`
- Live result: intended Bank D patch 14 Mooger #1 on Ch10, normal Note Off, no first-Pad reboot, H2 LIVE PASS [PF-004]

Representative address provenance:

| Role | Runtime VA | File offset | Flash offset | Evidence |
|---|---:|---:|---:|---|
| Official factory patch loader | `0x02005660` | `0x005660` | `0x009780` | PF-006 |
| Official current-patch consumer | `0x0201c5ec` | `0x01c5ec` | `0x02070c` | PF-007 |
| H2 Note Off callsite | `0x0201c63e` | `0x01c63e` | `0x02075e` | PF-003 |
| H2 Note On callsite | `0x0201c67c` | `0x01c67c` | `0x02079c` | PF-003 |
| H2 Note Off wrapper | `0x0201e13e` | `0x01e13e` | `0x02225e` | PF-003 |
| H2 Note On wrapper | `0x0201e170` | `0x01e170` | `0x022290` | PF-003 |
| UI state frame | `0x02029290` | `0x029290` | `0x02d3b0` | PF-008 |
| Grid/submode dispatch | `0x02029528` | `0x029528` | `0x02d648` | PF-008 |
| Object string setter | `0x0201a67c` | `0x01a67c` | `0x01e79c` | PF-013 |
| Keys Channel setter callsite | `0x02022de8` | `0x022de8` | `0x026f08` | PF-013 |
| Candidate event vector | `0x02058248` | `0x058248` | `0x05c368` | PF-011 |
| Candidate redraw/event trigger | `0x0201e06c` | `0x01e06c` | `0x02218c` | PF-015 |
| Bounded RAM-to-storage wrapper | `0x02004b02` | `0x004b02` | `0x008c22` | PF-018 |

## Proven facts

### 1. H2 is a safe single-source Ch10 base for the tested sequence

H2 owns exactly one `0x9c`-byte snapshot at `0x01c46520..0x01c465bb`, with valid byte `0x01c465bc` and publication lock `0x01c465bd`. The producer sets valid after the copy and unlocks after publication [PF-002].

The corrected wrappers preserve the official memcpy ABI:

- `r0`: destination
- `r1`: stock source
- `r2`: `0x9c`
- `r9`: MIDI channel nibble

Ch10 with `valid == 1` selects the owned source. Invalid or non-Ch10 paths restore the original destination and preserve stock source/count [PF-003].

H2's live result proves that the owned snapshot can be consumed by both Note On and Note Off without the R03 fallback fault in the tested sequence [PF-004]. This is the correct data-plane foundation to preserve.

### 2. Official v15 already has a 0x9c runtime patch snapshot flow

The official factory loader at `0x02005660` selects bank `0..3` at `0x01c33604`, selects preset `0..31` from `0x01c33600..0x01c33603`, and copies a `0xa3` stored record into the global current snapshot at `0x01c34c74` [PF-006].

The official consumer at `0x0201c5ec` copies `0x9c` bytes from `0x01c34c74` into per-note/voice slots [PF-007]. This proves a useful distinction:

- stored/factory record: `0xa3` bytes;
- runtime voice snapshot consumed by note paths: `0x9c` bytes.

It does not prove a side-effect-free API for converting any bank/preset into an independent patch-set snapshot. Calling the stock loader mutates global current-patch and UI state [BL-004].

### 3. Official v15 has a reusable 16-slot screen family

The main UI state base is `0x01c33260`. The page candidate is at `0x01c33460` (`+0x200`) and the stronger submode/grid state is at `0x01c33562` (`+0x302`) [PF-008].

`0x02029528` dispatches values `2..6`. Values `3`, `4`, and `6` reach separate 16-slot grid/render paths at `0x02029642`, `0x020296ea`, and `0x0202974e` [PF-009]. Grid-related fields include candidates at:

- `0x01c34899` (`UI_RAM+0x1639`)
- `0x01c348a2` (`UI_RAM+0x1642`)
- `0x01c348ea` (`UI_RAM+0x168a`)

Their exact screen names, selection semantics, writers, and reset behavior remain unresolved. They are observation targets, not yet safe storage fields [CI-001].

### 4. A partial official text/widget path is proven

The official code computes `0x02058314`, the `Keys Channel-` descriptor entry, at `0x02022de0` and calls `0x0201a67c` at `0x02022de8`. The setter replaces object field `+0x24` with a C string [PF-013].

Confirmed app-resident resources include:

| Resource | Text VA | Descriptor/pointer entry | Evidence limit |
|---|---:|---:|---|
| `Pad Bank-` | `0x0205d9c5` | `0x02058304` | Presence and pointer only |
| `Keys Channel-` | `0x0205d9e9` | `0x02058314` | Direct setter data flow proven |
| `SAVE` | `0x02057298` | not promoted to widget ABI | Presence only |
| `SAVED` | `0x0205d990` | not promoted to widget ABI | Presence only |

This supports reuse of existing widgets and same-length resources. It does not support a new page layout, arbitrary dynamic strings, or custom graphics [PF-014].

### 5. Input consumers are known, physical IDs are not

Pending input bytes `0x01c33569..0x01c3356f` (`+0x309..+0x30f`) are consumed and copied or decremented into live bytes `0x01c33299..0x01c3329f` (`+0x39..+0x3f`) by paths at `0x02028f0c`, `0x02029152`, and `0x02029612` [PF-010].

The upstream producer and physical IDs were not found. The 11-word run at `0x02058248` is real internal code-pointer data, but has no proven dispatcher/caller or physical event mapping [PF-011].

`0x0202439e` remains the strongest centered-delta encoder update candidate, but it is a mid-function entry and cannot be bound directly until live tracing links its enclosing caller to the physical encoder [PF-012].

### 6. H2 persistence is intentionally unavailable

H2 branches away before the first stock persistent write at `0x02026da6` and neutralizes the later packer call at `0x02026dac` [PF-005].

The stock wrapper `0x02004b02` is statically proven as bounded RAM-to-storage with count-style success, but decoded SAVE paths ignore its error return. The primitive at `0x02063260` remains undecoded [PF-018]. Early patch-set checkpoints must remain volatile.

## Constrained inferences

The following are design choices constrained by the evidence. They are not claims about existing v15 implementation details.

### Reuse the existing 16-slot widget graph

A per-note selector visually matches the proven 16-slot grid family. Reusing a stock grid avoids claiming an LCD ABI or allocating a custom framebuffer [CI-001]. The selected visual path must be chosen only after U0 maps a real screen to one of submodes `3`, `4`, or `6` and identifies the actual highlight field.

### Keep UI index separate from MIDI note identity

The visible grid has 16 cells, but no static evidence proves cell `0..15` equals a specific MIDI note number or physical Pad order. The design must keep:

- `ui_slot`: visible `0..15` position;
- `midi_note`: observed `0..127` note identity;
- `snapshot_id`: immutable patch snapshot reference;

as separate values until live mapping proves their relationship.

### Use immutable snapshots plus an atomic active map

H2's single snapshot was staged before the note event. A patch-set editor introduces concurrent selection and note activity. The safest eventual model is:

```c
/* Abstract design. No RAM address is assigned by current evidence. */
struct PatchSnapshot {
    uint8_t voice[0x9c];
    uint8_t valid;
    uint8_t generation;
};

struct PatchSetEntry {
    uint8_t midi_note;
    uint8_t snapshot_id;
    uint8_t bank;       /* display/provenance metadata only */
    uint8_t preset;     /* display/provenance metadata only */
    uint8_t flags;
};

struct PatchSet {
    struct PatchSetEntry slot[16];
    uint8_t selected_ui_slot;
    uint8_t active_generation;
};
```

Snapshots should be fully built in inactive storage, then published by an atomic map or generation switch. Active snapshots must never be overwritten in place while a Note On or Note Off consumer can read them.

This structure has no approved RAM placement. Sixteen independent snapshots alone require `16 * 0x9c = 0x9c0` bytes. H2's entire owned extension from `0x01c46520` through `0x01c465bf` is only `0xa0` bytes [BL-002]. A new RAM ownership and BSS/heap analysis is mandatory.

### Latch the Note On selection for Note Off

H2 Note On and Note Off independently choose the source at `0x0201e186` and `0x0201e154`. If the map changes between events, Note Off can receive a different patch snapshot [BL-003]. A production design must do one of the following:

1. latch `snapshot_id` per active note/voice at Note On and reuse it at Note Off; or
2. prohibit map changes while any Ch10 note is active, using a proven active-note gate.

Per-voice latching is preferable, but no active voice table or note register is proven by this evidence set.

### Preserve H2 fallback exactly

Any future per-note wrapper must retain these H2 properties:

- non-Ch10 branches before modifying stock `r1/r2`;
- invalid patch-set or unmapped note falls back to stock source;
- original destination is restored immediately before stock memcpy;
- copy size remains exactly `0x9c`;
- Note On and Note Off use the same mapping/latch rule;
- accepted-product publication cannot expose a partially copied snapshot.

## Hard blockers

### B1. MIDI note identity is not proven at H2 callsites

The proven H2 ABI exposes destination, stock source, length, and channel nibble, but not note number. Per-note selection cannot safely index a table until live tracing recovers either:

- the MIDI note register/stack field at `0x0201c67c` and `0x0201c63e`; or
- a stable, bounded destination-to-note/voice mapping that works for both Note On and Note Off.

This is the primary data-plane blocker [BL-001].

### B2. Physical buttons and encoder IDs are not proven

No new button binding is allowed until writes to `0x01c33569..0x01c3356f` identify the producer PC, physical control, press/release/hold behavior, and consumer helper [PF-010, PF-011, PF-012].

Recovery, boot, SAVE, and long-hold combinations must remain untouched.

### B3. Renderer invalidation and final draw are not proven

The `Keys Channel-` setter chain is partial. No evidence-backed path continues from `0x0201a67c` to traversal `0x0200f74c`, redraw candidate `0x0201e06c`, or final LCD/pixel writes [PF-015].

A selector can only reuse an existing stock screen after live observation identifies the exact object, highlight field, and invalidation path.

### B4. No product LED address is proven

The pinned SDK contains `led_ui_server` code, but accepted exact and relocation-aware product-v15 UI/input/LCD/display/widget matches are both zero. There is no evidence-backed LED function, RAM field, register, pin, or event binding [PF-017].

Therefore:

- U0 records visible LED changes only as physical observations.
- U1 must produce no intentional LED write.
- No address observed incidentally may be promoted without code/data-flow evidence.

### B5. No custom LCD path is proven

The ST7789-like sequence at `0x02058aec` conflicts with a real function at `0x02030e50` treating overlapping `0x02058b50` as a halfword table. No LCD write path is known [PF-016]. Custom graphics, bitmaps, resolution changes, and framebuffer allocation are excluded.

### B6. Factory patch binding has side effects and persistence is unsafe

The stock loader mutates global current patch and UI expansion fields. A side-effect-free factory-record reader or converter is not proven [BL-004]. H2 SAVE remains blocked, and early patch sets must not call `0x02004b02` [PF-005, PF-018].

## Recommended implementation sequence

### U0: read-only runtime mapping, mandatory before any UI patch

U0 is the safest first **live UI checkpoint**. It changes no firmware and writes no device state. Its purpose is to turn the current static blockers into exact runtime facts.

#### U0-A. Establish H2 baseline invariants

Use the exact live-proven H2 artifact and the same accepted Bank D patch 14 Mooger #1 packet used by the H2 validation record.

Observe before touching UI controls:

1. `0x01c465bc == 1` after accepted packet publication.
2. `0x01c465bd == 0` after producer unlock.
3. A hash or captured `0x9c` bytes at `0x01c46520` remains stable during passive UI navigation.
4. Ch1 retains stock voice.
5. Ch10 produces intended Mooger #1 sound.
6. Ch10 Note Off is normal.
7. No reboot occurs.

Any failure stops UI integration work because the baseline is no longer equivalent to H2 LIVE PASS.

#### U0-B. Map every candidate UI control to pending/live bytes

Set write watchpoints on:

- pending: `0x01c33569..0x01c3356f`;
- live: `0x01c33299..0x01c3329f`;
- page candidate: `0x01c33460`;
- submode: `0x01c33562`.

For one physical control at a time, record separate short press, release, repeat, and long hold where physically supported. For the encoder, record one detent clockwise and one detent counterclockwise.

For every event, capture exactly:

- first writer PC to the pending byte;
- pending offset and old/new value;
- first consumer PC among `0x02028f0c`, `0x02029152`, and `0x02029612`;
- live offset and old/new value;
- helper call taken;
- page/submode before and after;
- screen before and after;
- all visible LED changes and timing;
- whether `0x0201e06c` was called and its argument.

A physical event ID is accepted only if the same control/action repeats the same producer, byte, value transition, and consumer path at least three times.

#### U0-C. Resolve one known text object through visible redraw

Navigate to the stock `Keys Channel-` screen and observe:

1. Break at `0x02022de0`. Confirm the calculation produces `r1 = 0x02058314`.
2. Break at `0x02022de8`. Record `r0` as the object pointer and `r1 = 0x02058314`.
3. Enter `0x0201a67c`. Confirm `[object+0x24]` changes as documented.
4. Trace the next computed callback, dirty-field transition, or `0x0201e06c` call that precedes the visible label update.
5. Record the first proven path that reaches a display write or stable existing-widget refresh boundary.

U1 remains blocked if the object update cannot be connected to a visible refresh.

#### U0-D. Resolve one 16-slot stock grid

On the stock screen that visibly shows a 16-slot grid, record:

- `0x01c33460` page value;
- `0x01c33562` submode value;
- reads/writes to `0x01c34899`, `0x01c348a2`, and `0x01c348ea`;
- path entry among `0x02029642`, `0x020296ea`, and `0x0202974e`;
- exact field and bit/nibble that moves the visible highlight;
- reset value when entering and leaving the screen;
- whether selecting a cell causes any storage call or patch load.

The chosen U1 grid must have a reversible entry/exit path and must not invoke SAVE or factory loading merely by moving the highlight.

#### U0-E. Recover per-note identity at H2 Note On and Note Off

For each of the 16 intended physical Pads, and separately for injected Ch10 MIDI notes if available, break immediately before:

- Note On wrapper callsite `0x0201c67c`;
- Note Off wrapper callsite `0x0201c63e`.

Capture all registers, relevant stack words, destination `r0`, stock source `r1`, count `r2`, and channel `r9`. Vary only one MIDI note at a time.

Required result:

- identify a register, stack byte, or bounded formula that changes with note number;
- prove the same note identity is available or reconstructable on Note Off;
- prove mapping for all 16 intended notes, not just one Pad;
- prove destinations do not alias across simultaneously active notes in a way that invalidates latching.

Without this result, no per-note audio selector may be built [BL-001].

#### U0 pass gate

U0 passes only if all of the following are recorded:

- one safe physical entry action and one safe exit action;
- one proven encoder or button action for selection movement;
- one exact stock 16-slot grid state and highlight field;
- one setter-to-visible-refresh path;
- per-note identity at both H2 wrappers;
- no intentional or unexplained LED control dependency;
- unchanged H2 source and audio invariants;
- no storage calls.

### U1: safest first mutating UI checkpoint

U1 is a **visual-only, volatile selector shell**. It proves UI integration without changing audio behavior.

Required behavior:

1. Enter through only the U0-proven physical action.
2. Reuse only the U0-proven stock 16-slot grid and highlight mechanism.
3. Maintain a selected UI slot `0..15` in newly audited, owned RAM or in an existing field whose ownership has been proven by U0. Do not assume any current candidate field is free.
4. Move selection using only the U0-proven input path.
5. Display only existing stock resources or a same-length label replacement with fixed terminator and unchanged layout.
6. Exit through the U0-proven path and restore all stock page/submode/highlight values.
7. Make no change to note routing, H2 source, valid byte, lock, SAVE, persistence, LED state, or LCD driver path.

Exact U1 live observations:

- Entry opens the intended 16-cell view on every trial.
- Exactly one cell is highlighted.
- Forward movement visits `0..15` in order with the designed boundary rule.
- Reverse movement visits `15..0` in order.
- Boundary input does not corrupt adjacent cells or escape the screen.
- Exit returns to the exact prior stock screen and control behavior.
- `0x01c46520..0x01c465bd` is byte-for-byte unchanged before and after U1.
- `0x0201c63e` and `0x0201c67c` behavior remains H2-equivalent.
- Ch1 stock sound, Ch10 Mooger #1, normal Note Off, and no reboot all remain true.
- No call reaches `0x02004b02` or `0x02063260`.
- The H2 SAVE branch at `0x02026da6` remains active.
- Physical LED state is unchanged from the equivalent stock-screen action, unless U0 proved a stock-coupled LED effect. U1 adds no LED write.
- Reboot clears the U1 selection to its defined volatile default.

Stop immediately on reboot, audio change, stuck note, altered H2 source, unexplained LED change, storage call, persistent selection, or failure to restore the prior screen.

### U2: volatile per-note selector, after U1 and data-plane proof

U2 may connect the UI slot to Ch10 note routing only after BL-001, BL-002, and BL-003 are closed.

Minimum behavior:

- a validated 16-note map;
- immutable, separately owned `0x9c` snapshots;
- stock fallback for unmapped/invalid entries;
- same latched snapshot for Note On and Note Off;
- edits rejected or deferred while affected notes are active;
- no persistence;
- H2 exact fallback preservation tests for Ch1, non-Ch10, invalid entries, and all 16 Ch10 notes.

The safest first U2 content source is a prevalidated volatile snapshot set, not direct calls to `0x02005660`. Factory-bank browsing comes later after BL-004 is closed.

### U3: factory patch chooser/editor

Only after a side-effect-free record access or conversion path is proven:

- expose official bank range `0..3` and preset range `0..31`;
- preserve a clear distinction between metadata `(bank,preset)` and runtime `0x9c` snapshot;
- never mutate the stock current patch merely to render a candidate;
- audit every helper called by `0x02005660` before reusing it outside the stock path.

### U4: persistence

Persistence requires a separate versioned patch-set record. It must not alter the official `0xa3` patch record or dirty/saved table.

Before U4:

- allocate a proven storage range with bounds;
- define magic, version, length, CRC, and default record;
- propagate short/failure returns instead of copying the stock SAVE error omission;
- prove boot/default load, corrupt-record fallback, interrupted write, and rollback;
- explicitly decide whether stock SAVE remains blocked or a separate patch-set save action is introduced.

## Validation matrix for the eventual implementation

| Area | Minimum cases |
|---|---|
| H2 regression | Ch1 stock, Ch10 valid, Ch10 invalid fallback, non-Ch10 fallback, normal Note Off, no reboot |
| Note identity | all 16 intended Pads/notes, Note On and Note Off, repeated and simultaneous notes |
| UI navigation | entry, exit, forward/reverse, boundaries, repeat, long hold, rapid input |
| Screen | all 16 highlights, prior-screen restoration, no stale label/object pointer |
| LED | no new write in U1, stock-equivalent physical state, unexplained change is failure |
| RAM | canaries around all new state, maximum stack, no H2 source/lock overlap |
| Concurrency | edit during idle, attempted edit during active note, rapid Note On/Off, polyphony |
| Persistence | excluded through U3; U4 requires failure and power-loss tests |
| Recovery | exact package identity, changed-range audit, rollback scope, no new protected-sector changes without review |

## Final recommendation

Proceed next with U0 read-only runtime mapping only. Do not start an implementation patch from current static evidence.

Once U0 closes the physical-input, grid-field, visible-refresh, and per-note identity blockers, implement U1 as a visual-only volatile shell. This isolates UI risk from H2's live-proven audio path and gives a reversible checkpoint before adding memory expansion, per-note routing, factory patch conversion, LED behavior, or persistence.

## Package contents

- `report.md`: this design and exact future live observations.
- `evidence.json`: source hashes, address provenance, proven facts, constrained inferences, and blockers.
- `validate.py`: offline package validator.
- `validation.txt`: captured validator output.
- `SHA256SUMS`: hashes for all files above except itself.
