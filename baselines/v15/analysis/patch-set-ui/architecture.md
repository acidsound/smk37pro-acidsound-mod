# v15 Ch10 per-note patch set and UI architecture

Date: 2026-08-02
Status: implementation design based on official-v15 evidence and live-proven H2

## Goal

Provide an internal Ch10 instrument in which each configured MIDI note selects its own FM patch, while preserving the stock Ch1 instrument, normal Note Off, stock fallback, and eventual on-device selection/edit feedback.

The first production direction is a volatile 16-slot patch set. Persistence is deliberately deferred.

## Proven parent

H2 is the only live parent for this design.

- H2 app SHA-256: `d71f6c58b4fade00aebb8a0b7d9d024641c37c41ca4bbf3e525fd28773087f59`
- H2 package SHA-256: `c1752a69ed8f905af58db0de7c3def29c416b71e832e2834e664cd5d17b85011`
- Ch10 selected the staged Mooger #1 source.
- Ch1 remained on the stock source.
- Note Off was normal.
- First Pad press did not reboot.
- Corrected stock fallback restores the original memcpy destination.

No future candidate may regress those properties.

## Corrected note-mapping model

A physical Pad ordinal is not a stable firmware key.

The pinned official manual states that Pad MIDI messages are customizable in MIDI Suite and that the Pad Bank gesture exposes Pads 17–32. Live captures observed Ch10 notes 36, 38, 39, and 45, but did not establish a permanent 16-Pad sequence.

Therefore the model is:

```c
uint8_t note_to_slot[128];  // 0..15, 0xff = stock fallback
PatchSlot slot[16];         // config/UI order, not numeric-note order
```

Rules:

1. A set config contains exactly 16 distinct MIDI notes in `0..127`.
2. Slot order is the config order and becomes the 4x4 UI grid order.
3. `note_to_slot[note]` maps arbitrary, noncontiguous, unsorted notes to those slots.
4. Unconfigured notes use the H2-correct stock fallback.
5. Bank is user-facing `1..4`; patch is user-facing `1..32`.
6. Note On uses the official-v15 `r6 = msg[1]` value at the `0x0201c67c` hook.
7. Note Off uses the official-v15 `r5 = msg[1]` value at the `0x0201c63e` hook.

The offline compiler implements this contract and emits a 128-byte `note-map.bin`.

## Runtime representation

Each resident slot stores the exact H2-proven dispatcher source shape:

```c
struct PatchSlot {          // 0xa0 bytes
    uint8_t voice[0x9c];
    uint8_t valid;
    uint8_t control;
    uint8_t generation;
    uint8_t flags;
};
```

The complete 16-slot model remains:

- slots: `0x01c46520..0x01c46f20`, `0x0a00` bytes;
- header/map: `0x01c46f20..0x01c46fb0`, `0x90` bytes;
- proposed heap begin: `0x01c46fb0`;
- total owned reservation: `0x0a90` bytes.

This arithmetic is closed. Worst-case heap headroom is not yet live-proven.

## Publication model

Version 1 is load-once and immutable until reboot:

```text
EMPTY -> BEGIN -> LOADING -> PUT_SLOT x16 -> PUT_MAP -> COMMIT -> ARMED
reboot -> EMPTY
```

- Producer locking is nonblocking.
- Slot `valid` is written last after the complete 156-byte copy.
- Set `ARMED` is written last after every slot, map entry, bounds check, and checksum passes.
- Consumers never lock and use stock while the set is not exactly `ARMED`.
- No slot or map mutation is allowed after `ARMED`.

This avoids the Note On/Note Off generation race without active counters or per-voice reclamation in the first implementation.

## Consumer algorithm

Both event hooks use the same policy and separate note registers:

```c
if (channel != 9)                         stock_fallback();
if (set.state != ARMED)                   stock_fallback();
if (note > 127)                           stock_fallback();
slot_index = set.note_to_slot[note];
if (slot_index >= 16)                     stock_fallback();
slot = &set.slots[slot_index];
if (slot->valid != 1)                     stock_fallback();
memcpy(original_destination, slot->voice, 0x9c);
```

Every fallback must restore the original destination immediately before the stock memcpy, preserving the H2 fix that prevented the R03 first-Pad reboot.

## UI model

The UI has three separate identities:

```c
struct PatchSetUiEntry {
    uint8_t ui_slot;       // 0..15, fixed 4x4 position
    uint8_t midi_note;     // 0..127, user-configurable
    uint8_t bank;          // 1..4 for display
    uint8_t patch;         // 1..32 for display
};
```

They must not be collapsed into `note - 36` or a physical Pad number.

### Reusable official UI evidence

- main UI state: `0x01c33260`;
- page candidate: `+0x200`;
- grid/submode: `+0x302`;
- pending input bytes: `+0x309..+0x30f`;
- live input bytes: `+0x39..+0x3f`;
- official 16-slot grid paths: `0x02029642`, `0x020296ea`, `0x0202974e`;
- object C-string setter: `0x0201a67c`;
- proven caller example: `0x02022de8` for `Keys Channel-`;
- redraw/event candidate: `0x0201e06c`.

### UI policy

1. Reuse an official 16-cell grid. Do not add a framebuffer or direct LCD driver.
2. The selected cell edits `ui_slot`, not MIDI note arithmetic.
3. The first UI checkpoint is volatile and visual-only.
4. No LED behavior is added until an LED path is independently traced.
5. No new physical button binding is guessed. Input producer PCs and IDs must be traced first.
6. No persistence or SAVE behavior is added in the UI stages.

## Implementation sequence

### S1-C1: two-note audio selector

Purpose: prove note-indexed source selection with the smallest RAM/code delta.

- Use two live-observed notes, initially 36 and 45.
- Load two audibly distinct, pre-auditioned factory voices.
- Every other note follows stock fallback.
- Verify Ch1 before and after, both Note Offs, repeated hits, reversed release order, malformed packet rejection, and no reboot.

This checkpoint does not require a 16-slot grid or UI.

### S1-C2: 16-slot capacity

Purpose: expand only capacity after S1-C1 passes.

- Use the compiler's arbitrary 16-note config.
- Publish one 128-byte map and 16 immutable runtime voices.
- Validate every configured note-to-voice pair and unmapped fallback.
- Add heap/allocation, reconnect, repeated-hit, overlapping Ch1/Ch10, CC64, and all-notes-off stress.

### U0: read-only UI runtime mapping

Purpose: identify the real official grid page and physical event producers without changing behavior.

- Trace writers to `+0x309..+0x30f`.
- Record producer PC, value, press/release/hold behavior, consumer path, page, and submode.
- Identify the selected-cell field and redraw trigger.
- No UI RAM writes, renderer calls, or source changes.

### U1: visual-only volatile selector

Purpose: prove safe reuse of one official 16-cell grid.

- Enter only through U0-proven event IDs and context.
- Change only selected-cell visual state.
- Do not change audio source, note map, slot data, LEDs, SAVE, or storage.

### U2: selected-slot metadata display

Purpose: show slot, MIDI note, bank, patch, and name using proven existing widget/text paths.

- Prefer fixed-width or existing strings.
- Dynamic text is allowed only after object ownership, buffer lifetime, redraw path, and length constraints are proven.

### U3: volatile edit binding

Purpose: let the UI select a new bank/patch for one slot in an inactive set.

- Editing cannot mutate an ARMED set.
- A replacement set is built while inactive, then committed atomically.
- If live replacement remains prohibited, the UI records edits and applies them only after explicit reload/reboot.

### P1: persistence

Persistence remains blocked until VM/USRFLASH allocation, storage bounds, A/B sectors, boot hook, short-write behavior, power-loss behavior, and recovery are proven.

The safe custom persistent allocation is currently 0 bytes. Do not modify the stock `0xa3` Patch schema, app tail, `cfg_tool.bin`, or stock SAVE metadata.

## Gates before the first firmware child of H2

| Gate | Current state | Required evidence |
|---|---|---|
| Note register ABI | Static PASS, live trace pending | Exact callsite bytes and independent instruction-accurate review for Note On `r6` and Note Off `r5`. |
| Two-slot owned RAM | Pending | Minimal boundary arithmetic plus allocator/high-water discriminator. |
| 16-slot owned RAM | Blocked until S1-C1 | Worst-case headroom after heap moves to `0x01c46fb0`. |
| Executable placement | Pending | Exact wrapper/parser byte budget, branch reach, decoder review, no unproved cave. |
| Loader ingress | Pending | Exact length, CRC, state, collision, and stock SysEx preservation review. |
| Rollback | Required | Parent-to-child and official-v15 sector bundles generated from binary diffs. |
| UI event IDs | Blocked | U0 runtime trace. |
| Renderer/write path | Blocked | U0/U1 runtime trace. |
| Persistence | Blocked | Separate storage project after volatile audio/UI PASS. |

## Immediate next engineering target

Build **S1-C1**, not the full UI candidate:

1. derive the minimum two-slot RAM boundary;
2. prove allocator headroom for that boundary;
3. implement separate Note On and Note Off lookup wrappers with H2 fallback;
4. implement a guarded two-slot load/map transaction;
5. run PI32 decode, deterministic rebuild, rollback generation, and two independent offline reviews;
6. only then authorize a live checkpoint.

In parallel, prepare U0 instrumentation, but do not combine it with S1-C1. Each candidate must answer one runtime uncertainty.
