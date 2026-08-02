# Official v15 UI runtime evidence plan for R03 owned-RAM review

Date: 2026-08-02 UTC

Status: **plan and evidence review only**. This artifact was produced from existing official v15
`ui-preflash` evidence. No patch, flash, debugger, device connection, uploader, product SysEx,
or live instrumentation was used.

## Scope and SHA gate

- Working tree scope: `/Users/spectrum/Documents/SMK37ProMod` only.
- Firmware scope: official v15 only.
- Official app SHA-256: `36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055`.
- Runtime base: `0x02000000`.
- Main UI RAM base from preflash evidence: `0x01c33260`.
- Requested pending input range: `0x01c33569..0x01c3356f` = `0x01c33260 + 0x309..+0x30f`.

This report is not a firmware checkpoint and does not authorize flashing. It is a safe executable
plan for a later reviewed runtime checkpoint.

## Reviewed ui-preflash evidence

Primary evidence reviewed:

- `baselines/v15/analysis/ui-preflash/README.md`
- `baselines/v15/analysis/ui-preflash/events/report.md`
- `baselines/v15/analysis/ui-preflash/followup/event-dispatcher.md`
- `baselines/v15/analysis/ui-preflash/followup/event-dispatcher.json`
- `baselines/v15/analysis/ui-preflash/followup/renderer-xref.md`
- `baselines/v15/analysis/ui-preflash/followup/renderer-xref.json`
- `baselines/v15/analysis/ui-preflash/final-pass/events/report.md`
- `baselines/v15/analysis/ui-preflash/final-pass/events/final-pass-events.json`
- `baselines/v15/analysis/ui-preflash/final-pass/renderer/report.md`
- `baselines/v15/analysis/ui-preflash/final-pass/renderer/renderer-trace.json`
- `baselines/v15/analysis/r03-owned-ram/requirements.md`

Machine-readable digest for these inputs is in `evidence-summary.json`.

## Static evidence boundary

The official v15 preflash evidence supports these boundaries:

| Item | Static status | Evidence-backed boundary |
|---|---|---|
| Pending input bytes | Consumers proven, producers not found | `+0x309..+0x30f` are consumed by `0x02028f0c`/`0x02029152` and `0x02029612`; static producer write search is empty. |
| Live input bytes | Consumer transfer target | Pending bytes copy/decrement into live `+0x39..+0x3f`. |
| State frame | Strong candidate | `0x02029290` reconstructs `r11=0x01c33260`; `0x02029528` branches from `+0x302`. |
| Physical event IDs | Not proven | `0x02058248` is an 11-entry code-pointer run, but the dispatcher/caller is absent. Slot ordinals are not physical IDs. |
| Encoder | Strong candidate, not physical ID proof | Vector slot 10 points to `0x0202439e`; enclosing entries `0x02024368`/`0x0202443e` are called by `0x02025dea`/`0x02025e06`. |
| Renderer setter path | Partial chain only | `0x02020376` computes `r1=0x02058314` (`Keys Channel-`) and calls `0x0201a67c`. |
| Renderer continuation | Not proven | No direct or named indirect path from `0x02020376` or `0x0201a67c` to `0x0200f74c` or `0x0201e06c`. |
| Dirty/redraw transition | Candidate only | `0x0201e06c` is reached by many UI state/update routines and uses UI RAM, but not from the setter path by static proof. |
| Final LCD/pixel write | Not recovered | ST7789-like byte run remains byte-pattern-only and is not promoted. |

Therefore, the requested full identification cannot be completed by host-only static reading. The
safe next step is a runtime observation checkpoint with explicit observables and STOP gates.

## Can this genuinely be read-only?

Short answer: **only the current host-side review is genuinely read-only**.

| Mode | Allowed in this task? | Can identify producers/callbacks? | Read-only assessment |
|---|---:|---:|---|
| Host-read-only artifact review | Yes, already performed | No. It can define boundaries and watchpoints only. | Genuinely read-only. It reads files and emits this report. |
| Passive external observation of an unmodified official-v15 device, for example camera/audio/USB logs | Not performed | No for RAM producer PCs or computed callback targets. It may label visible physical actions only. | Device-observational, but insufficient. |
| External hardware debug watchpoints on official v15 without flash changes | Not performed | Possibly, if precise byte write watchpoints and PC/LR capture work. | Firmware image remains read-only, but the device is not operationally read-only because debug halt/trace perturbs timing and writes debug registers. |
| Firmware logging/instrumentation checkpoint | Not performed | Yes, if reviewed and exact-SHA gated. | Not read-only. It requires a reviewed firmware checkpoint, rollback package, and post-trace official-v15 restoration. |

Conclusion: identifying pending producers at `0x01c33569..0x01c3356f`, physical event IDs, computed
renderer callbacks, and dirty/redraw transition **cannot honestly be claimed as a genuinely
host-read-only task**. It requires either precise external debug observation or a reviewed firmware
instrumentation checkpoint. If external debug cannot capture all observables below without flash
changes, proceed only through the firmware-checkpoint path.

## Safe executable plan

### Phase 0: host-read-only preparation, allowed now

1. Verify the official app SHA-256 and runtime base from existing artifacts.
2. Re-run only static validators/scripts that read `build/v15-official-app.bin` and existing listings.
3. Generate the watchpoint/tracepoint manifest below.
4. Do not connect to the device, do not upload, do not flash, and do not emit SysEx traffic.

Required output before any live work:

- A reviewed trace manifest listing every address, field, expected hit type, and STOP condition.
- A reviewed rollback plan if firmware instrumentation is selected.
- A decision record choosing either external debug watchpoints or firmware instrumentation.

### Phase 1A: external debug watchpoint route, no firmware modification

Use this route only if the debug method can arm exact byte write watchpoints and capture PC/LR/registers
without patching flash or RAM code. If the debug tool cannot prove precision, STOP and move to Phase 1B.

1. Boot exact official v15 and verify identity before UI input.
2. Idle for a baseline window. Record that `0x01c33569..0x01c3356f` do not change during idle.
3. Arm byte write watchpoints on the seven pending bytes.
4. Run one physical stimulus at a time. Use an external action log with monotonically increasing
   `stimulus_id` values. Keep at least one idle interval between stimuli.
5. On each watchpoint hit, capture exact PC, LR, task/thread if available, old byte, new byte,
   timestamp/cycle, and the current physical `stimulus_id`.
6. Immediately after each producer hit, single-step or trace until the consumer boundary is observed
   at `0x02029152..0x020291cc` or `0x02029612`, then stop tracing for that stimulus.
7. Separately trace vector target entries and renderer/dirty candidates listed below.

This route is acceptable only if it records complete producer PC/LR and does not require modifying
firmware code. It still is not host-read-only.

### Phase 1B: reviewed firmware instrumentation route

Use this route only after a separate reviewed firmware checkpoint exists. The checkpoint must satisfy
the R03 offline safety posture before any flash attempt:

1. Exact official v15 app and package SHA gates.
2. Byte-level changed-address manifest.
3. Changed 4 KiB sector inventory.
4. Protected prefix unchanged.
5. Rollback package built from verified official v15.
6. Deterministic build and validator rerun.
7. Uploader wrong-package and wrong-token rejection tests.
8. No storage, SAVE, product SysEx mutation, or persistence changes in the instrumentation.
9. Bounded trace buffer with overflow detection. Overflow is a failed run, not partial evidence.
10. Two independent reviews of trace ABI and clobber/register preservation if code is inserted.

The instrumentation checkpoint should log the same observables as Phase 1A, then be removed by
restoring exact official v15 after evidence capture.

## Exact observables

### A. Pending input producer observables

Watch these absolute byte addresses:

| Field | Absolute address | Offset from UI base | Expected consumer |
|---:|---:|---:|---|
| pending[0] | `0x01c33569` | `+0x309` | `0x020291b6` reads, live `+0x39` |
| pending[1] | `0x01c3356a` | `+0x30a` | `0x020291a2` reads, live `+0x3a` |
| pending[2] | `0x01c3356b` | `+0x30b` | `0x02029166` reads, live `+0x3b` |
| pending[3] | `0x01c3356c` | `+0x30c` | `0x02029152` reads, live `+0x3c` |
| pending[4] | `0x01c3356d` | `+0x30d` | `0x0202918e` reads, live `+0x3d` |
| pending[5] | `0x01c3356e` | `+0x30e` | `0x0202917a` reads, live `+0x3e` |
| pending[6] | `0x01c3356f` | `+0x30f` | `0x02029612` reads/decrements, live `+0x3f` |

For every producer hit, record:

- `stimulus_id`, physical control name, action type, and action timestamp.
- Watchpoint address and byte offset.
- Old byte, new byte, and whether the write is increment, set, clear, copy, or decrement.
- Writer PC and containing function if decodable.
- LR/return PC and caller chain if available.
- Current UI state bytes: `+0x200`, `+0x302`, `+0x39..+0x3f`, `+0x309..+0x30f`.
- Task/thread/interrupt context if available.
- Whether the next observed consumer is `0x02029152..0x020291cc` or `0x02029612`.

Promotion rule: a physical event ID is promoted only when the same physical `stimulus_id` repeatedly
causes the same producer PC/LR and pending field transition, and the transition is consumed by the
known consumer boundary. A `0x02058248` slot ordinal alone is not a physical event ID.

### B. Physical stimulus matrix

Use deterministic one-action stimuli, separated by idle windows:

1. Baseline boot idle.
2. Each front-panel button short press, one at a time.
3. Each front-panel button long press/hold, one at a time, with hold duration recorded.
4. Encoder clockwise one detent.
5. Encoder counter-clockwise one detent.
6. Encoder press if present.
7. Known screen transitions that show Pad Bank/SAVE/Keys Channel labels, if reachable without SAVE.
8. Cancel/back/no-op controls, if present.

Do not run SAVE, firmware update, storage format, arbitrary SysEx fuzzing, or unsupported product
traffic during this UI trace.

### C. Callback vector and physical ID observables

Trace entries for the `0x02058248` ordinal targets:

`0x02029912`, `0x02029936`, `0x02029974`, `0x020299ce`, `0x020299f2`, `0x02029a16`,
`0x02029a2e`, `0x02029a46`, `0x02029a78`, `0x02029aaa`, `0x0202439e`.

For each hit, record:

- Hit target and inferred slot ordinal, if target matches the table.
- LR/caller PC. This is the primary evidence for the missing dispatcher.
- Register arguments and stack top words.
- Current physical `stimulus_id`.
- UI state before and after: `+0x302`, `+0x03a6`, `+0x03a7`, `+0x1636`, `+0x1637`, `+0x1639`,
  `+0x1672`, `+0x168a`, plus pending/live fields.
- Whether `0x0201e06c` follows within the same stimulus window.

Promotion rule: slot ordinal becomes a named physical event only after the dispatcher caller and
physical stimulus correlation are proven. Adjacent bytes at `0x02058274..0x020582d0` remain USB MIDI
descriptors and must not be interpreted as button IDs.

### D. Computed renderer callback observables

Trace these candidate computed-call sites from the final-pass renderer evidence:

| Callsite | Function | Static source classification | Runtime observable |
|---:|---|---|---|
| `0x0200f71e` | `0x0200f710` | `r0+0xc -> r2` object/vtable-field candidate | Loaded target, object pointer, LR, return result. |
| `0x0200f746` | `0x0200f73a` | `r0+0x14 -> r4` object/vtable-field candidate | Loaded target, object pointer, LR, return result. |
| `0x0200f770` | `0x0200f74c` | unresolved computed call in traversal candidate | Actual target and traversal context. |
| `0x0201ea90` | `0x0201ea80` | `r4+0x0 -> r2` object/vtable-field candidate | Loaded target and context pointer. |
| `0x0201eaae` | `0x0201ea94` | `r5+0x4 -> r2` object/vtable-field candidate | Loaded target and context pointer. |
| `0x020233e6` | `0x02023376` | indexed raw-table candidate | Index, table base, loaded word, called target. |

Also trace the known setter partial chain:

- `0x02022de0`: verify `r1 = 0x02058314` for the `Keys Channel-` descriptor path.
- `0x02022de8`: call to `0x0201a67c`.
- `0x0201a67c`: entry and return. Capture `r0`, `r1`, `[object+0x24]` before/after, and whether
  `0x0201a1bc` is called.

Promotion rule: a computed renderer callback is promoted only if the runtime log includes the callsite,
loaded target PC, source object/context pointer, LR, and a before/after UI state transition. Rows with
unknown function names or unresolved static targets remain candidates.

### E. Dirty/redraw transition observables

Trace `0x0201e06c` as the dirty/redraw/event-trigger candidate and `0x0200f74c` as the render traversal
candidate.

For each stimulus window, record the ordered chain:

1. Physical `stimulus_id`.
2. Pending producer write at `0x01c33569..0x01c3356f`, if any.
3. Consumer boundary hit at `0x02029152..0x020291cc` or `0x02029612`.
4. Vector target hit, if any.
5. State mutation fields before/after: `+0x200`, `+0x302`, `+0x03a6`, `+0x03a7`, `+0x00be`,
   `+0x00c0`, `+0x00c4`, `+0x00c6`, `+0x01fc`, `+0x0203`, `+0x0158`, `+0x1636`, `+0x1637`,
   `+0x1639`, `+0x1672`, `+0x168a`, `+0x16e7`, `+0x16e9`.
6. `0x0201e06c` entry with argument registers, LR, and touched list/queue fields around `+0x158`.
7. `0x0200f74c` entry and computed callback hits, if present.
8. Visible display result by external camera or screen log, if available.

Promotion rule: dirty/redraw transition is promoted only when the event chain is ordered and repeatable
from physical stimulus through state mutation into `0x0201e06c` and/or `0x0200f74c`. A standalone call
to `0x0201e06c` with no producer or state delta remains a candidate.

## Rollback and containment

### For host-read-only work

Rollback is file-level only:

1. Delete `baselines/v15/analysis/r03-owned-ram/ui-runtime-plan/` if the report is rejected.
2. No device or firmware state exists to restore because no device access occurred.

### For external debug watchpoints

1. Do not flash or patch.
2. Keep official v15 image and package hashes available before connecting.
3. On any STOP condition, remove probes, power-cycle only if safe, and re-verify official v15 identity.
4. If any persistent device state changes unexpectedly, stop and restore exact official v15 through the
   already-reviewed official recovery process before further tests.

### For firmware instrumentation checkpoint

1. Build rollback package from verified official v15 before any instrumentation flash.
2. Keep changed-sector inventory and exact restore commands in the checkpoint report.
3. After trace capture, restore official v15 immediately.
4. Compare managed Flash range against verified baseline after restore.
5. Treat any failed restore, hash mismatch, or changed unmanaged sector as a blocking incident.

## STOP conditions

Stop immediately and do not promote evidence if any condition below occurs:

### Pre-run STOP

- App SHA-256 is not exactly `36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055`.
- Runtime base is not `0x02000000`.
- The device is not confirmed official v15/identity `015` before live tracing.
- The selected method requires patching or flashing but no reviewed firmware checkpoint exists.
- The debug method cannot capture exact byte write address, PC, LR, and old/new value.
- Watchpoints are wider than the requested byte range and cannot distinguish `+0x309..+0x30f`.
- Trace buffer overflow handling is absent or untested.
- Any step proposes SAVE, storage write, arbitrary SysEx fuzzing, firmware update, or product packet
  mutation during this UI trace.

### Runtime STOP

- Unexpected reboot, USB disconnect, watchdog behavior, display corruption, stuck note, or audio anomaly.
- Any write to `0x01c33569..0x01c3356f` during idle baseline.
- A watchpoint hit has PC outside the official v15 app/code range or has missing LR/caller context.
- More than one producer PC writes the same field for the same stimulus and the ordering cannot be
  explained.
- A vector target is hit but LR/caller cannot identify the dispatcher.
- A computed callback target is outside the official app code range or points into data/USB descriptor
  bytes.
- `0x0201e06c` or `0x0200f74c` is hit without a correlated event/state delta and the trace cannot show
  ordering.
- Any instrumentation overflow, missed event marker, clobber suspicion, stack anomaly, or timing change
  that alters UI behavior.
- Any persistent setting/storage/SAVE behavior changes.

### Post-run STOP

- Repetition fails: same stimulus does not reproduce the same producer/callback/transition.
- Official v15 cannot be restored or verified after instrumentation.
- Managed Flash comparison differs from the verified baseline after rollback.
- Evidence lacks enough fields to distinguish physical event ID from vector slot ordinal.

## Go/no-go decision

- **Host-read-only now:** GO, completed by this report and `evidence-summary.json`.
- **Full runtime identification as genuinely read-only:** NO-GO. Static evidence already exhausted the
  relevant searches and did not recover producers, physical IDs, computed callback targets, or final
  dirty/redraw ordering.
- **External debug watchpoint checkpoint:** CONDITIONAL GO only if exact byte watchpoints and PC/LR capture
  are available without firmware modification and all STOP gates are accepted.
- **Firmware instrumentation checkpoint:** CONDITIONAL GO only after a separate reviewed checkpoint with
  manifest, rollback, validation, and restore plan. Not authorized by this report.

## R03 impact

R03 owned-RAM work must continue treating UI physical event IDs, renderer callbacks, dirty/redraw ABI,
and LCD write path as unresolved until the runtime observables above are captured. No R03 patch should
consume `0x02058248` slot ordinals as button IDs, write to pending input bytes, call `0x0201e06c`, call
`0x0200f74c`, or depend on the setter-to-renderer path without the reviewed runtime evidence.
