# Jcode official-v15 UI runtime plan review

Date: 2026-08-02 UTC

Status: plan and evidence review only. I did not patch firmware, flash firmware, access a device, send USB traffic, or claim debugger/watchpoint results.

## Scope

- Worktree: `/Users/spectrum/Documents/SMK37ProMod` only.
- Firmware: official v15 only.
- App SHA-256 gate: `36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055`.
- Runtime base: `0x02000000`.
- UI RAM base: `0x01c33260`.
- Requested pending range: `0x01c33569..0x01c3356f`, equivalent to `ui_ram+0x309..+0x30f`.

Machine-readable evidence is in `jcode-evidence-summary.json`.

## Evidence boundary from ui-preflash

The static evidence supports a consumer boundary, not a producer identity:

- Pending bytes `+0x309..+0x30f` are consumed by `0x02028f0c`/`0x02029152` and `0x02029612`.
- They transfer to live bytes `+0x39..+0x3f`.
- `0x02029290` is the state-frame candidate and reconstructs `0x01c33260`; `0x02029528` branches from `+0x302`.
- `0x02058248` is an 11-entry internal code-pointer run, but static evidence does not recover its dispatcher or physical event IDs.
- `0x02020376 -> 0x0201a67c` is proven for the `Keys Channel-` descriptor path, but no direct or named indirect path to `0x0200f74c` or `0x0201e06c` is recovered.
- `0x0200f74c` remains a render traversal candidate and `0x0201e06c` remains a dirty/redraw candidate.
- Final LCD/pixel write is not recovered. ST7789-like bytes are not an LCD ABI.

Do not promote physical IDs, producer PCs, renderer callbacks, or LCD writes from this static evidence alone.

## Read-only versus instrumentation boundary

Truly read-only host observation:

1. Offline static inspection.
2. USB descriptor enumeration with no endpoint writes.
3. Passive USB-MIDI IN observation.
4. Camera or human display observation while official firmware runs unchanged.

Active but not a firmware patch:

1. Manual physical button presses, holds, and encoder turns.
2. Any fixed USB-MIDI OUT matrix, if separately authorized, because it is active host stimulation.

Requires firmware patch or equivalent in-firmware instrumentation:

1. Identifying pending writers for `0x01c33569..0x01c3356f`.
2. Capturing PC/LR/register context at pending transitions.
3. Mapping physical actions to internal callback slots or event IDs.
4. Resolving computed renderer callback targets.
5. Observing `0x0201e06c` arguments and dirty/redraw field transitions.

No hardware watchpoints are claimed. Without a proven WL82/PI32 debug facility, the safe method is narrow software trace bracketing, not global store instrumentation.

## Safest executable plan

### Checkpoint 0: SHA and evidence gate

Observables:

- Official app SHA matches the v15 gate.
- Source evidence hashes match `jcode-evidence-summary.json` or drift is reviewed.
- Device identity, if ever used, is exact official v15.

STOP if SHA/device identity mismatches, or if any step requires OTA, flash, reset, storage writes, or vendor commands.

### Checkpoint 1: read-only and physical baseline

Observables:

- Descriptor-only USB identity, if connected later.
- Timestamped camera record of display state.
- Separately logged physical control action labels and timestamps.
- Passive USB-MIDI IN bytes only, if present.

This can correlate physical actions with visible effects. It cannot prove internal RAM writer PCs or event IDs.

STOP if the display enters an error/update/recovery state, or if anyone infers internal IDs from camera or USB-only data.

### Checkpoint 2: trace-only patch design gate

Requirements for a later reviewed patch:

- RAM-only ring buffer in a separately proven owned region.
- No storage wrappers, no filesystem writes, no persistent settings.
- Register/flag preservation at every patched site.
- Bounded trace records with build ID and app SHA gate.
- Known official-v15 rollback package and restore path before any flash.

Trace records must include tag, tick, site PC, LR, `r0..r3`, `+0x200`, `+0x302`, pending `+0x309..+0x30f`, live `+0x39..+0x3f`, and relevant dirty/timer fields where safe.

STOP if owned RAM is unproven, clobbers are unresolved, or trace extraction needs unreviewed vendor traffic.

### Checkpoint 3: pending transition bracketing

Instrument only:

- `0x02029290` entry/exit.
- `0x02029152` entry/exit.
- `0x02029612` entry/exit.
- Optional overflow helpers `0x02028e46/64/86/a6/c8/ea` only if needed.

Observables:

- Pending vector before frame and consumers.
- Live vector before/after consumers.
- LR at each site.
- Physical action timestamp alignment.

Promote only bounded timing such as “pending was already set before `0x02029290`” or “transition occurred between these two probed sites.” Do not name a producer PC from consumer snapshots.

STOP on dropped/out-of-order trace records, behavior changes, unreproducible multi-byte changes, or single-sample conclusions.

### Checkpoint 4: vector and physical action correlation

Instrument entries for all `0x02058248` targets: `0x02029912`, `0x02029936`, `0x02029974`, `0x020299ce`, `0x020299f2`, `0x02029a16`, `0x02029a2e`, `0x02029a46`, `0x02029a78`, `0x02029aaa`, and `0x0202439e`.

Observables:

- Entry address/slot tag, LR, `r0..r3`.
- UI state, pending, and live bytes at entry/exit.
- For `0x0202439e`, centered delta, clamp/store to `+0x00c6`, dirty bytes `+0x16e7/+0x16e9`, and timer `+0x00c4`.

Promote a physical mapping only after at least three repeated identical traces with no competing slots.

STOP if vector entries fire without correlated stimuli, multiple unexplained slots fire, or evidence is only table order.

### Checkpoint 5: renderer callback and dirty/redraw transition

Instrument only after earlier gates:

- `0x0201a67c` entry and post-update path.
- Computed call sources `0x0200f71e`, `0x0200f746`, `0x0200f770`, and if reached `0x0201ea90`/`0x0201eaae`.
- `0x0201e06c` entry/exit.

Observables:

- Object pointer, string/descriptor pointer, old/new `[object+0x24]`.
- Loaded computed-call target before indirect calls.
- `0x0201e06c` arguments and dirty/timer fields before/after.
- Timestamp-aligned display transition.

Promote a computed renderer callback only if the target is executable official-v15 app code, appears during a known UI action, and matches visible redraw/state changes.

STOP if target is out of executable range, no redraw correlation exists, or instrumentation changes redraw behavior.

### Checkpoint 6: producer narrowing

Use LR and bracket data to add one upstream probe generation at a time. Log pending bytes at entry/exit of narrowed candidate functions. Split inside a function only after a transition is bracketed there.

Name a producer only when the transition is isolated to a single writer block or a no-intervening-call function body.

STOP if narrowing would require broad/global store instrumentation, too much probe density, or multiple unresolved producer candidates.

## Rollback requirements for any later patch phase

- Hash-checked clean official v15 package is available.
- Restore path and success criteria are documented before patch install.
- Pre-patch boot, display state, and USB identity are recorded.
- Trace build contains no persistent storage mutation.
- After rollback, official v15 identity and baseline UI behavior are verified.

## Final recommendation

Proceed only with a two-stage campaign: first read-only/passive host plus camera baseline, then a separately reviewed RAM-only trace patch that brackets known consumers before narrowing producers. This is the minimum safe path to identify pending producers, physical mappings, computed renderer callbacks, and dirty/redraw transitions without unsupported hardware-watchpoint claims.
