# Post-R02 production Drum Set roadmap

Date: 2026-08-02 UTC

## Proven starting point

R02 live validation proved all of the following on official-v15-derived firmware:

- physical Pad MIDI reaches the Channel 10 branch;
- Ch1 and Ch10 can use independent `0x9c` runtime FM voice sources;
- the official product SysEx framing can stage an exact 156-byte runtime voice;
- Bank D display 14 Mooger #1 was reproduced on Pad Ch10;
- Ch10 Note On and Note Off using the same source produce no stuck note;
- changing the Ch1 UI patch does not change the staged Ch10 voice;
- exact official v15 was restored afterward and its managed Flash range matched the verified baseline byte-for-byte.

R02 itself is not a production base because `0x01c37fd0` is shared transient SysEx RAM and the SAVE packer caller is disabled.

## Candidate matrix

| Priority | Target | Why it is now actionable | Required evidence before patch | Live pass gate | Current decision |
|---:|---|---|---|---|---|
| P0 | One Ch10-owned immutable runtime voice | R02 proved that a self-contained `0x9c` runtime voice is sufficient when read from valid RAM | identify a RAM range with explicit owner, initialization point, lifetime, and no stock writer overlap; define `valid` and `generation` state | normal boot, Ch1 unchanged, Ch10 named timbre, Note Off, UI patch changes, additional product SysEx without Ch10 corruption | **Next implementation target, R03** |
| P0 | Ch1/Ch10 overlap and release stress | Basic separation and matched Note Off are proven, but allocator/stealing behavior is not | deterministic host test sequence and observable failure criteria | overlapping Ch1/Ch10 chords, reversed release order, repeated hits, CC64, CC120/123, no stuck voice or cross-channel timbre change | **Run immediately after R03 boots** |
| P1 | 16-pad note-to-patch map | The dispatcher has the MIDI note and Channel 10 state, and one independent voice works | prove the exact note/register value at both Note On and Note Off hooks; enumerate all 16 physical Pad notes; budget at least `16 * 0x9c = 2496` bytes plus metadata | every Pad selects its assigned named patch; Ch1 remains independent; all Note Off paths release the matching generation | **Eligible after owned-RAM proof** |
| P1 | Per-slot runtime loading protocol | Exact product SysEx staging and USB-MIDI transport are live-proven | define guarded slot selection, packet acceptance, copy-to-owned-buffer completion, checksum/version, and rejection behavior without arbitrary fuzzing | load all 16 slots, reject malformed/wrong-slot data, preserve active notes, survive unrelated supported MIDI traffic | **Design with 16-pad map** |
| P1 | Source generation and active-note identity | Changing a slot while a note is held can make Note Off consume a different source | determine whether Note Off needs only the same timbre bytes or an explicit generation record; locate safe per-active-note metadata | hold note, replace slot, release old note, play new note, both behave correctly without state leakage | **Mandatory before editable sets** |
| P2 | Drum Set persistence record | UI analysis proves the stock `0xa3` Patch record must not be expanded | choose separate versioned storage record; prove write/read wrapper bounds, failure return, boot load, rollback, and power-loss behavior | save, reboot, reload all 16 mappings; invalid/partial record falls back safely; stock Patch SAVE remains intact | **After volatile 16-slot map passes** |
| P2 | UI runtime trace | Static UI work has exhausted renderer/event xrefs | watch `0x01c33569..0x01c3356f`, identify physical event producer/ID, computed callback target, dirty/redraw transition, and storage command behavior | trace known buttons/encoder/grid navigation without changing firmware semantics | **Can run in parallel, read-only first** |
| P3 | Minimal Drum Set page using existing grid | A 16-slot grid and bank/preset fields exist, but event producer and renderer ABI are unresolved | complete UI runtime trace; reuse existing widgets, text setter, grid state; no custom LCD path | select slot, assign bank 1..4 and patch 1..32, audition, cancel, save, reload, no regression in stock pages | **Only after P2 UI trace gates** |
| P3 | Per-pad transpose and level | Proposed `DrumSlotRef` has room conceptually, but audio consumers are not proven | identify safe note/velocity transforms and bounds without modifying current voice internals | independent transpose/level on all pads, velocity preserved, no overflow or stuck notes | **After core 16-patch set** |
| P4 | Custom graphics, fonts, bitmap, direct LCD | No final LCD write/framebuffer ABI is known | renderer/LCD pipeline and resource format must be proven | visual regression and recovery tests | **Defer** |
| P4 | PCM drum engine or new oscillator | Channel separation does not prove product audio callback/mixer ABI | identify v15 decoder/mixer/output graph, RAM/CPU headroom, scheduler and safe code placement | simultaneous FM/PCM load and audio-quality tests | **Separate future goal, not part of current Drum Set path** |

## Recommended implementation sequence

### R03: owned single-voice checkpoint

1. Find and prove an owned RAM allocation large enough for one `0x9c` voice plus metadata.
2. Populate it only after the official SysEx handler has completed the exact packet.
3. Copy staging to the owned buffer immediately, then allow staging to be overwritten.
4. Route both Ch10 Note On and Note Off to the owned source.
5. Keep all boot-time hooks prohibited.
6. Preserve or explicitly gate stock product SysEx and SAVE call paths instead of leaving them silently broken.
7. Build an exact-sector rollback bundle before OTA.

R03 passes only if a second supported SysEx or UI patch operation no longer changes Ch10 and all overlap/release stress passes.

### R04: volatile 16-pad patch set

1. Expand owned storage to 16 immutable `0x9c` slots, 2496 bytes total, plus validity/generation metadata.
2. Map physical Pad notes to slot indices with explicit bounds and an unknown-note fallback.
3. Use the identical slot/generation rule for Note On and Note Off.
4. Load slots through a guarded host protocol before implementing UI or persistence.
5. Validate every physical Pad, named patch identity, overlap, repeated strikes, and release order.

### R05: persistence and recovery

1. Store a separate versioned Drum Set record. Do not change the stock 163-byte Patch record.
2. Prefer packed bank/preset references if deterministic materialization is proven. Otherwise store checked runtime/packed payloads with a format version and CRC.
3. Prove boot/default load, missing record, corrupt record, short write, and power interruption behavior.
4. Keep official-v15 and exact changed-sector rollback paths ready.

### R06: minimal UI

1. Complete read-only runtime event/renderer tracing first.
2. Reuse the existing 16-slot grid and existing text/widget paths.
3. Implement only slot select, bank/preset assignment, audition, cancel, SAVE/SAVED feedback.
4. Keep custom graphics, fonts, and direct LCD access out of the first UI build.

## Hard rules retained from R01d and R02

- No new early-boot or post-init hook without an independently reviewed boot proof.
- No app/text-resident runtime voice source.
- Note On-only source changes are prohibited.
- No shared transient SysEx workspace as permanent voice storage.
- No arbitrary SysEx fuzzing on the device.
- No Flash candidate without exact package hash gates, changed-sector inventory, independent review, and target-specific rollback.
- Any ambiguous audio result is failure, not partial success.

## Immediate decision

The next engineering target is **R03 owned single-voice RAM**, while **UI runtime tracing** may proceed in parallel as a read-only investigation. The 16-pad set, persistence, and UI implementation must remain gated behind those two results.
