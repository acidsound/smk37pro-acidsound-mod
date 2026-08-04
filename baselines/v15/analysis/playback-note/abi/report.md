# Playback Note ABI analysis for exact v15 S1-C3 r3-reload

Status: **TRACE PASS, PATCH-READY BLOCKERS**.  
Scope: offline-only static analysis. No device, flash, OTA, reset, USB, or MIDI transport was used. No v12 assumptions are used.

## Decision

The exact current candidate proves the S1-C3 r3-reload Note On and Note Off hooks both pass through the 16-slot selector. The current selector only substitutes the **voice source** selected by trigger note. It restores the native note registers before stock synth metadata stores, so the current candidate does **not** yet implement a local Playback Note.

A safe Playback Note design must substitute the local synth note symmetrically for Note On and Note Off while leaving the incoming Trigger Note and MIDI OUT path unchanged. This is not patch-ready yet because the current artifacts lack a proven playback-note metadata transport/writer and lack exact PI32 code that returns with the substituted native note register while preserving velocity and caller state.

## Exact candidate anchors

| Item | Address | Candidate bytes | Target / meaning |
|---|---:|---|---|
| Note Off hook | `0x0201c63e` | `80fffa1a0000` | call32 `0x0201e13e` |
| Note On hook | `0x0201c67c` | `80ffc01a0000` | call32 `0x0201e142` |
| Direct product reset wrapper | `0x0201e468` | `bfeaddfe` | short call `0x0201e226` |
| Direct reload | `0x0201e46c` | `bfeaf838` | preserved stock reload `0x02015660` |
| Segmented product stub | `0x0201e49c` | `bfeac1fe` | short call `0x0201e222` |
| Segmented reload | `0x0201e4a0` | `bfeade38` | preserved stock reload `0x02015660` |

Candidate app SHA-256: `7c672938023beee74d599f43ccd5c7642396b89819e929501274239aed5e5d4b`. Selector SHA-256: `ea2c76595a93cf2cf6a39236e09b749781e2721e3575d0c1b40194855cd4e915`. Producer SHA-256: `48abedfe48368aed6528900725404a4c8f41c0957f25196cc91b246a9b7a8607`.

## Trigger-note and synth-consumer proof

Exact v15 rows prove the native trigger-note registers:

- Note Off loads `msg[1]` into `r5` at `0x0201c62e`, redirects the copy call at `0x0201c63e`, then stores `r5` into synth metadata at `0x0201c648`.
- Note On loads velocity `msg[2]` into `r5` at `0x0201c66a`, loads trigger note `msg[1]` into `r6` at `0x0201c670`, redirects the copy call at `0x0201c67c`, then stores `r6` into synth metadata at `0x0201c686` and velocity `r5` at `0x0201c68c`.

The consumer copy ABI is also exact: `r0` is the per-voice destination payload, `r1` is the voice source, and `r2 = 0x9c`. S1-C3 changes only the call target. It does not change the post-copy stock metadata stores.

## Current selector behavior

- Note Off entry `0x0201e13e`: `mov r3,r5`, then branches to the shared core.
- Note On entry `0x0201e142`: `mov r3,r6`, then falls into the shared core.
- The shared core checks Ch10, trigger note `36..51`, publication state `ARMED`, and selected-slot `valid == 1`.
- Current source mapping is `source = 0x01c46520 + (trigger_note - 36) * 0xa0`.
- The selector pushes and pops `{rets,r9..r4}`, so native `r5` and `r6` are restored before stock synth note stores.

Therefore current r3-reload proves a good selector/wrapper route, but it does not yet prove Playback Note pitch substitution.

## Required substitution

For each trigger note `T` in the resident S1-C3 trigger range, define `P = playback_map[T - 36]`, where Original/null maps to `T`.

1. Leave the incoming message bytes and MIDI OUT caller argument unchanged.
2. Use the existing selector gate to ensure Ch10 and valid publication.
3. Select source slot from `P` only when `P` is supported by the resident source set, currently proven only for `36..51`.
4. Return from Note Off with native `r5 = P` so `0x0201c648` stores the mapped playback note.
5. Return from Note On with native `r6 = P` while preserving velocity `r5` so `0x0201c686` stores the mapped playback note and `0x0201c68c` stores the original velocity.
6. Use the identical lookup in both Note On and Note Off. Note On-only substitution is unsafe and repeats the known stuck-note class.

## MIDI OUT preservation

This design is local to the synth dispatcher wrapper. It does not mutate the incoming event buffer or the pad/MIDI OUT sender argument. The existing MIDI OUT helper constructs a note message from its argument and sends it through `FUN_02022f46`; that path is outside the S1-C3 selector and remains unchanged by a local post-copy synth metadata substitution.

## Repeated-hit and polyphony assessment

- Same trigger mapped to the same playback note behaves like repeated hits of one stock MIDI note, subject to stock voice allocation and stealing.
- Different triggers mapped to different playback notes should behave like independent stock notes, within stock polyphony limits.
- Different triggers mapped to the same playback note are ambiguous. The exact rows here prove the consumer-visible identity is the stored synth note. No separate trigger-pad identity field is proven. Many-to-one mappings can cross-release or steal each other and must be treated as unsupported until an active-note map or trigger identity field is proven.

## Blockers

1. **Playback-note firmware transport/persistence:** current UI document and send queue carry `playbackNotes`, but `sendAll` warns that only patch data is transmitted until a corresponding firmware protocol is installed. Current S1-C3 packets and producer have no validated playback-note metadata writer.
2. **Native-register return ABI:** current selector restores `r5` and `r6`; exact PI32 code is still needed to return with `r5` substituted on Note Off and `r6` substituted on Note On while preserving velocity and caller state.
3. **Range policy:** resident S1-C3 source slots are proven for notes `36..51`; UI validation accepts `0..127`. Firmware must either constrain consumed playback notes to `36..51` or prove sources for the wider range.

## Validation

Run:

```sh
python3 baselines/v15/analysis/playback-note/abi/validate.py
```

Expected result: `playback-note ABI validation PASS`.
