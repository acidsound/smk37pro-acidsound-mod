# FM drum extension safety and implementation plan

Last updated: 2026-07-15 (KST)

## Canonical objective

The stock instrument is treated as a single-channel, single-timbral FM
instrument. The project goal is to extend that architecture itself:

1. accept and distinguish multiple MIDI input channels;
2. retain an independent FM patch/program and controller state per part;
3. allocate FM voices against the originating part rather than one global
   patch;
4. mix all parts through the existing FM audio output path; and
5. connect Drum Seq lanes to those internal FM parts.

The first proof need only implement two simultaneous FM parts, for example
channel 1 with Patch A and channel 2 with Patch B. The scalable target is an
N-part design, potentially covering all 16 MIDI channels subject to CPU, RAM,
and total FM voice limits. PCM, ROM drum banks, and pre-rendered samples are
outside the objective.

### Branch ordering decision

Implement the reduced multichannel branch first, then build the GM-style drum
map on top of it.

The four archived stock SysEx banks are each 4,104 bytes. Removing the six-byte
SysEx header and two framing/checksum bytes leaves 4,096 bytes, consistent with
32 presets of 128 bytes per bank and 128 presets total. This makes a two-part
Patch-A/Patch-B proof much smaller than a useful GM drum map.

| Branch | Minimum new state | Primary unknowns | Recommended order |
| --- | --- | --- | --- |
| Two-part MIDI FM | two 128-byte stored patches plus expanded runtime/voice state | channel filter, independent per-part patch state, voice-to-part ownership | First |
| GM-style FM drums | note-to-patch table, many drum patches, fixed pitch, note-off/choke policy, voice-to-patch ownership | every two-part unknown plus per-note timbre selection | Second |

The common internal API should be designed as an explicit-timbre note request,
conceptually:

```text
fm_note_on(part_id, patch_id, note, velocity)
```

Normal MIDI channels obtain `patch_id` from their retained part state. The
first proof initializes that state to two fixed presets in firmware because
stock v12 does not respond to USB MIDI Program Change. A later UI or added
Program Change handler may update it. The drum channel obtains `patch_id` from
`drum_map[note]`, with a separately mapped pitch and choke group when required.
Drum Seq can later submit the same requests without going through USB MIDI.

Recommended milestones:

1. channel 1/Patch A and channel 2/Patch B sound simultaneously;
2. note-off on one channel affects only that channel's matching voices;
3. two fixed-preset parts share the existing total FM voice pool without
   cross-part voice corruption;
4. channel 10 maps two notes to two different FM patches;
5. add a per-part patch-selection mechanism, then expand toward the desired GM
   drum-note subset and connect Drum Seq.

### Observed USB MIDI Program Change behavior

Owner test, 2026-07-15: official v12/display version 1.05 did not change its
active patch in response to USB MIDI Program Change. Treat Program Change as
unavailable in stock behavior. The observation does not yet distinguish among
an absent parser case, a deliberately ignored message, or a handler that is
unreachable because of another filter; static analysis should identify which
case applies.

Program Change is therefore not a dependency of the two-part proof and should
not be added in the same first behavior patch. Compile two deliberately
different preset IDs into the prototype, initialize Part A and Part B from
those presets at boot, and use only channel-separated Note On/Note Off messages
from the host sequencer. Add Program Change later as a separate testable feature
after independent part state is proven.

### Patch-screen part and channel UI

The stock Patch screen has no part or MIDI-channel selector. K6 and K7 are
currently unused there, so they are suitable for the eventual two-part UI.
However, this UI is not part of the first engine proof. Keep the first behavior
patch smaller and independently testable:

- Part A is fixed to USB MIDI channel 1 and the local keyboard;
- Part B is fixed to USB MIDI channel 2;
- each part starts with a deliberately different preset fixed in the test
  build; and
- a host sequencer supplies simultaneous channel-1 and channel-2 notes.

After simultaneous independent timbres work, add this Patch-screen model:

| Control | Function |
| --- | --- |
| K6 | select the UI/edit/audition target Part A or Part B |
| K7 | assign that part's USB MIDI receive channel, initially 1-16 |
| existing Patch selector | load/change only the selected part's preset |
| local keyboard | send new local notes to the selected part for audition |

Part identity and MIDI receive channel must remain separate. This allows, for
example, Part A to receive channel 1 and Part B to receive channel 10 without
making the drum channel a special global mode. For the first implementation,
reject duplicate receive-channel assignments; layering two parts on one
channel can be designed later.

Changing K6 must not send all-notes-off, reload the FM engine, or modify any
active voice. It changes only the UI edit target and the destination of new
local-key events. Changing K7 affects future external routing and likewise
must not mutate active voices. An active voice retains the `part_id` captured
at note-on so its note-off and controller handling cannot be redirected by a
later UI selection.

Minimum state for this UI is conceptually:

```text
ui_selected_part
part[2] = { rx_channel, patch_id, patch_context, controller_state }
voice[] = { part_id, note, ...existing voice state }
```

Persisting the part/channel assignment across power cycles is a later storage
step. The first UI build may initialize Part A/Part B to channels 1/2 at every
boot so no settings-storage format needs to change during the audio proof.

## Decision boundary

The application-only custom upload pipeline is now live-validated. M001 booted
and then entered the normal OTA loader to install M02; M02 booted and displayed
its expected version marker. Continue using exact-SHA build-specific upload
commands and the protected-region manifest for every experiment.

The verified official-v12 recovery line currently covers these states:

- normal firmware accepts the USB OTA command;
- the unit enumerates as update loader `4D4A:4155`;
- `upload-resume-v12` serves the exact official v12 payload;
- the unit boots and reports updater version `012` again.

The remaining unverified boundary is a custom application that crashes before
normal USB and the OTA command handler initialize. That case still requires a
forced-download entry, automatic failed-boot fallback, or explicit brick-risk
acceptance. Do not describe that separate scenario as an upload-format doubt:
modified package acceptance and custom-to-custom OTA are confirmed.

## Recovery evidence

| Gate | State | Evidence |
| --- | --- | --- |
| Exact official image archived | PASS | v12 package SHA-256 is fixed in `src/ota.c` and the runbook |
| Official v12 stage-2 recovery | PASS | update loader completed 1,241 requests and booted version `012` |
| Full device backup | PASS | pre-restore and post-restore 1-MiB dumps are retained under ignored `backups/` |
| Application-only repack boundary | PASS offline | no-op output is byte-identical; protected regions remain unchanged after a one-byte test |
| Modified package acceptance and boot | PASS live | M001 installed, booted, and exposed the modified display string |
| OTA from a running custom app | PASS live | M001 entered `4D4A:4155`, installed M02, and M02 booted with display `M02` |
| Application string/UI mutation | PASS live | M04 displayed exact custom two-line text without changing functional code |
| Exact official rollback from custom app | PASS live | running M04 installed archived official v12; display 1.05 and stock Reset UI were restored |
| M05 application install and boot | PASS live | both OTA stages and 1,241 stage-2 requests completed; normal USB identity 012 returned |
| M05 simultaneous Ch1/N plus Ch2/N+1 audio | PASS live | owner confirmed intended two-timbre playback with overlapping host-sequencer loops |
| Direct local-pad MIDI capture | PASS live | 16 pads emit Ch10 notes 36-51 with velocity and paired Note On/Off on USB cables 0/1 |
| M06 local Ch10 pad-to-FM bridge | PASS offline | raw pad output is preserved and one internal FM dispatch is added before the per-voice Ch10 snapshot |
| M06 application install and boot | PASS live | both OTA stages and 1,241 stage-2 requests completed; normal USB identity 012 returned |
| M06 simultaneous local key N plus local pad N+1 audio | PASS live | owner confirmed intended local-key Ch1/N and local-pad Ch10/N+1 FM behavior |
| M07 Ch10 notes 36-51 use N+1 through N+16 | PARTIAL / FAIL isolation | 16 independent per-note timbres confirmed, but Ch1/local keys were contaminated by the same mapping |
| M08 Ch1 UI patch plus fixed Ch10 Bank 0 map | PASS live | owner confirmed Ch1/Ch10 isolation and UI Patch independence; maximum-polyphony stress remains pending |
| Forced recovery independent of app | REQUIRED / not yet demonstrated | M09 now proves the pre-USB app-failure boundary: black display after true power cycle and neither normal nor updater USB identity; recovery requires the Jieli forced-upgrade path |
| Staged application-only live testing | GRANTED | owner authorized and validated M001 then M02 on 2026-07-15 |

The official v11-v15 SMK packages contain identical `uboot.boot` and
`isd_config.ini` files. The configuration encodes `RESET=PB01_08_0` and
`UPDATE_JUMP=0`. The public rule file defines this as an active-low, eight
second long-press reset on PB1. AC7911B documentation maps PB1/RESET to QFN48
pin 42. Reset is not equivalent to forced-download entry.

The AC79 download documentation says that internal-Flash parts require the
Jieli forced-upgrade tool. AC7911B8 is the 8-Mbit embedded-Flash variant. The
tool resets the chip while sending a boot handshake; this has not been
reproduced on the SMK USB-C port.

References:

- <https://doc.zh-jieli.com/AC79/zh-cn/master/getting_started/preparation/update.html>
- <https://doc.zh-jieli.com/Tools/zh-cn/dev_tools/forced_upgrade/upgrade_and_download.html>
- <https://github.com/Jieli-Tech/fw-Bootloader>

## Static FM path

The stock v12 application already exposes three sequencer modes:

| Mode string | UI title |
| --- | --- |
| `drum` | `Drum Seq` |
| `key` | `Key Seq` |
| `live` | `Live Seq` |

The six pointers form one table at loaded address `0x02057018`. The
`midi_route` task name is at `0x02056F67` and has nine application references.
The relevant callers converge on the name-based task/message post wrapper at
`0x02061612`; `0x0206160C` is `os_time_dly`. At least one wrapper posts three
event words. The receiving MIDI task waits through `0x0206320C`.

### Observed patch-state limitation

Owner test, 2026-07-15: with Latch enabled, changing Patch immediately removes
the previously sounding patch and applies the new patch. Old and new patches
do not sound together.

This proves that the stock Patch control path exposes only one active timbre.
It rules out the simple scheme of switching the global preset before each
sequenced note. It does not yet distinguish between these internal designs:

- one global FM engine/context shared by every voice; or
- per-voice state that could retain a patch, while the stock Patch handler
  deliberately performs all-notes-off and reinitializes the engine.

Follow-up static analysis found that Note On and Note Off each copy `0x9c`
bytes of the current unpacked patch into a per-event/per-voice destination.
M05 uses this to test whether the downstream allocator preserves independent
per-voice timbres. The live audio result remains the deciding evidence.

Reusing the stock event route remains useful, but it is no longer sufficient
by itself:

```text
drum step tick
    -> existing step/pattern lookup
    -> added note-event expansion
    -> midi_route queue
    -> existing FM note-on/note-off path
    -> separate FM timbre context
```

Drum Seq modification is downstream work. It has little value until the MIDI
input and FM runtime can preserve at least two independent timbre contexts.

## Staged implementation

1. Identify the `midi_route` receive loop and label channel, Note,
   Program Change, and controller handling.
2. Locate the channel filter that currently selects the one configured FM
   input channel.
3. Trace a physical key note-on and note-off to the FM voice allocator.
4. Trace Patch change to all-notes-off and FM parameter reinitialization.
5. Determine whether the allocator accepts a context pointer or only one
   global preset state.
6. Create or preserve a second FM context so MIDI channels 1 and 2 can retain
   different patches and sound simultaneously.
7. Measure the RAM, CPU, and total voice cost of the two-part proof and define
   the practical part limit.
8. Locate the drum step callback and pattern memory layout.
9. Connect a Drum Seq lane to an internal FM part using the same part-aware
   note path as MIDI input.
10. Generalize the two-part proof to the practical N-part limit.
11. Design a minimal behavior patch with an incremented three-character build
    ID.
12. Repack it and require the protected-region manifest to pass.
13. **Completed:** validate exact-SHA custom upload, custom boot, visible build
    ID, custom-to-custom OTA, exact UI text mutation, and official rollback
    using M001 through M04.
14. Continue forced-recovery research using the actual SMK USB-C/mainboard path
    as a separate safety improvement.
15. Give every behavior build its own exact-SHA uploader allow-list entry and
    live transcript; never enable arbitrary package writes.

## M05 checkpoint definition

M05 deliberately avoids the full two-part state model. It is the smallest
live test of the newly identified per-voice patch snapshot:

- MIDI channel 1 receives current patch N;
- MIDI channel 2 receives same-bank patch `(N + 1) & 31`;
- no UI, Program Change, storage format, or Drum Seq change;
- Yamaha single-voice preset SysEx pack/save is temporarily unavailable.

The build and protected-region checks pass offline. It is not considered
multitimbral until a host sequencer proves that a sustained Ch1/N voice and an
overlapping Ch2/N+1 voice retain different sounds simultaneously. If both
channels sound the same, or an existing voice changes timbre when the other
channel starts, the per-event snapshot is not sufficient and the next work
returns to allocator/runtime context ownership.

Live result, 2026-07-15: the owner confirmed the intended simultaneous Ch1/N
and Ch2/N+1 behavior using channel-separated sequencer loops. The checkpoint
passes. The downstream FM path preserves the per-voice patch snapshot, so the
next branch can build note-to-patch drum mapping on this proven mechanism
instead of first creating a separate FM engine context.

## M06 checkpoint definition

M06 connects the existing physical pad contract to the proven FM snapshot
mechanism:

- local keys and incoming USB Ch1 use current patch N;
- local pads and incoming USB Ch10 use same-bank patch `(N + 1) & 31`;
- pad notes 36-51, strike velocity, and Note Off timing are preserved;
- all 16 pad notes use the same FM patch at their original pitches;
- there is still no GM note-to-patch map, UI, Program Change, or persistence.

The live success criterion is simultaneous local keyboard N plus local-pad
N+1 playback, with no doubled pad attack, stuck note, cross-part Note Off, or
loss of the original Ch10 MIDI output. A successful result validates the local
input bridge. The following build can then map selected GM notes to different
FM patch snapshots.

Live result, 2026-07-15: the owner confirmed that M06 worked as intended. The
local-input bridge checkpoint passes, so the next implementation branch is a
Ch10 note-to-FM-patch table for the physical GM notes 36-51.

## M07 checkpoint definition

M07 implements that branch for all 16 physical pads in one build. Ch10 notes
36-51 select same-bank patches N+1 through N+16 respectively, with wrap at the
32-preset boundary. Ch1/local keys retain N, and both Ch10 Note On and Note Off
derive the same per-note snapshot. This is the full routing and voice-retention
test for a 16-entry drum map. The selected factory presets are intentionally a
diagnostic palette; percussion-specific FM parameter design follows only after
the hardware proves that every note retains its own timbre.

Live result, 2026-07-15: both OTA stages completed and normal USB identity 012
returned. The owner confirmed that notes retained independent timbres, but
Ch1/local keys incorrectly received the same note-dependent mapping. M07 is a
per-note snapshot proof only; channel isolation failed. The next build must
restore the exact M06 channel gate before adding note selection and must use a
fixed Ch10 bank/map rather than the UI-relative N base.

## M08 checkpoint definition

M08 puts the channel gate before note capture. Ch1/local keys use the stock
current-patch snapshot. Ch10 notes 36-51 use fixed Bank 0 preset IDs 0-15;
the UI bank and preset state are restored after each event. This is the first
build intended to keep the Ch10 map unchanged across UI Patch changes. Both
OTA stages completed and USB identity 012 returned on 2026-07-15; live audio
verification then passed in normal use. The owner did not yet push the engine
to maximum polyphony, so voice-pool saturation and stealing policy remain open.

The decoder patch needed to reproduce current Pi32v2 analysis is
`patches/ghidra-jieli-pi32v2-smk37.patch`.

## M09 checkpoint definition

**Historical failed checkpoint; do not install.** M09 completed OTA but never
returned display or either USB identity. The investigation is recorded in
`docs/m09-brick-incident.md`.

M09 replaces M08's temporary factory-bank selection with an app-resident drum
ROM. Static analysis confirmed a Yamaha DX7 six-operator storage/runtime pair:
128-byte VMEM voices expand to the exact 156-byte snapshot already retained by
each event/voice. Eight expanded percussion templates and a 16-entry map fit in
a zero-filled range with no statically visible references. That evidence did
not establish a safe data cave; the range and the new direct-copy wrapper were
both unproven changes in the failed image.

The intended invariant was stronger than M08:

- Ch1/local keys always use the UI-selected stock current patch;
- Ch10/local pads always use the embedded FM drum map;
- UI Patch changes cannot affect Ch10 because Ch10 does not read or modify any
  bank/preset selector;
- user-edited packed banks at flash `0xF4000..0xF7FFF` remain untouched;
- Note On and Note Off derive the same template from the same note.

M09 was intended as a first playable FM-drum palette, not the final sound
design, but it never reached live audio verification. Any successor requires a
new build ID, a proven application-independent recovery path, and isolation of
the data-storage and wrapper changes.

PCM/sample replacement is explicitly out of scope. The target is FM-only
multitimbral playback. Drum Seq may supply the timing, step grid, pattern
storage, and UI, but its existing sound generator must not be used as the new
rhythm voice. The minimum functional target is two simultaneous FM parts:

- live keyboard FM patch; and
- independently retained rhythm FM patch driven by Drum Seq timing.

Further rhythm tracks must either reference additional FM timbre contexts or
share the rhythm context by an explicit design choice; they must not fall back
to PCM one-shots.

## Validated live custom-package gate

Custom builds use the three-character display/build ID scheme defined in
`docs/firmware-versioning.md`. The four-character M001 trial booted but rendered
as `M00`; M02 uses `M02\0` in the original four-byte field and renders in full.
Both retained updater/base version `012`, and M001 successfully initiated the
OTA that installed M02.

An upload-disabled test package has been generated under ignored `build/` by
replacing the eight bytes `Drum Seq` with the equal-length `FM Drum ` label.

- package: `build/fm-drum-ui-gate.fwsc`
- manifest: `build/fm-drum-ui-gate-manifest.json`
- package SHA-256:
  `340f175ebecd0bcd3a307c7466ed97475658055544c4b3cdb97c8d115e4d9b2c`
- application bytes changed: 8
- total flash bytes changed including nested CRC fields: 16
- boot/layout, raw `uboot.boot`, raw `isd_config.ini`, and post-application
  resources/reserved hashes: unchanged
- offline packet generation: PASS

The normal live uploader rejects this SHA because it remains hard-locked to
the official v12 package. This artifact changes only a label and does not add
FM drum behavior.
