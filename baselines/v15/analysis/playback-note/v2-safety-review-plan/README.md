# S1-C4 Playback Note v2 safety review plan

Scope: review checklist for a corrected S1-C4 Playback Note candidate. Basis is the official S1-C3 v1 baseline artifacts under `baselines/v15/analysis/flash-candidates/S1C3-16slot-functional-v2-r3-reload` and its reviewed S1-C3 inputs only. This plan is offline only. Do not access a device, open MIDI/USB, flash, reset, or modify any firmware candidate while using it.

## Hard fail-closed rule

A candidate is **BLOCK** unless every checklist item below is proven from static artifacts and reproducible validator output. Any missing proof, uncertain decode, out-of-window branch, changed protected sector, live transport dependency, or reordered publication step is a blocker.

## Review checklist

### 1. Exact source baseline and invariants

- [ ] Candidate declares the S1-C3 basis app SHA-256 `7c672938023beee74d599f43ccd5c7642396b89819e929501274239aed5e5d4b` or explicitly explains any smaller derived app basis.
- [ ] Direct product callsite remains `0x0201e468`; direct reload call remains byte-exact at `0x0201e46c` with bytes `bfeaf838`.
- [ ] Segmented product route remains no-mutation; segmented reload call remains byte-exact at `0x0201e4a0` with bytes `bfeade38`.
- [ ] Selector note invariant remains `slot = note - 36` for notes `36..51`; physical pad permutation is UI-only and never feeds producer, selector, sender, packet order, or runtime slot order.

### 2. Fail-closed fallback instruction ordering

- [ ] Entry rejects direct traffic with `r9 != 0xa3` before `testset`, state, count, valid, voice, trigger-note, or metadata mutation.
- [ ] Failed nonblocking `testset` returns immediately and does not clear another owner.
- [ ] `state == ARMED`, `loaded_count == 16`, invalid state, and `state == EMPTY && loaded_count != 0` all unlock and reject before any slot or metadata mutation.
- [ ] The normal fallback path is still the S1-C3 fail-closed behavior: no publication until a complete valid slot copy has a `csync` and valid-last commit.
- [ ] Any Playback Note-specific fallback must be ordered before publication and must default to no audible/note change if its trigger source, metadata, or branch condition is invalid.

### 3. Trigger Note source invariance

- [ ] Trigger Note is derived only from the same note-order source as S1-C3, `note = 36 + slot`, not physical pad order, UI order, incoming velocity, sender file order beyond the exact 16-slot allowlist, or mutable runtime metadata.
- [ ] For every slot `0..15`, the candidate proves Trigger Note values exactly `36..51` and the physical pad sequence remains only display metadata.
- [ ] Segmented route cannot publish, alter, or infer Trigger Note.

### 4. Symmetric Note On/Off metadata and Note On velocity

- [ ] Note On and Note Off use the same Trigger Note byte for the slot.
- [ ] Note On and Note Off use symmetric channel/status metadata, except for the required status distinction between Note On and Note Off.
- [ ] Note On velocity is explicitly defined and bounded. It must not be copied from untrusted packet bytes unless those bytes are already in the exact pinned packet payload and independently decoded.
- [ ] Note Off velocity is explicitly defined, or proven irrelevant by the target MIDI path, and cannot corrupt Note On velocity or note identity.
- [ ] Metadata writes are either valid-last under the same slot publication protocol or are immutable constants proven by static decode.

### 5. ARMED and valid ordering

- [ ] Slot publication order is exactly: clear `valid[i]`; copy exactly `0x9c` voice bytes; write Playback Note metadata; `csync`; write `valid[i]=1`; write `loaded_count=i+1`.
- [ ] For slot 0 only, `state=LOADING` occurs before the first copy; consumers still reject because `state != ARMED`.
- [ ] For slot 15 only, a final `csync` occurs after `loaded_count=16` and before `state=ARMED`.
- [ ] `state=ARMED` is the final publication action and no later accepted packet can mutate any slot, metadata, count, valid byte, or trigger note.

### 6. `0x9b` restoration and voice copy boundary

- [ ] The S1-C3 voice copy size remains exactly `0x9c` bytes per slot unless the candidate proves a deliberate one-byte metadata extraction.
- [ ] If Playback Note temporarily alters byte `0x9b`, the original byte at offset `0x9b` is restored before the voice copy is published valid.
- [ ] Any metadata extraction from byte `0x9b` must happen before restoration and before `valid[i]=1`.
- [ ] No candidate may publish a slot with `voice[0x9b]` left as transient Playback Note metadata.

### 7. Producer reset and later packet behavior

- [ ] Boot/BSS reset remains `EMPTY`, `loaded_count=0`, `valid[0..15]=0`, and no stale Playback Note metadata can appear valid.
- [ ] There is no host-triggered producer reset, partial reload, or re-arm command in the candidate unless separately reviewed and fail-closed.
- [ ] Packet 17+ and all accepted direct traffic after `ARMED` reject without mutation.
- [ ] Unlock-on-reject paths are complete and cannot deadlock the producer after Playback Note validation failure.

### 8. Code window and branch target gates

- [ ] Producer entry remains `0x0201e1a2`, or every callsite and branch target is recalculated and decoded from exact bytes.
- [ ] Owned executable window is respected: S1-C3 producer/stub window `0x0201e1a2..0x0201e254`; selector window `0x0201e13e..0x0201e19e`.
- [ ] Direct callsite bytes and target, segmented callsite bytes and target, and both reload calls are independently decoded from candidate bytes.
- [ ] Every branch, conditional branch, call, literal load, and fallthrough target stays inside the intended code window or an existing reviewed firmware target.
- [ ] No branch lands in data, padding, middle of an instruction, selector code, packet data, or rollback/OTA support code.

### 9. Rollback gates

- [ ] Rollback manifest is present and restores official v15 flash exactly.
- [ ] Protected hashes for boot/layout, ISD config, U-Boot boot area, and post-app resources/reserved match the official hashes.
- [ ] Changed flash sectors are enumerated, minimal, and covered by rollback sectors.
- [ ] Rollback is built and validated offline only; using rollback on hardware requires separate explicit authorization.

### 10. OTA and sender gates

- [ ] Exact OTA check is offline-only by default and upload requires an explicit confirmation token.
- [ ] Dry-run sender verifies all packet files, length `163`, direct header `f0430000011b`, terminator `f7`, exact order `slot0-note36` through `slot15-note51`, and pinned hashes before any USB/MIDI open.
- [ ] Live sender is compile-time fail-closed unless explicitly enabled and separately authorized.
- [ ] `device_accessed=false`, `midi_transport_opened=false`, and `flash_performed=false` are recorded for review artifacts.

## Required reviewer output

The corrected S1-C4 candidate review must end with one of:

- **PASS for offline artifacts only**: all static safety gates pass, but no device action is implied.
- **BLOCK**: at least one checklist item lacks exact evidence.

Do not issue a live-send, reset, OTA upload, or flash recommendation from this checklist alone.
