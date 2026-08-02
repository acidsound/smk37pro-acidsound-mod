# v15 per-note Ch10 patch-set + UI checkpoint sequence

Date: 2026-08-02 UTC
Status: planning and validation artifact only

## Scope and non-action statement

This report synthesizes the v15 UI-preflash static findings, the H2 live PASS, and the post-R02 roadmap into a staged implementation and validation sequence. It does **not** authorize or perform a firmware patch, package build, flash, OTA, storage write, or device connection. No device was accessed while producing this package.

The sequence deliberately separates:

1. **Stage 1: host-loaded per-note set**
2. **Stage 2: physical control without display**
3. **Stage 3: display**
4. **Stage 4: persistence**

UI event handling may enter only in Stage 2 after a read-only event trace. Renderer integration may enter only in Stage 3 after a read-only renderer/dirty-path trace. Persistence may enter only in Stage 4 after the volatile audio and UI state machines pass.

## Evidence baseline

### H2 live-proven parent

H2 is the only live parent assumed by this sequence. The exact live report records:

- app SHA-256 `d71f6c58b4fade00aebb8a0b7d9d024641c37c41ca4bbf3e525fd28773087f59`
- package SHA-256 `c1752a69ed8f905af58db0de7c3def29c416b71e832e2834e664cd5d17b85011`
- rollback ZIP SHA-256 `c7e0f92852c78d5864a2d60d2bee86215babe7b810e0e62d3c9f2c7d5e69739c`
- owned voice `0x01c46520..0x01c465bc`, valid byte `0x01c465bc`, lock byte `0x01c465bd`
- both Ch10 Note On and Note Off consume the owned source only when valid is exactly 1
- stock fallback restores the original memcpy destination before both stock copies
- intended Bank D patch 14 Mooger #1 sound, normal Note Off, and no packet-time or first-Pad reboot
- five exact changed Flash sectors relative to official v15: `0x04000`, `0x20000`, `0x22000`, `0x2a000`, `0x62000`

H2 does not prove a 16-slot arena, note-index extraction, live slot replacement, overlap stress, UI control, renderer behavior, persistence, or long-duration stability.

### UI-preflash boundary

Static v15 analysis established useful state and function candidates but intentionally did not promote missing ABIs:

- main UI/Patch state base: `0x01c33260`
- pending input bytes: `+0x309..+0x30f`, consumed into live `+0x39..+0x3f`
- screen/page candidate: `+0x200`
- grid/submode candidate: `+0x302`
- selected bank: `+0x3a4`, range 0..3
- selected preset per bank: `+0x3a0+bank`, range 0..31
- existing 16-slot grid paths under candidate state dispatch `0x02029528`
- object C-string setter form at `0x0201a67c`, with a known `Keys Channel-` path from `0x02020376`
- renderer traversal candidate `0x0200f74c` and dirty/redraw candidate `0x0201e06c`
- bounded RAM-to-storage wrapper `0x02004b02`, returning the requested count only on full success and zero otherwise
- contrasting read wrapper `0x02004870 -> 0x020047d8`

Still unresolved statically:

- the physical event producer and stable physical event IDs
- the computed callback target after the known text setter
- the final LCD write/framebuffer ABI
- UI callback context, reentrancy, clobbers, and scratch ownership
- a safe separate Drum Set storage address/key and actual media failure/power-loss behavior

These unknowns define explicit admission gates below. They are not implementation details that may be guessed.

## Global engineering rules

1. Every candidate starts from one exact parent hash. A child is never built from an unverified working binary.
2. Every checkpoint changes one runtime uncertainty. Supporting offline work may be bundled only when it is necessary to expose that single discriminator.
3. Ch10 Note On and Note Off use the same slot-selection and validity rule.
4. Unknown notes, invalid slots, unavailable generations, malformed host packets, and busy slots take a defined no-change or stock-fallback path.
5. A slot becomes visible to consumers only after its full 156-byte voice and metadata are complete. Valid is published last.
6. The Stage 1 minimum-risk replacement policy is **reject update while that slot has active notes**. This preserves one immutable source generation through Note Off without immediately requiring double-buffered voices. A later double-buffer design is a separate candidate.
7. Nonblocking publication is retained. No raw blocking spin loop is allowed.
8. No boot-time or post-init hook is introduced without a separate boot proof.
9. The stock 163-byte (`0xa3`) Patch record is never expanded or repurposed.
10. Stages 1 through 3 perform no persistent writes. SAVE remains blocked or inaccessible until Stage 4.
11. Existing widget/grid/text paths are preferred. Custom graphics, fonts, framebuffer, and direct LCD access are outside this sequence.
12. Any reboot, hang, stuck note, cross-channel timbre change, unexplained audio, unrelated SysEx corruption, renderer corruption, or ambiguous observation is a FAIL and immediate stop.

## Data and protocol contract to prove before Stage 1 candidate construction

The following is a contract, not a claim that addresses are already available.

### Volatile set

Use an independently audited owned arena large enough for:

- 16 immutable runtime voices: `16 * 0x9c = 2496` bytes
- per-slot `valid`, `generation`, and `active_count`
- a 16-entry note-to-slot table with explicit `0xff` unmapped value
- transaction state for guarded host loading
- guards/alignment required by the PI32v2 implementation

The arena start/end and resulting `HEAP_BEGIN` change must be derived from the exact official-v15/H2 BSS and heap model. The H2 160-byte reservation is not silently widened. Heap reduction and maximum allocation headroom must be reviewed and stress-tested as a new risk.

### Slot publication

For target slot `s`:

1. Validate exact packet framing, payload length, slot range, transaction/version, and checksum before changing owned state.
2. Acquire a nonblocking slot lock. On failure, reject without changing the slot.
3. If `active_count[s] != 0`, return BUSY and leave voice, generation, and valid unchanged.
4. Clear valid, copy exactly 156 bytes into the inactive/unpublished slot body, verify the copied body, increment generation, then publish valid last.
5. Release with the same reviewed barrier/try-lock discipline as the H2 lineage.

No arbitrary SysEx probing is permitted. A custom selector/envelope may be used only after an offline parser audit proves exact length gates, rejection isolation, stock-command preservation, and no collision with supported product traffic. The known official 156-byte product packet remains the voice-format anchor.

### Active-note identity

At minimum, a Note On increments the selected slot's active count after successful source selection, and its matching Note Off decrements the same slot. Repeated same-note strikes and release ordering must be defined. If the hook cannot reliably associate Note Off with the original slot, Stage 1 stops and must add reviewed per-active-note identity metadata before continuing.

The busy-reject policy is the preferred first implementation because the published slot cannot change while an old note can still require it. Supporting replacement during active notes requires two versions or per-active-note snapshots and is a later, separately reviewed design.

## Rollback sector discipline

### Known H2 floor

The exact H2-to-official rollback inventory is:

`0x04000, 0x20000, 0x22000, 0x2a000, 0x62000`

These sectors are evidence for H2 only. They are not assumed to be the complete sector list for any child.

### Every Stage 1 to Stage 3 candidate

Before any future installation authorization, generate both:

- **parent rollback**: every 4 KiB managed-Flash sector that differs between the exact candidate and its exact parent
- **official rollback**: the union of inherited and new sectors required to return to exact official v15

The sector inventory is computed from binaries, not predicted from source addresses. Every listed sector must carry parent bytes, candidate bytes, SHA-256 values, and a deterministic restore bundle. All unlisted managed sectors must compare byte-for-byte with the parent. Persistent/user-data sectors must show zero writes in Stages 1 through 3.

### Stage 4 candidates

Stage 4 adds a separate data rollback domain:

- identify the exact storage key/address and every erase sector it can touch
- capture and hash each whole sector before the first write
- keep code-sector rollback separate from data-sector restore
- use a versioned A/B or journaled record with sequence, length, CRC, and commit marker last
- never restore data sectors from a different unit or capture

If the exact data erase sectors or neighboring records cannot be proven, persistence is blocked.

## Checkpoint sequence

Each checkpoint has exactly one discriminator. Passing observations outside that discriminator are guard observations, not additional reasons to promote the checkpoint.

# Stage 1: host-loaded per-note set

**Entry:** exact H2 parent, H2 rollback ready, offline note-register audit complete, owned-arena/heap proof complete, guarded loader parser review PASS.

**UI event:** absent. **Renderer:** absent. **Persistence:** absent and writes blocked.

### S1-C1: two-note selector proof

**Only new uncertainty:** whether the Ch10 consumer hooks can extract one stable note identity and select between two immutable owned slots without changing Ch1 or fallback behavior.

**Build boundary:** reserve only the reviewed arena needed for two slots plus metadata, support exactly two allowlisted host Ch10 note values, and leave every other note on the H2/stock-defined fallback path. Load two unmistakably different named voices through the guarded host path.

**Single discriminator:** two allowlisted host Ch10 notes produce their two assigned named timbres, with their matching Note Offs, while the same packet order and all other conditions are held constant.

**Live observations to record:** boot identity; loader accept/reject result; note numbers sent; audible identity per note; normal Note Off; Ch1 control note before and after; packet-time and note-time reboot; BUSY/invalid fallback behavior.

**Pass:** both notes are unambiguous, correctly assigned, release normally, and guards remain normal.

**Stop:** either note aliases the other, note extraction is unstable, any source is ambiguous, Note Off differs from Note On selection, Ch1 changes, or the device reboots/hangs.

**Rollback:** exact child-to-H2 code sectors only, plus the independent exact official-v15 rollback. No data sectors.

### S1-C2: 16-note capacity proof

**Only new uncertainty:** whether expanding the proven two-slot selector to 16 slots and metadata is safe.

**Build boundary:** preserve S1-C1 logic and expand only capacity/table bounds. Load a deterministic 16-voice set whose neighboring slots are audibly distinguishable. Unknown notes remain fallback/no-change.

**Single discriminator:** each of the 16 allowlisted host Ch10 notes produces exactly its assigned voice and no other slot's voice.

**Live observations to record:** all note-to-slot pairs in fixed ascending order; Note Off for every note; guard notes below/above table; Ch1 before/mid/after; heap/allocation and reconnect smoke tests; loader rejection for slot 16 and malformed length.

**Pass:** the 16-entry expected/observed table matches exactly and all guards remain normal.

**Stop:** any duplicate, shifted, stale, missing, or ambiguous assignment; bounds escape; heap symptom; stuck note; cross-channel change; reboot/hang.

**Rollback:** exact child-to-S1-C1 sector delta. No data sectors.

### S1-C3: atomic per-slot replacement proof

**Only new uncertainty:** whether one slot can be replaced without exposing a partial or wrong generation to active notes.

**Build boundary:** add the reviewed per-slot `active_count`, generation, and BUSY rejection. Do not add double buffering in this checkpoint.

**Single discriminator:** while a note from slot `s` is held, replacement of `s` is rejected with no state change; after release, the same replacement is accepted and the next note uses the new voice.

**Live observations to record:** old voice identity; hold state; BUSY response; old Note Off behavior; generation before/after; accepted retry; new voice identity; neighboring slot and Ch1 controls.

**Pass:** held update is a true no-op, old release is normal, post-release update commits once, and the next note uses only the new generation.

**Stop:** held update mutates any byte/state, old release sticks or changes timbre, generation advances on rejection, partial audio appears, or a neighboring slot changes.

**Rollback:** exact child-to-S1-C2 sector delta. No data sectors.

### S1-C4: volatile set stress gate

**Only new uncertainty:** whether the completed host-loaded volatile set remains correct under deterministic overlap and release stress.

**Build boundary:** no code or data-format change from S1-C3. This is a validation-only checkpoint.

**Single discriminator:** the prescribed Ch1/Ch10 overlap, repeated-strike, reversed-release, CC64, CC120, and CC123 matrix completes with zero stuck notes and zero cross-channel/slot timbre substitutions.

**Live observations to record:** exact MIDI sequence and timing; active counts before/after; audible identity; release order; all-notes-off response; reconnect result; final Ch1 and all-16-slot smoke pass.

**Pass:** the matrix has no deviation and returns all active counts to zero.

**Stop:** any residual active count, stuck voice, voice stealing that changes source identity, cross-channel substitution, crash, or non-reproducible result.

**Rollback:** unchanged from S1-C3 because this checkpoint makes no binary change.

**Stage 1 exit:** host-loaded 16-note set, immutable while active, with deterministic stress PASS. No physical UI event, display, or persistence code may have entered.

# Stage 2: physical control without display

**Entry:** Stage 1 exit PASS. Renderer remains untouched. Persistence remains blocked.

**UI event enters here, but only after S2-C1 read-only trace passes.**

### S2-C1: physical event producer/ID trace

**Only new uncertainty:** whether one intended physical control has a stable producer, event form, and consumer transition in official/H2-lineage runtime behavior.

**Build boundary:** none. Use read-only runtime observation first. Watch `0x01c33569..0x01c3356f` (`0x01c33260 + 0x309..+0x30f`) and correlate one control action with pending-to-live transitions and the enclosing consumer. Do not infer an ID from `0x02058248` alone.

**Single discriminator:** repeated press/release of one chosen non-recovery physical control produces one stable, distinguishable event signature and consumer path, with press/release semantics identified.

**Live observations to record:** control name; pending/live field and width; press/release/repeat values; producer PC/caller; consumer PC; callback context; untouched recovery/boot controls.

**Pass:** the same action repeats the same signature, a different control does not alias it, and context/clobber notes are sufficient for a hook review.

**Stop:** unstable or shared signature, unbounded repeat, recovery/boot overlap, unknown callback context, or any need to guess an ID.

**Rollback:** none because this is read-only and has no candidate binary.

### S2-C2: physical slot selection without display

**Only new uncertainty:** whether the proven event can safely alter a dedicated volatile selected-slot field without renderer involvement.

**Build boundary:** add one event consumer that clamps/wraps within 0..15 and changes only the dedicated Drum Set selected-slot field. Do not reinterpret unresolved stock UI fields unless their writer/reader ownership is proven. Feedback is audio-only through an explicit audition action or subsequent Pad strike.

**Single discriminator:** one physical selection action changes the audition target from slot `n` to exactly slot `n+1`, while the slot contents remain unchanged.

**Live observations to record:** selected slot before/after; event count; auditioned timbre; neighboring and boundary behavior; stock page behavior; Ch1 control.

**Pass:** exactly one step occurs per intended action, boundary behavior matches the specification, and only selection state changes.

**Stop:** skipped/double steps, event leakage into stock pages, slot mutation, renderer artifact, or any recovery-control conflict.

**Rollback:** exact child-to-S1-C3 code-sector delta. No data sectors.

### S2-C3: physical volatile assignment/audition

**Only new uncertainty:** whether proven controls can stage and commit one bank/preset assignment to the selected volatile slot without display feedback.

**Build boundary:** reuse the proven bank range 0..3 and preset range 0..31. Assignment materialization must use a separately audited loader/copy path. Commit only to volatile owned slot state and retain BUSY rejection.

**Single discriminator:** assigning one known bank/preset through physical controls changes only the selected slot to the intended named voice, confirmed by audition.

**Live observations to record:** selected slot; bank/preset inputs; candidate state; commit result; intended voice; all neighboring slots; Ch1; busy-slot rejection.

**Pass:** only the selected slot changes and audition matches the exact expected patch.

**Stop:** wrong materialization, adjacent-slot change, stock current Patch corruption, Ch1 change, busy-slot mutation, or ambiguous sound.

**Rollback:** exact child-to-S2-C2 code-sector delta. No data sectors.

### S2-C4: physical cancel proof

**Only new uncertainty:** whether an uncommitted physical edit can be discarded without changing the active volatile set.

**Build boundary:** add cancel for staged edit state only. Do not add display or persistence.

**Single discriminator:** after changing the staged bank/preset and invoking cancel, the selected slot still auditions the pre-edit voice and its generation is unchanged.

**Live observations to record:** committed generation/voice; staged selection; cancel event; post-cancel generation/voice; neighboring slot and Ch1 controls.

**Pass:** staged state is discarded and committed state is byte-identical.

**Stop:** generation changes, slot contents change, cancel invokes a stock save/load path, or state cannot be distinguished without guessing.

**Rollback:** exact child-to-S2-C3 code-sector delta. No data sectors.

**Stage 2 exit:** select, assign, audition, and cancel work from proven physical events with audio/state evidence and no display dependency.

# Stage 3: display

**Entry:** Stage 2 exit PASS. Persistence remains absent. SAVE/SAVED must not be presented as functional.

**Renderer enters here, but only after S3-C1 read-only trace passes.**

### S3-C1: renderer/dirty transition trace

**Only new uncertainty:** whether a known stock text update reaches a stable computed callback and dirty/redraw transition that can be reused without direct LCD access.

**Build boundary:** none. Trace a known stock path such as `0x02020376 -> 0x0201a67c` and capture the actual runtime continuation, callback target/context, dirty transition, and redraw scheduling. Final LCD write need not be known if the existing widget graph is reused, but custom drawing remains prohibited.

**Single discriminator:** one known stock text-field change produces one repeatable setter-to-callback-to-dirty/redraw chain with a stable ABI.

**Live observations to record:** object pointer; text pointer; setter arguments; computed target; callback context; clobbers/stack; dirty state before/after; redraw consumer; reentrancy evidence.

**Pass:** the full reusable object-level chain is observed twice with identical ABI and no guessed target.

**Stop:** callback target varies without explanation, dirty state is not attributable, buffer ownership is unknown, or only final pixels can be manipulated directly.

**Rollback:** none because this is read-only.

### S3-C2: read-only Drum Set status view

**Only new uncertainty:** whether the existing grid/widget/text path can render the already-proven volatile selected-slot state without changing edit behavior.

**Build boundary:** add a read-only view using the existing 16-slot grid and existing string setter/resource conventions. It reads Stage 2 state but does not write selection, slot data, stock Patch state, or storage. Use same-length/bounded labels only where required by the proven object contract.

**Single discriminator:** the displayed selected-slot highlight follows the already-proven hidden selected-slot state exactly across all 16 positions.

**Live observations to record:** state value and highlight for all positions; redraw count; stock-page entry/exit; text bounds; visual corruption; audio audition identity.

**Pass:** a 16-entry state/display table matches exactly with no stock-page regression.

**Stop:** stale/wrong highlight, out-of-bounds text, redraw loop, flicker/corruption, state mutation by render code, or stock-page regression.

**Rollback:** exact child-to-S2-C4 code-sector delta. No data sectors.

### S3-C3: volatile edit feedback view

**Only new uncertainty:** whether display feedback can distinguish staged versus committed volatile assignment state accurately.

**Build boundary:** render selected slot, staged bank/preset, committed bank/preset, and a nonpersistent marker. Reuse Stage 2 actions unchanged. Do not enable SAVE/SAVED semantics.

**Single discriminator:** after stage, commit, and cancel operations, the display's staged/committed marker always matches the underlying volatile state and audible slot identity.

**Live observations to record:** displayed and underlying fields at each transition; audition result; cancel result; page navigation; redraw latency; no storage calls.

**Pass:** every transition matches state and audio, and instrumentation confirms zero persistence calls.

**Stop:** false committed indication, display/audio disagreement, accidental SAVE/SAVED presentation, storage call, or edit behavior changes relative to Stage 2.

**Rollback:** exact child-to-S3-C2 code-sector delta. No data sectors.

**Stage 3 exit:** minimal existing-widget display is correct for volatile state. No custom graphics or persistent save behavior exists.

# Stage 4: persistence

**Entry:** Stage 3 exit PASS, separate record address/key and erase sectors proven, whole-sector pre-write capture ready, read/write/default/failure paths reviewed, and A/B journal format independently reviewed.

**Persistence enters here. UI SAVE/SAVED enters only at S4-C4.**

### Record contract

Use a separate versioned Drum Set record, never the stock `0xa3` Patch record. Minimum fields:

- magic and format version
- total length and slot count
- monotonic sequence/generation
- 16 note values and 16 bank/preset references, or a justified checked payload form
- CRC over header and payload
- commit marker written last

Prefer packed bank/preset references only if deterministic runtime materialization is proven for every slot. Otherwise store a fully specified checked payload with explicit format version. On boot, select the newest fully committed valid A/B record. Missing, unsupported, short, or corrupt records load a safe volatile default and do not modify the stock Patch store.

### S4-C1: normal save/reboot/load proof

**Only new uncertainty:** whether a separate fully written record survives reboot and restores the exact 16-slot set.

**Build boundary:** add the reviewed A/B record writer and boot/default reader, initially triggered through a controlled host command rather than UI SAVE. Treat `0x02004b02` success only as `return == requested_length`; verify CRC/readback before marking the transaction committed.

**Single discriminator:** after saving a known 16-slot set and rebooting, the reloaded note/bank/preset table and all 16 audible assignments match the pre-save set exactly.

**Live observations to record:** selected data slot; sequence; requested/returned write count; readback CRC; reboot; chosen record; 16-entry table and audio check; stock Patch checksum/state.

**Pass:** one exact record is selected and the full set matches byte/logical/audio expectations with stock Patch intact.

**Stop:** partial count treated as success, wrong record selected, boot delay/fault, any mismatch, stock Patch change, or writes outside inventoried data sectors.

**Rollback:** exact code-sector delta plus unit-specific captured data-sector restore. Do not mix the two domains.

### S4-C2: invalid-record fallback proof

**Only new uncertainty:** whether a corrupt or unsupported newest record is ignored safely.

**Build boundary:** no normal-path feature addition. Use a controlled offline-generated invalid test record or an injected read result within the reviewed test harness. Do not fuzz arbitrary storage.

**Single discriminator:** when the newest record fails one declared validity check, boot selects the older valid record or safe default and performs no automatic rewrite.

**Live observations to record:** invalidity reason; candidate record sequence; chosen fallback; zero write calls during fallback; 16-slot/default state; stock Patch state.

**Pass:** deterministic fallback occurs with no boot loop and no write.

**Stop:** corrupt record is accepted, boot loops, fallback varies, data is rewritten automatically, or stock Patch/store is touched.

**Rollback:** same code/data rollback discipline as S4-C1.

### S4-C3: short-write/interruption recovery proof

**Only new uncertainty:** whether an incomplete new transaction leaves the previous committed record recoverable.

**Build boundary:** add no user feature. Exercise a deterministic short-write/fault injection before the commit marker. A real power interruption is not attempted until the injected fault path passes and a separately approved recovery procedure exists.

**Single discriminator:** after the injected incomplete transaction and reboot, the previous committed record is selected and the incomplete record is ignored.

**Live observations to record:** injected cutoff; returned count; commit marker state; reboot; selected sequence; old set identity; zero repair write; neighboring storage-sector hashes.

**Pass:** old committed set returns exactly and incomplete data remains non-authoritative.

**Stop:** new partial record is selected, old record is damaged, boot loops, automatic repair writes occur, or neighboring sector hashes change.

**Rollback:** exact code-sector delta plus captured data-sector restore. Stop before any real power-cut test unless separately authorized.

### S4-C4: UI SAVE/SAVED integration

**Only new uncertainty:** whether the Stage 3 UI can invoke the proven persistence transaction and report success/failure truthfully.

**Build boundary:** bind SAVE to the S4-C1 transaction. Show SAVED only after full-count write, commit, readback, and CRC verification. A failure retains the dirty/nonpersistent indication and returns control without changing the prior committed record.

**Single discriminator:** the UI shows SAVED if and only if the complete verified transaction succeeds; an injected failure never shows SAVED and the prior record remains active after reboot.

**Live observations to record:** UI action/event; storage request/return; commit/readback/CRC; rendered state; injected failure state; reboot result for success and failure branches.

**Pass:** UI truth table, storage state, and reboot state agree for both branches.

**Stop:** premature SAVED, silent failure, false dirty clearing, stock SAVE path collision, prior record loss, or any unbounded retry.

**Rollback:** exact child-to-S4-C3 code-sector delta plus captured data-sector restore.

**Stage 4 exit:** persistence is versioned, separate, recoverable, and truthfully integrated with the existing-widget UI.

## Stage admission summary

| Capability | First allowed entry | Admission evidence | Explicitly forbidden before |
|---|---|---|---|
| Per-note audio selector | S1-C1 | exact note/register audit at Note On and Note Off, two-slot owned arena | H2 alone does not prove it |
| 16-slot capacity | S1-C2 | S1-C1 live PASS and heap/arena review | before two-note discriminator |
| Mutable slots | S1-C3 | active identity or busy-reject contract | before immutable set passes |
| UI event handling | S2-C2 | S2-C1 read-only producer/ID trace | any guessed event/vector ID |
| Renderer integration | S3-C2 | S3-C1 setter/callback/dirty runtime trace | Stage 1 and Stage 2 |
| Custom LCD/graphics | not in this sequence | final LCD/framebuffer ABI and separate review | all four stages |
| Persistence core | S4-C1 | separate key/address, erase sectors, A/B record, failure plan | Stages 1 through 3 |
| UI SAVE/SAVED | S4-C4 | S4-C1 through S4-C3 PASS | all earlier checkpoints |

## Global stop conditions

Stop the current candidate and restore its exact parent when any of these occurs:

- unexpected reboot, watchdog, hang, boot delay, or version/identity mismatch
- ambiguous timbre or a result that depends on subjective similarity
- Note On and Note Off select different slot/generation rules
- stuck note, active-count leak, cross-channel timbre change, or unexplained allocator symptom
- malformed/unsupported host traffic changes state instead of rejecting
- any managed Flash sector outside the reviewed inventory changes
- any persistent/user-data write before Stage 4
- guessed physical event ID, guessed computed renderer target, or use of `0x02058248` as proof by itself
- direct LCD/framebuffer/custom graphics use
- stock `0xa3` Patch record expansion or collision
- persistence returns short/zero but UI or state treats it as success
- rollback bundle, hashes, parent identity, or unit-specific data backup cannot be verified

## Required evidence bundle for every future candidate

1. exact parent app/package hashes
2. deterministic build inputs and output hashes
3. byte-range and 4 KiB sector diff against parent
4. ABI audit for every changed callsite and hook
5. owned RAM range, zero/init path, heap effect, guard bytes, and reader/writer inventory
6. host parser accept/reject table and no-arbitrary-fuzzing statement
7. one-discriminator live script with expected PASS/FAIL interpretation
8. raw observation log, including guard observations
9. exact parent rollback and official-v15 rollback
10. independent offline review before any live authorization
11. for Stage 4, whole data-sector pre-write captures and restore hashes

## Decision summary

- The immediate implementation target is **Stage 1 S1-C1**, not UI or persistence.
- The first production-shaped volatile design is a 16-slot owned arena with valid/generation/active-count metadata and busy rejection for active-slot replacement.
- Physical UI event code waits for a read-only producer/ID trace.
- Display code waits for a read-only setter-to-callback-to-dirty trace and reuses the existing object/grid system.
- Persistence is last, uses a separate versioned A/B record, and never expands the stock Patch record.
- SAVE/SAVED is a Stage 4 truth indicator, not a Stage 3 cosmetic feature.

## Source provenance

- `baselines/v15/analysis/channel-separation-reanalysis/post-r02-roadmap.md` SHA-256 `2dd1879a6020096804bb21fe538dabb81bf3c1b71cd1a225c69b9cbf34facb12`
- `baselines/v15/analysis/flash-candidates/H2-owned-source-corrected-fallback/live-validation-20260802.md` SHA-256 `b2aca5903390cffe573f42c89aa6407a52c28f967124a07b407887959d1c8fd7`
- `baselines/v15/analysis/ui-preflash/README.md` SHA-256 `1f6209fbd5fb41f2ec60b25c2e28daa3a8487d11d9275f27368acbb98c15ad7f`
- `baselines/v15/analysis/ui-preflash/final-pass/events/report.md` SHA-256 `1db782f6cc39b85b109af39999915bb8a4d7cf7233cb0bff77227d8f41b0537d`
- `baselines/v15/analysis/ui-preflash/final-pass/renderer/report.md` SHA-256 `c1e9c67b0fa426fbaae9632620415ac2f65aead94d31de77ea9cd6635819138d`
- `baselines/v15/analysis/ui-preflash/followup/persistence-direction.md` SHA-256 `c7ef98a1e9305105c173d0ce5f820b438c6ffcda416ad7adb839c2785d64bf42`
- `baselines/v15/analysis/ui-preflash/review/requirements.md` SHA-256 `1ef9a8d2e9ddf55df7a89bedbc6850c976c19f3fa3eb7b8c7ca0f118e002e79b`

Repository revision observed during synthesis: `6d9430e7b91feed2bebb5140fbb056865e3bf347`.
