# S1C5 power-cycle restore, exact-v15-only decision

Scope: read-only findings only. No firmware, FWSC, device, MIDI, flash, OTA, or reset action was produced or performed.

## Decision

**BLOCK.** There is no exact-v15-proven, additive S1C5 power-cycle restore mechanism with an assignable executable address today.

The fixed Bank D 1..16 set does **not** need a 2,496-byte embedded runtime payload. Its packed factory sources already exist contiguously. That solves the data-source problem, but not the safe on-device materialization problem:

1. S1C5's only audited replacement window is fully occupied: `0x0201e13e..0x0201e254` is 278 bytes, with 88-byte selector, 188-byte producer, and 2 bytes inert tail. Preserving the live-good S1C5 producer leaves exactly **2 bytes**.
2. The only exact v15 unpack implementation is inlined inside `0x02005660`. Its packed-source through final runtime-byte body is `0x020056a0..0x0200576e`, **206 bytes**, uses the global current object, and has no destination-pointer ABI. Even deleting the whole 188-byte S1C5 producer plus 2-byte tail yields only 190 bytes, **16 bytes less than that known body before any 16-slot loop, locking, validation, publication, or Note ABI repair**.
3. Calling `0x02005660` repeatedly is not a safe substitute. It mutates global bank/preset-selected current state, copies through `0x01c34c74`, calls four tail helpers, and writes through `*(0x01c33260+0x15c)`. No exact evidence proves 16 or 17 loader calls inside a MIDI Note handler are race-free, latency-safe, or UI/state-neutral.
4. The known R01d early hook at `0x02005f9c` is explicitly revoked. `0x02005fa4` is after the stock storage reads and loader, but it is still in the same pre-return boot initializer and has no evidence of being safe for custom work before USB enumeration.
5. No other executable cave or app extension is owned. Safe app extension is 0 bytes, and generic zero/`0xff` runs remain unproved.

## Exact S1C5 address and ABI baseline

| Item | Exact range/value |
|---|---|
| Note Off hook | `0x0201c63e`, 6 bytes `80fffa1a0000`, target `0x0201e13e` |
| Note On hook | `0x0201c67c`, 6 bytes `80ffc01a0000`, target `0x0201e142` |
| Note Off Playback Note reload | `0x0201c644..0x0201c64a`, `lb.z r5,[r0]` plus two NOP-equivalent moves |
| Note On Playback Note reload | `0x0201c682..0x0201c688`, `lb.z r6,[r0]` plus two NOP-equivalent moves |
| Note On velocity store | `0x0201c68c`, `8d42`, preserved |
| selector | `0x0201e13e..0x0201e196`, 88 bytes |
| producer | `0x0201e196..0x0201e252`, 188 bytes |
| inert tail | `0x0201e252..0x0201e254`, 2 bytes |
| resident voices | `0x01c46520..0x01c46f20`, 16 records at stride `0xa0`, voice length `0x9c` |
| lock/count/state | `0x01c465bd/0x01c465be/0x01c465bf` |
| Playback Note map | `0x01c46f20..0x01c46f30`, 16 volatile bytes used by S1C5 |

At the common dispatcher `0x0201c5ec`, `r9` is the channel nibble. Note Off has trigger note in `r5`; Note On has trigger note in `r6` and velocity in `r5`. Both hooks enter with `r0=event destination`, `r1=stock current source`, and `r2=0x9c`. The S1C5 selector preserves `r4..r9` and `rets`, returns `r0=original destination+0x9c`, and the patched caller reloads the mapped note from `[r0]`.

A lazy initializer inserted here would therefore have to preserve the same frame, preserve Note On velocity, reacquire or reload `r2=0x9c` after every call, publish each slot valid last, publish state `ARMED=2` last, and return through the existing metadata-pointer ABI. No bytes are assigned for this because placement is blocked.

## Lazy first-Ch10 Note On/Off assessment

A first-event trigger is the narrowest lifecycle that definitely avoids the R01d pre-USB stage. The logical integration point is the current state test at `0x0201e164..0x0201e16a`, after channel/range acceptance and before resident-slot consumption.

**RAM-only direct materialization could be admissible in principle**, if an exact destination-parameter unpack routine and executable placement were proved. It must use the existing `testset` lock and fail closed if the producer is active. It must not perform storage I/O, change selected bank/preset, or call the global loader.

**Loader-based lazy materialization is rejected.** A full-set implementation would set Bank D and presets 0..15, call `0x02005660`, copy `0x9c` from `0x01c34c74` to each resident slot, restore the original selection, and call the loader again. That is 17 global loader executions in one MIDI event and does not reverse every intermediate helper/UI side effect. Per-slot lazy loading merely spreads the same unsafe global mutation across later Note events and creates active-note/UI race questions.

The first event may be Note Off. Any approved design must make initialization idempotent for both adapter entries and must never emit a custom Note Off from a different slot/generation than its Note On.

## Post-storage-init hook assessment

The stock initializer establishes storage pointers and reads persistent tables before the revoked callsite:

- `0x02005eee`: store runtime handle to `g+0x160`.
- `0x02005ef2`: store factory pointer to `g+0x164`.
- `0x02005f0e`: `0x02004870` reads 0x80 flag bytes from `+0x9180`.
- `0x02005f20`: `0x02004870` reads 9 selection bytes from `+0x9200`.
- `0x02005f9c`: stock loader call, the exact R01d-redirection site that must not be reused.
- `0x02005fa4`: stock post-loader initializer call with `r0=*(g+0x15c)`.
- `0x02005faa`: function returns.

`0x02005fa4` is the narrowest syntactic after-storage callsite, but not a safe approved hook. Redirecting its 4-byte call would require a wrapper that first preserves `0x020057e0`, and there is neither placement nor live proof that additional pre-USB work is safe. The exact-v15 evidence therefore contains **no automatic safe post-storage boot hook**.

## Existing `0x02005660` calls

| Callsite | Bytes | Classification | Return consumer |
|---|---|---|---|
| `0x02005f9c` | `bfea60fb` | revoked pre-USB init callsite | loads *(r6+0x15c), then calls 0x020057e0 |
| `0x0201e46c` | `bfeaf838` | post-product direct SysEx reload | immediate pop; return ignored |
| `0x0201e4a0` | `bfeade38` | post-product segmented-final SysEx reload | goto common continuation; return ignored |
| `0x0202422e` | `bfea170a` | UI bank/preset change reload | loads *(g+0x15c), then calls 0x020057e0 |
| `0x020255a6` | `bfea5b00` | conditional default-load/bank-block reload | falls through; return ignored |

The SysEx callsites are post-USB but require host traffic, so they cannot provide autonomous power-cycle restore. The UI callsite requires a user bank/preset change. The default-load callsite is conditional runtime behavior, not a proven every-boot post-storage callback.

## Bank D 1..16 without embedding 2,496 bytes

**Source-data result: PASS. Device materializer result: BLOCK.**

For zero-based bank 3 and presets 0..15, packed sources are contiguous at `*(g+0x164)+0x3000..+0x3800`. No reference table is needed for this exact set. The clean-dump physical model is `0x0f7000..0x0f7800`. All 16 saved flags are zero, so the loader's first `0x9c` result is the pure packed-voice expansion.

The stock raw `0xa3` table cannot be copied directly. In the clean dump, Bank D 1..16 raw prefixes are the same placeholder hash and differ from their desired runtime voices by 82 to 101 bytes.

| Slot | Trigger | Patch | Name | Packed offset | Raw offset | Raw/runtime differing bytes |
|---:|---:|---|---|---:|---:|---:|
| 0 | 36 | D1 | BUZZ BASS | `0x0f7000` | `0x0fbd20` | 91 |
| 1 | 37 | D2 | Bang ????? | `0x0f7080` | `0x0fbdc3` | 95 |
| 2 | 38 | D3 | BASSE BIEN | `0x0f7100` | `0x0fbe66` | 89 |
| 3 | 39 | D4 | BASS-THING | `0x0f7180` | `0x0fbf09` | 98 |
| 4 | 40 | D5 | BASS SLAP | `0x0f7200` | `0x0fbfac` | 90 |
| 5 | 41 | D6 | BEAMER 2 | `0x0f7280` | `0x0fc04f` | 87 |
| 6 | 42 | D7 | Onglon | `0x0f7300` | `0x0fc0f2` | 82 |
| 7 | 43 | D8 | SOFTSTEEL | `0x0f7380` | `0x0fc195` | 88 |
| 8 | 44 | D9 | BASS-ROADS | `0x0f7400` | `0x0fc238` | 97 |
| 9 | 45 | D10 | E.ORGAN 1 | `0x0f7480` | `0x0fc2db` | 83 |
| 10 | 46 | D11 | YEAAAHH | `0x0f7500` | `0x0fc37e` | 101 |
| 11 | 47 | D12 | HAND DRUM | `0x0f7580` | `0x0fc421` | 90 |
| 12 | 48 | D13 | HAND CLAP1 | `0x0f7600` | `0x0fc4c4` | 98 |
| 13 | 49 | D14 | Mooger #1 | `0x0f7680` | `0x0fc567` | 90 |
| 14 | 50 | D15 | Moog Solo2 | `0x0f7700` | `0x0fc60a` | 85 |
| 15 | 51 | D16 | Mooger Low | `0x0f7780` | `0x0fc6ad` | 95 |

The shortest safe architecture after future placement proof is:

```text
first accepted Ch10 note while state != ARMED
  -> testset existing lock; if busy, fail closed to stock
  -> state = LOADING; clear count/valid
  -> for i=0..15:
       packed = *(0x01c33260+0x164) + 0x3000 + i*0x80
       dest   = 0x01c46520 + i*0xa0
       unpack packed128 -> dest[0..0x9b] with destination-parameter, no globals
       dest[0x9c] = VALID last
       playback_map[i] = selected fixed policy
  -> csync; state = ARMED last; unlock
  -> resume the original S1C5 selector ABI
```

This is an architecture only, not an address/byte patch. It remains blocked until an exact PI32 routine fits a proven executable range and independently matches all 16 pinned runtime hashes.

## Playback Note persistence options

| Option | Persistent bytes | Decision |
|---|---:|---|
| Derive Original as `36+slot` | 0 data bytes | Only fixed Original playback survives power cycle without new storage. It can be generated during materialization. |
| Compile a fixed custom 16-byte map into app-owned read-only data | 16 bytes | BLOCK preserving S1C5 because the audited window has 2 spare bytes and safe app extension is 0. |
| Keep S1C5 wire byte 161 / RAM `0x01c46f20+slot` | 16 volatile bytes | Existing live-good behavior, but lost on power cycle. The producer restores voice byte `0x9b` to `0x3f`, so it is not in-record persistence. |
| Put 16 map bytes in a separate custom A/B record | 16 bytes plus header/domain overhead | BLOCK until a non-overlapping storage allocation, read lifecycle, commit semantics, and corruption/power-loss behavior are proved. |
| Reuse stock `0xa3` records, flags, or selection bytes | nominally small | BLOCK. Those fields have stock schema and ownership; changing them would couple Drum Set state to stock Patch SAVE and rollback. |

## Exact blocking gates

1. Prove an executable range large enough for a destination-parameter unpacker plus 16-slot loop while preserving S1C5 producer and selector behavior, or produce a fully reassembled smaller S1C5 implementation with exact review.
2. Independently decode and hash-check the on-device unpacker against all 16 pinned Bank D runtime objects.
3. Keep the first-note path RAM-only. No loader, storage read/write, selected-bank mutation, or UI-object mutation.
4. Prove lock/state behavior for Note On, Note Off, concurrent producer ingress, repeated hits, active notes, and failure fallback.
5. For custom Playback Notes, prove either app-owned literal placement or a separately owned persistent record. Current safe budgets are 2 app-window bytes and 0 custom storage bytes.
6. Do not use `0x02005f9c`. Do not promote `0x02005fa4` without separate post-USB/live proof.

## Reproduction

```sh
python3 baselines/v15/analysis/persistence-s2/restore/analyze_restore.py
(cd baselines/v15/analysis/persistence-s2/restore && shasum -a 256 -c SHA256SUMS)
```

Expected result: `RESULT BLOCK`, with all evidence checks passing. BLOCK is the design decision, not a validator failure.
