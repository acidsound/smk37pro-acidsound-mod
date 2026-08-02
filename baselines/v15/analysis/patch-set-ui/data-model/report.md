# Official-v15-only per-note Ch10 patch-set data model on live-proven H2

Date: 2026-08-02 UTC
Scope: exact official v15 static evidence plus the recorded live-proven H2 checkpoint. This analysis created no firmware candidate, performed no flash operation, and accessed no device.

## Decision

**Data-model design: PASS. Firmware implementation: BLOCKED pending the gates in this report.**

The smallest defensible first patch-set model is:

- **128 MIDI note keys**, one for every protocol-valid data-byte value `0..127`;
- **16 resident patch payload slots**, matching the intended 16-Pad product/UI target without assuming any unproved contiguous Pad-note numbering;
- one direct `note_to_slot[128]` lookup table;
- one immutable `0x9c` (156-byte) runtime payload per resident slot;
- load-all, publish-once semantics: the set is writable only in `LOADING`, becomes readable when `state == ARMED`, and cannot be replaced in place until reboot;
- exact H2 fallback behavior for non-Ch10, unarmed, out-of-range, unmapped, or invalid-slot events.

This separates two counts that must not be conflated:

| Count | Value | Meaning |
|---|---:|---|
| MIDI note keys | 128 | Complete Ch10 note-number domain and direct lookup-table size. |
| Resident patch slots | 16 | Number of independent 156-byte voices held in owned RAM for the 16-Pad patch-set target. |
| Proven physical Pad mappings | 1 | Only Note 36 from observed `99 24 66`; the Pad ordinal and other 15 note numbers are not established. |
| Dispatcher indexed records | 16 | Static `0..15` record/index bound, not proof of 16-note audio polyphony. |

A 128-payload design would consume `128 * 156 = 19,968` bytes before metadata and is not minimal for the 16-Pad goal. A 16-payload design with a 128-byte indirection table preserves full MIDI-note bounds and allows aliases while using one eighth of that payload RAM.

## Evidence boundary

Primary exact inputs are SHA-gated by `validate.py` and listed in `evidence.json`.

- Official v15 app SHA-256: `36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055`.
- Official v15 package SHA-256: `f7f1831cd7c9ad8b4831b6e71ea0bdbcdff9ae4c4077276b3c965511bf4d4fff`.
- Quarkslab exhaustive listing SHA-256: `f51e384f5f0efc415f321bbfbbe15d051301953338191282872807dcf8683347`.
- Kagaimiq exhaustive listing SHA-256: `814510c15ba600c7420026204c5f4121bce6a5d074422cc20204755d3280e013`.
- H2 app SHA-256: `d71f6c58b4fade00aebb8a0b7d9d024641c37c41ca4bbf3e525fd28773087f59`.
- Live-proven runtime packet SHA-256: `6a9b4097cce1d28780ef3a507f42999743cc10e09770c17c5c78d185e9abff27`.

The analysis does not import v12 addresses, ABI, RAM ownership, or patch behavior.

## 1. H2 producer and consumer contract

H2 establishes the usable base contract:

1. The accepted product-packet producer receives the official staging pointer in `r0` after the stock final-`F7` gates.
2. It performs a nonblocking PI32 `csync; testset` on `0x01c465bd`.
3. It copies exactly `0x9c` bytes to owned RAM `0x01c46520`.
4. It stores `valid = 1` at `0x01c465bc` only after the copy.
5. Both Ch10 Note Off and Note On consumers use the owned source only when `valid == 1`.
6. Both stock fallbacks restore the original destination `r0` immediately before stock `memcpy` and preserve stock `r1/r2`.

The H2 live record proves the exact 163-byte Mooger packet was accepted, the owned source was consumed by a physical Pad Ch10 event, the named timbre was heard, Note Off was normal, and no reboot occurred. It does not prove arbitrary replacement, persistence, full Pad mapping, or polyphony stress.

The proposed layout deliberately keeps **slot 0 voice and validity at the exact H2 addresses**:

- slot 0 voice: `0x01c46520..0x01c465bc`;
- slot 0 valid: `0x01c465bc`;
- global producer lock: `0x01c465bd`.

This makes the model an extension of H2 rather than a different source lifecycle.

## 2. Factory loader and the 156-byte runtime object

Official v15 `0x02005660` is a global-state loader, not a caller-directed `load(src,dst)` function.

- It reads selected bank/preset from the main object at `0x01c33260`.
- It copies a raw `0xa3` record to `0x01c34c74`.
- It expands the matching packed `0x80` record into the first `0x9c` bytes.
- It owns tail bytes `0x9c..0xa2`, applies flag-dependent postprocessing, and calls shared-state helpers.
- The dispatcher consumes only the first `0x9c` bytes.

Therefore every resident slot stores exactly the **live-proven expanded runtime prefix of 156 bytes**. It must not store or expose either of these as the dispatcher source:

- packed `0x80` factory record;
- raw `0xa3` current/backing record.

The loader must not run in the note hot path. Slot materialization must occur before `ARMED`, using a validated runtime payload or a separately proved offline/loader materialization path.

## 3. Runtime source and per-voice copy

Official v15 dispatcher `0x0201c5ec` computes the channel nibble at `0x0201c5fe` and uses current runtime source `0x01c34c74` for both event classes.

- Note Off copy call: `0x0201c63e`.
- Note On copy call: `0x0201c67c`.
- Copy size: `0x9c`.
- Destination form: `engine + voice_index * 0xa0 + 0xa2`.
- Record stride: `0xa0 = 0x9c` tone bytes plus four event metadata bytes.

The static rows identify the event note registers at the existing H2 call hooks:

- Note Off: `r5 = msg[1]` at `0x0201c62e`, then `r5` is stored to event metadata at `0x0201c648`.
- Note On: `r6 = msg[1]` at `0x0201c670`, then `r6` is stored to event metadata at `0x0201c686`; `r5 = msg[2]` is velocity.

Both independent listings decode the note-byte loads. This is strong static evidence, but it has not been confirmed by a live register trace. A firmware candidate must still gate its wrapper ABI against the exact callsite bytes and preserve the note register before using scratch registers.

## 4. MIDI note range and physical Pad mapping

A valid MIDI 1.0 channel-message data byte is seven bits, so the safe note domain is `0..127`. The lookup must still reject any value with bit 7 set before indexing RAM.

Only one physical mapping is established in the repository:

```text
99 24 66  -> status 0x99, Ch10 Note On, note 0x24 = 36, velocity 0x66 = 102
```

No official-v15 evidence enumerates the other 15 physical Pad note numbers or associates Note 36 with a specific Pad ordinal. The data model therefore:

- initializes all 128 map entries to `0xff` in RAM;
- accepts explicit host-provided note mappings while `LOADING`;
- treats any `0xff` or `>= 16` map entry as stock fallback;
- does **not** assume a contiguous General MIDI range such as `36..51`;
- may map multiple note numbers to one resident patch slot.

The existing 16-Pad roadmap and grid evidence justify 16 resident slots as the target, but not a built-in default note map.

## 5. Recommended minimal aligned RAM layout

Base: the exact H2 heap-prefix owner, `0x01c46520`.

Total reservation: `0x0a90` bytes, `0x01c46520..0x01c46fb0`.

```c
#define PATCH_SET_BASE       0x01c46520u
#define PATCH_SLOT_COUNT     16u
#define MIDI_NOTE_COUNT      128u
#define PATCH_VOICE_SIZE     0x9cu
#define PATCH_SLOT_STRIDE    0xa0u
#define PATCH_SET_SIZE       0x0a90u
#define PATCH_SET_HEAP_BEGIN 0x01c46fb0u

struct PatchSlot {                 // 0xa0 bytes
    uint8_t voice[0x9c];           // expanded runtime source
    uint8_t valid;                 // exactly 1 only after complete copy
    uint8_t control;               // slot 0 retains H2 global lock here
    uint8_t generation;            // set generation copied at load
    uint8_t flags;                 // zero in v1
};

struct PatchSetHeader {            // 0x90 bytes, after 16 slots
    uint8_t format_version;        // 1
    uint8_t state;                 // 0 EMPTY, 1 LOADING, 2 ARMED
    uint8_t set_id;                // host transaction identity, 1..127
    uint8_t set_generation;        // increments only on successful COMMIT
    uint8_t loaded_count;          // 0..16
    uint8_t last_error;            // diagnostic only
    uint8_t reserved0[2];
    uint8_t note_to_slot[128];     // 0..15, 0xff = stock fallback
    uint8_t reserved1[8];
};
```

Exact ranges:

| Range | Size | Purpose |
|---|---:|---|
| `0x01c46520..0x01c46f20` | `0x0a00` | 16 slot records at stride `0xa0`. |
| `0x01c46520..0x01c465bc` | `0x009c` | Slot 0 voice, exact H2 source address. |
| `0x01c465bc` | 1 | Slot 0 valid, exact H2 valid address. |
| `0x01c465bd` | 1 | Global nonblocking producer lock, exact H2 lock address. |
| `0x01c46f20..0x01c46fb0` | `0x0090` | Header and 128-entry note map. |
| `0x01c46fb0` | 0 | Proposed shifted heap begin, exclusive end of owned state. |

Payload-only floor is `16 * 0x9c = 0x09c0` bytes. A tightly packed functional floor with 128 map bytes, 16 valid bytes, and four control bytes is `0x0a54` bytes. The recommended `0x0a90` layout costs only `0x3c` bytes more, preserves slot alignment and the H2 slot-0 addresses, and provides explicit version/state fields.

Official heap arena is `0x39810` bytes from `0x01c46520` to `0x01c7fd30`. Reserving `0x0a90` would leave `0x38d80` bytes. This arithmetic proves placement, **not heap headroom**. No implementation may shift the heap boundary until a heap high-water gate covers the additional `0x09f0` bytes beyond H2's existing `0x00a0` reservation.

## 6. O(1) lookup algorithm

Separate wrappers are required because the note register differs between the two callsites.

```c
const uint8_t *select_ch10_source(uint8_t channel,
                                  uint8_t note,
                                  const uint8_t *stock_source) {
    if (channel != 9) return stock_source;
    if (header->state != ARMED) return stock_source;
    if (note > 0x7f) return stock_source;

    uint8_t slot = header->note_to_slot[note];
    if (slot >= PATCH_SLOT_COUNT) return stock_source;

    struct PatchSlot *p = &slots[slot];
    if (p->valid != 1) return stock_source;
    return p->voice;
}
```

Callsite use:

- Note Off wrapper uses the preserved `r5` note candidate.
- Note On wrapper uses the preserved `r6` note candidate.
- Both use the same map, slot base, validity rule, and immutable slot bytes.
- Every fallback restores original destination `r0` immediately before stock `memcpy` and leaves stock `r1/r2` unchanged, exactly as H2.

Cost is one state load, one bounded 128-byte table lookup, one slot bound, one multiply/shift by `0xa0`, one valid load, and the existing 156-byte copy. No loop is required in the note hot path.

## 7. Publication, concurrency, and locking

The v1 model is intentionally **fill once and immutable after commit**.

### State machine

```text
boot/BSS zero -> EMPTY
BEGIN          -> LOADING
PUT_SLOT x16   -> LOADING
PUT_MAP        -> LOADING
COMMIT          -> ARMED, published last
reboot          -> EMPTY
```

Rules:

1. Only producers use the H2 nonblocking lock at `0x01c465bd`.
2. A failed `testset` returns `BUSY` immediately. It never spins.
3. Consumers never take the producer lock.
4. Consumers use stock while state is not exactly `ARMED`.
5. `PUT_SLOT` writes `valid = 0`, copies all 156 bytes, writes generation/flags, executes `csync`, then writes `valid = 1`.
6. `COMMIT` verifies all 16 slots valid, verifies every map entry is `0xff` or `< 16`, checks the canonical set checksum, executes `csync`, then writes `state = ARMED` last.
7. Every mutating command is rejected once `state == ARMED`.
8. No ABORT, replacement, or map edit is allowed after `ARMED`; reboot/BSS zero is the only reset in v1.

This is the minimal concurrency policy that follows H2's proved valid-last publication while eliminating the hard Note On/Note Off generation race. There is no producer after `ARMED`, so both event classes always read the same immutable source identity.

A future hot-edit model would require per-active-voice slot/generation identity or double-buffered slots plus a proved reclamation protocol. It is explicitly outside this v1 model.

## 8. Proposed guarded update packet format

The official accepted voice packet remains important evidence:

```text
F0 43 00 00 01 1B + 156 payload bytes + F7
```

It is exactly 163 bytes; the recorded Mooger payload is entirely seven-bit and was live-proven through H2. However, that official format has no patch-set slot or transaction field. A stateful selector followed by the official packet would create an avoidable cross-packet race.

The data model therefore specifies a **single-message private development envelope** for a future reviewed ingress. It is a transport contract only; no handler or firmware candidate is created here.

```text
F0 7D 53 4D 4B 0F 01 CMD SET_ID FLAGS LEN_LO7 LEN_HI7 BODY CRC0 CRC1 CRC2 F7
```

- `0x7d`: non-commercial/development SysEx ID; production must use an authorized identity.
- `53 4d 4b`: ASCII `SMK` discriminator.
- `0f`: official firmware family/version discriminator for v15.
- protocol version: `01`.
- all non-delimiter bytes must be `< 0x80`.
- `FLAGS` is zero in protocol v1; nonzero values are rejected.
- body length is a 14-bit little-endian seven-bit pair.
- CRC is CRC-16/CCITT-FALSE over bytes `53` through the final body byte, encoded little-endian in three seven-bit chunks: bits `0..6`, `7..13`, `14..15`.
- exact length and terminal `F7` are mandatory before any state mutation.

Commands:

| CMD | Body | Exact total bytes | Effect |
|---:|---|---:|---|
| `0x01 BEGIN` | `slot_count=16, note_domain_code=0` where zero means all 128 notes | 18 | EMPTY only; sets transaction identity and enters LOADING. |
| `0x02 PUT_SLOT` | `slot_index` + exact 156-byte runtime payload | 173 | LOADING only; slot `<16`; valid-last publish into that slot. |
| `0x03 PUT_MAP` | 128 entries, each `0..15` or wire sentinel `0x7f` | 144 | LOADING only; target converts `0x7f` to RAM `0xff`. |
| `0x04 COMMIT` | canonical set CRC-16 in three seven-bit chunks | 19 | Requires 16 valid slots and a valid map; writes ARMED last. |

Canonical set checksum input is:

```text
note_to_slot_wire[128] || slot[0].voice[156] || ... || slot[15].voice[156]
```

`PUT_SLOT` does not pass packed `0x80` or raw `0xa3` data to the dispatcher. Its body is the exact H2-proven 156-byte runtime representation.

The custom handler ingress, USB-MIDI packetization, code placement, and coexistence with stock Yamaha SysEx remain implementation gates. The stock staging range `0x01c37fd0..0x01c38fd0` must never become durable patch-set storage.

## 9. Polyphony implications

The model is read-shared and immutable after `ARMED`, so simultaneous Note On events may safely copy from the same or different resident slots. Each accepted event still receives a private 156-byte copy in the stock per-voice record.

Important limits:

- The dispatcher statically bounds an indexed record delta to `0..15` and uses the low nibble as a record index.
- This proves a 16-record bookkeeping bound, not 16 active oscillators and not a safe 16-note polyphony claim.
- The repository explicitly leaves allocator/voice stealing, overlapping Ch1/Ch10 chords, repeated strikes, reversed release order, sustain, and all-notes-off stress unproved.
- Note Off recopies 156 bytes. Immutability between Note On and Note Off is therefore mandatory in v1.
- Mapping multiple notes to one patch slot is safe at the source level because consumers only read and each voice receives its own copy.

No RAM count in this report is justified by an assumed polyphony number. Sixteen resident payloads are patch identities for 16 Pads, not active-voice storage.

## 10. Bounds and rejection behavior

Every future implementation must enforce all of the following before computing a source pointer:

1. exact official-v15 app input and original callsite bytes;
2. message length `>= 3` as in stock before note access;
3. channel nibble exactly `9` for Ch10;
4. note `<= 0x7f`;
5. state exactly `ARMED`;
6. map entry `< 16`; RAM `0xff` means fallback;
7. slot valid exactly `1`;
8. `slot_base = 0x01c46520 + slot * 0xa0`;
9. `slot_base + 0x9c <= 0x01c46f20`;
10. copy length exactly `0x9c`;
11. all invalid cases use H2's corrected stock fallback ABI;
12. no producer mutation once `ARMED`;
13. packet body length, byte range, transaction ID, command state, and CRC all validate before mutation.

Unknown Ch10 notes intentionally fall back to the stock current Patch. A later policy may choose silence, but silence is not part of the H2-proven fallback contract.

## 11. Why no active-count or per-note generation array is needed in v1

The earlier editable-set roadmap considered active counters and generation identity because replacing a source while a note is held can make Note Off copy a different patch. That is a real hazard.

This design removes the hazard instead of tracking it:

- consumers see no owned set until one atomic set-level `ARMED` publication;
- all sources and mappings are immutable after publication;
- no per-active-note source record is required;
- no consumer lock, spin, retry, or deferred decrement is required;
- no stale counter can wedge updates, because runtime updates are prohibited.

This is smaller and more defensible than a hot-edit model. It is also the closest multi-slot extension of live-proven H2.

## 12. Implementation blockers before any firmware candidate

A firmware candidate remains blocked until all of these are closed:

1. **Pad enumeration:** record all 16 physical Pad Note On and Note Off numbers. Only Note 36 is currently known.
2. **Note-register ABI gate:** independently confirm the Note Off `r5` and Note On `r6` values at the two hook callsites, or prove them with a second instruction-accurate method acceptable for release.
3. **Heap headroom:** prove that moving heap begin from H2 `0x01c465c0` to `0x01c46fb0` cannot expose allocation failure under worst observed operation.
4. **Executable placement:** budget two per-note lookup wrappers and the packet/state producer without reusing an unproved cave or breaking stock paths beyond the explicit H2 policy.
5. **SysEx ingress:** identify a bounded parser hook for the private envelope, or replace the envelope with another reviewed host transport. Do not overload transient `0x01c37fd0` as durable storage.
6. **Memory ordering:** verify PI32 instruction bytes and `csync; testset`/unlock ordering for the enlarged producer and set-level commit.
7. **Live stress plan:** define rollback-backed Ch1/Ch10 overlap, repeated hit, reverse release, CC64, CC120/123, malformed packet, and reconnect tests.
8. **No persistence claim:** v1 is volatile. Stock Patch SAVE remains a separate concern and must not be silently redefined.

## Reproduction

From repository root:

```sh
python3 baselines/v15/analysis/patch-set-ui/data-model/validate.py
python3 baselines/v15/analysis/patch-set-ui/data-model/validate.py --check-output
shasum -a 256 -c baselines/v15/analysis/patch-set-ui/data-model/SHA256SUMS
```

`validate.py` is read-only unless invoked with `--write-output`, which writes only this directory's deterministic `validation.txt`. It does not build firmware, invoke an uploader, access USB, or touch a device.
