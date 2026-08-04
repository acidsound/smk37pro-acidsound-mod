# Official v15 and current S1C5 power-cycle persistence storage analysis

Date: 2026-08-04 UTC  
Scope: exact official v15 application, exact current S1C5 application, and repository static evidence only. No firmware image was changed, no device or transport was opened, and no flash or persistent-storage operation was performed.

## Decision

**Storage-capacity decision: PASS with explicit stock-record reservation.**

The 16 current S1C5 patches and 16 Playback Notes can be encoded in the first `0x9c` bytes of 16 existing stock raw `0xa3` records without touching the seven-byte stock tail, the `0x80` flag table, the nine-byte selection block, or bytes after the known stock extent.

The exact reversible encoding is:

```text
raw[i][0x00..0x9a] = S1C5 slot[i].voice[0x00..0x9a]   // 155 bytes
raw[i][0x9b]       = S1C5 playback_note[i]             // 1 byte, 0..127
raw[i][0x9c..0xa2] = unchanged stock tail              // 7 bytes
```

On restore:

```text
slot[i].voice[0x00..0x9a] = raw[i][0x00..0x9a]
playback_note[i]           = raw[i][0x9b] & 0x7f
slot[i].voice[0x9b]        = 0x3f
```

This works because current S1C5 already proves that byte `voice[0x9b]` is reconstructible. Its producer extracts the Playback Note from staging byte `0x9b`, stores it in `0x01c46f20+slot`, restores staging and resident slot byte `0x9b` to `0x3f`, and only then publishes slot validity.

There is **no proven unused stock record or stock metadata field**. All 128 records are allocated library records. All seven raw tail bytes have stock consumers. The flags and all nine selection bytes have stock lifecycle meaning. Therefore this is not a claim of free stock space. It is a deliberate reservation of raw-record prefixes under current S1C5.

For a defensible recognized and corruption-checked set, the narrowest recommendation is:

- **17 raw-record prefixes** for a single-copy, fail-closed design: 16 payload records plus one manifest record.
- **34 raw-record prefixes** for A/B copies that retain the previous valid generation across an interrupted update.

No custom persistent allocation is required in either case, but an explicit record-reservation policy is required. If byte-for-byte preservation of all 128 raw records is mandatory, this path is blocked and the narrowest alternative is a separately proven `0x1000` custom domain for one fail-closed copy or two `0x1000` domains for A/B.

## Exact artifact gates

| Artifact | SHA-256 |
|---|---|
| official v15 app | `36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055` |
| current S1C5 app | `8b16e9f5a3ec873ac9a51e64f12c5be20156a01a6e8eb65878eed9636179f189` |
| official exhaustive listing | `f51e384f5f0efc415f321bbfbbe15d051301953338191282872807dcf8683347` |
| current S1C5 selector/producer decode | `3cb4c44c5ea2c3c99db25db4dcacdf6f2999f8dd90a42b3179f0e0f89b5f6826` |
| current S1C5 selector/producer evidence | `c2c057912c8ed2ecaed37a8158a836b81985207b8f34586820b376f28c167eec` |

`validate.py` reproduces 80 exact checks and emits the extracted official rows in `exact-rows.tsv`.

## 1. Stock store object and boot initialization

Let:

```c
uint8_t *g = (uint8_t *)0x01c33260;
```

The two relevant fields are not interchangeable:

| Field | Established role | Boot producer |
|---|---|---|
| `*(g+0x160)` | storage address/offset view used by `0x02004b02` and `0x02004870` | `0x02005eea` calls `0x0200464e`, then `0x02005eee` stores `r0` |
| `*(g+0x164)` | direct read/mapped pointer used by stock Patch loader | `0x02005ef2` stores `r5` |

Exact boot order in the unchanged official/S1C5 window `0x02005edc..0x02005fac`:

1. `0x02005ee2` calls `0x0200463a` on the opened object and receives `r5` through the caller output frame.
2. `0x02005eea` calls `0x0200464e(r0=r5)`.
3. `0x02005eee` stores the translated result to `g+0x160`.
4. `0x02005ef2` stores `r5` to `g+0x164`.
5. `0x02005ef8` closes/releases the temporary open object through `0x02004678`.
6. `0x02005f0e` reads the 128-byte flag table.
7. `0x02005f20` reads the nine-byte selection block.
8. Invalid selection metadata is replaced and persisted at `0x02005f7c -> 0x02005512`.
9. `0x02005f9c` calls stock loader `0x02005660`.
10. `0x02005fa0` begins the post-loader continuation.

The current S1C5 app is byte-identical to official v15 across this entire initialization window and across the stock loader and read/write wrappers.

## 2. Closed stock layout

The stock Patch store relative to either view closes exactly at `+0x9209`:

| Relative range | Size | Meaning |
|---|---:|---|
| `+0x0000..+0x4000` | `0x4000` | four packed banks, `4 * 32 * 0x80` |
| `+0x4000..+0x9180` | `0x5180` | 128 raw records, `128 * 0xa3` |
| `+0x9180..+0x9200` | `0x80` | per-record flag table |
| `+0x9200..+0x9209` | `0x09` | selected-bank/preset and related selection state |

```text
0x4000 + 128 * 0xa3 = 0x9180
0x9180 + 0x80       = 0x9200
0x9200 + 0x09       = 0x9209
```

Raw record `index` is:

```text
index = bank * 32 + preset
0 <= bank <= 3
0 <= preset <= 31
```

Its two views are:

```text
read pointer:  *(g+0x164) + 0x4000 + index*0xa3
write address: *(g+0x160) + 0x4000 + index*0xa3
```

No byte after `+0x9209` is admitted by this analysis. No backing-region identity or allocation ownership beyond the stock extent is needed for the record-prefix path.

## 3. Exact wrapper ABIs

### Write wrapper `0x02004b02`

External ABI:

```c
uint32_t write_02004b02(
    const void *ram_source,   // r0
    uint32_t storage,         // r1
    uint32_t length);         // r2
```

Return:

```text
requested length on complete success
0 on any short or failed inner result
```

Exact wrapper behavior:

- `0x02004b04`: save requested length in `r4`.
- `0x02004b06`: move external storage argument to inner `r2`.
- `0x02004b08`: move length to inner `r1`.
- `0x02004b0a`: call `0x02004a7a` as `r0=source, r1=length, r2=storage`.
- `0x02004b0c..0x02004b12`: return `length` only if the inner return equals `length`, otherwise return zero.

`0x02004a7a` checks `storage + length <= *(0x01c454b0+0x18)` before invoking the lower request primitive through `g+0xd1c`.

A custom commit must treat only `return == requested_length` as success. The official SAVE routine ignores both write returns.

### Read wrapper `0x02004870`

External ABI:

```c
uint32_t read_02004870(
    void *ram_destination,    // r0
    uint32_t storage,         // r1
    uint32_t length);         // r2
```

Return:

```text
requested length on complete success
0 on any short or failed inner result
```

`0x02004870` rearranges arguments for `0x020047d8`. The inner read obtains an allocated/read buffer and `0x02004866` copies it to the caller destination through `0x02048cce`.

The stock boot path uses this wrapper for flags and selection:

```text
0x02005f0e:
  r0 = g+0x129c
  r1 = *(g+0x160)+0x9180
  r2 = 0x80

0x02005f20:
  r0 = g+0x3a0
  r1 = *(g+0x160)+0x9200
  r2 = 9
```

The boot caller ignores both returns. A custom restore or write verification path must not.

## 4. Stock raw loader `0x02005660`

External ABI is effectively:

```c
void loader_02005660(void);
```

It ignores caller arguments and reads global selection:

```text
bank   = g[0x3a4]
preset = g[0x3a0 + bank]
```

It returns early for `bank > 3` or `preset > 31`.

Raw copy:

```text
0x02005682  r7 = *(g+0x164)
0x0200568a  offset = (bank*32+preset)*0xa3
0x02005690  source = r7+0x4000+offset
0x02005694  destination = g+0x1a14 = 0x01c34c74
0x02005698  length = 0xa3
0x0200569a  memcpy
```

The important separation follows:

- The raw copy initially copies all `0xa3` bytes.
- The packed `0x80` record then reconstructs and overwrites **every byte `0x00..0x9b`** of the current `0x9c` voice prefix.
- Raw tail bytes `0x9c..0xa2` survive and drive stock helpers and flag-dependent synchronization.

This makes the raw prefix dormant for playback after the packed expansion, but it does not make the record free. Official SAVE normally refreshes both raw and packed representations.

## 5. No unused tail, flag, or selection byte

### Raw tail `0x9c..0xa2`

Every byte has proven stock meaning:

| Raw offset | Stock use |
|---:|---|
| `0x9c` | `0x02005770 -> 0x0200552e` |
| `0x9d` | `0x02005776 -> 0x0200558e` |
| `0x9e` | `0x0200577c -> 0x020055f8` |
| `0x9f` | `0x02005782 -> 0x0200562c` |
| `0xa0` | flag-dependent mirror paired with current voice byte `0x86` |
| `0xa1` | flag-dependent mirror paired with current voice byte `0x87` |
| `0xa2` | loaded at `0x0200578a` and stored to `*(g+0x15c)+0x16` |

Therefore no Playback Note, signature, CRC, or commit marker should be put in the tail if stock loader compatibility is required.

### Flag table `+0x9180`

- Boot reads all 128 bytes to `g+0x129c`.
- Loader distinguishes flag `0`, flag `1`, and other values.
- Official SAVE writes constant `1` to the selected entry at `0x02026dbe`.
- The bank-block path clears 32 entries and flushes the table.

The table is not spare per-record metadata.

### Selection block `+0x9200`

- `0x02005512` persists exactly nine bytes from `g+0x3a0`.
- Boot reads all nine bytes.
- Boot requires `g[0x3a8] == 8`.
- On failure it constructs defaults and writes the full block.

It has insufficient capacity for 16 notes and no proven free byte.

## 6. Official SAVE and current S1C5

### Official `0x02026d6c`

The SAVE path is embedded in a larger UI handler. Relevant live registers are:

```text
r8  = g = 0x01c33260
r6  = handler state, rejected when 0xff
r15 = constant 1, established at 0x020252a8
```

Exact flow:

1. `0x02026d6c..0x02026d74`: require `g[0x1ec] == 0`.
2. `0x02026d7a`: skip data writes when `r6 == 0xff`.
3. Compute selected `index = bank*32+preset`.
4. `0x02026da6`: write `g+0x1a14`, length `0xa3`, to `*(g+0x160)+0x4000+index*0xa3`.
5. `0x02026dac`: call stock `0x0201e13e` packer to refresh the selected packed `0x80` record.
6. `0x02026dbe`: set `g[0x129c+index] = 1`.
7. `0x02026dd0`: write the 128-byte flag table to `*(g+0x160)+0x9180`.
8. `0x02026dd8`: set `g[0x1ec] = 1` and leave through common cleanup.

Both `0x02004b02` returns are ignored. The flag and cleanup state can be updated after a failed write.

### Current S1C5 difference

Current S1C5 inherits the earlier SAVE block:

| Site | official bytes | S1C5 bytes | Result |
|---|---|---|---|
| `0x02026da6` | `beeaacee` | `04960000` | branch to `0x02026dd4`, before raw write, packer, flag update, and flag flush |
| `0x02026dac` | `bfeac7b9` | `00000000` | stock packer call neutralized |

The original stock packer body at `0x0201e13e` is also no longer present. Current S1C5 uses `0x0201e13e` as the Note Off selector entry and `0x0201e196` as its producer.

Consequences:

- Current S1C5 stock SAVE does not overwrite the proposed reserved raw prefixes.
- Stock SAVE is not available as a custom commit engine.
- Simply restoring the call at `0x02026da6` would be unsafe because the following `0x0201e13e` lifecycle is now unrelated selector code.
- The fastest commit path is a separate guarded host command that calls `0x02004b02` directly and verifies each result and readback.

## 7. Why 16 payload records fit

Current S1C5 RAM and publication contract:

| Address | Meaning |
|---|---|
| `0x01c46520 + slot*0xa0` | resident voice base, 16 slots |
| `slot+0x9c` | per-slot valid byte |
| `0x01c465bd` | producer lock |
| `0x01c465be` | loaded count |
| `0x01c465bf` | state, `2 == ARMED` |
| `0x01c46f20+slot` | Playback Note map |

Exact producer proof:

```text
0x0201e1e8  staging_last = staging+0x9b
0x0201e1ec  playback_note = *staging_last
0x0201e1ee  playback_map[slot] = playback_note
0x0201e1f0  r2 = 0x3f
0x0201e1f2  *staging_last = 0x3f
0x0201e1fa  memcpy(slot, staging, 0x9c)
0x0201e202  slot[0x9b] = 0x3f
0x0201e208  slot.valid = 1
0x0201e218  state = ARMED after slot 15
```

Thus each persistent payload needs only:

```text
155 non-reconstructible voice bytes + 1 Playback Note byte = 156 = 0x9c
```

Sixteen payloads occupy `16 * 0x9c = 0x9c0` bytes distributed over 16 existing record prefixes. The raw record stride remains `0xa3`, and the seven-byte tails remain unchanged.

## 8. Minimum defensible formats

### Option A: exactly 16 records, payload only

Capacity is sufficient. It has no room for a conventional magic, version, sequence, or CRC without using stock tail bytes.

One compact possibility is to use bit 7 of each seven-bit Playback Note byte as 16 distributed integrity bits. That can carry a CRC16 or version-seeded tag while the lower seven bits carry the note. This is physically valid, but it provides only 16 bits of recognition and integrity and cannot preserve the old generation during an interrupted update.

This is the absolute minimum, not the recommended first implementation.

### Option B: 17 records, recommended fastest fail-closed path

Reserve 16 payload prefixes and one manifest prefix. Keep all 17 tails unchanged.

Suggested manifest fields within its `0x9c` prefix:

```text
magic[8]
format_version
commit_state
payload_record_count = 16
stored_voice_bytes = 0x9b
record_base_index
generation/sequence
payload_crc32
header_crc32
reserved-zero bytes
```

Canonical CRC input should include, in slot order:

```text
voice[0x00..0x9a]
playback_note & 0x7f
```

Write order:

1. Build one `0x9c` scratch record per slot. Copy 155 voice bytes and append the Playback Note.
2. Call `0x02004b02(scratch, record_write_address, 0x9c)`.
3. Require return `0x9c`.
4. Read back with `0x02004870` and compare all `0x9c` bytes.
5. Repeat for all 16 payload records.
6. Write the committed manifest last.
7. Read back and validate manifest CRC and the complete payload CRC.
8. Report SAVED only after the final readback succeeds.

If power is lost while payload records are changing, the old manifest CRC no longer matches and boot leaves S1C5 unarmed. This is fail-closed, but the prior generation may be lost.

### Option C: 34 records, A/B retained-generation path

Reserve two independent 17-record groups. Write and verify the inactive group, write its manifest last, then make it the newest valid sequence. Never modify the old valid group until the new group is complete.

Boot validates both manifests and payloads, then chooses the newest unambiguous valid sequence. This is the narrowest record-reuse design that preserves the previous set across an interrupted update without relying on unproven stock flags or selection bytes.

## 9. Safe restore after boot

### Hook point

The narrow exact lifecycle point is the call at `0x02005f9c`:

```text
0x02005f9c  call 0x02005660
0x02005fa0  ldw r0,r6,#0x15c
0x02005fa4  call 0x020057e0
```

A future wrapper can replace only the call target at `0x02005f9c` and implement:

```c
void stock_loader_then_s1c5_restore(void) {
    loader_02005660();
    restore_reserved_s1c5_records();
}
```

It must preserve the PI32 callee-saved registers, especially `r6`, because the existing continuation uses `r6` immediately at `0x02005fa0`.

This point is after:

- store open and `g+0x160/g+0x164` publication
- flag read
- selection read/default repair
- stock current-Patch load

It is before the immediate post-loader helper call. It avoids an early hook and does not invoke the global stock loader repeatedly to materialize custom slots.

### Fastest read source

At boot, the fastest proven source is the same direct view stock loader uses:

```text
*(g+0x164) + 0x4000 + index*0xa3
```

This avoids 16 separate storage reads. Validate the manifest and CRC over the direct prefixes, then copy only accepted data to S1C5 RAM.

For runtime write verification, use `0x02004870` from `*(g+0x160)` because coherence of the already-open `g+0x164` view after writes is not established.

### Publication order

The restore wrapper must use the current S1C5 fail-closed order:

1. Acquire or exclude through lock `0x01c465bd`. If lock acquisition fails, return with custom state hidden.
2. Set `state=0` at `0x01c465bf` before inspecting persistent data.
3. Set loaded count at `0x01c465be` to zero.
4. Clear all 16 valid bytes at `0x01c46520 + slot*0xa0 + 0x9c`.
5. Validate manifest magic, version, bounds, record range, committed state, sequence, and CRC.
6. For each slot, copy raw bytes `0x00..0x9a` to the resident voice.
7. Load `raw[0x9b] & 0x7f` to `0x01c46f20+slot`.
8. Write resident `voice[0x9b] = 0x3f`.
9. Execute `csync`, then set that slot valid to `1`.
10. After all 16 records validate, set loaded count to `16`.
11. Execute `csync`, then set state to `2` last.
12. Clear the lock with ordering barriers.

On any missing, corrupt, out-of-range, short, or ambiguous data:

- leave `state != 2`
- keep or clear valid bytes
- release the lock
- return to stock boot

The current selector checks `state == 2` before checking slot validity or reading the Playback Note map. Therefore failure leaves Note On and Note Off on the existing stock fallback path.

## 10. What is and is not proven

### Proven

- Exact official and S1C5 storage initialization, loader, and wrapper windows are unchanged.
- Exact `+0x160` write/read-wrapper view and `+0x164` direct loader view.
- Exact stock layout through `+0x9209`.
- Exact 128-record `0xa3` arithmetic.
- Exact official SAVE data flow and ignored returns.
- Exact current S1C5 SAVE disable bytes.
- Exact S1C5 byte-`0x9b` Playback Note extraction and `0x3f` reconstruction.
- Physical capacity of 16 raw prefixes for 16 patches plus 16 Playback Notes.
- All seven stock tail bytes have consumers.

### Not proven

- Any record is factory-unused or user-disposable.
- A record reservation policy acceptable to the product/UI.
- Lower primitive power-loss atomicity.
- Coherence of `*(g+0x164)` immediately after a runtime write.
- Executable placement for the commit and boot-restore routines. Current S1C5 already occupies the `0x0201e13e..0x0201e254` cave.
- Live behavior of a persistence implementation. No implementation or device action occurred here.

## Final storage recommendation

1. Reserve explicit stock raw record indices. Do not claim they are free.
2. Use only each reserved record's first `0x9c` bytes.
3. Encode 155 voice bytes plus one Playback Note. Never touch the seven-byte tail.
4. Leave packed records, flags, and selection unchanged.
5. Use 17 records for the fastest fail-closed implementation, or 34 for retained-generation A/B.
6. Commit through a separate guarded host command using `0x02004b02`, full-length return checks, `0x02004870` readback, and CRC.
7. Restore through a wrapper at `0x02005f9c`, after stock loader execution, with S1C5 state published last.
8. If all 128 raw records must remain byte-identical, stop. The narrowest alternative is a proven custom `0x1000` domain, or `0x2000` for A/B.
