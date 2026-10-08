# Official v15-only persistence options for H2 Ch10 patch sets

## Scope and answer

This is an offline analysis of the exact official v15 application/package and the existing H2 checkpoint. It performs no firmware patch, OTA, flash operation, or device access.

**Current decision:** keep the first per-note Ch10 patch set volatile. H2 has live-proven one owned `0x9c` runtime voice, but official-v15 evidence does not yet prove a free persistent allocation, the runtime identity of `*(0x01c33260+0x160)`, a safe boot hook after storage initialization, or power-loss behavior. The official layout has large nominal VM and USRFLASH regions, but the **safe unallocated budget is currently 0 bytes** until their allocation maps are closed.

The first persistence-capable design should use a separate, versioned, checked record. It must not change the stock `0xa3` Patch format, reuse stock SAVE metadata, append into the app area, or write storage from the MIDI Note path.

## Evidence basis

SHA gates reproduced by `validate.py`:

| Artifact | SHA-256 |
| --- | --- |
| official v15 app | `36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055` |
| official v15 FWSC | `f7f1831cd7c9ad8b4831b6e71ea0bdbcdff9ae4c4077276b3c965511bf4d4fff` |
| H2 app | `d71f6c58b4fade00aebb8a0b7d9d024641c37c41ca4bbf3e525fd28773087f59` |
| official v15 exhaustive listing | `f51e384f5f0efc415f321bbfbbe15d051301953338191282872807dcf8683347` |

Primary repository evidence:

- `baselines/v15/analysis/ui-preflash/state-persistence/`
- `baselines/v15/analysis/ui-preflash/followup/persistence-direction.*`
- `baselines/v15/analysis/channel-separation-reanalysis/runtime-source/`
- `baselines/v15/analysis/channel-separation-reanalysis/factory-loader/`
- `baselines/v15/analysis/channel-separation-reanalysis/post-r02-roadmap.md`
- `baselines/v15/analysis/flash-candidates/H2-owned-source-corrected-fallback/`
- `baselines/v15/analysis/r03-owned-ram/app-tail-placement/`
- `tools/smk37_v15_app_patch.py`

`evidence.json` binds these sources by SHA-256 and records all computed layouts and decisions.

## What H2 establishes, and what it does not

H2 live validation established:

- accepted product data can publish an exact `0x9c` or 156-byte voice into owned RAM at `0x01c46520`
- Ch10 Note On and Note Off can consume that same owned source safely
- the tested Mooger #1 voice sounded correctly and released normally
- stock fallback is safe after restoring the original memcpy destination

H2 does **not** establish:

- a 16-slot or 128-note map
- source generation and active-note identity during slot replacement
- reboot persistence
- a persistent allocation
- stock Patch SAVE compatibility
- power-loss or short-write recovery

H2 also deliberately disables stock SAVE before its first persistent write. It is a safe volatile checkpoint, not a persistence base that can simply call the old SAVE code.

## Official flash and JLFS layout

The official FWSC UFW entry `flash.bin` is at UFW payload offset `0x400` and is exactly `0x9c000` bytes. The JLFS directory is stored in the application-area header and uses offsets relative to physical flash base `0x4000`.

| JLFS entry | header | entry-relative offset | physical start | physical end | size |
| --- | ---: | ---: | ---: | ---: | ---: |
| `app.bin` | `0x04020` | `0x00120` | `0x04120` | `0x9ab54` | 617,012 |
| `cfg_tool.bin` | `0x04040` | `0x96b54` | `0x9ab54` | `0x9acd3` | 383 |
| `VM` | `0x04060` | `0x9c000` | `0xa0000` | `0xc4000` | 147,456 or `0x24000` |
| `PRCT` | `0x04080` | `0x00000` | `0x04000` | `0xa0000` | 638,976 or `0x9c000` |
| `BTIF` | `0x040a0` | `0xc0000` | `0xc4000` | `0xc5000` | 4,096 |
| `USRTRIM` | `0x040c0` | `0xc1000` | `0xc5000` | `0xc6000` | 4,096 |
| `USRFLASH` | `0x040e0` | `0xc2000` | `0xc6000` | `0xef000` | 167,936 or `0x29000` |
| `USR` | `0x04100` | `0xf4000` | `0xf8000` | `0x102000` | 40,960 |

Consequences:

1. `app.bin` ends at `0x9ab54`.
2. The entire 383-byte gap to `app_area_end` at `0x9acd3` is `cfg_tool.bin`.
3. JLFS-preserving append capacity is **0 bytes**.
4. The UFW `flash.bin` ends at `0x9c000`, before physical VM at `0xa0000` and USRFLASH at `0xc6000`.
5. Runtime data written to a proven allocation in VM or USRFLASH would not require changing the FWSC `flash.bin` entry. However, the directory proves region capacity only. It does not prove free subranges or which region backs the Patch store.
6. The separate UFW archive entry named `USR` is not, by name alone, proof of a safe preseed path for live JLFS `USR`, `VM`, or `USRFLASH` contents.

## Official stock Patch store accounting

Official code addresses the stock patch store through `*(0x01c33260+0x160)`.

| Relative range | Bytes | Official meaning |
| --- | ---: | --- |
| `+0x0000..+0x4000` | 16,384 | four packed banks, `4 * 0x1000` |
| `+0x4000..+0x9180` | 20,864 | 128 records, `4 * 32 * 0xa3` |
| `+0x9180..+0x9200` | 128 | SAVE/SAVED flag table |
| `+0x9200..+0x9209` | 9 | selected bank/preset block |

The arithmetic closes exactly:

```text
0x4000 + 128 * 0xa3 = 0x9180
0x9180 + 0x80       = 0x9200
0x9200 + 0x09       = 0x9209
```

Known stock extent is `0x9209`, or 37,385 bytes.

If this store began at the start of VM, the arithmetic remainder would be 110,071 bytes or `0x1adf7`. If it began at the start of USRFLASH, the remainder would be 130,551 bytes or `0x1fdf7`. These are **apparent headroom figures only**. They are not safe budgets because none of these facts is proven:

- `+0x160` equals the start of VM or USRFLASH
- the runtime storage bound covers the full JLFS region
- bytes after `+0x9209` are unallocated
- stock journal, allocator, metadata, or another subsystem does not use the remainder

Therefore the currently safe custom allocation is **0 bytes**.

## Patch-set size and budget

The physical Pad target is 16 notes. A general MIDI note map has 128 entries. Both budgets are included to prevent a 16-slot design from silently becoming a 128-note commitment.

| Representation | 16 slots | 128 notes | Assessment |
| --- | ---: | ---: | --- |
| bank/preset references, 2 bytes each | 32 | 256 | smallest, but deterministic materialization and loader side effects are unproven |
| exact H2 runtime voices, `0x9c` each | 2,496 or `0x9c0` | 19,968 or `0x4e00` | preferred first payload after allocation proof |
| full stock records, `0xa3` each | 2,608 or `0xa30` | 20,864 or `0x5180` | preserve stock schema, do not repurpose its existing library |

An example 16-slot custom record with a 64-byte header is 2,560 bytes or `0xa00`. It fits inside one 4 KiB domain. Two 4 KiB A/B copies consume 8,192 bytes.

An equivalent 128-note runtime record is 20,032 bytes or `0x4e40` before domain padding. It needs five 4 KiB domains per copy and 40,960 bytes for two rounded A/B copies.

The 16-slot payload is the correct first persistence target. A full 128-note set should wait until storage ownership and multi-domain atomicity are proven.

## What can be persisted safely

### Safe now

1. **No custom persistence.** Load one or 16 exact runtime voices through a guarded host protocol into owned RAM.
2. **Use stock records as a read-only patch library.** A volatile note-to-record map can point at existing bank/preset content, provided all runtime voices are materialized outside the Note path and validated acoustically.
3. **Keep stock storage bytes unchanged.** This preserves official data and makes firmware rollback independent from custom persistent-state cleanup.

### Safe only after additional proof

A separate custom record in a proven VM or USRFLASH allocation can be safe after all of these gates pass:

- exact backing region for `+0x160` or another official storage handle
- runtime total bound from `0x01c454b0+0x18`
- complete allocation and journal map
- non-overlapping 4 KiB-aligned A/B ranges
- post-storage boot hook
- read, write, short-write, corrupt-record, reboot, and interruption behavior

The recommended first persistent payload is 16 exact `0x9c` runtime voices, plus format metadata and integrity fields. This carries forward the H2-proven object shape and avoids inventing a modified stock Patch record.

### Blocked

- custom bytes after stock `+0x9209` without an allocation map
- repurposing stock `0xa3` records, flag bytes, or selection bytes as custom metadata
- changing the stock `0xa3` record schema
- appending after `app.bin`
- overwriting `cfg_tool.bin`
- extending `app.bin` or `flash.bin`
- pre-seeding VM or USRFLASH by assuming the FWSC UFW entries update those live regions
- storing app/text literals as mutable persistent voice state

## Boot load lifecycle

No custom boot-load lifecycle is proven today. The existing `0x02005f9c` path calls stock factory loader `0x02005660` and then helper `0x020057e0`. This proves a stock current-patch initialization path, not a safe custom persistence hook.

A safe future lifecycle is:

1. Let stock storage, UI, and Patch initialization finish unchanged.
2. At a separately proven post-storage hook, use read wrapper `0x02004870` to read only A/B headers.
3. Reject records unless magic, format version, header length, payload length, slot count, committed state, sequence, and CRC are all valid.
4. Select the newest unambiguous committed copy.
5. Read into scratch or inactive owned RAM.
6. Revalidate the complete payload.
7. Publish `valid` and `generation` last.
8. Keep each active note bound to the same immutable slot and generation through Note Off.
9. Perform no loader call, storage I/O, bank switch, or global UI-state change in the MIDI Note path.
10. On missing, short, corrupt, or ambiguous data, leave custom `valid` clear and fall back to stock or explicitly host-loaded volatile data.

A reference-only format is not automatically safer at boot. Materializing references by repeatedly changing the global selected bank/preset and calling `0x02005660` would execute global loader/helper/UI side effects. That is prohibited until a side-effect-free materializer is independently proven.

## SAVE interception and failure behavior

### Official SAVE

Official `0x02026d6c` performs:

1. gate on `+0x1ec == 0` and non-`0xff` state
2. write current `0xa3` snapshot to `+0x4000+(bank*32+preset)*0xa3`
3. call stock packer `0x0201e13e` to update the packed `0x80` bank record
4. set the selected `+0x129c` saved flag
5. flush the `0x80` flag table to `+0x9180`
6. exit through the stock local cleanup

`0x02004b02` is a bounded RAM-to-storage wrapper. It returns the requested length only on full success and returns 0 otherwise. The stock SAVE path ignores both write returns and can mark state saved after a failed transfer. A custom design must not copy this behavior.

### H2 SAVE block

| Site | official bytes | H2 bytes | Meaning |
| --- | --- | --- | --- |
| `0x02026da6` | `beeaacee` | `04960000` | official first write call replaced by branch to local exit |
| `0x02026dac` | `bfeac7b9` | `00000000` | later stock packer call neutralized |

H2 replaces the stock packer body with owned-source producer/consumer code. Therefore a production persistence build must not just remove the first branch. Doing so would reach a neutralized or replaced stock lifecycle.

Required order:

1. relocate H2 producer/consumer code to separately proven code space
2. restore the official `0x0201e13e` packer body
3. restore official stock SAVE callsites and validate stock Patch SAVE independently
4. add a separate custom commit command, initially through the guarded host protocol
5. integrate the physical SAVE UI only after a proven Drum Set page/context dispatcher exists
6. display SAVED only after full-length write, readback, CRC, and commit verification

## Custom record integrity and atomicity

Recommended v1 header fields:

- magic
- format version
- header length
- payload length
- slot count
- sequence number
- payload kind
- payload CRC16 or CRC32
- header CRC
- commit state

For the 16-slot set:

- reserve two independent 4 KiB domains
- write the inactive payload first
- write a provisional header without committed state
- read back and verify the complete record
- write committed state last
- reread the header
- switch the active sequence only after verification
- retain the old valid copy until the new copy is fully committed

On short write, wrapper return 0, CRC mismatch, torn header, duplicate/ambiguous sequence, or readback mismatch, keep the previous valid copy and do not report SAVED.

The exact erase/open/commit meaning of `0x02004a54` modes and the lower request primitive `0x02063260` remains unproven. The A/B design is a requirement, not a claim that power-loss safety already exists.

## CRC and repack implications

### Runtime persistent write

Writing a proven, already allocated VM or USRFLASH range through official runtime wrappers does not change:

- `app.bin`
- app-area JLFS directory metadata
- SFC-encrypted application bytes
- UFW `flash.bin` data CRC
- UFW entry-list/header CRCs
- FWSC framing

It still requires custom record CRC and commit validation.

### Fixed-size application change

Any future firmware implementation based on the current validated fixed-layout packer must:

1. update `app.bin` JLFS data CRC and header CRC
2. update `app_area_head` data CRC and header CRC
3. SFC re-encrypt the fixed app area
4. update UFW `flash.bin` data CRC
5. update encrypted UFW entry-list CRC and UFW header CRC
6. repack FWSC at unchanged total size while preserving metadata slots

### Layout change

Changing any of these is blocked by current tooling and evidence:

- `app.bin` size
- app-area end
- VM or USRFLASH offset/size
- UFW `flash.bin` size
- named JLFS file placement

Such a change is not a normal CRC refresh. It changes loader-visible layout and rollback boundaries.

## Rollback boundaries

Firmware and persistent data are separate rollback domains.

### Firmware domain

H2 changes sectors:

- `0x04000`
- `0x20000`
- `0x22000`
- `0x2a000`
- `0x62000`

A future persistence implementation needs its own exact changed-sector inventory, exact target hashes, deterministic package gate, independent review, and target-specific rollback bundle.

### Persistent-data domain

Official UFW `flash.bin` ends at `0x9c000`, before VM and USRFLASH. Restoring official app sectors does not prove that a custom persistent record has been erased.

Safe rollback policy:

- official firmware must ignore the custom namespace after app rollback
- prefer version rejection or a narrow, separately guarded tombstone
- never erase all VM or USRFLASH without a complete allocation map
- do not make rollback depend on rewriting stock Patch records
- if a custom build ever modifies stock records, restore those data separately from app sectors

The cleanest boundary is a custom record that stock firmware never references and a custom firmware version that refuses unknown/corrupt records.

## Staged path

| Phase | Persistence | Required gate |
| --- | --- | --- |
| P0 H2 single voice | none | already H2 LIVE PASS for one owned voice |
| P1 volatile 16-slot set | none | note map, validity, generation, active-note identity, overlap, repeated-hit, and release stress |
| P2 read-only storage probe | headers only | prove storage base, runtime bound, allocation map, post-storage hook, and no stock overlap |
| P3 guarded host commit | separate A/B custom record | short-write, corrupt-record, readback, reboot, and interruption validation |
| P4 boot auto-load | read custom record | valid-last publication and safe fallback on every invalid state |
| P5 UI SAVE integration | custom commit only in Drum Set context | restore stock packer/SAVE and prove UI event/context dispatch plus truthful SAVED state |

This sequence first avoids persistence, proves the 16-slot runtime behavior, then adds read-only boot discovery, and only then enables writes.

## Final recommendation

1. Build the volatile 16-slot set next.
2. Keep H2 SAVE blocked during that phase.
3. Do not claim any bytes after stock `+0x9209` as free.
4. Prove the runtime storage region, full allocation map, and post-storage hook before assigning an address.
5. Use two 4 KiB custom records carrying 16 exact `0x9c` voices plus a versioned header.
6. Use a separate guarded host commit before UI SAVE integration.
7. Restore and independently validate stock packer/SAVE before allowing stock Patch persistence in the same firmware.
8. Treat app rollback and persistent-record rollback as separate operations.

## Reproduction

From repository root:

```sh
python3 baselines/v15/analysis/patch-set-ui/persistence/validate.py
shasum -a 256 -c baselines/v15/analysis/patch-set-ui/persistence/SHA256SUMS
```

Expected validator result: `RESULT PASS`, currently with 33 checks.
