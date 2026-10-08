# R03 SysEx RAM reservation audit for official v15

Scope: exact official v15 only. This pass reads the official v15 app/package, v15 Quarkslab/Kagaimiq listings, R03 requirements, prior SysEx-staging evidence, RAM-ownership evidence, and persistence-direction evidence. It performs no patching, flashing, device access, or v12-derived reasoning.

## Verdict

**BLOCK.** The `0x01c37030` containing object cannot provide an explicitly reserved `0xa4` slice at `0x01c37fd0..0x01c38074` by merely patching known bounds/destinations. The exact SysEx/default-load staging subobject is the contiguous 4 KiB range `0x01c37fd0..0x01c38fd0`, and the proposed slice is inside that live stock range.

A reservation would need a new proven 4 KiB replacement staging/bank-image buffer, or split-copy/checksum/storage logic that preserves all stock paths. No such destination allocation, executable body, or concurrency proof is present in the official-v15 static evidence. Therefore this is not a PASSable R03 owned-RAM candidate.

## SHA gates

- app: `36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055`
- official package: `f7f1831cd7c9ad8b4831b6e71ea0bdbcdff9ae4c4077276b3c965511bf4d4fff`
- Quarkslab exhaustive listing: `f51e384f5f0efc415f321bbfbbe15d051301953338191282872807dcf8683347`
- Kagaimiq exhaustive listing: `814510c15ba600c7420026204c5f4121bce6a5d074422cc20204755d3280e013`

## Exact bounds

| object/range | exact bound | basis | decision |
| --- | --- | --- | --- |
| Containing direct base | `0x01c37030` | Five decoded code references in both listings plus one raw data occurrence. It is shared by queue, init/audio, SysEx staging, and UI/default-load storage paths. | No closed allocation end proven for the containing object. Not ownable by absence-of-xrefs. |
| Queue subobject | `0x01c37030..0x01c37430` under stock 0x100-word index invariant | `0x0201bed8` and `0x0201c2e4` store words at `base+idx*4`; `0x020274c2` consumes from the same lower queue. | Does not overlap the proposed slice, but proves the base is shared with USB/task queue state. |
| SysEx/default-load staging subobject | `0x01c37fd0..0x01c38fd0` | `0x01c37030+0xfa0`; large bulk final length is `0x1002`, checksum loop is `0x1000`, default-load writes the same `0x1000` source to storage. | Overlaps and owns the whole proposed slice. |
| Proposed R03 slice | `0x01c37fd0..0x01c38074` (`0xa4` bytes) | First `0xa4` bytes of the staging subobject. | BLOCK. It is not free and cannot host durable valid/generation metadata. |

Boot zeroing of `0x01c099d4..0x01c4651c` initializes the broad RAM span, but zero-on-boot is not an allocation owner. It does not reserve a subrange for R03.

## Complete decoded writer/consumer set for `0x01c37030` direct-code users

Both exhaustive listings decode the same direct-code references: `0x02008b7e`, `0x0201bed2`, `0x0201c2de`, `0x0201e3fc`, `0x02025528`. The app also contains one raw data occurrence at `0x0208fe66`, not a decoded writer row.

| id | mode | bound/formula | proposed-slice overlap |
| --- | --- | --- | --- |
| `audio_init_dynamic_blocks` | writer | 0x01c37030 + r4*0x3c8 + 0xb10 + *(0x01c33260+0x390+r4*4) for 0x1a words, plus byte fields at +0xb8f and pointer fields at +0xb78/+0x2df*4 | `not statically closed; dynamic r4/offset owner prevents free-slice proof` |
| `usb_task_queue_writer_a` | writer | 0x01c37030 + 4*(uint16_t)(0x01c33260+0x9e), capped/incremented as a 0x100-word queue in decoded rows; bounded object 0x01c37030..0x01c37430 exclusive if the stock index invariant holds | `False` |
| `usb_task_queue_writer_b` | writer | same 0x100-word queue as writer_a: 0x01c37030..0x01c37430 exclusive under stock index invariant | `False` |
| `complete_single_voice_sysex` | writer_then_packer_consumer | 0x01c37fd0..0x01c3806d for accepted 0xa3-byte host message, first 0x9c bytes consumed by packer; terminal F7 lands at +0x9c | `True` |
| `segmented_single_voice_sysex` | writer_then_packer_consumer | 0x01c37fd0 + accumulated offset, final accepts offset+len == 0x9e and calls packer on 0x01c37fd0 | `True` |
| `large_bulk_sysex_stage` | writer_and_checksum_reader | contiguous 0x1000 bytes: 0x01c37fd0..0x01c38fd0; final accumulated length compare is 0x1002 and checksum loop count is 0x1000 | `True` |
| `default_load_selected_bank_block` | stock_storage_consumer_of_stage | 0x02004b02 source 0x01c37fd0..0x01c38fd0, len 0x1000, destination *(0x01c33260+0x160)+bank*0x1000 | `True` |
| `stock_save_current_path` | stock_save_packer_caller_not_stage_writer | SAVE writes 0x01c33260+0x1a14 for 0xa3 to storage and calls 0x0201e13e(current); it does not use 0x01c37fd0 but constrains hook strategy | `False` |

`writer_set.tsv` contains the same inventory in machine-readable form. `evidence.json` contains the supporting rows for each item.

## Required patches if attempting reservation

A valid reservation cannot be claimed by only proving that a future patch would avoid the first `0xa4` bytes. At minimum, every stock producer/consumer below would need a destination or bound rewrite, plus a proven replacement allocation and code budget:

| address | current row | why relevant |
| --- | --- | --- |
| `0x0201e448` | `add r8,r6,#0xfa0` | complete one-shot single-voice staging destination |
| `0x0201e488` | `add r6,r6,#0xfa0` | segmented-final single-voice staging base |
| `0x0201e4c2` | `add r0,r0,#0xfa0` | large/final bulk staging destination plus accumulated offset |
| `0x0201e4d6` | `movz r1,#0xfa0` | large bulk checksum/read loop base offset |
| `0x0201e524` | `add r0,r0,#0xfa0` | large/intermediate chunk staging destination |
| `0x0201e580` | `add r0,r6,#0xfa0` | initial segmented single-voice staging destination |
| `0x02025564` | `add r0,r10,#0xfa0` | default-load selected-bank 0x1000 source buffer |
| `0x02025568` | `movz r2,#0x1000` | default-load selected-bank source length if attempting to shrink/split |
| `0x0201e4b8` | `movz r1,#0x1002` | large bulk final accumulated length if attempting to shrink/split |
| `0x0201e4ec` | `jne r0,#0x1000` | large bulk checksum loop count if attempting to shrink/split |
| `0x0201e51c` | `ja r5,#0xfff` | large bulk maximum accumulated byte bound if attempting to shrink/split |

This list is not a safe patch plan. It is the minimum static set proving why the reservation is currently BLOCKED. The lower queue refs at `0x0201bed2/0x0201c2de/0x020274c2` also show that a blind global change of `0x01c37030` would corrupt unrelated USB/task queue state.

## Scenario review

- One-shot single voice: accepted `F0 43 00 00 01 1B + 0x9c + F7` writes `len-6 = 0x9d` bytes at `0x01c37fd0`; the packer consumes the first `0x9c`. This directly overlaps `0x01c37fd0..0x01c3806d`.
- Segmented single voice: initial and final paths use the same `+0xfa0` base, accumulated length state at `obj+0x9c`, and final packer call. It overlaps the same proposed slice.
- Larger bulk: official path accepts/checksums a contiguous `0x1000` bytes at `0x01c37fd0..0x01c38fd0`. The proposed `0xa4` slice is at the start of that object, so shrink/split would change stock large-bulk semantics unless all length, checksum, and copy logic is redesigned.
- USB/task concurrency: decoded queue producers use lock/csync around the lower `0x01c37030` queue, but no lock, valid bit, or generation field protects the staging area. Later supported SysEx can rewrite the proposed slice between Note On and Note Off.
- Stock SAVE/default-load: SAVE itself uses current snapshot and calls `0x0201e13e`, so global packer hooks would affect SAVE. The default-load path consumes `0x01c37fd0..0x01c38fd0` as a `0x1000` RAM source for storage at `0x0202556e`; reservation would corrupt or require relocating that bank-image source. Decoded SAVE/storage paths ignore the `0/len` return before marking saved in the reviewed evidence, so error-prone split writes are unacceptable without deeper proof.

## PASS/BLOCK matrix

| Requirement | Result | Evidence |
| --- | --- | --- |
| Exact start/end/alignment for proposed slice | PASS | `0x01c37fd0..0x01c38074`, 16-byte aligned start. |
| Exact owning allocation for slice | BLOCK | The exact stock staging allocation is larger: `0x01c37fd0..0x01c38fd0`. The proposed slice is owned by stock SysEx/default-load staging. |
| Complete known static writer/consumer set | PASS for decoded direct-code refs | Five decoded base refs plus raw xref inventory are recorded. Dynamic init formulas are not closed enough to prove free space. |
| One-shot and segmented safety | BLOCK | Both write/use the proposed slice. |
| Larger bulk safety | BLOCK | Contiguous 4 KiB stage requires the slice. |
| USB/task concurrency | BLOCK | No valid/generation/lock for the proposed stage slice; lower queue shows unrelated shared ownership of same base. |
| Stock SAVE/default-load behavior | BLOCK | Default-load consumes the same 4 KiB source; packer hooks affect SAVE. |
| Explicit reservation by patching all bounds/destinations | BLOCK | Requires relocation/splitting of stock 4 KiB staging, checksum, default-load storage source, and a new proven allocation. Not present. |

## Validation

| check | status | detail |
| --- | --- | --- |
| official-v15-app-sha256 | PASS | `36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055` |
| official-v15-package-sha256 | PASS | `f7f1831cd7c9ad8b4831b6e71ea0bdbcdff9ae4c4077276b3c965511bf4d4fff` |
| quarkslab-listing-sha256 | PASS | `f51e384f5f0efc415f321bbfbbe15d051301953338191282872807dcf8683347` |
| kagaimiq-listing-sha256 | PASS | `814510c15ba600c7420026204c5f4121bce6a5d074422cc20204755d3280e013` |
| stage-arithmetic | PASS | `0x01c37030+0xfa0=0x01c37fd0` |
| stage-bound | PASS | `0x01c37fd0+0x1000=0x01c38fd0` |
| proposed-slice-bound | PASS | `0x01c37fd0+0xa4=0x01c38074` |
| proposed-inside-stage | PASS | `0x01c37fd0..0x01c38074 inside 0x01c37fd0..0x01c38fd0` |
| raw-base-xrefs | PASS | `{"value": "0x01c37030", "count": 6, "refs": ["0x02008b80", "0x0201bed4", "0x0201c2e0", "0x0201e3fe", "0x0202552a", "0x0208fe66"]}` |
| no-direct-stage-immediate | PASS | `{"value": "0x01c37fd0", "count": 0, "refs": []}` |
| quark-decoded-base-refs | PASS | `["0x02008b7e", "0x0201bed2", "0x0201c2de", "0x0201e3fc", "0x02025528"]` |
| kagaimiq-decoded-base-refs | PASS | `["0x02008b7e", "0x0201bed2", "0x0201c2de", "0x0201e3fc", "0x02025528"]` |
| overlap-set-complete-for-hard-blockers | PASS | `["complete_single_voice_sysex", "default_load_selected_bank_block", "large_bulk_sysex_stage", "segmented_single_voice_sysex"]` |
| decision-block | PASS | `BLOCK` |
| v12-excluded | PASS | `["build/v15-official-app.bin", "build/SMK-37_Pro_015.fwsc", "baselines/v15/analysis/quarkslab/results/quarkslab-exhaustive-listing.tsv.gz", "baselines/v15/analysis/quarkslab/results/kagaimiq-patched-exhaustive-listing.tsv.gz", "baselines/v15/analysis/r03-owned-ram/requirements.md", "baselines/v15/analysis/channel-separation-reanalysis/sysex-staging/report.md", "baselines/v15/analysis/channel-separation-reanalysis/sysex-staging/sysex_staging_trace.json", "baselines/v15/analysis/r03-owned-ram/ram-ownership/report.md", "baselines/v15/analysis/ui-preflash/followup/persistence-direction.md"]` |

## Reproduce

```sh
python3 baselines/v15/analysis/r03-owned-ram/sysex-reservation/analyze_sysex_reservation.py
cd baselines/v15/analysis/r03-owned-ram/sysex-reservation
shasum -a 256 -c SHA256SUMS
```

Generated files: `analyze_sysex_reservation.py`, `evidence.json`, `writer_set.tsv`, `validation.txt`, `report.md`, `SHA256SUMS`.
