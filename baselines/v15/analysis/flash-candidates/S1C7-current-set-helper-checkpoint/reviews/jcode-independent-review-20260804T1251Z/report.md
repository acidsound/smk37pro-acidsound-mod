# Independent review of S1-C7 current-set helper checkpoint

Date: 2026-08-04T12:51Z  
Reviewer: Jcode  
Target commit: `d83b0b1fb2ad6636bc90b9d5d03afb15d7682e5d` (`d83b0b1`)  
Scope: offline review only. No device, USB/MIDI live transport, flash, OTA upload, or reset was used.

## Decision

**PASS for gated live use as the S1-C7 current-set helper checkpoint.**

This is not a full normal-firmware persistence writer. It is safe to describe as a checkpoint that restores exact host-seeded current-set prefixes when the resident RAM slot is not ARMED. Treat any claim of autonomous future WebMIDI persistence as **BLOCKED** until a reviewed writer with `0x02004b02` full-length checks, `0x02004870` readback, manifest/commit-last semantics, failure reporting, and rollback exists.

## Offline rebuild and validators

Executed from an isolated archive of exact commit `d83b0b1`, not the dirty working tree.

| Check | Result |
|---|---|
| `make clean && make all && build/smk37-fw self-test` | PASS, `self-test: ok` |
| `python3 validate.py` in S1-C7 candidate | PASS |
| full `python3 build_s1c7_current_set_helper_checkpoint.py` rebuild | PASS |
| rebuilt `app.bin` vs committed artifact | byte-identical PASS |
| rebuilt FWSC vs committed artifact | byte-identical PASS |
| rebuilt `exact_ota.c` and JSON manifests | byte-identical PASS |
| compile `exact_ota.c` with support sources and libusb flags | PASS |
| `exact_ota check` candidate FWSC | PASS |
| `exact_ota check` S1C5 and official v15 controls | rejected PASS |
| `python3 validate_rollback.py` default mode | PASS, no device path opened |
| `prepare_s1c5_raw_prefix_seed.py self-test` | PASS, synthetic regular-file readback and rollback |

Key rebuilt hashes:

```text
71cfc1fcbeecd1a9277f88272be6b122a96f33fbd741d7486c670ffab6e58646  app.bin
3dfb7e23debbd3a3055945b121991cf7a58b5f1cb59ff98f6dfba7dd084f2593  SMK37Pro-v15-S1C7-current-set-helper-checkpoint.fwsc
2c986e11ddfa8ed7e1e49e5faf8e1ef2014083c5416be24372aea1103e39ed31  exact_ota.c
d56abbc45eacfc667c0a13af4e78fc161e4f8864eb75f63937cede09cb8fe814  app-manifest.json
c414c106d356527a7981afc2c1cd5e122952d6b0fd038d48c58a0e95acbb22ee  package-manifest.json
24b3c0c9cb5fc5546c02b16f6e28bd9005d189c8401d3ccb32b71b1f10f90529  evidence.json
```

## Selector, helper, calls, and SAVE skip

Independent byte checks against `app.bin` passed:

| Item | Evidence |
|---|---|
| selector window | `0x0201e13e..0x0201e196`, SHA-256 `b77f2787874ad37d724e1c6305e74f97c8a6eb9fe6b51627c8fce35dd257daeb` |
| producer window | `0x0201e196..0x0201e254`, SHA-256 `53bc57acd7e787320400d0d945ec6b3f2e59f2074ae81c9053eb2c11f72560d4`, byte-identical to S1C5 |
| helper window | `0x02026d80..0x02026dd4`, SHA-256 `e9ea13c277736c000e5b7f275f97d319b725b2376e9ac15aac97209a8b0f4396` |
| SAVE UI skip | bytes `04ac00160016` at `0x02026d7a..0x02026d80`, `goto 0x02026dd4` plus padding |
| selector stock path call | `0x0201e186 -> 0x02026db2` |
| selector persistent fallback call | `0x0201e18c -> 0x02026d80` |
| helper read wrapper call | `0x02026d92 -> 0x02004870` |
| helper stock copy call | `0x02026db4 -> 0x02048cce` |
| read failure fallback | `0x02026d9c` restores `r1` from `r7`, then `0x02026d9e -> 0x02026db2` stock copy |
| helper returns | both persistent and stock-copy exits use `pop {pc,r9..r4}` |

Selector behavior matches the checkpoint contract: non-Ch10, out-of-pad-range, ARMED+valid RAM slots use the original stock/resident copy path. Not-ARMED or invalid RAM slots call the persistent helper to read exact host-seeded raw prefixes.

## `0x02004870` ABI and failure fallback

The referenced storage evidence defines:

```c
uint32_t read_02004870(void *ram_destination /* r0 */, uint32_t storage /* r1 */, uint32_t length /* r2 */);
```

Return is requested length on complete success and `0` on short or failed inner result. Exact rows at `0x02004870` save requested length in `r4`, call `0x020047d8`, zero `r4` if `r0 != r4`, then return `r0 = r4`.

S1-C7 calls it with `r0=destination prefix`, `r1=0x7d20 + slot*0xa3`, `r2=0x9c`. The helper accepts nonzero as full success, which is consistent with the wrapper's all-or-zero return contract. On zero, it restores the original source pointer and performs stock copy, so failed/short persistent reads fail closed to known stock behavior rather than leaving a partial prefix as trusted state.

## Producer identity, segmented support, and reset scope

S1-C7 preserves `0x0201e196..0x0201e254` byte-for-byte from S1C5, and S1C5 preserved the producer/segmented-final basis from S1-C4 v3. S1C5 evidence also keeps the segmented product callsite at `0x0201e49c` (`bfeac4fe`) targeting `0x0201e228`. The S1-C7 builder gate rechecks the exact S1C5 app/package hashes before deriving the candidate, so producer identity, Chrome segmented-final support, and reset/no-reset scope are inherited rather than reimplemented.

## Exact OTA and firmware rollback

`exact_ota.c` is exact-hash gated to FWSC SHA-256 `3dfb7e23debbd3a3055945b121991cf7a58b5f1cb59ff98f6dfba7dd084f2593`, product name `SMK-37 Pro`, and version `15`. Offline `check` accepts only the S1-C7 FWSC and rejects S1C5 and official v15 controls. Upload requires the explicit confirmation token `INSTALL-SMK37PRO-V15-S1C7-CURRENT-SET-HELPER-CHECKPOINT-3DFB7E23`.

Firmware rollback artifacts reconstruct official v15 flash for the changed official sectors `0x04000`, `0x20000`, `0x22000`, `0x2a000`, and `0x62000`; default `validate_rollback.py` verified all packaged recovery sector sizes and hashes. The manifest correctly states that package-external host-seeded raw records need target-specific pre-dump rollback validation.

## Host-seeded prefix package audit

S1-C7 itself emits prefix artifacts only. It contains no USB/MIDI/flash writer for host seeding and marks `persistent_storage_write_performed=false`. Prefixes are exactly 16 records, 156 bytes each, for record indices `96..111`, storage offsets `0x7d20..0x86ad`, physical offsets `0x0fbd20..0x0fc6ad`, with tail policy `preserve live raw bytes 0x9c..0xa2; prefix artifacts never include tails`.

The separate guarded host prefix RMW tool, `baselines/v15/analysis/persistence-s2/host-prefix-seed/prepare_s1c5_raw_prefix_seed.py`, does not open device paths or transport APIs. It requires two identical 1 MiB regular-file pre-dumps to build sector artifacts, validates two identical regular-file post/readback dumps before trusting a write, preserves raw tails, and validates rollback by requiring the rollback readback dump to equal the exact pre-dump byte-for-byte. Its synthetic self-test exercised build, readback validation, and rollback validation successfully.

Therefore the host-seeded prefix path cannot mutate a device from the committed scripts. Any external sector writer remains outside this commit and must be gated on exact dual pre-dumps, exact dual post-write readbacks, and exact rollback readback before live use.

## Live-use gates I would require

1. Install only the exact FWSC hash above using the exact OTA wrapper and confirmation token.
2. If host seeding is used, generate write sectors only from two identical target-specific full dumps.
3. After any external host-seed sector write, require two identical full readback dumps matching the manifest-applied expected post image.
4. Verify rollback with a post-rollback full dump equal to the exact pre-dump before declaring recovery complete.
5. Do not represent S1-C7 as future-edit persistence. It restores the seeded current set only until a full writer successor passes review.
