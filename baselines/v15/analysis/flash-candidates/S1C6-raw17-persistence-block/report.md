# S1C6 raw17 persistence successor fit-first result: BLOCK

## Decision

**BLOCK.** No app, FWSC, exact OTA, or rollback bundle is emitted.

The 17-record raw-prefix storage format is feasible as a data format, and an offline encoder is included, but the full requested successor is not defensible today because the on-device selector fallback and especially the persistence writer cannot be placed with exact S1C5 evidence.

## Input gates

- S1C5 app SHA-256: `8b16e9f5a3ec873ac9a51e64f12c5be20156a01a6e8eb65878eed9636179f189`.
- S1C5 FWSC SHA-256: `0a6ac1ae7d4bd34e252eb8f23a4d2c5f39d7454376ade1a3b75ff7d03155ea91`.
- S1C5 live validation SHA-256: `94fc5083ff1ce1061c474eba18a30ad3f10a277f85c84f6cee5a117c2593f152`.
- storage-s2 report SHA-256: `7867925da16e1c85a7c809dffa8127c371e863987b1570fdc1488460f921dbc7`.
- restore-s2 report SHA-256: `c9ce9d4da638790c7e2803a1e85133cedfb8a069204d81ddbdb1bc5eba32b7c1`.

## Reserved raw-prefix format

- Payload records: `96..111`.
- Manifest record: `112`.
- Payload encoding: `raw[i][0x00..0x9a]=voice[0x00..0x9a], raw[i][0x9b]=playback_note; raw tails 0x9c..0xa2 preserved`.
- Tail policy: preserve every raw tail byte `0x9c..0xa2`.
- Volatile WebMIDI rule: `if S1C5 RAM state is ARMED and selected slot valid, keep current RAM selector behavior; persistent fallback is only for not-armed state`.

Offline prefix encoder: `baselines/v15/analysis/flash-candidates/S1C6-raw17-persistence-block/persistence_writer.py`, SHA-256 `945e89457cd54c84d6523897d7804b57de73f8ab24412259de3eeb13a5faaba8`, CRC `0xa400dfab`. It performs no device or persistent-storage write.

## Fit proof

| Item | Bytes | Decision |
|---|---:|---|
| S1C5 owned selector/producer window `0x0201e13e..0x0201e254` | 278 | occupied by current S1C5 selector/producer/tail |
| Disabled SAVE dead slice `0x02026da8..0x02026dd4` | 44 | only standalone placement while preserving SAVE no-write branch |
| Minimal selector tail-call skeleton | 50 | must coexist with producer in owned window |
| Minimal direct raw-prefix fallback helper, no manifest validation | 54 | BLOCK vs SAVE slice |
| Manifest-note fallback variant | 66 | BLOCK vs SAVE slice |
| Single payload write helper, no readback and no manifest | 42 | PASS_BUT_INSUFFICIENT and still insufficient |
| Compact direct-only raw16/no-readback variant | 276 | fits only by dropping segmented/reset/manifest/readback |
| Compact variant with segmented-final stub | +4 over base | overruns by 2 byte(s) |
| Compact variant with slot0 reset floor | +30 over base | overruns by 28 bytes |
| Compact variant with readback floor | +20 over base | overruns by 18 bytes |

A defensible writer additionally needs at least one producer call insertion, full-length return checks, `0x02004870` readback, manifest/CRC construction, commit-last ordering, and failure reporting. Those requirements are not present in the lower bound above.

## Why artifacts are not emitted

An app/FWSC with only a raw fallback reader would not persist current WebMIDI updates. An app/FWSC without verified manifest validation and writer placement would risk consuming uninitialized or corrupt stock raw prefixes. Therefore release artifacts would be misleading.

## Reproduce

```sh
python3 baselines/v15/analysis/flash-candidates/S1C6-raw17-persistence-block/analyze.py --check
python3 baselines/v15/analysis/flash-candidates/S1C6-raw17-persistence-block/validate.py
(cd baselines/v15/analysis/flash-candidates/S1C6-raw17-persistence-block && shasum -a 256 -c SHA256SUMS)
```

## Unblock requirements

1. Prove larger owned executable placement, or a complete split-control exact PI32 implementation with independent return/branch review.
2. Fit and verify a writer using `0x02004b02` full-length checks and `0x02004870` readback.
3. Validate manifest/CRC commit-last semantics and volatile-RAM precedence.
4. Only then emit app/FWSC, exact OTA, and rollback artifacts.
