# S1C6 raw-record persistence successor candidate

Date: 2026-08-04 UTC. Scope is deterministic offline analysis and raw-record/rollback artifact generation only. No device, MIDI transport, flash, OTA, or reset action is performed.

## Decision

**DATA/ROLLBACK PASS, firmware hook BLOCK.**

The current S1C5 16 voices plus Playback Notes can be represented in 17 reserved stock raw records: 16 payload records plus one manifest/map record. The preferred reservation is **C32 manifest plus D17..D32 payload records**. The direct mapped read formula is:

```text
payload = *(g+0x164) + 0x4000 + (112+slot)*0xa3; playback = *(g+0x164) + 0x4000 + 95*0xa3 + 0x20 + slot
```

The generated records validate that a direct raw-prefix fallback would restore every normalized S1C5 voice and every Playback Note without using packed-record unpacking. The seven-byte raw tails are preserved from the stock records.

No installable firmware package is emitted because the executable fit gates fail. Preserving the exact volatile RAM ARMED selector path and exact WebMIDI producer leaves only **2 bytes** in the owned window, while the most optimistic direct-mapped raw fallback primitive alone needs **32 bytes** before manifest validation or branch integration. Replacing the selector while preserving the producer gives 90 bytes, but the current ARMED selector is already 88 bytes, so the lower bound is 120 bytes.

## Persistent raw-record candidate

| Slot | Payload record | Mapped payload offset from `*(g+0x164)` | Playback Note | Restored normalized voice SHA-256 |
|---:|---:|---:|---:|---|
| 0 | 112 | `0x8750` | 60 | `e2beb705a28e83940b2708f8ba0976e8c093ca12f45d0045f290b1589760d76b` |
| 1 | 113 | `0x87f3` | 60 | `5dab954752769609d64dd162360182138c8bc399030b88cf8d61b76fb7208f97` |
| 2 | 114 | `0x8896` | 60 | `3e140cc8613ec555fcae2109d216c5e838d3193b305352992dc4062556af8b60` |
| 3 | 115 | `0x8939` | 60 | `5f60dc8f39b4ec43dc4368050701550ca56581948451f0c8083ace61e9d98dc7` |
| 4 | 116 | `0x89dc` | 60 | `5da8be28b3468a534aa488b02d47522df36e6b5b02b14f992bcb869fc4bb9ecc` |
| 5 | 117 | `0x8a7f` | 60 | `d38dfdac699a0fadbf7c99c98103a5f2bf7297a6746e94525d7eca3472223d40` |
| 6 | 118 | `0x8b22` | 60 | `7727f3b7856a73b3c32bca1b6e15ed74672d6dc97e00641761ef14237b0d8a44` |
| 7 | 119 | `0x8bc5` | 60 | `8b0463a7b52857203105525af3456636b3a427e5db5f1eb75ea687bd6677bbbb` |
| 8 | 120 | `0x8c68` | 60 | `1602db2d94930482f631d087bf4b645d626f12b88da1e8deee21202210b7177c` |
| 9 | 121 | `0x8d0b` | 60 | `33dd55bbc6ebc2361260b9a581203f682b49388f9e4284b95de15136b630a178` |
| 10 | 122 | `0x8dae` | 60 | `9c5abf35d8c039be1c8603f4fb5296f7b7d3e28503b330b5d3dd33c1b5a6dff9` |
| 11 | 123 | `0x8e51` | 60 | `98bc86e7d9625c837ee6c07fa3f01cbd6079960c9d1071017cf51194aa48c1bf` |
| 12 | 124 | `0x8ef4` | 60 | `452efa8d41eecc7a5c57f1dfdecc072e1bc4266020cfe824edbc1b87415c2e38` |
| 13 | 125 | `0x8f97` | 60 | `e0bf5adb328b25de2c64d24cf8f6fe8f8e293e968dd56dbbfbf771ad92fe8275` |
| 14 | 126 | `0x903a` | 60 | `cfa79fc5ba72bcd50b0465a116e109da90ca5dcdcdc40bc89cdad218ee468417` |
| 15 | 127 | `0x90dd` | 60 | `a28849a192d5dad000622c8aa749baa6508ad73e2c1cc6659b33a0419b6a0e88` |

Manifest/map record index: **95**. Manifest map offset: `0x7c9d`.

Artifacts:

- `records/candidate-reserved-records.bin`: concatenated 17-record candidate image.
- `records/record-NNN-candidate.bin`: per-record candidate images.
- `rollback/reserved-stock-raw-records/manifest.json`: exact original reserved-record rollback manifest.
- `rollback/reserved-stock-raw-records/record-NNN-official.bin`: per-record stock rollback images.

## Fit lower bound

| Required primitive for raw fallback | Minimum bytes |
|---|---:|
| load global g pointer 0x01c33260 | 6 |
| ldw mapped raw base from [g+0x164] | 4 |
| copy slot index for raw stride | 2 |
| mul slot by raw stride 0xa3 | 4 |
| add mapped base to payload offset | 2 |
| add preferred payload-base mapped offset 0x8750 | 4 |
| copy source pointer for manifest-map load | 2 |
| add preferred manifest-map mapped offset 0x7c9d | 4 |
| add slot to manifest-map pointer | 2 |
| lb.z Playback Note from manifest map | 2 |

Total primitive lower bound: **32 bytes**.

Excluded from that lower bound: manifest magic/version/count/CRC validation, A/B generation choice, interrupted-update behavior, branch integration, and destination byte repair for layouts that place Playback Note in `raw[0x9b]` instead of the manifest map.

## Hook review

| Hook/callsite | Classification | Decision |
|---|---|---|
| `0x02005f9c` | revoked pre-USB storage-init loader callsite | BLOCK |
| `0x02005fa4` | post-storage but still pre-return boot initializer call | BLOCK: no live proof and no wrapper placement |
| `0x0201e46c/0x0201e4a0` | post-product SysEx reloads | NOT autonomous across power cycle |
| `0x0202422e` | UI bank/preset reload | NOT every boot and mutates UI-selected patch state |

Removing the exact reset wrapper would reclaim enough bytes on paper, but it is rejected because `0x0201e228` is the current direct WebMIDI reset entry. That would not preserve the requested producer.

## Reproduce

```sh
python3 baselines/v15/analysis/flash-candidates/S1C6-raw-record-persistence/build_s1c6_raw_record_persistence.py
python3 baselines/v15/analysis/flash-candidates/S1C6-raw-record-persistence/validate.py
(cd baselines/v15/analysis/flash-candidates/S1C6-raw-record-persistence && shasum -a 256 -c SHA256SUMS)
```

Expected result: `S1C6 raw-record persistence offline validation PASS; firmware fit BLOCK`.
