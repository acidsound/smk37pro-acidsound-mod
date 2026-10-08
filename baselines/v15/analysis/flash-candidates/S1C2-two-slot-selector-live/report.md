# S1-C2 two-slot selector live candidate PASS

Date: 2026-08-02 UTC  
Status: **PASS, candidate built offline**  
Scope: exact official v15 package plus exact live-PASS S1-C1 parent app. No device access, flash, OTA, reset, or live MIDI traffic was performed.

## Decision

The previous BLOCK is cleared by route separation at the two H2 product callsites, without reading PI32 `rets`.

- Direct callsite `0x0201e468` encodes `bfea9bfe` and targets the main producer entry `0x0201e1a2`.
- Segmented callsite `0x0201e49c` encodes `bfeac9fe` and targets the no-mutation immediate-return entry `0x0201e232` inside `0x0201e1a2..0x0201e254`.
- Caller reloads at `0x0201e46c` and `0x0201e4a0` remain byte-exact: `bfeaf838` and `bfeade38`.
- Note Off `0x0201c63e` and Note On `0x0201c67c` are pinned to the exact 96-byte selector entries. The selector maps Ch10 note36 to slot0 and note45 to slot1 for both Note On and Note Off, with prior H2 fallback for all other notes.

## Exact artifacts

- App: `app.bin`, SHA-256 `4afd13d7301c2ae209c11d3fe932d019faa770b551f2d8a38cf4c018c7aafa8a`.
- FWSC: `SMK37Pro-v15-S1C2-two-slot-selector-live.fwsc`, SHA-256 `63e3cfa39473df08bd225df2c8ae81dbfe7aafbd31da6cc6dcf64ca03453681e`.
- Selector: 96 bytes at `0x0201e13e..0x0201e19e`, SHA-256 `adb8774971811f6dbdce8b7338f2265f18b8bb22544ccab746e74610366d4e35`.
- Producer plus segmented stub: `148` bytes at `0x0201e1a2..0x0201e236`, SHA-256 `a05e79c0b46e1e12b1244af3f49866c911fcc41937bc14196825d3080d780784`. Fits the 178-byte owned range ending at `0x0201e254`.
- Official-v15 exact-sector rollback manifest: `rollback/official-v15-recovery-sectors/manifest.json`.

## Pinned packets for guarded sender

| Order | Slot | Fixed note | Factory source | Packet file | Runtime SHA-256 | Packet SHA-256 |
|---:|---:|---:|---|---|---|---|
| 1 | 0 | 36 | Bank D patch 14, Mooger #1 | `host/packets/slot0-note36-direct-product-163.bin` | `e0bf5adb328b25de2c64d24cf8f6fe8f8e293e968dd56dbbfbf771ad92fe8275` | `6a9b4097cce1d28780ef3a507f42999743cc10e09770c17c5c78d185e9abff27` |
| 2 | 1 | 45 | Bank D patch 12, HAND DRUM | `host/packets/slot1-note45-direct-product-163.bin` | `98bc86e7d9625c837ee6c07fa3f01cbd6079960c9d1071017cf51194aa48c1bf` | `c4e8458edeb04d8106ca60a35243525e6b5f3f5de272091492409a440e3a9a8d` |

## Validation matrix

The validator independently decodes the PI32 bytes and enforces:

- direct `r9 == 0xa3` gate occurs before `testset` and all lock/state/slot mutation;
- direct exact length first packet publishes slot0/note36 and enters LOADING;
- direct wrong length and non-direct LR return with zero lock/state/slot mutation;
- direct exact length second packet publishes slot1/note45 and writes ARMED last;
- later direct exact packets reject without mutation;
- app/FWSC package embeds exactly the candidate app;
- rollback sectors reconstruct official-v15 flash exactly;
- `guarded_sender.py` and `exact_uploader.py` self-test without opening any device transport.

Validation output is captured in `validation.txt`. `SHA256SUMS` pins all candidate files.
