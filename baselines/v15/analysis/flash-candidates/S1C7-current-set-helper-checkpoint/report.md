# S1-C7 current-set helper checkpoint PASS

## Decision

**PASS_CURRENT_SET_CHECKPOINT.** App/FWSC/exact OTA and rollback artifacts were built offline. This is intentionally not promoted as a full persistence writer because no `0x02004b02` writer/readback/manifest commit-last body is included.

## Key properties

- Helper region: `0x02026d80..0x02026dd4` (84 bytes), skipped by UI patch `04ac00160016` at `0x02026d7a`.
- Selector/producer window: selector calls persistent helper or stock-copy helper; producer `0x0201e196..0x0201e254` is preserved byte-for-byte from S1C5.
- Chrome segmented-final and reset are preserved by keeping the S1C5 producer unchanged.
- Restore path uses `0x02004870` full-length read wrapper. If the wrapper returns zero, helper restores the stock source pointer and performs stock copy.
- Exact host-seeded records are emitted as offline prefix artifacts under `host-seeded-records/`; they are not written to a device.
- `exact_ota.c` compiles against current `src/*.c` support sources and accepts only this FWSC while rejecting S1C5 and official-v15 controls in offline `check` mode.

## Limitation

Full normal-firmware write persistence using `0x02004b02` plus readback/manifest commit-last remains follow-up work. This checkpoint restores the exact seeded current set only.
