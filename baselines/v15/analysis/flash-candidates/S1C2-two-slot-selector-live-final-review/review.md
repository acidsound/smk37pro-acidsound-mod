# S1-C2 two-slot selector live final review

Date: 2026-08-03 UTC  
Reviewer: Jcode  
Pre-review HEAD observed: `3d749c2` (`Fix S1-C2 OTA v15 version gate`)  
Requested lineage present: `f0bac93`, `172c6ba`, `90b6b79` are ancestors of reviewed HEAD.  
Scope: `baselines/v15/analysis/flash-candidates/S1C2-two-slot-selector-live` at FWSC SHA-256 `63e3cfa39473df08bd225df2c8ae81dbfe7aafbd31da6cc6dcf64ca03453681e`, plus `tools/smk37_v15_s1c2_ota.c` and `tools/smk37_v15_s1c2_send.c`. No device, OTA, flash, reset, or live MIDI traffic was performed.

## Decision

**BLOCK immediate S1-C2 live flash authorization for current committed `HEAD`.**

Reason: the live-safety artifact bytes independently verify, but two exact committed gates are broken from a clean `HEAD` archive:

1. **Exact committed OTA tool does not compile.** `tools/smk37_v15_s1c2_ota.c` passes 8 arguments to `ota_upload_exact`, while committed `src/ota.c` declares 7 arguments. This was masked by the dirty worktree `src/ota.c`, where compilation passed, but current committed `HEAD` fails.
2. **Exact committed validator is not clean-runnable.** `validate.py` imports `smk37_v15_app_patch` from root `tools/`, but `tools/smk37_v15_app_patch.py` is not tracked in `HEAD`; clean archive execution fails with `ModuleNotFoundError`.

These are broken exact gates, not documentation-only parent-input reproducibility residuals. They must be fixed or committed before live flash authorization.

## Positive safety checks completed

- `shasum -a 256 -c SHA256SUMS`: **PASS** in the candidate path and in a clean `HEAD` archive.
- Worktree validator: **PASS** with FWSC `63e3…681e`, app `4afd13…fa8a`, producer 148 bytes, segmented stub `0x0201e232`.
- Python host dry-run: **PASS**, two packets in order, send disabled.
- Dirty-worktree C compile with libusb: **PASS** for both tools, but not authorization-grade because `src/ota.c` was dirty.
- Clean `HEAD` C sender compile/dry-run: **PASS** for slot0 note36 then slot1 note45.
- C sender swapped-order dry-run: **REJECTED** as expected.
- C OTA exact package check in dirty worktree: exact candidate **accepted**, official package **rejected**, but clean `HEAD` OTA compile fails and therefore blocks.
- Independent raw-byte inspection: **PASS**.
  - Hooks: Note Off `0x0201c63e -> 0x0201e13e`, Note On `0x0201c67c -> 0x0201e142`.
  - Product routes: direct `0x0201e468 -> 0x0201e1a2`, segmented `0x0201e49c -> 0x0201e232`.
  - Reloads intact: `bfeaf838` and `bfeade38`.
  - Selector raw: 96 bytes, SHA-256 `adb8774971811f6dbdce8b7338f2265f18b8bb22544ccab746e74610366d4e35`, CH10 gate, slot0 base `0x01c46520`, slot1 `+0xa0`, stock copy tail `0x02048cce`.
  - Producer raw: SHA-256 `a05e79c0b46e1e12b1244af3f49866c911fcc41937bc14196825d3080d780784`, `r9 == 0xa3` gate before testset/state/slot mutation, slot0 note36 LOADING/valid0 sequence, slot1 note45 valid1 before ARMED, segmented stub push/pop only.
- Five-sector rollback reconstruction: **PASS**. Sectors `0x04000`, `0x20000`, `0x22000`, `0x2a000`, `0x62000` reconstruct official flash SHA-256 `f77e9ab3cee79113be78f3efacffb03c6cb9b87b78263010e16e81c472df0f9a`.

## Commands with blocking evidence

```sh
# clean HEAD archive OTA compile
cc -O2 -g -std=c11 -Wall -Wextra -Wpedantic -Isrc \
  tools/smk37_v15_s1c2_ota.c src/device_info.c src/fwsc.c src/protocol.c \
  src/sha256.c src/usb_probe.c -o build-out/smk37-v15-s1c2-ota \
  $(pkg-config --cflags --libs libusb-1.0)
```

Result:

```text
tools/smk37_v15_s1c2_ota.c:55:13: error: too many arguments to function call, expected 7, have 8
```

```sh
# clean HEAD archive validator
python3 baselines/v15/analysis/flash-candidates/S1C2-two-slot-selector-live/validate.py
```

Result:

```text
ModuleNotFoundError: No module named 'smk37_v15_app_patch'
```

## Required fixes before re-review

1. Commit a consistent OTA API/tool pair so `tools/smk37_v15_s1c2_ota.c` compiles from clean `HEAD` with libusb.
2. Commit `tools/smk37_v15_app_patch.py` or make `validate.py` self-contained so the exact committed validator runs from clean `HEAD`.
3. Re-run: checksum ledger, validator, clean `HEAD` C compiles, exact package accept/official reject, exact two-packet dry-run/order reject, and raw rollback verification.
