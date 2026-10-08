# S1C5 independent offline review v2 addendum

Decision: **PASS**.

This addendum re-reviews the exact S1C5 candidate from commit `90080a59564e6255a30aa08dcf05d3ae4d8831df` at `baselines/v15/analysis/flash-candidates/S1C5-playback-register-return` after current HEAD `03fb5a3cb02532f1be5f8c07cd59cc902c08fd93` committed the v15 OTA/device-identity transport changes. The review was offline only. No device, USB transport, MIDI transport, OTA upload, live send, reset, or flash action was performed.

## Provenance and clean-checkout result

- Review checkout: detached, clean checkout at `03fb5a3cb02532f1be5f8c07cd59cc902c08fd93`.
- `git status --porcelain=v1` was empty before validation and remained empty afterward.
- The complete candidate directory has no diff between exact candidate commit `90080a5` and review HEAD `03fb5a3`.
- Exact candidate tree: `ae88bd64345e29fe542984307f49d372f52ab675`.
- Candidate `app.bin`: `8b16e9f5a3ec873ac9a51e64f12c5be20156a01a6e8eb65878eed9636179f189`.
- Candidate FWSC: `0a6ac1ae7d4bd34e252eb8f23a4d2c5f39d7454376ade1a3b75ff7d03155ea91`.
- Candidate `exact_ota.c`: `03da93a1f59d4cacf4bdeb05c244752501d6880c7a8e3c51ed0ab5e09ab015c2`.
- Committed source blobs used by the compile were `src/ota.c` `e40e1a6d7681367dadb57e94735ad6bbebaac95b` and `src/device_info.c` `e2f4d6ff13550df619c7707fe24194537b2b45f0`.

## Deterministic candidate validation

The committed candidate validator and dry-run validator both passed in the clean checkout:

- `python3 validate.py`: **PASS** with the exact app and FWSC hashes above.
- `python3 dry_run_validate.py --json`: **DRY_RUN_PASS**, 16 packets, every playback-note byte at wire offset 161 equal to C4/60, device access false, MIDI transport false, and sending disabled.
- Two clean rebuilds performed by the independent gate harness reproduced byte-identical app and FWSC artifacts.

## Exact OTA wrapper compile and controls

The exact committed wrapper was compiled against the committed sources at review HEAD:

```text
cc -O2 -g -std=c11 -Wall -Wextra -Wpedantic \
  exact_ota.c \
  ../../../../../src/device_info.c \
  ../../../../../src/fwsc.c \
  ../../../../../src/protocol.c \
  ../../../../../src/sha256.c \
  ../../../../../src/usb_probe.c \
  -o <tmp>/exact_ota \
  $(pkg-config --cflags --libs libusb-1.0)
```

Result: **PASS**, return code `0`, with no compiler diagnostics. Toolchain was Apple Clang 21.0.0 and libusb 1.0.30.

The wrapper was invoked only in offline `check` mode:

| Input | Expected | Actual | Result |
|---|---:|---:|---|
| exact S1C5 candidate FWSC | 0, accept | 0 | **PASS** |
| S1C4 v3 segmented-final parent FWSC | 1, reject | 1 | **PASS** |
| official v15 FWSC | 1, reject | 1 | **PASS** |

The candidate reported `exact v15 S1-C5 Playback Register Return package: PASS (701120-byte OTA payload)`. Both controls reported `offline check rejected: not exact S1-C5 Playback Register Return package`.

## Prior PASS-gate regression check

All gates that passed in the first independent review still pass:

- **PASS** `deterministic-app-fwsc-rebuild`
- **PASS** `parent-relative-four-changed-bytes`
- **PASS** `pi32-lb-z-decode-and-semantics`
- **PASS** `selector-r0-return-contract`
- **PASS** `note-on-velocity-and-note-off-symmetry`
- **PASS** `repeated-playback-note-60-no-slot-collapse`
- **PASS** `protected-regions`
- **PASS** `rollback-reconstructs-official-v15`

The two formerly failing or blocked transport gates now also pass:

- **PASS** `exact-ota-current-src-api-compilation`
- **PASS** `exact-ota-candidate-accept-parent-official-reject`

## Resolution of the v1 blocker

The v1 review failed because its then-current `src/ota.c` exposed a seven-argument `ota_upload_exact`, while the exact candidate wrapper correctly retained the v15 version argument and supplied eight arguments. Commit `03fb5a3` added `expected_version` to the committed exact-upload API and validation path, restoring the eight-argument contract and adding v15 normal-mode USB identity support. Consequently, the exact unchanged candidate wrapper now compiles, accepts only its pinned S1C5 package hash, and rejects both requested controls.

This closes the prior offline release blocker. It does not claim live transport or device behavior, which was intentionally outside this review.
