# Independent final review: S1-C2 two-slot selector live v2 at `3d749c2`

Date: 2026-08-03 UTC

Reviewed commit: `3d749c277011a58f7cd275ad4a42c0e124d09a5f`

Scope: `baselines/v15/analysis/flash-candidates/S1C2-two-slot-selector-live-v2/`, committed exact transport tools under `tools/`, and their committed support sources. The working tree was dirty and later advanced to another commit while I was working, so I validated an isolated `git archive 3d749c277011a58f7cd275ad4a42c0e124d09a5f` materialization under scratch. I did not access a device, flash, reset, OTA transport, live MIDI transport, or the network.

## Decision

**BLOCK**

The candidate app/package artifacts and Python validators are reproducible and internally consistent, but the requested exact OTA live transport tool is not buildable from commit `3d749c2`. That blocks a self-contained live v2 candidate with exact transport tools.

## Blocking finding

### Exact OTA transport tool does not compile from committed sources

Command run inside an archived copy of `3d749c277011a58f7cd275ad4a42c0e124d09a5f`:

```sh
cc -O2 -g -std=c11 -Wall -Wextra -Wpedantic -Isrc \
  tools/smk37_v15_s1c2_ota.c \
  src/device_info.c src/fwsc.c src/protocol.c src/sha256.c src/usb_probe.c \
  -o "$SCRATCH/bin/smk37-v15-s1c2-ota" \
  $(pkg-config --cflags --libs libusb-1.0)
```

Compiler result:

```text
tools/smk37_v15_s1c2_ota.c:55:13: error: too many arguments to function call, expected 7, have 8
   53 |         return ota_upload_exact(
      |                ~~~~~~~~~~~~~~~~
   54 |             argv[2], argv[3], argv[5], 15, PACKAGE_SHA256, DESCRIPTION, CONFIRM,
   55 |             "v15 S1-C2 live v2 installed; split-entry two-slot selector armed");
      |             ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
tools/../src/ota.c:623:12: note: 'ota_upload_exact' declared here
```

Static source mismatch in the same archived commit:

```text
src/ota.c:
623 static int ota_upload_exact(
624     const char *firmware_path, const char *transcript_path,
625     const char *confirmation,
626     const uint8_t expected_sha256[SMK37_SHA256_LENGTH],
627     const char *package_description, const char *expected_confirmation,
628     const char *completion_message)

tools/smk37_v15_s1c2_ota.c:
return ota_upload_exact(
    argv[2], argv[3], argv[5], 15, PACKAGE_SHA256, DESCRIPTION, CONFIRM,
    "v15 S1-C2 live v2 installed; split-entry two-slot selector armed");
```

Because the exact OTA tool cannot compile, I could not execute its offline `check` accept/reject path at the reviewed commit. This fails the requested exact OTA accept/reject and exact transport-tool criteria.

## Positive checks completed before the block

These checks reduce ambiguity but do not clear the OTA transport blocker.

### Self-contained archive and checksum ledger

- `git archive 3d749c277011a58f7cd275ad4a42c0e124d09a5f` materialized successfully.
- `shasum -a 256 -c SHA256SUMS` passed for all 31 listed S1-C2 live v2 files before validation.
- `python3 validate.py` passed and regenerated the same `validation.txt` / `independent-decode.tsv` content.
- `shasum -a 256 -c SHA256SUMS` passed again after validation.

Key hashes confirmed:

- FWSC: `63e3cfa39473df08bd225df2c8ae81dbfe7aafbd31da6cc6dcf64ca03453681e`
- App: `4afd13d7301c2ae209c11d3fe932d019faa770b551f2d8a38cf4c018c7aafa8a`
- Selector: `adb8774971811f6dbdce8b7338f2265f18b8bb22544ccab746e74610366d4e35`, 96 bytes
- Producer/stub: `a05e79c0b46e1e12b1244af3f49866c911fcc41937bc14196825d3080d780784`, 148 bytes

### Deterministic rebuild

Command:

```sh
python3 baselines/v15/analysis/flash-candidates/S1C2-two-slot-selector-live-v2/build_s1c2_two_slot_selector_live.py \
  --output-dir "$SCRATCH/rebuild" \
  --determinism-check
```

Result:

```json
{
  "app_sha256": "4afd13d7301c2ae209c11d3fe932d019faa770b551f2d8a38cf4c018c7aafa8a",
  "package_sha256": "63e3cfa39473df08bd225df2c8ae81dbfe7aafbd31da6cc6dcf64ca03453681e",
  "producer_bytes": 148,
  "segmented_stub": "0x0201e232"
}
```

I compared 20 generated rebuild outputs against the committed candidate artifacts, excluding `SHA256SUMS` because the builder's scratch output ledger covers only generated files while the committed ledger also covers committed inputs and validator files. Generated app, FWSC, manifests, report, decode, sender dry-run script, host packets, and rollback sector artifacts all matched byte-for-byte.

### Selector and producer route gates

The committed validator and byte checks verified:

- Note Off hook `0x0201c63e` targets selector entry `0x0201e13e`.
- Note On hook `0x0201c67c` targets selector entry `0x0201e142`.
- Direct product callsite `0x0201e468` encodes `bfea9bfe` and targets `0x0201e1a2`.
- Segmented product callsite `0x0201e49c` encodes `bfeac9fe` and targets immediate-return stub `0x0201e232`.
- Stub bytes at `0x0201e232` are `79045904`.
- Reload callsites remain intact: `0x0201e46c = bfeaf838`, `0x0201e4a0 = bfeade38`.
- Producer prefix enforces `r9 == 0xa3` before the first `testset` / lock / state / slot mutation.

### Protected prefix, changed sectors, and rollback reconstruction

The committed validator confirmed:

- Protected flash prefix `0x0000..0x3fff` unchanged.
- App/FWSC package embeds exactly the candidate app.
- Official rollback sector manifest applies five exact official sectors:
  - `0x04000`
  - `0x20000`
  - `0x22000`
  - `0x2a000`
  - `0x62000`
- Applying those sectors to candidate flash reconstructs official v15 flash SHA-256 `f77e9ab3cee79113be78f3efacffb03c6cb9b87b78263010e16e81c472df0f9a`.
- Rollback reconstruction also restores official app SHA-256 `36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055`.

### Sender order, hash, and packetization

The exact sender tool compiled from `3d749c2` and the offline dry-run path behaved correctly:

```sh
cc -O2 -g -std=c11 -Wall -Wextra -Wpedantic -Isrc \
  tools/smk37_v15_s1c2_send.c src/sha256.c \
  -o "$SCRATCH/bin/smk37-v15-s1c2-send" \
  $(pkg-config --cflags --libs libusb-1.0)
```

Positive dry-run:

```text
S1-C2 live v2 sender dry-run PASS: slot0 note36 then slot1 note45, each 163 SysEx bytes -> 220 USB-MIDI bytes
```

Reject checks:

- Swapped packet order rejected with slot0 SHA mismatch.
- Mutated packet rejected with slot0 SHA mismatch.
- `send ... --confirm WRONG` rejected before libusb transport.

Pinned send order and packet hashes:

1. `host/packets/slot0-note36-direct-product-163.bin`, SHA-256 `6a9b4097cce1d28780ef3a507f42999743cc10e09770c17c5c78d185e9abff27`, 163 SysEx bytes to 220 USB-MIDI bytes.
2. `host/packets/slot1-note45-direct-product-163.bin`, SHA-256 `c4e8458edeb04d8106ca60a35243525e6b5f3f5de272091492409a440e3a9a8d`, 163 SysEx bytes to 220 USB-MIDI bytes.

`python3 host_sender_dry_run.py --json` also passed offline.

## Required remediation

Commit a self-consistent OTA transport implementation. Either:

1. update committed `src/ota.c` / `src/ota.h` so `ota_upload_exact` accepts the expected version parameter used by `tools/smk37_v15_s1c2_ota.c`, or
2. update `tools/smk37_v15_s1c2_ota.c` to match the committed `ota_upload_exact` signature while preserving the exact v15 package gate.

After that, rerun the offline compile and `check` accept/reject tests from a clean archive of the exact commit.
