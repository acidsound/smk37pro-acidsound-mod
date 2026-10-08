# SMK-37 Pro Flash Layout and Cipher Analysis

## Summary

This document describes the byte-level relationship between the official FWSC
firmware packages (v12, v15) and live flash dumps from the SMK-37 Pro device.
The analysis enables safe, guarded sector-specific restoration after a failed
dump or write session.

## Flash Region Map

| Range          | Size     | Name            | Package Format        | Live Format                    | Restore Action |
|----------------|----------|-----------------|-----------------------|--------------------------------|----------------|
| 0x0000..0x3FFF | 16 KiB   | Boot header     | Plain (mixed cipher)  | Device-specific, mixed cipher  | **PRESERVE**   |
| 0x4000..0x42FF | 768 B    | JLFS header     | **Plain**             | Plain ^ lfsr(0x132b)           | **PRESERVE**   |
| 0x4300..0x9A832| 601 KiB  | App area        | Ciphers (sfc base 0x4000) | Ciphers (sfc base 0x4000) | **RESTORE**    |
| 0x9A833..0x9BFFF| 1.8 KiB | Tail metadata   | Static (per FW version) | Dynamic (device-specific)     | **PRESERVE**   |
| 0x9C000..0xFFFFF| 512 KiB | Beyond package  | N/A                   | Live-only data                 | **PRESERVE**   |

Total chip size: 0x100000 (1 MiB). Package flash.bin size: 0x9C000 (630 KiB).

## Cipher Details

### SFC Cipher (App Area)

The app area (0x4300..0x9A832) uses the SFC LFSR cipher:

```python
CHIP_KEY = 0x980F
SFC_BASE = 0x4000

def sfc_cipher(data, offset, size, base, key):
    for rel in range(0, size, 32):
        chunk = min(size - rel, 32)
        block_key = key ^ ((offset + rel - base) >> 2)
        lfsr_xor(data, offset + rel, chunk, block_key)

def lfsr_xor(data, offset, size, key):
    for i in range(size):
        data[offset + i] ^= key & 0xFF
        key = ((key << 1) ^ (0x1021 if key & 0x8000 else 0)) & 0xFFFF
```

- **Key schedule**: 16-bit LFSR (polynomial 0x1021), output = low byte
- **Block key**: `CHIP_KEY ^ ((offset - base) >> 2)`, recomputed every 32 bytes
- **Self-inverse**: XOR operation, so encoding and decoding are identical
- **Verified**: `sfc_cipher(package_flash, 0x4300, 0x9A833-0x4300, 0x4000, CHIP_KEY)`
  produces byte-exact match with the live dump for the entire app area

### JLFS Header Cipher (0x4000..0x42FF)

The JLFS header sector uses a different cipher than the app area:

- **Package stores**: plain (unencrypted) JLFS header
- **Live stores**: `plain ^ lfsr(0x132b)` where `lfsr` is a single 16-bit LFSR
  stream with key `0x132b` (NOT `CHIP_KEY = 0x980F`)
- **Key origin**: unknown. `0x132b` does not appear in the package data and is
  not derivable from `CHIP_KEY` via the standard SFC key schedule. It may be
  device-specific or derived from a hardware fuse.
- **Critical**: The JLFS header contains the file system table (app_area_head,
  app.bin, cfg_tool.bin, PRCT, CODE, BTIF, AUTORIM, USRFLASH, etc.). It must
  NOT be overwritten with the package's plain version, as the live device
  expects the encrypted form.

### Boot Header (0x0000..0x3FFF)

- **Package**: Contains readable strings (e.g., "AC791N_STORY", version "30.01")
  mixed with encrypted data. Block 0 (0x0000..0x00FF) matches `lfsr(CHIP_KEY)`.
- **Live**: Entirely different from the package. The boot header is
  device-specific and contains hardware identification, calibration data, and
  boot configuration that varies per unit.
- **Action**: Never overwrite the boot header during restore.

### Tail Metadata (0x9A833..0x9BFFF)

- **Package**: Contains static data (file system metadata, configuration tables)
  that varies between FW versions but is the same for all devices running that
  FW version.
- **Live**: Contains dynamic device-specific data (file system journal, usage
  counters, calibration state). The live tail data is NOT found in either the
  v12 or v15 package flash.bin.
- **Action**: Never overwrite the tail metadata during restore.

## FWSC Package Structure

The FWSC (Jieli Firmware Secure Container) file has this layout:

```
Offset    Size     Content
0x00000   0x40     UFW header
0x00040   0x50*N   UFW entries (N varies)
0x00xxx   0x9C000  flash.bin (the actual flash image)
```

The FWSC file on disk uses a block-interleaved format:
- 20 blocks of 48 bytes each (47 data + 1 checksum)
- Followed by the remaining payload

Extraction:
```python
from smk37_app_patch import FWSC_BLOCK_SIZE, FWSC_DATA_SIZE, FWSC_SLOTS, Ufw

raw = open("SMK-37_Pro_015.fwsc", "rb").read()
payload = bytearray()
for i in range(FWSC_SLOTS):
    payload.extend(raw[i*FWSC_BLOCK_SIZE : i*FWSC_BLOCK_SIZE + FWSC_DATA_SIZE])
payload.extend(raw[FWSC_SLOTS * FWSC_BLOCK_SIZE:])
flash = Ufw.parse(bytes(payload)).flash()  # 0x9C000 bytes
```

## Known FW Versions

| Version | Package          | flash.bin SHA-256 (first 16) | Notes |
|---------|------------------|-------------------------------|-------|
| v12     | SMK-37_Pro_012.fwsc | c6a9187e706aeae9…          | Stock v12 |
| v15     | SMK-37_Pro_015.fwsc | f77e9ab3cee79113…          | Stock v15 |

- `script.ver` is **identical** between v12 and v15
- `tail.bin` is **identical** between v12 and v15 (contains `JLUFW` magic)
- `blimit.bin`, `USR`, `ota.bin` **differ** between v12 and v15
- `flash.bin` differs mainly in the JLFS header area and scattered app bytes

## Guarded Restore Procedure

The `tools/smk37_guarded_restore.py` script implements a safe, guarded restore:

1. **Extract** the flash.bin from the FWSC package (UFW parser)
2. **Load** the live flash dump (0x100000 bytes)
3. **Replace** ONLY the app area (0x4300..0x9A832) with the package data
4. **Preserve** all other regions byte-exact:
   - Boot header (0x0000..0x3FFF)
   - JLFS header (0x4000..0x42FF)
   - Tail metadata (0x9A833..0x9BFFF)
   - Beyond-package region (0x9C000..0xFFFFF)
5. **Output** a restored dump file ready for the normal write path

### Safety Guarantees

- **No chip erase**: The script operates on file-level dumps, never on hardware
- **No full overwrite**: Only the app area is modified; all device-specific
  regions are preserved
- **No JLFS corruption**: The JLFS header is left untouched, preserving the
  device's file system structure
- **No tail data loss**: Dynamic metadata (journal, counters) is preserved
- **Dry-run mode**: `--dry-run` reports changes without writing output
- **Verification**: `--verify` checks the current dump state before restoring

### Usage

```bash
# Dry run: report what would change
python3 tools/smk37_guarded_restore.py \
  --package build/SMK-37_Pro_015.fwsc \
  --dump    current-device-dump.bin \
  --output  /dev/null \
  --dry-run

# Actual restore: produce a restored dump
python3 tools/smk37_guarded_restore.py \
  --package build/SMK-37_Pro_015.fwsc \
  --dump    current-device-dump.bin \
  --output  restored-stock-v15.bin

# Restore from a patched app area (e.g., a modified firmware build)
python3 tools/smk37_guarded_restore.py \
  --package build/SMK-37_Pro_015.fwsc \
  --dump    current-device-dump.bin \
  --app-src patched_app_area.bin \
  --output  restored-patched.bin
```

## Unresolved Questions

1. **JLFS header key (0x132b)**: Origin unknown. If the device is re-flashed
   with a different FW version, the JLFS header may need to be re-encrypted
   with the correct key. For now, preserving the existing JLFS header is safe.

2. **Boot header cipher**: The boot header uses a mixed cipher scheme that is
   not fully characterized. Block 0 matches `lfsr(CHIP_KEY)` but subsequent
   blocks do not follow the standard SFC key progression. The boot header is
   device-specific and should never be overwritten.

3. **Tail metadata dynamics**: The tail region contains dynamic data that
   changes with device usage. The exact format and update mechanism are not
   fully documented. Preserving the existing tail data is the safe default.

4. **Multi-version restore**: If restoring from a different FW version (e.g.,
   v12 → v15), the JLFS header and tail metadata may need to be updated in
   addition to the app area. This is not yet supported by the restore script.

## Validation

All findings were validated against the v15 clean baseline dump
(`baselines/v15/device-dumps/v15-clean-baseline-a.bin`):

- App area (0x4300..0x9A832): **0 mismatches** after sfc_cipher decode
- Boot header: **16,352 byte differences** (expected, device-specific)
- JLFS header: **766 byte differences** (expected, ciphered vs plain)
- Tail metadata: **6,079 byte differences** (expected, dynamic data)
- Restored dump: All preserved regions **byte-identical** to original
