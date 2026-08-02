# v15 R03 fixed-prefix controlled checkpoint

Date: 2026-08-02

## Decision

**Atomic offline integrity: PASS. Live flash: pending independent safety review.**

R03 replaces R02's transient SysEx workspace dependency with a fixed, boot-zeroed,
allocator-excluded `0xa0`-byte RAM prefix. The design is deliberately one-shot:
the first accepted product packet publishes a 156-byte voice and sets `valid=1`
last. Later packets cannot replace the snapshot until reboot. This removes the
retired active-count lifecycle and its CC120/CC123 or missing-Note-Off deadlock.

This report does not claim live success. The device was not accessed while these
artifacts were built or validated.

## Exact artifacts

- app SHA-256: `1fff37674f4bb1d5b988dc1415ab29c7114bbcad9e12bfcd7cec9b687d1f6ecb`
- FWSC SHA-256: `0ed23e567a623db4b143fa30a6846626d746098ed126c149ac724c0fab6c1937`
- guarded rollback ZIP SHA-256: `6396f253825d067986131d830bcca8cce16ff9ca39b21c4220369958e90344f1`
- changed Flash sectors: `0x04000`, `0x20000`, `0x22000`, `0x2a000`, `0x62000`
- protected prefix `0x0000..0x3fff`: unchanged

## RAM ownership construction

The official SDK `sbrk()` relocation-aware match at `0x0205e9da` recovered:

- stock `HEAP_BEGIN = 0x01c46520`
- `HEAP_END = 0x01c7fd30`
- all 80 non-relocation bytes exact

R03 applies both required patches:

1. boot BSS zero size at `0x0200001e`: `0x3cb48 -> 0x3cbec`
2. matched `HEAP_BEGIN` immediate at `0x0205e9f8`:
   `0x01c46520 -> 0x01c465c0`

This initializes and excludes `0x01c46520..0x01c465c0` from the allocator:

- voice: `0x01c46520..0x01c465bc` (`0x9c` bytes)
- valid byte: `0x01c465bc`
- producer lock byte: `0x01c465bd`
- alignment/guard: `0x01c465be..0x01c465c0`

Heap capacity decreases by 160 bytes. Allocator code and ABI are unchanged, but
live heap-pressure testing remains mandatory before this can graduate beyond a
controlled checkpoint.

## Event-path behavior

- Note Off callsite `0x0201c63e` -> wrapper `0x0201e13e`
- Note On callsite `0x0201c67c` -> wrapper `0x0201e16e`
- Ch10 and `valid==1`: copy the same owned `0x9c` voice into the stock destination
- other channels or invalid state: call stock `memcpy`
- first one-shot/segmented accepted post-F7 caller at `0x0201e468` or
  `0x0201e49c` -> producer `0x0201e1b4`
- producer acquires the official PI32v2 atomic byte lock, rechecks `valid`, copies
  the voice, stores `valid=1`, then releases the lock
- subsequent accepted packets return without modifying the snapshot
- stock SAVE caller `0x02026dac` remains explicitly disabled
- the revoked R01d early post-init hook at `0x02005f9c` is unchanged

The retained 124-row PI32 trace confirms every patched branch and call target.
Quarkslab decodes the embedded `csync` and `testset` instructions but omits the
four-byte spin-loop branch at `0x0201e1a2`. That single decoder gap is covered by
the pinned SDK `arch_spin_lock` source and exact official PI32 clang object:
`40 e8 fd ff = ifeq goto -6`, with source/object hashes enforced by the validator.

## Rollback gate

The R03 rollback bundle restores exactly the five changed sectors. Its guard:

- requires two fresh byte-identical 1 MiB forced-loader dumps
- requires every current target sector to match the exact R03 sector hash
- permits erase/write only inside the five audited 4 KiB sectors
- uses 256-byte maximum writes with CRC16-XMODEM and readback verification
- verifies all non-restored sectors remain byte-identical
- implements no chip erase, full-flash write, boot-prefix write, reset, or run-app

The guard FakeTransport self-test and deterministic ZIP rebuild both pass.

## Remaining live gates

1. normal boot and USB identity `015` before any pad input
2. send the exact guarded Mooger #1 product packet once after boot
3. Ch1 stock timbre and Note Off remain correct
4. Ch10 Mooger #1 timbre and Note Off are correct
5. changing Ch1 patch does not alter Ch10
6. send a second different product packet and confirm Ch10 remains the first snapshot
7. reboot without staging and confirm Ch10 safely falls back to stock
8. restage after reboot and repeat Note On/Off
9. exercise UI, patch browsing, SEQ, USB reconnect, and polyphonic note stress without reset or allocation regression
10. do not press SAVE while R03 is installed

Any boot failure, USB loss, reboot, stuck note, cross-channel timbre change, or
heap-pressure symptom is a hard stop followed by the exact R03 rollback path.

The isolated uploader `tools/smk37_v15_r03_ota.c` accepts only package SHA-256
`0ed23e...1937`, device/package version `015`, and confirmation token
`INSTALL-SMK37PRO-V15-R03-0ED23E56`. Its offline check accepts R03 and rejects
the official v15 package before any device access.

## Reproduce

```sh
python3 tools/build_v15_r03_fixed_prefix.py \
  build/v15-official-app.bin build/v15-R03-fixed-prefix-app.bin \
  --manifest baselines/v15/analysis/flash-candidates/R03/app-manifest.json

python3 tools/smk37_v15_app_patch.py repack-app \
  build/SMK-37_Pro_015.fwsc build/v15-R03-fixed-prefix-app.bin \
  build/SMK37Pro-v15-R03-fixed-prefix.fwsc \
  --manifest baselines/v15/analysis/flash-candidates/R03/package-manifest.json

python3 tools/validate_v15_r03.py

cc -O2 -g -std=c11 -Wall -Wextra -Wpedantic \
  $(pkg-config --cflags libusb-1.0) \
  tools/smk37_v15_r03_ota.c \
  src/device_info.c src/fwsc.c src/protocol.c src/sha256.c src/usb_probe.c \
  -o build/smk37-v15-r03-ota $(pkg-config --libs libusb-1.0)

build/smk37-v15-r03-ota check \
  build/SMK37Pro-v15-R03-fixed-prefix.fwsc
```
