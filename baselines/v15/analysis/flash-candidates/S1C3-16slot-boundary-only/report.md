# S1-C3 16-slot boundary-only diagnostic PASS

Date: 2026-08-03 UTC  
Status: **PASS, boundary-only candidate built offline**  
Scope: exact official v15 package plus exact live-PASS S1-C2 live v2 parent app. No device access, flash, OTA, reset, or MIDI traffic was performed.

## Decision

This is a narrow S1-C2-parent-only boundary diagnostic. It is **not** a functional 16-slot implementation and does not claim heap headroom or 16-slot consumption. The build is defensible only because it changes exactly two parent instructions, four app bytes total, and preserves all S1-C2 live v2 code and behavior:

- boot BSS zero size at `0x0200001e`: `c2ff8ccc0300` -> `c2ffdcd50300`;
- HEAP_BEGIN immediate at `0x0205e9f8`: `c5ff6066c401` -> `c5ffb06fc401`.

## Exact reservation and boundaries

- Required full 16-slot data-model reservation: `0x0a90` bytes.
- Reserved RAM: `0x01c46520..0x01c46fb0`.
- Candidate HEAP_BEGIN: `0x01c46fb0`.
- Boot BSS zero: `0x01c099d4..0x01c46fb0`, size `0x0003d5dc`.
- Additional over exact S1-C2 parent: `0x0950` bytes.
- Additional over H2/H0 first owned-source reservation: `0x09f0` bytes.

Layout admitted from the data-model:

| Range/address | Size | Purpose |
|---|---:|---|
| `0x01c46520..0x01c46f20` | `0x0a00` | 16 slot records at stride `0xa0` |
| `0x01c46520..0x01c465bc` | `0x009c` | slot 0 voice, exact H2 source |
| `0x01c465bc` | 1 | slot 0 valid, exact H2 valid |
| `0x01c465bd` | 1 | global nonblocking producer lock, exact H2 lock |
| `0x01c46f20..0x01c46fb0` | `0x0090` | header plus 128-entry note map |

## Artifacts

- App: `app.bin`, SHA-256 `c18ed6f4e8ba2c16b99c41e6264cc36804fb38d8800d03ec518ab6bd838a8d14`.
- FWSC: `SMK37Pro-v15-S1C3-16slot-boundary-only.fwsc`, SHA-256 `2345102aadded732b13e22d1410d3f7b05f104ffc408bd1d6eba03ea2afc058c`.
- Official-v15 rollback: `rollback/official-v15-recovery-sectors/manifest.json`.
- S1-C2-parent-relative app changed bytes: `4`.
- Official-v15 changed flash sectors: `0x04000, 0x20000, 0x22000, 0x2a000, 0x62000`.
- S1-C2-parent-relative changed flash sectors: `0x04000, 0x62000`.

## Flash command, if later explicitly authorized

Offline check:

```sh
cc -O2 -g -std=c11 -Wall -Wextra -Wpedantic -Isrc tools/smk37_v15_s1c3_boundary_ota.c src/device_info.c src/fwsc.c src/protocol.c src/sha256.c src/usb_probe.c -o build/smk37-v15-s1c3-boundary-ota $(pkg-config --cflags --libs libusb-1.0)
build/smk37-v15-s1c3-boundary-ota check baselines/v15/analysis/flash-candidates/S1C3-16slot-boundary-only/SMK37Pro-v15-S1C3-16slot-boundary-only.fwsc
```

Upload command/token:

```sh
build/smk37-v15-s1c3-boundary-ota upload baselines/v15/analysis/flash-candidates/S1C3-16slot-boundary-only/SMK37Pro-v15-S1C3-16slot-boundary-only.fwsc baselines/v15/analysis/flash-candidates/S1C3-16slot-boundary-only/live-install-YYYYMMDDTHHMMZ.txt --confirm INSTALL-SMK37PRO-V15-S1C3-16SLOT-BOUNDARY-2345102A
```

Confirmation token: `INSTALL-SMK37PRO-V15-S1C3-16SLOT-BOUNDARY-2345102A`

## Evidence boundary and risk

Live evidence used:

- H0/H2 established the first owned-source boundary at `0x01c46520..0x01c465c0` and live H2 consumption of slot 0.
- S1-C1 live-PASS established the additional `0xa0` boundary-only shift through `0x01c46660` while preserving H2 behavior.
- S1-C2 live v2 is the exact parent and established the current two-slot selector/producer package behavior.
- The data-model requires `0x0a90` bytes for 16 resident `0x9c` payload slots plus the 128-note map/header.

This candidate still needs later live heap-headroom testing. It does not close the data-model functional blockers: Pad enumeration, private 16-slot ingress, full selector/map implementation, and stress proof.

## Validation

`validation.txt` records exact official/S1-C2 parent hashes, exact parent bytes before patching, exactly four S1-C2-parent-relative app-byte changes, package embedding, official-v15 rollback reconstruction, and SHA256 inventory.
