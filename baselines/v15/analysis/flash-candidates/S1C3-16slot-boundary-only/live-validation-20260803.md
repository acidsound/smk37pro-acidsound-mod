# S1-C3 16-slot boundary-only live validation

Date: 2026-08-03 UTC

## Exact artifact

- FWSC SHA-256: `2345102aadded732b13e22d1410d3f7b05f104ffc408bd1d6eba03ea2afc058c`
- App SHA-256: `c18ed6f4e8ba2c16b99c41e6264cc36804fb38d8800d03ec518ab6bd838a8d14`
- Reserved RAM: `0x01c46520..0x01c46fb0`, `0x0a90` bytes
- Exact S1-C2-parent-relative code changes: only the two BSS/HEAP boundary immediates, four app bytes total

## Installation

The exact-hash uploader completed OTA. Its immediate post-update check encountered the known macOS interface-4 reclaim race, then independent device identity checks passed as `SMK-37 Pro_015` before and after staging.

The exact S1-C2 slot packets were restaged in order:

1. Note 36 / `Mooger #1`
2. Note 45 / `HAND DRUM`

## Live observations

- The user heard `Mooger #1` at physical Pad 9 / Ch10 Note 36.
- The user heard `HAND DRUM` at physical Pad 14 / Ch10 Note 45.
- A subsequent 90-second direct USB-MIDI capture remained connected and received three complete Pad 1..16 sequences, 198 total raw events, without monitor failure or device disconnect.
- The device and MidiSuite UI remained operational; the screenshot showed the connected controller UI.
- No reboot or stuck-note failure was reported during this checkpoint.

## Verdict

**LIVE PASS** for the `0x0a90` boundary-only reservation.

This proves the full proposed 16-slot/header RAM prefix can be excluded from the heap and zeroed as BSS on this device while retaining the live-PASS S1-C2 two-slot behavior. It does not yet prove consumption of all sixteen slots, a 16-packet producer, full-set publication, UI editing, persistence, or worst-case application stress beyond the recorded Pad capture.
