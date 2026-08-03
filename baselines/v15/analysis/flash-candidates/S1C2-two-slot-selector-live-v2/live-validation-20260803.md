# S1-C2 live validation

Date: 2026-08-03 UTC

## Installed artifact

- FWSC SHA-256: `63e3cfa39473df08bd225df2c8ae81dbfe7aafbd31da6cc6dcf64ca03453681e`
- App SHA-256: `4afd13d7301c2ae209c11d3fe932d019faa770b551f2d8a38cf4c018c7aafa8a`
- Device identity after OTA and after staging: `SMK-37 Pro`, version `015`
- OTA transport completed. The wrapper returned failure only because macOS reclaimed interface 4 before its immediate post-update identity check. Independent identity checks then passed twice.

## Staging

The guarded sender successfully transmitted, in exact order:

1. Slot 0, Ch10 Note 36, Bank D patch 14 `Mooger #1`
2. Slot 1, Ch10 Note 45, Bank D patch 12 `HAND DRUM`

Both transfers were 163 SysEx bytes packetized as 220 USB-MIDI bytes.

## Live observations

- Physical Pad/Ch10 Note 36 selected `Mooger #1`.
- The initial report that every other Pad used the Ch1 sound was not a slot failure. The physical location corresponding to MIDI Note 45 was not known during that test.
- A direct raw Ch10 discriminator transmitted Note 36, Note 45, and fallback Note 40 in order.
- User confirmed the direct discriminator was fully normal:
  - Note 36 selected `Mooger #1`.
  - Note 45 selected `HAND DRUM`.
  - Note 40 followed the expected fallback behavior.
- No reboot or stuck-note failure was reported in this validation.

## Verdict

**LIVE PASS** for the S1-C2 two-slot selector checkpoint.

This proves two distinct resident Ch10 patches can be staged and selected by individual MIDI note while other notes retain the fallback path. It does not yet identify the physical location of every Pad note, implement more than two resident slots, provide UI editing, or provide persistence.
