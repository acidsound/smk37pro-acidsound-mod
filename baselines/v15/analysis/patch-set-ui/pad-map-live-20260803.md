# v15 physical Pad number to MIDI note map

Date: 2026-08-03 UTC
Device state: S1-C3 16-slot boundary-only with the S1-C2 two-slot behavior retained, identity `SMK-37 Pro_015`
Authoritative capture: `pad-map-2x8-confirm-20260803.log`
Supersedes: the incorrect 4×4 interpretation previously recorded in this file

## Physical numbering

The official MidiSuite UI and the physical controller use a **2×8** layout:

```text
Top:     Pad  1   2   3   4   5   6   7   8
Bottom:  Pad  9  10  11  12  13  14  15  16
```

The user pressed Pad `1..16` in this exact order. After removing the duplicated USB-MIDI cable 1 stream, the same complete sequence was captured **three times identically**.

| Physical Pad | Position | MIDI note | Hex |
|---:|---|---:|---:|
| 1 | top row, col 1 | 40 | `0x28` |
| 2 | top row, col 2 | 41 | `0x29` |
| 3 | top row, col 3 | 42 | `0x2a` |
| 4 | top row, col 4 | 43 | `0x2b` |
| 5 | top row, col 5 | 48 | `0x30` |
| 6 | top row, col 6 | 49 | `0x31` |
| 7 | top row, col 7 | 50 | `0x32` |
| 8 | top row, col 8 | 51 | `0x33` |
| 9 | bottom row, col 1 | 36 | `0x24` |
| 10 | bottom row, col 2 | 37 | `0x25` |
| 11 | bottom row, col 3 | 38 | `0x26` |
| 12 | bottom row, col 4 | 39 | `0x27` |
| 13 | bottom row, col 5 | 44 | `0x2c` |
| 14 | bottom row, col 6 | 45 | `0x2d` |
| 15 | bottom row, col 7 | 46 | `0x2e` |
| 16 | bottom row, col 8 | 47 | `0x2f` |

Exact Pad `1..16` Note On sequence:

```text
40, 41, 42, 43, 48, 49, 50, 51,
36, 37, 38, 39, 44, 45, 46, 47
```

All sixteen note values also had matching Ch10 Note Off events.

## S1-C2 live anchors

- Physical **Pad 9** -> Note 36 -> slot 0 -> `Mooger #1`.
- Physical **Pad 14** -> Note 45 -> slot 1 -> `HAND DRUM`.

The user independently identified both locations by sound before the confirmation capture. The capture agrees exactly.

## Firmware and UI implication

The configured Pad notes are the contiguous set `36..51`, so the current low-level selector may still use a note-ordered resident slot index `note - 36`. However, **note order is not physical Pad-number order**.

If resident slots are note-ordered, the UI permutation is:

```text
physical Pad -> note-ordered slot
1..4   -> 4..7
5..8   -> 12..15
9..12  -> 0..3
13..16 -> 8..11
```

Equivalently:

```text
Pad 1..16 -> slot 4,5,6,7,12,13,14,15,0,1,2,3,8,9,10,11
```

The UI must display and edit by physical Pad number while translating through this mapping. It must not label `slot 0` as `Pad 1`.

This is a live mapping for the user's current device configuration. Because MidiSuite can configure Pad MIDI assignments, it must not be promoted to an immutable hardware-wide mapping without configuration/persistence evidence.
