# v15 physical Pad to MIDI note map

Date: 2026-08-03 UTC
Device state: S1-C2 live v2, identity `SMK-37 Pro_015`
Capture: `pad-map-live-20260803.log`

The user pressed the 4×4 Pad matrix from left to right, top row to bottom row. After removing the duplicated USB-MIDI cable 1 stream and earlier exploratory presses, one exact complete row-major sequence begins at Ch10 Note On index 52.

| Physical Pad | Position | MIDI note | Hex |
|---:|---|---:|---:|
| 1 | row 1, col 1 | 48 | `0x30` |
| 2 | row 1, col 2 | 49 | `0x31` |
| 3 | row 1, col 3 | 50 | `0x32` |
| 4 | row 1, col 4 | 51 | `0x33` |
| 5 | row 2, col 1 | 44 | `0x2c` |
| 6 | row 2, col 2 | 45 | `0x2d` |
| 7 | row 2, col 3 | 46 | `0x2e` |
| 8 | row 2, col 4 | 47 | `0x2f` |
| 9 | row 3, col 1 | 40 | `0x28` |
| 10 | row 3, col 2 | 41 | `0x29` |
| 11 | row 3, col 3 | 42 | `0x2a` |
| 12 | row 3, col 4 | 43 | `0x2b` |
| 13 | row 4, col 1 | 36 | `0x24` |
| 14 | row 4, col 2 | 37 | `0x25` |
| 15 | row 4, col 3 | 38 | `0x26` |
| 16 | row 4, col 4 | 39 | `0x27` |

## S1-C2 locations

- Note 36 / Mooger #1 is physical Pad 13, bottom-left.
- Note 45 / HAND DRUM is physical Pad 6, second row and second column.

## Invariant useful for firmware

The Pad notes are the contiguous range 36 through 51. A resident slot index can therefore be computed as `note - 36`, while the visual row-major Pad index is:

- notes 48..51 -> Pads 1..4
- notes 44..47 -> Pads 5..8
- notes 40..43 -> Pads 9..12
- notes 36..39 -> Pads 13..16

The direct capture also contained unrelated Note 64 and exploratory repeated presses. These are excluded because the exact complete 16-note row-major sequence is independently present and all 16 notes have matching Ch10 Note Off events in the raw log.
