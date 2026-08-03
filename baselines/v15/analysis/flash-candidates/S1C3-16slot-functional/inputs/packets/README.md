# S1-C3 exact Bank D 1..16 packet PASS input

Status: **PASS** for offline functional integration and dry-run validation. **BLOCK** for live send/device access unless explicitly authorized later with the generated exact sender and confirmation token.

- Source commit: `fe3350063c56a0cff7ab855735b0c7e8a04c957e` (`fe33500`).
- Source directory: `baselines/v15/analysis/patch-set-ui/s1c3/packet-set-bank-d-1-16`.
- Packet order: note order slots `0..15` -> MIDI notes `36..51`.
- Each packet is exact Yamaha product SysEx: `F0 43 00 00 01 1B` + 156 runtime bytes + `F7`, total 163 bytes.
- Physical Pad permutation from `2a23cf5017eff520f775e511f8d3d80e15163e7d` is UI-only and must not change producer, selector, packet, or sender ordering.

No device, USB/MIDI transport, flash, reset, or live send was performed by this integration input.
