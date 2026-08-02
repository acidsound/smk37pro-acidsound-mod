# v15 R02 transient SysEx-staging checkpoint

R02 is an experimental checkpoint, not a production channel-separation design.
It removes the R01d boot-time preload hook and reuses the live-booted R01b/R01c
channel wrapper shape. Ch10 Note On and Note Off both copy `0x9c` bytes from the
official bulk-SysEx staging address `0x01c37fd0`.

## Why this checkpoint exists

Official v15 statically proves that a complete message with header
`F0 43 00 00 01 1B`, `0x9c` payload bytes, and final `F7` is copied to
`0x01c37fd0` before the packer and current-patch reload calls. R02 neutralizes
the replaced packer entry callers and sends an exact 156-byte Mooger #1 runtime
voice into that staging range.

## Hard limitations

- `0x01c37fd0` is transient shared SysEx workspace, not durable Ch10 storage.
- No other SysEx or bulk preset traffic may occur after loading the R02 voice or
  between a Ch10 Note On and its Note Off.
- Do not press SAVE while R02 is installed. Its direct packer caller is disabled.
- Do not press a pad before the exact R02 runtime packet has been sent.
- A reboot loses the staged voice. Send the exact packet again before pad tests.
- Passing this checkpoint proves only that a loader-compatible runtime voice can
  be consumed from a separately populated RAM source. It does not solve final
  ownership, persistence, per-note patch sets, or concurrent SysEx safety.

## Exact artifacts

- app SHA-256: `eebc5190b2e19dedbba68becb27851e9a26cf35f8356319f75bd9f6c20714948`
- package SHA-256: `93bdf1a7212738b06be8b78919324902729befce8ea07626b0b7aaf7c91e640b`
- runtime packet SHA-256: `6a9b4097cce1d28780ef3a507f42999743cc10e09770c17c5c78d185e9abff27`
- rollback ZIP SHA-256: `7035ab4815322f7461c27d4e5f438eb8726c0d5a525d0b2c32a4a999db22383d`
- changed sectors: `0x04000`, `0x20000`, `0x22000`, `0x2A000`

## Required live order

1. Install R02 and confirm normal boot plus firmware identity `015` without
   touching pads.
2. Send only `build/v15-R02-mooger1-runtime.syx` with the guarded sender.
3. Select Bank D display 14 and compare keyboard Ch1 against Pad Ch10.
4. Change Ch1 to a clearly different UI patch and verify Ch10 remains Mooger #1.
5. Repeat Pad Note On/Off without any intervening SysEx and check for stuck notes.
6. Restore exact official v15 after the checkpoint regardless of result.
