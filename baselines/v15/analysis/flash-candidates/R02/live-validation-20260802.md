# v15 R02 live validation

Date: 2026-08-02 UTC

## Result

**PASS as a controlled checkpoint.** R02 proved that Channel 10 can consume an independently staged, loader-compatible runtime FM voice while Channel 1 continues using the UI-selected patch.

This is not yet a production design. The successful source was the official transient SysEx workspace at `0x01c37fd0`, so durable ownership, concurrent SysEx safety, persistence, and per-note patch sets remain future work.

## Exact artifacts

- R02 package SHA-256: `93bdf1a7212738b06be8b78919324902729befce8ea07626b0b7aaf7c91e640b`
- R02 app SHA-256: `eebc5190b2e19dedbba68becb27851e9a26cf35f8356319f75bd9f6c20714948`
- Mooger #1 staging packet SHA-256: `6a9b4097cce1d28780ef3a507f42999743cc10e09770c17c5c78d185e9abff27`
- R02 rollback ZIP SHA-256: `7035ab4815322f7461c27d4e5f438eb8726c0d5a525d0b2c32a4a999db22383d`
- Exact-gated uploader SHA-256: `b7d45c70ba46ec8a9eb8c5da9747eb0b6d62071a2a4bee4a3b5bad52bfbaa709`

## Live sequence and observations

1. Installed the exact R02 package through the SHA- and token-gated v15 uploader.
2. The uploader completed both OTA stages. Its integrated post-update check hit the known macOS `LIBUSB_ERROR_ACCESS` condition.
3. A separate read-only query immediately proved normal boot and identity `SMK-37 Pro_015` before any pad input.
4. Sent exactly one guarded 163-byte product SysEx packet, encoded as 220 USB-MIDI bytes, before touching pads.
5. The user selected Bank D display **14**, Mooger #1, and compared the keyboard reference against Pad Channel 10.
6. User-reported live checks all passed:
   - keyboard Ch1 reference played correctly;
   - Pad Ch10 matched Mooger #1;
   - Pad Ch10 Note Off worked with no stuck note;
   - after changing the Ch1 UI patch, Pad Ch10 remained Mooger #1.
7. No SAVE, reboot, or additional SysEx occurred during the controlled comparison.

## What is now proven

- The previously demonstrated Ch1/Ch10 call-path split is functional on official-v15-derived code.
- Both Ch10 Note On and Note Off can consume the same independently populated `0x9c` runtime voice source.
- The 156-byte runtime representation staged through the official product SysEx path is sufficient to reproduce the intended Bank D display 14 Mooger #1 timbre.
- Ch1 patch changes do not overwrite the staged Ch10 voice during this constrained test.
- The prior R01b/R01c wrong-timbre behavior was not evidence that the voice data was invalid. R02 shows that correct loader-compatible runtime staging and lifecycle are decisive.

## What is not yet proven

- `0x01c37fd0` is not safe permanent storage. Another SysEx or bulk/preset operation may overwrite it.
- R02 has no persistent Ch10-owned RAM object, generation/version guard, or synchronization.
- Reboot persistence is absent.
- A 16-pad per-note patch set, UI editor, SAVE/load lifecycle, and resource budgeting are not implemented.
- Production-safe Note On/Off behavior under concurrent SysEx or patch-management operations is not established.

## Mandatory post-test restoration

The exact official v15 package SHA-256 `f7f1831cd7c9ad8b4831b6e71ea0bdbcdff9ae4c4077276b3c965511bf4d4fff` was installed immediately after the checkpoint.

Restoration evidence:

- separate read-only identity query: `SMK-37 Pro_015`;
- device managed range `0x00000..0x9bfff` read back as 638,976 bytes;
- managed-range SHA-256: `9d68aaece688d23f487cad734c387399a720e9dbebed613a09304dc666a11936`;
- managed range is byte-identical to the verified post-recovery official-v15 baseline prefix.

Therefore the device ended this checkpoint on the verified official v15 application baseline, not R02.
