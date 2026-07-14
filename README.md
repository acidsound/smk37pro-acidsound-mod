# SMK-37 Pro direct USB research tool

Native macOS tooling for inspecting the SMK-37 Pro over USB-C without using
CoreMIDI or SysEx APIs. It can query the device, read and dump main flash,
inspect `.fwsc` packages, and reproduce the vendor's two-stage OTA protocol.

The project is intentionally locked to the archived official
`SMK-37 Pro_012` package for live writes. Display firmware 1.05 reports updater
version `012`.

## Build and test

Requirements: a C11 compiler, `pkg-config`, and libusb 1.0.30 or newer.

```sh
make
make test
```

For live-device commands on macOS, use the wrapper so `MIDIServer` does not
own the USB-MIDI streaming interface:

```sh
scripts/smk37-fw-direct device-info
scripts/smk37-fw-direct dump backups/live.bin
```

See `docs/firmware-runbook.md` for the guarded upload procedure and
`docs/research-notes.md` for evidence, hashes, hardware findings, and remaining
unknowns. The safety gates and static implementation route for the FM drum
extension are tracked in `docs/fm-drum-plan.md`. Custom display/build IDs and
their immutable artifact ledger are defined in `docs/firmware-versioning.md`.
The M09 boot failure, likely causes, and recovery-safety lessons are recorded
in `docs/m09-brick-incident.md`.

The offline v12 application-only verifier/repacker is
`tools/smk37_app_patch.py`. It does not communicate with the device, and the
live recovery uploader rejects its modified output by SHA-256.
