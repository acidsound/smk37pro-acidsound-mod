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
Public FCC and community PCB evidence, the absence of a confirmed reset/boot
jumper, and the photo-first internal inspection gate are recorded in
`docs/internal-recovery-entry.md`.

The Windows forced-mode checkpoint is packaged from `windows-readonly/`. It
can run the reviewed official WL82 loader from volatile RAM and acquire two
byte-identical 1 MiB forced-loader dumps, but deliberately contains no Flash
write path and never authorizes restoration.
Build its portable ZIP with `tools/build_windows_readonly_bundle.py` after
supplying the hash-locked official loader.

The guarded sector-specific restore tool is `tools/smk37_guarded_restore.py`.
It restores only the app area (`0x4300..0x9A832`) from an FWSC package to a
live or forced-loader flash dump, preserving the boot header, JLFS header,
tail metadata, and beyond-package region byte-exact. See
`docs/flash-layout-cipher-analysis.md` for the full flash region map, cipher
details, and safety guarantees.

The offline v12 application-only verifier/repacker is
`tools/smk37_app_patch.py`. It does not communicate with the device, and the
live recovery uploader rejects its modified output by SHA-256.
