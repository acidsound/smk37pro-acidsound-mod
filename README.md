# SMK-37 Pro Acidsound Mod

[English](README.md) | [한국어](README.kr.md)

A firmware mod research project for the SMK-37 Pro drum machine. We analyze the
official firmware's USB OTA path directly and mod the firmware so that arbitrary
Yamaha DX7 drum voices can be loaded into the internal **Ch10 drum synth**. All
work proceeds with records verified on a live device.

> ⚠️ **This is a personal research project.** Flashing a live device carries a
> brick risk; only flash after passing the hash-locked OTA gate and having a
> rollback procedure ready.

## Current status (2026-08)

- **Installed firmware**: **S1-C5 Marked Playback Note**, based on official v15 (015) —
  latest live-device flash succeeded (2026-08-04, `post-update=SMK-37 Pro_015 verified`).
- **Features**: load a DX7 single-voice SysEx onto each of the 16 pads and set the
  internal Ch10 synth's playback note per pad.
- **Distribution**: only the most recently flash-verified firmware is uploaded to
  [Releases](https://github.com/acidsound/smk37pro-acidsound-mod/releases).
- **Web app**: [Patch Set Editor (GitHub Pages)](https://acidsound.github.io/smk37pro-acidsound-mod/patch-set-editor/) —
  a dependency-free static app that sends 16 patches to the live device via Chrome Web MIDI.

## Repository layout

```
├── docs/                # mod docs (runbook, versioning, plans, incident records)
├── src/                 # host-side USB OTA tool C sources (libusb)
├── scripts/             # smk37-fw-direct wrapper (avoids the MIDIServer conflict)
├── tools/               # mod build/verify/rollback scripts
├── patch-set-editor/    # web editor (Pages hosting target; public/ is the site root)
├── Makefile
└── .github/workflows/   # Pages deployment (patch-set-editor subpath)
```

Intermediate artifacts of development and analysis (OTA logs, flash dumps,
candidate analyses, rollback material, etc.) are not included in this repository;
they are kept in the local workspace. Only the **final records (docs, sources,
tools) and firmware that recently flashed successfully** are uploaded here.

## Build (host tool)

Requirements: a C11 compiler, `pkg-config`, and libusb 1.0.30+.

```sh
make
make test
```

For live-device commands on macOS, use the wrapper so `MIDIServer` does not
own the USB-MIDI interface.

```sh
scripts/smk37-fw-direct device-info
scripts/smk37-fw-direct dump backups/live.bin
```

## Web editor

The editor in [`patch-set-editor/`](patch-set-editor/) is deployed to Pages
automatically by GitHub Actions on every push to main.

- Site: <https://acidsound.github.io/smk37pro-acidsound-mod/patch-set-editor/>
- Usage: open it in Desktop Chrome → **Connect Web MIDI** → allow SysEx
  permission → load patches → **Send 16 patches**. (Always resend after a reboot.)
- Details: [`patch-set-editor/README.md`](patch-set-editor/README.md)

## Safety rules (core)

- The OTA uploader accepts only an **exact SHA-256 match gate**. Never substitute
  arbitrary switches for it.
- Before writing to the live device, take a baseline with read-only
  `device-info`/dump, and have a rollback procedure ready for failure before
  proceeding.
- Past failures (M09/M10 boot failures, S1C7 live failure) are recorded in
  `docs/`. Do not repeat them.

## Documentation

| Document | Contents |
|---|---|
| [`docs/firmware-runbook.md`](docs/firmware-runbook.md) | Live-device OTA procedure · safety boundaries |
| [`docs/firmware-versioning.md`](docs/firmware-versioning.md) | Custom build ID scheme · immutable ledger |
| [`docs/fm-drum-plan.md`](docs/fm-drum-plan.md) | Ch10 FM drum expansion plan |
| [`docs/v15-s1c-status.md`](docs/v15-s1c-status.md) | v15 S1C series timeline · status |
| [`docs/m09-brick-incident.md`](docs/m09-brick-incident.md) | M09 boot failure analysis |
| [`docs/forced-recovery-plan.md`](docs/forced-recovery-plan.md) | Forced recovery plan |
| [`docs/research-notes.md`](docs/research-notes.md) | Research notes · hardware investigation |

## License · Disclaimer

This repository contains no official firmware images or flash dumps (only mod
results and documentation). You are responsible for any damage, data loss, or
voided warranty caused by using modded firmware. Related trademarks belong to
their respective owners.
