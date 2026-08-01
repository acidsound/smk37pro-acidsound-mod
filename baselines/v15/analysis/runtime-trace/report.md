# Official-v15 endpoint 0x04/0x84 runtime observation report

Date: 2026-08-01 UTC

## Requested boundary

- Device target: official v15 only.
- USB identity expected from the clean v15 baseline: `4353:cf4d`.
- Unit serial expected from the same captured baseline: `1120041B00020312`.
- Interface/endpoints: MIDIStreaming interface 4, bulk OUT `0x04`, bulk IN
  `0x84`, maximum packet 64.
- Prohibited: OTA/upgrade commands, flash writes, device reset, configuration
  changes, arbitrary/high-volume fuzzing, and v12 assumptions.

## Work completed

A standalone, reproducible observer was created at
`v15_usb_midi_observer.c`, with the guarded runner `run_observation.sh`.
The source builds under libusb 1.0.30 with:

```text
-std=c11 -O2 -g -Wall -Wextra -Wpedantic -Werror
```

Its dry-run enumerates 50 fixed outbound USB-MIDI events covering cable numbers,
channels, defined CIN classes, Program Change, CC, pitch bend, SysEx packet
boundaries, universal Identity Request, and a small conservative malformed set.
At most 10 deterministic cleanup events can follow. There is no arbitrary input
or fuzz loop.

Static safety inspection confirmed:

- only official-v15 VID/PID constants are present;
- endpoint writes are only through libusb bulk endpoint `0x04`;
- endpoint reads are only through libusb bulk endpoint `0x84`;
- no libusb control transfer, reset, set-configuration, or driver-detach call is
  present;
- `F0 22 24` occurs only in the explicit rejection check, not in the matrix;
- every test write is 4-byte aligned and no short bulk transfer test exists.

## Live execution result

No runtime packets were sent because the device was not visible to macOS or
libusb during the observation window.

Evidence:

- the repository's existing descriptor-only probe returned no matching device;
- `system_profiler SPUSBDataType` reported no external USB device entry;
- `ioreg -p IOUSB` contained no `SMK`, `4353`, or `cf4d` identity;
- six checks over 30 seconds from `18:58:53Z` through `18:59:19Z` found no v15
  identity;
- an additional 60 exact-identity checks over five minutes from `19:02:30Z`
  through `19:07:32Z` found zero devices;
- CoreAudio exposed no matching SMK audio service;
- the new exact-v15 observer found zero devices during enumeration at
  `19:02:20Z` and during an explicit `--execute all` attempt at `19:07:42Z`;
  see `enumeration-20260801T1902Z.log` and
  `execution-attempt-20260801T1907Z.log`.

The observer therefore refused before interface claim and before any endpoint
transfer. This is the safe outcome for an absent or non-enumerated target.

## Dispatcher conclusions

No new dispatcher semantic conclusion can honestly be drawn from this run,
because both the enumeration and explicit live execution attempt refused before
interface claim. There was no OUT transfer and no IN response. In particular,
this run does not establish whether v15 accepts or ignores any cable number,
CIN, channel, Program Change, CC, pitch bend, SysEx boundary, or malformed case.

The tool is ready to produce those constraints as soon as the exact v15 device
enumerates. A successful run will log raw packet/result pairs and IN traffic.
Physical speaker audio and display/state changes still require human observation
at each logged `OBSERVATION_WINDOW`; USB success alone must not be reported as
an audible or UI effect.

## Reproduction

Read-only enumeration:

```sh
baselines/v15/analysis/runtime-trace/run_observation.sh --enumerate
```

Inspect the complete fixed matrix without a device:

```sh
baselines/v15/analysis/runtime-trace/run_observation.sh --dry-run all
```

Execute only after the exact official-v15 unit is visible:

```sh
EXECUTE_V15_USB_MIDI=YES \
  baselines/v15/analysis/runtime-trace/run_observation.sh --execute all
```

No commit was made.
