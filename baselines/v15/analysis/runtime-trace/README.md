# Official-v15 USB MIDI runtime trace

## Scope

This directory is intentionally limited to the official-v15 USB identity
`4353:cf4d`, MIDIStreaming interface 4, bulk OUT endpoint `0x04`, and bulk IN
endpoint `0x84`. It does not use v12 identities, behavior, packet captures, or
interpretations.

The observer is host-side only. It contains no OTA implementation, flash read
or write implementation, vendor control-command mode, arbitrary packet input,
device reset, configuration change, or kernel-driver detach operation.

## Safety invariants

`v15_usb_midi_observer.c`:

- refuses unless exactly one `4353:cf4d` device is present;
- optionally requires the captured unit serial
  `1120041B00020312`;
- verifies interface 4 is USB Audio/MIDIStreaming and endpoints `0x04/0x84`
  are 64-byte bulk endpoints before opening the test path;
- requires an explicit `--execute` mode for every OUT transfer;
- exposes only a compiled fixed matrix, not arbitrary hex input;
- sends only 4-byte-aligned USB-MIDI event packets;
- rejects any fixed case containing the known upgrade SysEx prefix
  `F0 22 24`;
- caps a run at 80 outbound events. The complete test matrix uses 50 events,
  plus at most 10 cleanup events;
- pairs every audible Note On with a short-delay Note Off and sends bounded
  note-off, all-notes-off, and pitch-center cleanup;
- stops immediately on `LIBUSB_ERROR_NO_DEVICE`;
- never calls `libusb_control_transfer`, `libusb_reset_device`,
  `libusb_set_configuration`, or a kernel-driver detach function.

The SysEx cases are deliberately limited to empty/boundary messages, the
non-commercial manufacturer ID `0x7d` with no payload command, and the standard
universal non-realtime Identity Request. No Jieli or SMK vendor SysEx is sent.

## Fixed matrix

The groups are:

- `cables`: cables 0, 1, 2, and boundary cable 3, each with a velocity-24 Note
  On followed by Note Off;
- `channels`: channels 1, 10, and boundary channel 16;
- `cin`: defined CIN 2, 3, 8, 9, A, B, C, D, E, and F messages using neutral or
  reset values;
- `program`: Program Change 0, 1, restore 0 on channel 1, and Program Change 0
  on channel 10;
- `cc`: modulation 0/64/0, sustain off, and all-notes-off;
- `pitch`: minimum, center, maximum, restore center;
- `sysex`: well-formed endings through CIN 5, 6, and 7, plus universal Identity
  Request split across CIN 4 and 7;
- `malformed`: reserved CIN 0/1 with zero payload, harmless CIN/status
  mismatches with note-off semantics, nonzero Program Change padding, SysEx end
  without start, and a data byte in the status slot.

Short bulk transfers, unterminated long SysEx, random bytes, high cable numbers,
and high-rate fuzzing are intentionally excluded.

## Build and inspect without a device

```sh
baselines/v15/analysis/runtime-trace/run_observation.sh --dry-run all
```

Direct equivalent:

```sh
mkdir -p build/runtime-trace
cc -std=c11 -O2 -g -Wall -Wextra -Wpedantic -Werror \
  $(pkg-config --cflags libusb-1.0) \
  baselines/v15/analysis/runtime-trace/v15_usb_midi_observer.c \
  -o build/runtime-trace/v15-usb-midi-observer \
  $(pkg-config --libs libusb-1.0)
build/runtime-trace/v15-usb-midi-observer --dry-run all
```

## Exact-v15 enumeration with no interface claim or endpoint transfer

```sh
baselines/v15/analysis/runtime-trace/run_observation.sh --enumerate
```

Override the unit serial only when intentionally testing another confirmed
official-v15 unit:

```sh
V15_SERIAL=OTHER_SERIAL \
  baselines/v15/analysis/runtime-trace/run_observation.sh --enumerate
```

## Live execution

The wrapper adds a second opt-in beyond the binary's `--execute` flag:

```sh
EXECUTE_V15_USB_MIDI=YES \
  baselines/v15/analysis/runtime-trace/run_observation.sh --execute all
```

Run groups separately when a human is available to annotate audible output and
display/state changes:

```sh
EXECUTE_V15_USB_MIDI=YES \
  baselines/v15/analysis/runtime-trace/run_observation.sh --execute cables
```

Every run appends a timestamped TSV log containing device identity, each exact
OUT packet and libusb result, every IN transfer, disconnect detection, cleanup,
and interface release. `OBSERVATION_WINDOW` rows mark where a human observer
should record audio, display, and other state changes. The host tool cannot see
the physical display or objectively hear the keyboard's local speakers, so
those fields must not be inferred from successful USB transfers.
