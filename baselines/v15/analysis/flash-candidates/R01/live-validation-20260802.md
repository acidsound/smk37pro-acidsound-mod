# v15 R01 live validation, 2026-08-02

## Artifact

- Package: `build/SMK37Pro-v15-R01-hand-drum.fwsc`
- Package SHA-256: `292809383e89ba7032619ae338dfb5bd195409600f417de5e8edb98149f66462`
- App SHA-256: `e12ac71df2be155a977b6135eedee2bda821226bf354cf8062d3a9624df474c7`
- Official-v15 input SHA-256: `36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055`
- OTA transcript: `logs/v15/ota-v15-r01-live-20260802T1738Z.log`

## Preconditions

- The physical Pad fault was repaired by the user.
- A Pad press emitted USB MIDI `99 24 66`, proving human MIDI Channel 10,
  Note 36, velocity 102 at the external MIDI boundary.
- `tools/validate_v15_mod_capabilities.py`, `make test`, and OTA packet dry-run
  passed before installation.
- Device preflight reported `SMK-37 Pro_015`.

## Installation observation

The OTA normal-mode and update-mode interfaces were both claimed and the tool
reported `OTA completed; waiting for normal firmware`. The tool's immediate
post-update identity check failed only because macOS CoreMIDI reclaimed
interface 4 first (`LIBUSB_ERROR_ACCESS`). After stopping `MIDIServer`, a
separate `device-info` call returned:

```text
name: SMK-37 Pro
version: 015
```

This is recorded as a successful install with a host-side post-check race, not
as an OTA transfer failure.

## Live functional observation

The user pressed the repaired physical Pads after R01 installation and reported
that Channel 10 changed to a different sound. This live-proves that the human
Channel-10 branch is reached and can select a source different from the stock
Ch1 path.

A raw MIDI test also transmitted:

- Ch1 notes 60, 64, 67 with matching Note Off events;
- Ch10 notes 36, 40, 43 with matching Note Off events.

The confirmed positive claims are therefore:

- the stock/non-Ch10 branch and Channel-10 branch select different runtime
  timbre sources on the installed R01 artifact;
- physical Pad Channel-10 activity reaches the behavior needed for the R01
  separation goal;
- the R01 package installs and boots as firmware identity `015`.

However, the intended `HAND DRUM ` identity was **not** confirmed. R01 also
failed Note Off for Ch10 and left a sustained/stuck voice. The later R01b and
R01c experiments routed Note On and Note Off through the same Ch10 source and
thereby restored working Note Off, but neither the requested BUZZ BASS nor Bank
D display number 14 (`Mooger #1`, binary index 13) matched the corresponding
stock UI Patch. Both later experiments instead produced an unintended sound
whose pitch continuously fell while Note On remained held.

The live result is therefore classified as:

| Claim | Result |
|---|---|
| Ch1/Ch10 branch separation | **PASS** |
| Physical Pad reaches the Ch10 branch | **PASS** |
| Shared Ch10 source for Note On/Off prevents the R01 stuck note | **PASS in R01b/R01c** |
| Static 156-byte snapshot selects the named factory voice | **FAIL** |
| Ch10 can yet be assigned an intentional known Patch | **NOT ESTABLISHED** |

The earlier assumption that a deterministically expanded 128-byte DX7 factory
entry can be copied directly as the dispatcher source object is revoked. The
object at `0x01c34c74` must be treated as a runtime object with an unproven
producer, lifecycle, or post-load initialization until those are recovered
from official v15 code.

## Claims not promoted by this observation

This checkpoint does not claim:

- a 10-minute soak test;
- exhaustive stuck-note and release-order coverage;
- isolated per-note drum voices;
- Program Change, CC, pitch-bend, SysEx, or sequencer regression completion;
- recovery behavior under interrupted storage or power loss.

It also specifically does not claim that HAND DRUM, BUZZ BASS, or Mooger #1 was
successfully selected for Ch10.

The device was restored to exact official v15 after the disproven R01c
experiment. No further voice-selection patch should be flashed until the
runtime object producer and required initialization are independently proven.
