# v15 physical Pad MIDI-note evidence

Date: 2026-08-02

## Decision

The firmware and host tooling must **not** assume that the 16 physical Pads are permanently mapped to MIDI notes 36..51.

The official user manual states that MIDI messages emitted by Faders, Knobs, and Pads are customizable with MIDI Suite. It also documents a Pad Bank gesture that switches the physical controls to Pads 17–32. Therefore the stable patch-set key is the incoming Channel 10 MIDI note value, not a fixed physical-pad ordinal.

The v15 patch-set format consequently accepts exactly 16 distinct notes chosen from the full MIDI range 0..127 and emits a 128-byte note-to-slot lookup table. A 36..51 configuration remains a diagnostic example only.

## Official documentation evidence

Pinned repository:

- Repository: `https://github.com/jonathaslacerda/smk-37-pro-docs`
- Commit: `8f1bf1115cc8fe874bbac326d4f1f1513d743844`
- Manual: `manual/smk-37-pro-user-manual.pdf`
- Git blob: `7d7836d91193155f5c2d6b12fad585fd73ae0abd`

Relevant manual statements:

- `Pad Bank: Press both Knob Bank and Fader Bank buttons simultaneously to switch control to pads 17–32.`
- `You can customize the MIDI messages sent by the Faders/Knobs/Pads using the MIDI Suite software.`

These statements make a permanent physical-pad-to-note table an invalid firmware invariant.

## Live captures

All captures used `build/smk37-fw midi-monitor` and duplicated each USB-MIDI event on cable 0 and cable 1.

### Capture A, 60 seconds

Observed Channel 10 data after cable de-duplication:

| Order | Message | Meaning |
|---:|---|---|
| 1 | `89 25 40` | Note Off 37; matching Note On began before capture or was missed |
| 2 | `99 27 1f` | Note On 39 |
| 3 | `89 27 40` | Note Off 39 |
| 4 | `99 24 10` | Note On 36 |
| 5 | `89 24 40` | Note Off 36 |
| 6 | `99 24 16` | Note On 36, second strike |
| 7 | `89 24 40` | Note Off 36 |
| 8 | `99 26 1d` | Note On 38 |
| 9 | `89 26 40` | Note Off 38 |

Unrelated Channel 1 CC messages were also observed.

### Capture B, 90 seconds

Observed one complete Channel 10 pair:

- `99 2d 13`: Note On 45
- `89 2d 40`: Note Off 45

A Channel 1 keyboard Note 81 pair was unrelated.

### Capture C, 180 seconds

No MIDI events were received. This is not evidence about Pad mapping.

## Confirmed live facts

- Physical Pad input can emit Channel 10 Note On and Note Off.
- Live-observed notes include 36, 38, 39, and 45.
- Note On velocity varies per strike.
- Note Off velocity was `0x40` in these captures.
- A complete 16-Pad ordinal mapping was not captured.
- Such a mapping is mutable user configuration, so it must not be compiled into firmware as a fixed table.

## Implementation consequence

`tools/build_v15_patch_set.py` now requires:

- exactly 16 slots;
- 16 distinct note values in 0..127;
- bank values 1..4;
- patch values 1..32.

It emits `note-map.bin`, 128 bytes total:

- each configured note contains its runtime slot index 0..15;
- every unconfigured note contains `0xff`.
- runtime slot indices preserve config order, allowing the same order to represent the 4x4 on-device UI grid even when MIDI note values are noncontiguous or unsorted.

The runtime consumer can therefore perform bounded O(1) lookup for arbitrary MIDI Suite Pad assignments without assuming notes 36..51.
