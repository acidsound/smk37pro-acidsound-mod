# Pinned AC79 SDK signatures versus official v15

## Scope and conclusion

This directory analyzes only the exact official v15 application image and the
public SDK revision cited by `../public-research.md`. No v12 artifact was read.
Nothing was patched, flashed, or committed.

**Defensible result:** the pinned SDK is a strong code-lineage match for v15,
including five independently exact USB-device primitives and eighteen positive
relocation-aware calibration functions. However, the pinned SDK's public MIDI
synth implementation does **not** produce a defensible byte, relocation-aware,
table, string, or operation-table match in v15. Therefore this evidence does
not assign v15 Note On, Note Off, synth context, or voice structure addresses.
Doing so would violate the requested two-independent-match threshold.

The exact v15 image does contain two independently recognizable MIDI ingress
components, documented below. They establish MIDI message decoding and some
16-slot/channel routing state, but they do not establish the downstream synth
ABI.

## Immutable inputs

- Official v15 `app.bin`: 617,012 bytes, SHA-256
  `36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055`.
- Runtime mapping used here: file offset `x` maps to `0x02000000 + x`.
- SDK: `https://gitee.com/Jieli-Tech/fw-AC79_AIoT_SDK`, branch
  `release/AC79NN_SDK_V1.2.0`, commit
  `e30b1ee375d1f2993fc23bf92c8b99006a6e5f9d`.
- `lib_midi_dec.a`: SHA-256
  `3f4a38dbec69eb2f85c56838eaa461252c8ee0e419211d06aebf46ce9bc62f03`.
- `audio_server.a`: SHA-256
  `16de11ce1f363f37cdc9c1e84cb169ebdc3bfc802d6f932172bcb40f07d2f6ae`.
- `sdk.elf`: SHA-256
  `250b0534fee9f57208b42e38c97c36982875fac901db1d9979e781f0d26e0cf3`.

`report.json` contains deterministic archive-member hashes, all exact ELF
matches, exact v15 fingerprints, and hash guards for both inputs.

## What is actually in the public archives

The archive members are LLVM IR bitcode, not final ELF objects. Producer data
identifies clang 4.0.1 and pi32v2/r3. Relevant members are:

| archive | member | bytes | SHA-256 |
|---|---|---:|---|
| `lib_midi_dec.a` | `midi_fread_tone.o` | 19,268 | `9e40881f024389b7a7586337735daf627a7ff55ec517476e75f8a9475a333a0a` |
| | `midi_synth.o` | 62,952 | `cdf37140e8ed16cf5fd9584f68eae03f45c838998893e4e6f264342fa2834460` |
| | `midi_tabs.o` | 1,888 | `bdbcbc023669ee799ddc10aab51660b2844766d3793e445542e31e45bcb95c7f` |
| `audio_server.a` | `midi_ctrl_decoder.c.o` | 29,788 | `b689323c0f1b5a12c23b29289bf4a9784c7bbe4d5a62ebfc621d29c41d3f7e88` |
| | `midi_dec.c.o` | 115,972 | `65bcde837323646284b04e8f4eb3237e823b13753efdf1722ded9ca6676517c5` |
| | `midi_event.c.o` | 115,568 | `1e687cac28d974bf9f04f4a608edff64e9d7816223f9fc5aad5852950806552f` |
| | `midi_play.c.o` | 73,944 | `b5d70cddb12d8bffbd55a58323a716b7ad63c7dd6e5d6edd2558635a38b01143` |

Notable exported or recoverable symbols include `midi_fread`,
`midi_fread_addr`, `midi_fread_zone`, `Midi_IIR_Init`, `SetKeyDecay`,
`midi_ctrl_gen_sample`, `midi_dec_gen_sample`, `get_midi_ctrl_ops`,
`midi_ctrl_obj`, `MIDI_CTRL_OPEN`, `MIDI_CTRL_MAIN`, `midi_player_prog`,
`midi_play_note_on`, `midi_play_note_off`, `midi_pitchBend`, `midi_vellfo`,
`query_play_key`, and `midi_glissando`. The first archive does not contain the
controller wrapper. That wrapper and the Note On/Off implementations are in
`audio_server.a`.

The pinned USB device source supports MSD, UAC, HID, CDC, UVC, and printer
composition. It does not contain a USB-MIDI device-class implementation. MIDI
decoding is built separately through `audio_dec_midi_ctrl` and
`lib_midi_dec.a`.

## Public SDK MIDI ABI and state model

This is a search model recovered independently from the public header and LLVM
IR metadata. It must not be assigned to v15 without matching code or data.

`MIDI_CTRL_CONTEXT` is 44 bytes and contains eleven 32-bit function pointers:

| offset | operation |
|---:|---|
| `0x00` | `need_workbuf_size` |
| `0x04` | `open` |
| `0x08` | `run` |
| `0x0c` | `set_prog` |
| `0x10` | `note_on` |
| `0x14` | `note_off` |
| `0x18` | `pitch_bend` |
| `0x1c` | `ctl_confing` |
| `0x20` | `vel_vibrate` |
| `0x24` | `query_play_key` |
| `0x28` | `glissando` |

The public signatures are:

```c
u32 note_on(void *work_buf, u8 key, u8 velocity, u8 channel);
u32 note_off(void *work_buf, u8 key, u8 channel, u16 time_ms);
```

The controller commands are Note On `0xf0`, Note Off `0xf1`, Set Program
`0xf2`, Pitch Bend `0xf3`, velocity vibrato `0xf4`, query `0xf5`.
`note_on_parm` is three bytes `(key, velocity, channel)`. `note_off_parm` is
four bytes `(key, channel, little-endian u16 time_ms)`.

Compiler output confirms the pi32v2 ABI uses `r0` through `r3` for the first
four scalar/pointer arguments, a fifth argument on the downward-growing stack,
and `r0` for the return value. Header prototypes, LLVM call sites, and generated
machine code are independent observations of this ABI.

Recovered public SDK layouts:

- decoder work state: 2,672 bytes before its flexible pool;
- channel control: 7 bytes, present as 16 entries;
- player/voice record: 272 bytes;
- `Voice_s`: 24 bytes;
- envelope: 36 bytes;
- tone zone: 40 bytes.

Public Note On masks key and velocity with `0x7f`, treats velocity zero as a
stop, scans active players by channel and key, resolves tone zones, then calls
`player_control_note_on`. Public Note Off scans the same player set, calls
`control_stop`, and, when `time_ms != 0`, computes a sample-count decay and
calls `SetKeyDecay`.

## Exact and relocation-aware matching

### Positive controls

The stripped v15 image contains 95 unique exact function bodies among 560
12-to-256-byte functions from the pinned `sdk.elf`. Five USB anchors are exact:

| SDK symbol | v15 file offset | v15 VA |
|---|---:|---:|
| `usb_set_pull_up` | `0x003f30` | `0x02003f30` |
| `usb_set_pull_down` | `0x004050` | `0x02004050` |
| `usb_set_direction` | `0x00416c` | `0x0200416c` |
| `usb_output` | `0x004192` | `0x02004192` |
| `usb_set_die` | `0x0042fc` | `0x020042fc` |

The relocation-aware matcher was calibrated on official-toolchain recompiles of
`gpio.c.o` and `sdfile_new.c.o`. It accepted twenty-one functions. Examples:
`usb_set_pull_up` aligns four unique 16-byte windows covering 48 fixed bytes at
`0x3f30`; `usb_output` aligns six windows covering 64 bytes at `0x4192`;
`sdfile_str_to_upper` has a strict masked match at `0x2d7a6` plus two windows
covering 24 bytes. See `calibration-object-matches.json`.

### MIDI result

The same official clang 4.0.1 toolchain compiled seven selected MIDI bitcode
members to relocation-bearing pi32v2 ELF objects. Across 57 functions:

- strict relocation-masked function matches: **zero**;
- candidates meeting the calibrated two-window/24-byte threshold: **zero**;
- only weak hit: one isolated 16-byte window from `__midi_ctrl_output` at
  `0x40c5c`; rejected because it has one window and no independent support;
- exact full public MIDI lookup tables in v15: **zero** for pan, 12-tone power,
  key-volume, inverse sample-rate, positive/negative power, and ADPCM step/index
  tables;
- exact SDK-ELF functions with MIDI/Note/Pitch/Glissando names: **zero**.

This negative result is meaningful because the same compiler/object/matcher path
recovers many exact and relocation-aware USB and filesystem positives from the
same revision.

## Exact v15 MIDI ingress findings

These are product-side findings, not matches to the public synth objects.

1. **Raw MIDI stream parser at file `0x1050`, VA `0x02001050`.** Its exact
   824-byte region hash is in `report.json`. It recognizes channel statuses by
   `(status & 0xf0) - 0x80 <= 0x60`, obtains message lengths from a 16-entry
   status-nibble table, supports running status and SysEx boundaries, and writes
   completed messages to a ring buffer. This independently proves a general
   MIDI byte-stream decoder.
2. **Product MIDI message handler at file `0x1e64a`, VA `0x0201e64a`.** Its
   exact 216-byte region hash is in `report.json`. It handles exact statuses
   `0x90`, `0x9f`, `0xb0`, and channelized pitch bend `(status & 0xf0)==0xe0`.
   The pitch-bend path loops exactly 16 routing records, compares the low status
   nibble against a stored channel, and writes the 14-bit value into parallel
   16-entry halfword arrays at global-state offsets `0x704` and `0x724`.
3. **Independent caller at file `0x2d1b4`.** It validates a seven-byte
   `f0 35 59 ... f7` packet, reconstructs a status byte through a nibble table,
   writes that byte into a message buffer, and calls `0x0201e64a` with the
   buffer pointer in `r0`. This supports the handler boundary and one-argument
   ingress ABI.

The handler's `0x90` path is product-specific, restricted to note `0x73`, and
updates an eight-byte global block with either zero or `0x7f`. It is not a
sufficient basis for naming a general synth Note On function. No corresponding
general Note Off target was established.

## Rejected candidates

- The only aligned eleven-code-pointer run is at `0x58248`. Although its shape
  resembles the eleven-entry public `MIDI_CTRL_CONTEXT`, disassembly shows tiny
  product UI/button-state callbacks with incompatible operation sizes. Rejected.
- The unique nine-entry sample-rate sequence at `0x583fc` is followed directly
  by USB Audio Class interface descriptors. It is UAC descriptor data, not a
  synth sample-rate table. Rejected.
- Short key-volume-like byte runs at `0x564a0` and `0x58789` were below the
  specificity threshold and had no independent support. Rejected.
- `midi_route` and MIDI USB descriptors prove transport presence only. They do
  not identify synth implementation addresses. Rejected as synth evidence.

## Confidence

- SDK revision, archive membership/hashes, public MIDI ABI/layouts: **high**.
- Pinned-SDK lineage and USB exact matches: **high**, multiple independent exact
  and relocation-aware matches.
- Exact v15 MIDI ingress parser/handler and 16-slot channel routing state:
  **high** for the described behavior.
- V15 downstream synth API, Note On/Off targets, and voice-record ABI:
  **unresolved**. No address is claimed.
