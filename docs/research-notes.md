# SMK-37 Pro modding research notes

Last updated: 2026-07-15 (KST)

This is the project source of truth for findings that have already been checked. Before searching the web again, check this file first. Revisit a source only when a result is missing, contradictory, or likely to have changed.

## Evidence labels

- **Confirmed**: directly observed on the unit, extracted from a binary, or stated by an official source.
- **Strong inference**: multiple independent facts agree, but a part marking, schematic, or electrical measurement is still missing.
- **Unverified**: technically plausible but not yet demonstrated on the SMK-37 Pro.

When adding a result, record the date, evidence, source or measurement, confidence, and remaining uncertainty. Do not silently replace an older conclusion; mark it superseded and explain why.

## Source snapshot

- Community documentation repository: `jonathaslacerda/smk-37-pro-docs`
- Inspected commit: `8f1bf1115cc8fe874bbac326d4f1f1513d743844` (2026-03-24)
- Repository: <https://github.com/jonathaslacerda/smk-37-pro-docs>
- Official AC79 documentation used: <https://doc.zh-jieli.com/AC79/zh-cn/release_v1.2.0/>
- Official AC79 SDK branch used: <https://gitee.com/Jieli-Tech/fw-AC79_AIoT_SDK/tree/release/AC79NN_SDK_V1.2.0>

## Current conclusions

### Physical I/O

**Confirmed**

The rear panel has:

- Sustain
- 3.5 mm Audio Out
- 3.5 mm MIDI Out
- USB-C

There is no analog Audio In jack. A guitar, microphone, line-output synth, or headphone output cannot be connected to the stock unit as an analog input.

Evidence:

- Owner observation, 2026-07-14
- User manual: <https://github.com/jonathaslacerda/smk-37-pro-docs/blob/main/manual/smk-37-pro-user-manual.pdf>

### USB-C audio behavior

**Confirmed on the owner's firmware 1.05 unit**

The manual states that a USB host should enumerate the SMK-37 Pro as both MIDI and Audio. It documents both directions:

- Host playback: PC/Mac audio is sent over USB-C and exits the SMK Audio Out jack.
- Device capture: the SMK internal audio can be selected as a recording input by a DAW.

This is digital USB Audio Class behavior, not an analog input. In USB terminology, computer-to-SMK playback uses an OUT endpoint from the host's perspective.

It does not mean that an analog source can be connected through a passive USB-C adapter. A USB audio interface also cannot normally be connected directly because both the interface and SMK are USB devices; a PC, phone, or other USB host must sit between them.

Read-only macOS enumeration on 2026-07-14 confirmed:

- USB manufacturer/interface identity: `SMK-37 Pro Midi`
- USB audio identity: `SMK-37 Pro Audio`
- USB VID: `0x4C4A`
- USB PID: `0xC755`
- USB specification: `0x0200` (USB 2.0)
- Device revision: `0x0100`
- Link speed: 12 Mb/s (USB Full-Speed)
- Configurations: one
- USB audio playback: two output channels at 44.1 kHz
- USB audio capture: two input channels at 44.1 kHz
- Interface 0: Audio Control, class 1/subclass 1
- Interfaces 1 and 2: Audio Streaming, class 1/subclass 2
- Interface 3: MIDI Audio Control, class 1/subclass 1
- Interface 4: MIDI Streaming, class 1/subclass 3, two endpoints

A native macOS read-only probe using libusb confirmed the complete active
configuration without using CoreMIDI:

- Interface 4 endpoint `0x04`: host-to-device, bulk, 64-byte maximum packet.
- Interface 4 endpoint `0x84`: device-to-host, bulk, 64-byte maximum packet.
- No vendor-specific, HID, mass-storage, or DFU interface is exposed in normal
  mode.
- The direct-USB implementation target is therefore interface 4 itself. It can
  bypass the macOS MIDI API, but it must still implement the class endpoint's
  on-wire packet framing.
- macOS `usbaudiod` bound to the USB audio interfaces
- macOS `MIDIServer` bound to the MIDI streaming interface

The device-specific USB serial was observed but is intentionally omitted from this potentially publishable document.

At enumeration time, macOS still had the Bluetooth device named `SMK-37 Pro` selected as the default system output. This is relevant when distinguishing the two playback transports, but both transports were subsequently confirmed by owner use.

**Confirmed by owner use on 2026-07-14**

- Bluetooth audio playback through the SMK-37 Pro works normally.
- USB Audio playback from a host through the SMK-37 Pro works normally.
- The rear 3.5 mm Audio Out works with earphones.
- The owner has used the instrument as a Bluetooth audio receiver/speaker endpoint.

Do not spend further investigation time proving the established Bluetooth or USB playback-to-Audio-Out paths. The remaining audio questions concern adding a new analog or native SoC LINEIN path.

**Confirmed by owner use on 2026-07-14**

The two-channel USB capture source exposed by the stock SMK-37 Pro firmware is the instrument's internal sound output. There is no stock selector for an external analog or USB input source.

### USB hub topology

A standard USB hub does not route audio between attached devices. In this topology:

```
MacBook (USB host)
└── USB hub
    ├── SMK-37 Pro (USB audio/MIDI device)
    └── USB microphone (USB audio device)
```

macOS sees two independent USB audio devices. The microphone does not enter the SMK firmware, DSP, or fixed USB capture stream. The Mac can nevertheless use the microphone as its input and the SMK as its output. A DAW can monitor the microphone through `SMK-37 Pro Audio`, but the routing and mixing occur in macOS and add software/USB latency.

To record the USB microphone and SMK internal synth simultaneously on macOS, create an Aggregate Device containing both interfaces, select one clock source, and enable drift correction for the other device. This combines devices at the Core Audio layer; it does not alter SMK hardware behavior.

Connecting a hub to the SMK instead of to a computer does not solve this. The current SMK USB-C behavior is USB peripheral/device mode, not a demonstrated USB host mode capable of enumerating a microphone. A powered hub supplies power but does not create a USB host or audio router.

### Main SoC identification

**Strong inference**

The main SoC is very likely an AC7911B8-family Jieli device:

- U10 top marking visible in the board photograph: `JL C108221-11B8`
- Firmware container chip family: `AC791N`
- Firmware/package size matches the B8 8-Mbit (1-MiB) internal-flash variant
- Package and public SDK board configuration match AC7911B8 QFN48

The exact public mapping between the custom `C108221-11B8` marking and the catalog part number has not been found, so record this as high-confidence rather than absolute identification.

Sources:

- Board photograph: <https://github.com/jonathaslacerda/smk-37-pro-docs/blob/main/images/smk37pro/internals-board2.jpg>
- AC7911B datasheet: <https://gitee.com/Jieli-Tech/fw-AC79_AIoT_SDK/blob/release/AC79NN_SDK_V1.2.0/doc/datasheet/AC791N规格书/datasheet/AC7911B_Datasheet_V1.4.pdf>
- AC7911B8 SDK board configuration: <https://gitee.com/Jieli-Tech/fw-AC79_AIoT_SDK/blob/release/AC79NN_SDK_V1.2.0/apps/wifi_story_machine/board/wl82/board_7911B8_cfg.h>

`AC791N_STORY` is not proof that the public `wifi_story_machine` application is the SMK source. The same PID is a generic value in the public WL82 packaging rule.

- Packaging rule: <https://gitee.com/Jieli-Tech/fw-AC79_AIoT_SDK/blob/release/AC79NN_SDK_V1.2.0/cpu/wl82/tools/isd_config_rule.c>

## Audio In research

### Existing output path

**Strong inference**

U13 is consistent with a Cirrus Logic CS4344 stereo DAC. The CS4344 accepts digital audio using SDIN, SCLK, LRCK, and MCLK and produces AOUTL/AOUTR. It is output-only and cannot accept analog audio.

Useful pins when tracing the board:

- pin 1: SDIN
- pin 2: SCLK
- pin 3: LRCK
- pin 4: MCLK
- pin 7: AOUTL
- pin 10: AOUTR

Sources:

- Output-stage photograph: <https://github.com/jonathaslacerda/smk-37-pro-docs/blob/main/images/smk37pro/internals-board3.jpg>
- CS4344 datasheet: <https://statics.cirrus.com/pubs/proDatasheet/CS4344-45-48_F2.pdf>

### Practical analog-input modification

**Feasible, not yet built**

The lowest-risk modification is to mix an external line input into the analog path after the CS4344 and before the final output stage:

`Input jack -> AC coupling/protection -> level control or buffer -> resistor/active summing -> existing output path`

This can provide monitoring without modifying SMK firmware. It will not automatically feed the external source into SMK effects or USB recording, and its relationship to the master volume depends on the insertion point.

Do not connect an external source directly in parallel with AOUTL/AOUTR. Use summing resistors or an active mixer so that two output drivers do not fight each other.

### Native SoC Line In

**Supported by the SoC; unverified on the SMK board**

AC7911B provides four 16-bit Audio ADC channels, microphone amplifiers, analog multiplexers, LINEIN sources, I2S input, and SPDIF receive. Official LINEIN candidates are:

- AUX0: PA0
- AUX1: PH7
- AUX2: PA5
- AUX3: PH4

The public audio example supports LINEIN sampling, and the official development board includes a 3.5 mm line input.

Sources:

- Audio ADC and LINEIN example: <https://doc.zh-jieli.com/AC79/zh-cn/release_v1.2.0/module_example/audio/audio_adc.html>
- Development-board function diagram: <https://doc.zh-jieli.com/AC79/zh-cn/release_v1.2.0/board_description/function_diagram/index.html>
- USB/UAC example: <https://doc.zh-jieli.com/AC79/zh-cn/release_v1.2.0/module_example/peripherals/usb.html>
- USB audio implementation: <https://gitee.com/Jieli-Tech/fw-AC79_AIoT_SDK/blob/release/AC79NN_SDK_V1.2.0/apps/common/audio_music/usb_audio_api.c>

Unknown on the SMK board:

- whether any AUX-capable pin is unused
- whether the pins are already assigned to LCD, keys, encoders, or other controls
- required input bias and full-scale level
- whether the stock firmware has reachable LINEIN configuration

The SDK's simple `linein_to_fdac` example is not a drop-in solution because the SMK output appears to use the external CS4344. A native modification would need:

`Audio ADC -> PCM stream -> mix with synth output -> I2S -> CS4344`

The board labels `ADC3` and `ADC5` refer to low-resolution control ADCs used by potentiometer/wheel circuits, not the audio ADC. They are unsuitable for full-band audio.

## LCD and UI research

### Controller

**Strong inference**

The v15 application contains an LCD initialization table with commands including `0x11`, `0x36`, `0x3A 0x05`, `0xB2`, `0xB7`, `0xBB`, `0xC2`, `0xE0`, `0xE1`, and `0x21`. The structure closely matches the official Jieli ST7789V driver. `0x3A 0x05` selects RGB565 pixel data.

The display is therefore likely ST7789V or command-compatible. A 240 x 240 resolution is likely for the 1.54-inch square panel but is not yet confirmed from the FPC marking or a bus capture.

The command sequence identifies the controller family, not the electrical bus. The ten-pin FFC suggests a serial interface, but SPI versus another wiring must remain unconfirmed until continuity measurement or logic capture.

Sources:

- Official ST7789V driver: <https://gitee.com/Jieli-Tech/fw-AC79_AIoT_SDK/blob/release/AC79NN_SDK_V1.2.0/apps/common/ui/lcd_driver/lcd_st7789v.c>
- AC79 LCD interfaces: <https://doc.zh-jieli.com/AC79/zh-cn/release_v1.2.0/module_example/peripherals/lcd.html>

### UI resources

**Confirmed from the v15 package**

The extracted package contains `app.bin`, `cfg_tool`, and `cfg/eq_cfg_hw.bin`, but no separately exposed `JL.sty`, `menu.res`, `str.res`, PNG, or JPEG UI bundle.

UI strings and colors appear directly in `app.bin`, including:

- `Cut Off-`
- `Distortion-`
- `Algorithm-`
- `Feedback-`
- `Mono/Poly`
- `Firmware`
- `SAVE` and `SAVED`
- `#F5BC27` and `#D9D9D9`

Practical modification levels:

1. Same-length ASCII or six-digit color patch: smallest binary experiment.
2. Position, font, and layout changes: requires Pi32v2 disassembly and cross-reference work.
3. New font, Korean text, icons, or pages: requires renderer/resource analysis.
4. Higher-resolution display: requires driver, buffer, coordinate, memory, and bandwidth changes.
5. A same-resolution, command-compatible panel may improve brightness or viewing angle but will not improve the UI design.

Sources:

- AC79 UI framework: <https://doc.zh-jieli.com/AC79/zh-cn/release_v1.2.0/module_example/ui/ui.html>
- AC79 UI tool: <https://doc.zh-jieli.com/AC79/zh-cn/release_v1.2.0/module_example/ui/ui_tool.html>

## Firmware research

### Owner unit state

**Confirmed by owner observation on 2026-07-14**

- Firmware version shown by the SMK-37 Pro: `1.05`

**Confirmed by direct USB query and package parsing on 2026-07-14**

- Device updater identity: `SMK-37 Pro_012`
- Community release index: firmware 12 is display version 1.05
- Matching recovery package: `SMK-37_Pro_012.fwsc`
- Package size: 701,140 bytes
- Package SHA-256: `c6a9187e706aeae921447ec88e29fecbc618e3f1fc3de54c743c78e41781580a`
- Parsed OTA payload size: 701,120 bytes
- Parsed OTA payload SHA-256: `23e65eb292ad8b3039085f3fa27ee738b5fa7d56ac02611c2908f6136858af9a`

The earlier inference that filename `015` might mean display version 1.05 was
wrong and is superseded. Package `015` is a different, newer firmware and must
not be used for same-version recovery of this unit.

### Extracted v15 facts

**Confirmed by local unpacking**

- Container chip: `AC791N`
- VID: `0.01`
- PID: `AC791N_STORY`
- Entry address: `0x02000120`
- Flash class: 1 MiB
- Update span: `0x0FF000`; final 4 KiB is outside this packaged span
- `uboot.boot`: 14,384 bytes
- `app.bin`: 617,012 bytes
- `cfg_tool`: 383 bytes
- `cfg/eq_cfg_hw.bin`: 2,873 bytes
- Chip scrambler value observed by the tooling: `0x980F`; this is not proof of a signature key or signature bypass
- Declared regions include VM, PRCT, BTIF, USRTRIM, USRFLASH, and USR

The community repository contains distinct SMK-37 Pro v11-v15 applications. Elite, MKE-P37, and Starrykey packages are also distinct and must not be cross-flashed merely because their version numbers match.

Sources:

- Firmware index: <https://github.com/jonathaslacerda/smk-37-pro-docs/blob/main/firmware/FIRMWARE.md>
- Jieli firmware tools: <https://github.com/kagaimiq/jl-misctools>
- Independent v12 extraction record: <https://gist.github.com/probonopd/18b3ed65a69d0229eb630c47d7e316dc>

### What is currently possible

**Confirmed**

- Unpack an official `.fwsc` update into boot, app, and configuration components.
- Diff v11-v15 and perform static analysis of `app.bin`.
- Query the connected product/version directly over USB-C without CoreMIDI.
- Read arbitrary main-flash ranges through the stock updater protocol.
- Dump the complete 1-MiB live flash through normal-mode USB-C.
- Parse the M-UPGRADE `.fwsc` wrapper and reproduce its OTA payload exactly.
- Build the device-requested type-`0x30` update response packet exactly.
- Perform a read-only same-product/same-version upload preflight.
- Complete a stock v12 verification stage over direct USB-C.
- Follow the normal-to-OTA USB re-enumeration and discover the update-mode
  transport from its descriptors.
- Complete the stock v12 write stage, acknowledge its final completion
  request, boot normal firmware, and query version `012` again.
- Dump the complete 1-MiB flash again after the restore.

The live dump is stored under ignored `backups/` rather than source control:

- File: `backups/smk37-pro-v012-live-20260714.bin`
- Size: 1,048,576 bytes
- SHA-256: `ba1b40a0b4b6234b384b1d812e851c659ded292b57ac55bfee4e04d8489cb1fa`
- The final 4 KiB is all `0xFF`.
- A separate first-4-KiB read exactly matches the first 4 KiB of the full dump.

The dump is in the flash's encrypted/scrambled representation. Applying the
known Jieli cipher with key `0x980F` to its first 32 bytes produces the same
first 32 bytes as the unpacked official v12 image, including `AC791N_STORY`.
This validates the dump/package pairing, but it is not yet a general decoder
for every flash address or a proven byte-for-byte restorable image.

The post-restore dump is also retained under ignored `backups/`:

- File: `backups/smk37-pro-v012-post-restore-20260715.bin`
- Size: 1,048,576 bytes
- SHA-256: `288a2e70a515d39f98e4616461f152ae2a61c01e8a0cbd5e1d592b83cb750ecd`
- It differs from the pre-restore dump at 173,460 byte positions.
- The first difference is at `0x4000`; the last is at `0xC0FFF`.
- Blocks outside the changed ranges remained byte-for-byte identical.

This difference does not mean that the restore failed. The device requested
and consumed the `.fwsc` OTA payload, acknowledged upgrade completion, booted
normally as version `012`, and then allowed a complete new flash dump. The
701,120-byte `.fwsc` payload is an encoded update representation and is not
expected to equal the raw flash byte-for-byte.

Official updater:

- <https://www.m-vave.com/download>

**Not yet demonstrated safely**

- Have the stock loader accept and write a modified application-only package.
- Recover the SMK when a modified application cannot boot far enough to accept
  the normal USB OTA command.
- Enter AC7911B8 mask-ROM/forced-download mode on the SMK mainboard.
- Run a RAM-only dumper on an unmodified device.

The fixed-layout v12 repacker is now complete offline. This does not remove the
second and third risks above: a successful custom write followed by an early
application crash is different from an interrupted update that already left
the unit in update-loader mode.

The public `jl-misctools` new-fw support is incomplete and does not constitute a full repacker. No public-key signature was identified in the inspected material, but absence of evidence is not evidence that the update chain accepts arbitrary modified images.

Official AC79 flash APIs make a custom dumper technically possible after code execution is obtained. SDTAP requires firmware support and parts of the documented workflow depend on Jieli/FAE tooling.

Sources:

- Flash API: <https://doc.zh-jieli.com/AC79/zh-cn/release_v1.2.0/module_example/peripherals/flash_api.html>
- SDTAP: <https://doc.zh-jieli.com/AC79/zh-cn/release_v1.2.0/module_example/system/SDTAP.html>
- Update system: <https://doc.zh-jieli.com/AC79/zh-cn/release_v1.2.0/module_example/system/update.html>
- Public bootloader: <https://github.com/Jieli-Tech/fw-Bootloader>

### Reverse-engineering route

The application should be analyzed as Pi32v2 code using `0x02000120` as the load/entry basis. A useful strategy is to build a matching public AC79 SDK ELF, create function signatures from the ELF, and use them to label common SDK functions before investigating SMK-specific UI and audio code.

Sources:

- Pi32v2 Ghidra support: <https://github.com/virtualabs/ghidra-jieli>
- Example new-fw/Pi32v2 analysis workflow: <https://blog.quarkslab.com/nerd-life-weeks-firmware-teardown-we-were-right.html>

The public SDK does not include the SMK FM engine, key/pad scanning, control mapping, product USB descriptors, CS4344 routing, or UI state machine. It can support a new AC7911B application, but preserving the current instrument functionality would require substantial product-specific reverse engineering.

### FM drum execution-path findings

Static analysis record, 2026-07-15:

- The v12 application contains three sequencer mode strings, `drum`, `key`,
  and `live`, and three corresponding UI titles, `Drum Seq`, `Key Seq`, and
  `Live Seq`.
- A six-entry pointer table at loaded address `0x02057018` pairs those mode
  names and titles. This proves that the stock sequencer already has distinct
  drum, key, and live modes; it does not by itself prove simultaneous tracks.
- The task name `midi_route` is loaded at `0x02056F67`. Nine application code
  sites reference it.
- Pi32v2 byte sequence `80 ff <signed-le32>` is a 48-bit PC-relative call whose
  destination is `instruction_address + signed_immediate`. The earlier
  `0x0206160C` task-post identification was off by one instruction:
  `0x0206160C` is `os_time_dly`, while the name-based task/message post wrapper
  is `0x02061612`. The task-queue receive function is `0x0206320C`.
- The `midi_route` call sites that set `r0` to the task name call
  `0x02061612`; the public SDK signature and wrapper behavior identify this as
  the name-based task/message post wrapper with high confidence.
- One route wrapper calls it with `argc = 3`, which is compatible with a
  three-word MIDI/event message. The exact status/note/velocity mapping and
  the receiving task loop are not yet proven.

This changes the most practical extension strategy. The first behavior patch
should reuse the existing `midi_route` and stock FM note path rather than add a
new synthesizer. The remaining reverse-engineering target is:

1. locate the drum sequencer tick/step callback;
2. identify its existing per-step drum trigger;
3. trace `midi_route` receive dispatch to the stock FM note-on/note-off entry;
4. demonstrate an offline code-cave or same-size branch patch that emits more
   than one note without changing USB, boot, or update initialization.

Owner behavior test, 2026-07-15: when Patch is changed while Latch is on, the
previously sounding patch disappears immediately and only the newly selected
patch remains. No overlap between the two timbres was observed. Consequently,
polyphonic note emission through `midi_route` is not enough to meet the actual
goal: v12 currently exposes polyphony within one timbre, not channel-separated
multitimbrality.

The easy preset-time-multiplexing hypothesis is rejected for the stock control
path. Static analysis must now determine whether Patch change explicitly sends
all-notes-off before loading a new preset, or whether every FM voice directly
shares one global patch state. True real-time multitimbral FM requires a second
preserved FM context or substantial voice-allocator modification.

Follow-up static analysis resolves the immediate uncertainty for a minimal
test. The actual MIDI receive loop is `0x0202C876`, its queue receive call is
`0x0206320C`, the byte parser is `0x02000C34`, the high-level handler is
`0x0201DD3C`, and normal MIDI dispatch enters `0x0201C16A`. On Note On the
dispatcher copies `0x9c` bytes from the current unpacked patch at `0x01C35104`
into a per-event/per-voice destination before queueing the event. The Note Off
helper at `0x0201C09C` performs the same snapshot. This does not prove live
multitimbral audio, but it supplies a direct falsifiable route: give each
channel a different patch snapshot and observe whether downstream voices retain
it independently.

The packed-preset loader at `0x020051E2` selects the bank through
`0x01C33A94`, reads that bank's current preset index from the array beginning
at `0x01C33A90`, and unpacks the chosen 128-byte preset into the current patch
buffer. Each bank has 32 presets and a `0x1000`-byte packed stride.

### M05 minimal two-timbre implementation

M05 implements only the owner's checkpoint: USB MIDI channel 1 snapshots the
current patch N, while channel 2 temporarily loads and snapshots
`(N + 1) & 31` from the same bank, then restores N immediately. Other channels
retain stock behavior. The channel-2 snapshot is held transiently in unused
SysEx receive scratch RAM at `0x01C38460`; there is no new UI, Program Change,
or persistent part state.

The wrapper occupies `0x0201DC14` through `0x0201DC7D`, replacing the stock
Yamaha SysEx single-voice pack/save function. Its two old SysEx callers at
`0x0201DF4C` and `0x0201DF7A` are disabled so they cannot enter the wrapper
with the old ABI. Note Off at `0x0201C0C8` enters the wrapper through
`0x0201DC14`; Note On at `0x0201C1C4` enters through `0x0201DC18`. Both paths
use the exact official-v12 `memcpy` entry at `0x0204850C`.

The exact archived official v12 application differs from the first live dump
in later linked-library placement. The live-dump analysis had placed `memcpy`
at `0x02048514`; the archived official image used for M05 places it eight bytes
earlier at `0x0204850C`. The M05 builder therefore requires the exact official
app SHA-256
`7383d5f02dcbb85465c14acbb20df2fa3b8452b505c65a0ac2a9139627cd95b6`
and refuses the earlier dump.

Static disassembly, exact-stock-byte assertions, fixed application size,
protected-region hashes, package inspection, direct-device identity, and
upload preflight all pass. Package SHA-256 is
`0beab977977bd175ea484be44851c76958d22de4e787b9cbc34ddfaa8400c1f6`.
M05 then completed both OTA stages, all 1,241 stage-2 requests, and the
`0xF0000000` completion acknowledgement. It rebooted and reported USB identity
012. This proves installation and application startup, not audio behavior;
only simultaneous Ch1/N plus Ch2/N+1 playback can establish two-timbre success.

Owner live test, 2026-07-15: a host sequencer sent overlapping channel-1 and
channel-2 loops to M05. The owner confirmed that the implementation worked
exactly as intended: channel 1 retained current patch N while channel 2 sounded
the adjacent patch N+1 at the same time. The per-event/per-voice `0x9c`-byte
patch snapshot is therefore honored by the downstream FM voice path. This is
direct evidence of two-part multitimbral FM, not merely multichannel MIDI
parsing.

### Local pad capture and M06 bridge

Direct libusb capture on 2026-07-15 established the physical pad contract
without CoreMIDI or SysEx APIs. The owner pressed all 16 pads and released each
one. Every pad emitted human MIDI channel 10, with Note On status `0x99`, Note
Off status `0x89`, and live strike velocity. The note set is the contiguous GM
drum range 36 through 51. Each event appeared on USB MIDI cables 0 and 1, but
the duplication occurs after the single local raw-message callback.

The local control dispatcher at `0x02029F0E` has an arbitrary raw-MIDI action
type. Its press path calls `0x02023576`, which reads the stored message length
and sends the raw bytes through `0x0201C01C`. Unlike the local keyboard helper,
this stock pad path does not also call the FM dispatcher. This explains why
the pads can advertise Ch10 over USB while remaining outside the stock FM
part.

M06 replaces the callback's zero-length test plus short output call at
`0x0202357A` with a call to a bridge at `0x0201DC80`. The bridge preserves the
original MIDI output, accepts only three-byte channel-10 messages, and calls
the local FM dispatcher `0x0201C272` once. The existing per-voice snapshot
wrapper now compares channel nibble 9, so both local pads and incoming USB
Ch10 use same-bank patch `(N + 1) & 31`. Local keys and USB Ch1 retain patch N.
The bridge preserves notes 36-51, velocity, and physical Note Off timing.

M06 app SHA-256 is
`bc56b86afab4f64d29e4d389f7b99c7af656c5f4a9c98c93931ac218e08e6919`;
package SHA-256 is
`61b2f5707a2b5779ffa118612957b232027de72f377d56adc9d68d6ed302aac4`.
Offline rebuild reproducibility, exact stock-byte assertions, Ghidra branch and
call targets, protected-region hashes, package inspection, and packet dry-run
all pass. This is still one pitched FM patch across all 16 pad notes, not the
later GM note-to-patch drum map.

M06 then installed from the running M05 application. Both OTA stages, all
1,241 stage-2 requests, and `0xF0000000` completed; normal USB identity 012
returned after automatic reboot. Local key/pad audio remains an owner-side live
test and is not inferred from the successful install.

Owner live result, 2026-07-15: the local keyboard remained on Ch1/patch N and
the physical pads played Ch10/patch N+1 exactly as intended. The raw local-pad
bridge, paired Note On/Off flow, channel-10 timbre snapshot, and simultaneous
local two-part FM path are therefore verified on hardware. The next unknown is
no longer local routing; it is selecting a different FM patch snapshot for
each GM drum note.

### M07 16-note FM map

M07 extends the verified M06 wrapper with note capture at both stock snapshot
hooks. At the Note Off memcpy hook, the note/channel are retained in r5/r8;
at the Note On hook they are retained in r8/r9. The wrapper normalizes those
values before any loader calls, preserves the note in r7, and computes the
same-bank preset as `(N + ((note - 35) & 31)) & 31`. Physical Ch10 notes 36-51
therefore select N+1 through N+16. Ch1 and local keys continue to snapshot N.

The wrapper and local-pad bridge occupy 168 of the 296 bytes in the replaced
Yamaha single-voice SysEx function. The M07 application SHA-256 is
`43e40ee627a33d06da589f036fc98ac13ed7edbbe1639ba6277e77385aa4423a`;
the package SHA-256 is
`b80ed7480152f07652eb8f809305f50d2bdb2990fb89875c317f27d5e99de082`.
The protected boot/config and resource hashes are unchanged. This offline
build is a 16-timbre routing proof, not yet a claim that the chosen factory
presets sound like finished GM percussion.

M07 then installed from the running M06 application. Both OTA stages completed
and normal USB identity 012 returned. The install transcript is
`backups/ota-M07-install-20260715.log`. Owner audio testing confirmed distinct,
independent note timbres, but also found that Ch1/local keys were contaminated
by the same note-dependent patch selection. The M07 channel gate is therefore
a regression even though the per-note snapshot mechanism itself works.

M07 also deliberately used current UI state: physical pad note `p` selected
`(N + p - 35) & 31` in the currently selected bank. Consequently it was never
independent of Patch UI changes. The corrected architecture needs Ch1 to use
the current UI patch while Ch10 selects fixed bank/preset IDs from its own
drum map.

### M08 channel isolation and fixed logical drum bank

M08 removes M07's pre-gate note move. Note On and Note Off now have separate
entry stubs that compare the M06-proven channel registers first; non-Ch10
events immediately call the stock memcpy path. Ch10 then maps notes 36-51 to
fixed Bank 0 preset IDs 0-15. Before loading that preset it saves the current
UI bank and Bank 0 preset index, and restores both after copying the per-voice
snapshot. UI Patch changes should therefore affect Ch1 only.

The application SHA-256 is
`73ae9baa5c732f91e91e7133cda4a9146a00d3b70333ed53814e3747a1297e25`;
the package SHA-256 is
`4498a935951e32d21b85167e5ba369a5051d32d93ba66e51229d5d255c8dc31f`.
The package safety gate, deterministic rebuild, packet dry-run, both live OTA
stages, and post-update USB identity 012 all passed. Owner audio verification
then confirmed the intended behavior: Ch1 retained the UI-selected patch,
Ch10 retained its fixed per-note map across UI Patch changes, and no problem
was observed in normal simultaneous use. The test did not saturate the voice
pool, so the maximum usable polyphony and voice-stealing behavior remain
unmeasured.

### DX7 VMEM identity and physical voice storage

Confirmed offline, 2026-07-15:

- Every supplied preset file is a 4,104-byte Yamaha message with header
  `F0 43 00 09 20 00`, 4,096 data bytes, checksum, and `F7` terminator.
- The body is 32 voices of 128-byte DX7 VMEM data. Voice names begin at byte
  118. The standard six-operator VMEM fields and bit packing round-trip
  exactly through `tools/dx7_vmem.py`.
- The stock loader at `0x020051E2` expands the selected 128-byte voice to the
  156-byte runtime form at `0x01C35104`: six operators of 21 bytes, pitch EG,
  algorithm, feedback/sync, LFO, transpose, ten-byte name, and operator mask.
- The live 1 MiB flash stores four packed banks at physical offsets
  `0xF4000`, `0xF5000`, `0xF6000`, and `0xF7000`. The first two contain owner
  edits; banks 3 and 4 exactly match the archived SysEx bodies. These sectors
  are outside the v12 OTA payload ending at `0x9BFFF` and must not be treated
  as disposable app space.
- The related 163-byte per-preset records begin at `0xF8000`. The loader first
  copies one such record, then overwrites its DX7 voice fields from the packed
  bank. Runtime bytes 156-162 carry non-voice settings and are not part of the
  per-event 156-byte timbre snapshot.

This resolves the engine family: the SMK voice format is DX7-compatible
six-operator FM, not a TX81Z/DX21 four-operator format. It also identifies a
candidate Ch10 architecture: an event needs only an independent 156-byte
snapshot; it does not need to mutate a factory/user bank or call the global
patch loader. M09 later proved that its chosen storage and wrapper must not be
classified as safe from this format result alone.

DX7 format implementation reference used for independent confirmation:

- Dexed repository: <https://github.com/asb2m10/dexed>
- inspected commit: `2e182b3db85c09083ab13c8b9b00565ce7d9ff85`
- format and pack/unpack references: `Documentation/sysex-format.txt` and
  `Source/PluginData.cpp`

### M09 app-resident FM drum kit

M09 stores eight expanded 156-byte DX7 percussion templates plus a 16-byte
GM-note map at application addresses `0x020959EE..0x02095EDD`. The official-v12
range was all zero and a full Ghidra destination-reference scan over the larger
`0x020959ED..0x02095F95` cave found zero references. The runtime data occupies
1,264 of 1,448 available aligned bytes.

For Ch10 Note On and Note Off, `(note - 36) & 15` selects the note-map entry,
the wrapper copies that template directly to the existing event/voice
destination, and the stock downstream allocator retains it. Ch1, local keys,
and every non-Ch10 channel take the stock memcpy path. No bank selector,
preset index, factory/user flash sector, or current UI patch buffer is touched.

The initial GM subset is:

| Note | GM role | M09 template |
| --- | --- | --- |
| 36 | Bass Drum 1 | kick |
| 37 | Side Stick | stick |
| 38 | Acoustic Snare | snare |
| 39 | Hand Clap | clap |
| 40 | Electric Snare | snare |
| 41, 43, 45, 47, 48, 50 | Toms | tom at incoming note pitch |
| 42, 44 | Closed/Pedal Hi-Hat | closed-hat at incoming note pitch |
| 46 | Open Hi-Hat | open-hat |
| 49, 51 | Crash/Ride | cymbal at incoming note pitch |

Template provenance is byte-audited in `tools/m09_drum_voices.py`. The initial
prototype uses SynprezFM cartridges bundled by the GPL-3.0 Dexed repository,
but that ZIP states no separate patch-data license. Treat the templates as
local research material and replace them with originally authored voices
before distributing firmware without a separate license review.

Build identity: application SHA-256
`8c63f6f44877810b7f23ba88a91870aa758add099cb02d3de9721b6f636ecdbe`;
package SHA-256
`5ac1264eba85ce5f1747458a90203bc144d21f87dc66f189ca055b74700ab5c8`.
The protected-region gate, exact wrapper disassembly, deterministic build,
host self-tests, and OTA packet dry-run pass.

Live OTA on 2026-07-15 completed both stages through request 1241 and received
the updater's final completion acknowledgement. The expected normal USB
identity did not reopen afterward. A fresh descriptor-only host scan then
found neither `4c4a:c755` normal mode nor `4d4a:4155` updater mode, so this is
not merely a claimed MIDI/audio interface. The device's physical display and
power state must be checked before choosing between a delayed normal boot,
power-cycle recovery, and the v12 recovery path. Until then M09 is
flash-transfer-complete but boot/audio unverified.

Owner-side follow-up established the failure state. Before the true power
cycle the display was black while previously lit pad LEDs remained on. Merely
unplugging and reconnecting USB-C did not change the state or create a USB
device because the internal battery kept the unit powered. After explicitly
turning the instrument off, waiting, and powering it on normally, both the
display and pad LEDs remained off. A subsequent host scan still found neither
normal nor updater identity. Classify M09 as `BOOT-FAILED / NO-USB` and never
reinstall it.

The strongest M09-specific fault hypothesis is that the large zero-filled
application range was not a safe persistent-data cave despite having no
statically discoverable direct references. It may be reached through an
indirect base pointer, initialized as required-zero runtime state, or checked
by an internal application invariant. M08 used only the replaced code region
and booted. M09 allocated 1,264 bytes in the new range, of which 789 bytes
actually differ from zero. M09 also changed 162 bytes of wrapper/bridge code,
so the data range is not a proven sole cause. Static destination-reference
scans are insufficient evidence for writable application data storage. The
ranked hypotheses, counter-evidence, and process causes are recorded in
`docs/m09-brick-incident.md`.

Official AC79 documentation says internal-Flash parts require the Jieli
forced-upgrade tool when normal firmware cannot enter download mode. The tool
forces a reset while transmitting a mask-ROM handshake such as `usbkey`;
switch 1 periodically interrupts target power and sends `usbkey`, while the
default/manual and switch-3 modes send the same handshake with different reset
timing. This product-specific path has not yet been exercised on SMK-37 Pro.
Recovery now requires obtaining that hardware path, identifying the resulting
WL82 download identity/protocol, and writing an exact official-v12-compatible
image. Do not open, short, probe, or reset the mainboard until that procedure
and image format are established.

Pi32v2 processor source used for this pass:

- repository: <https://github.com/quarkslab/ghidra-jieli>
- pinned commit: `e1bd0707874b77b759401555d24839ad43af1267`
- teardown/workflow reference:
  <https://blog.quarkslab.com/nerd-life-weeks-firmware-teardown-we-were-right.html>

Scope correction from the owner, 2026-07-15: PCM or pre-rendered FM drum
one-shots are not an acceptable fallback. The intended instrument is FM-only.
The existing Drum Seq may be reused for clock, steps, patterns, and UI, but the
new rhythm notes must be generated by the FM engine. The first implementation
milestone is two-part multitimbral FM: one independently retained keyboard
patch and one independently retained rhythm patch sounding at the same time.

Final objective clarification from the owner: the current product is assumed
to support only one FM MIDI channel and one active timbre. The primary mod is
to expand this base engine to multichannel, multitimbral FM. Drum Seq channel
or lane separation is useful only after that foundation exists. The minimum
technical proof is simultaneous channel-1/Patch-A and channel-2/Patch-B FM
playback; Drum Seq is then attached to the same internal part abstraction.

Implementation-order decision: build the two-part multichannel proof before a
GM-style note-to-timbre drum channel. The archived SysEx files are consistent
with 32 presets of 128 bytes per bank, four banks total. A two-part prototype
therefore minimizes new patch state and isolates the fundamental channel,
per-part patch-state, and voice-ownership changes. The drum branch requires
the same foundation plus note-to-patch mapping, fixed-pitch rules, and percussion
note-off/choke behavior. Once the part-aware FM note API exists, channel 10 can
be added as a special note-mapped consumer rather than a separate engine.

USB MIDI Program Change observation, 2026-07-15: on official v12/display 1.05,
an owner test found that incoming PC did not change the active patch. This is a
confirmed external behavior but does not yet reveal whether the parser drops
PC or a later handler ignores it. Remove PC from the first multitimbral proof:
initialize Part A and Part B with two different preset IDs compiled into the
test build and send only channel-separated Note On/Note Off from the host.
Implement PC later as an independent feature after per-part state works.

Patch-screen UI decision: do not couple the first engine proof to a new UI.
First hard-code Part A to local keys/USB channel 1 and Part B to USB channel 2,
then verify independent fixed-preset notes from a host. Once that works, use
the currently empty Patch-screen K6 for Part A/B selection and K7 for the
selected part's receive-channel assignment. Existing patch controls
edit only the selected part, and local keys audition that part. Part selection
must never reset active voices; every voice must retain the part ID captured at
note-on. Power-cycle persistence and same-channel layering are explicitly
deferred until the two-part audio path works.

The repeatable Pi32v2 decoder additions used for this work are stored as
`patches/ghidra-jieli-pi32v2-smk37.patch`. The combined patch applies cleanly
to a fresh `ghidra-jieli` checkout and its SLEIGH specification compiles under
Ghidra 12.1.2.

### Custom-firmware feasibility

Decision recorded: 2026-07-15

Custom build identity decision: preserve every official updater/OTA version
field at `012` and replace only the four-byte visible application string `1.05`.
The M001 trial package SHA-256 is
`af9ef78c80391d5a7eaa9d8d8bd5d6b3e77e891c532150fb80578bdcaa28a6a2`.
It installed and booted, but the screen rendered only `M00`, proving a
three-character display limit. M02 therefore stores `M02\0`; its package
SHA-256 is
`c2aa5ee8e82a5c1a85f58c3361404838a9f3bd9a7657698db23e8fd52bf149b1`.
M001 entered the normal OTA loader and installed M02; M02 booted and displayed
in full. Protected-region hashes remained unchanged for both builds. Version
IDs and installation/recovery status are tracked in
`docs/firmware-versioning.md`.

M03/M04 display and rollback result, 2026-07-15: M03 proved that `Reset
Factory` supplies the K8/title label but that `Reset to confirm` is not the
second visible string on the active confirmation screen. The observed screen
instead composed standalone `Reset`, `Cancel Reset`, and `K%d` strings. M04
blanked the unwanted `Reset` and knob-label fields, mapped `Cancel Reset` to
`acidsound`, and rendered the exact two-line target `Hello,` / `acidsound`.
M04 package SHA-256 is
`fffb9552d3ea8433b98e150d4c529e95e3dd6b2bb103b8839be06f2f5f7e6246`.
The running M04 application then entered normal OTA and installed the exact
official v12 package. USB identity 012, display 1.05, and the stock Reset UI
were all verified after rollback. This completes a custom-to-official live
round trip for a normally booting application-only patch.

Custom firmware is technically plausible, but there are three materially
different routes:

1. **Fixed-size binary patch of official v12 — most practical.** Patch an
   existing string, RGB color, constant, or a small instruction sequence in
   `app.bin`, preserve all file sizes and offsets, recompute JLFS/UFW CRCs,
   reapply the Jieli cipher, and rebuild the 20-slot `.fwsc` wrapper. No public
   key signature was identified in the inspected v12 format, which is
   encouraging but does not prove that modified packages are accepted.
2. **Larger behavior/UI patch — plausible but difficult.** Pi32v2 code can be
   loaded into Ghidra and v11-v15 differences provide useful anchors, but the
   available processor module describes Pi32v2 support as very early-stage and
   incomplete. Layout, font, renderer, and state-machine changes require
   substantial manual cross-reference work.
3. **Clean-room replacement firmware — possible as an AC79 application, not
   yet as a replacement instrument.** The public AC79 SDK supplies generic
   LCD, USB, audio, LINEIN, flash, and UI facilities. It does not supply the
   SMK-specific synth engine, presets, keyboard/pad/control scanning, board
   map, or product UI. A minimal demonstration firmware is conceivable; a
   feature-compatible musical instrument would be a large reverse-engineering
   project.

The current public `jl-misctools` new-fw utility is an unpacker, not a complete
repacker. Its own documentation says the implementation is far from complete,
and reserved areas are not handled. The repository contains reusable CRC,
cipher, JLFS, and bank-building primitives, so a fixed-layout SMK-specific
repacker can be written without inventing every format primitive from scratch.

Required gates before a modified package is sent to the unit:

1. **Completed 2026-07-15:** rebuild an unmodified v12 into a byte-for-byte
   identical `.fwsc` file. Both files have SHA-256
   `c6a9187e706aeae921447ec88e29fecbc618e3f1fc3de54c743c78e41781580a`;
   `cmp` reports no difference.
2. **Completed 2026-07-15:** validate every decoded JLFS/UFW structure used by
   the application-only pipeline, including header/list/data CRCs, offsets,
   sizes, chip key, and the 20-slot FWSC wrapper.
3. **Completed offline 2026-07-15:** add an exact-v12, equal-length app patcher
   that emits a change manifest and rejects changes outside its whitelist. A
   one-byte `app.bin` test changed nine flash bytes total: the application byte
   plus the two nested data/header CRC pairs. All protected hashes remained
   identical.
4. **No longer blocking:** later M001 and M02 writes completed normally, so the
   earlier post-success OTA timeout did not prevent subsequent updates.
5. **Completed as an offline package invariant:** limit the first patch to the
   application area and prove that the bootloader/OTA loader and every byte
   before `0x4000` and after `0x9A832` are unchanged.
6. **Completed 2026-07-15:** retain complete 1-MiB pre-restore and post-restore
   flash dumps in ignored `backups/` and record their hashes above.
7. **Not completed:** demonstrate an entry path that does not depend on the
   modified application booting and handling the normal OTA command.
8. **Completed live 2026-07-15:** install M001, boot it, enter OTA from M001,
   install M02, and boot M02. This proves modified-image acceptance and the
   normal OTA path from a running custom application.
9. **Completed live 2026-07-15:** install exact-string UI build M04, verify its
   behavior, then install the archived official v12 from M04 and verify display
   1.05 plus the restored stock UI.

The first sensible custom image is a reversible visual constant or same-length
ASCII change. It should not alter boot code, USB descriptors, flash layout,
audio initialization, or the OTA command path.

### Official macOS M-UPGRADE reference

The community repository now links an official/vendor-hosted macOS image:

- URL: <https://yms-file-store.oss-cn-hongkong.aliyuncs.com/software/pc/M-UPGRADE.dmg>
- Download size observed 2026-07-14: 58,541,828 bytes
- SHA-256: `47a08093b1398a781146169743431881d31bb808b1a63781c0d119ff840dba32`
- Application architectures: arm64 and x86-64
- It is ad-hoc signed without a Team ID; Gatekeeper does not accept it as a
  normally signed third-party app.
- It links CoreMIDI, but the native project tool does not use CoreMIDI.

The application retains C++ symbols. Relevant confirmed functions include
`flash_read`, `getLRequest`, `sendDataToLDevice`,
`make_flash_update_packet`, `get_device_name_and_version`, and the complete
OTA worker. It is used as a protocol reference, not executed against the unit.

### `.fwsc` and OTA protocol

The official parser first tests 36 metadata slots, then 20. SMK-37 Pro packages
use 20 slots. Each slot is 48 bytes; the first 47 bytes are firmware data and
the final byte contributes to encoded product/version metadata. Concatenating
the 47-byte portions and the remainder of the file removes 20 metadata bytes
and produces the exact OTA payload.

For v12 this decodes to:

- Product: `SMK-37 Pro`
- Version: `012`
- File: 701,140 bytes
- Transmitted payload: 701,120 bytes

The device drives OTA by sending 15-byte type-`0x30` requests containing flash
type, 32-bit address, and 24-bit length. The host responds with:

`00 59 30 | payload-length+8 | flash-type | address | data-length | data | checksum`

The checksum is the one's complement of the 8-bit sum from flash type through
the data. The native implementation also checks `address + length` against the
parsed payload before any response. This is an added safety check; no
equivalent bounds check was found in the inspected official OTA worker.

Special request addresses are:

- `0xE0000000`: verification completed; host responds with eight bytes
  beginning with ASCII `success`, then the device enters OTA mode.
- `0xF0000000`: upgrade completed; host sends the same success response and
  finishes.

The outer upgrade-mode command is `f0 22 24 35 7f f7`.

**Live stock-restore result, 2026-07-15**

- The command was sent once to begin the first, verification-only stage.
- The device requested the package tail in 512-byte chunks and a final
  481-byte chunk, all within the validated 701,120-byte payload.
- It then requested address `0xE0000000`, length 8.
- The native tool returned the official eight-byte `success\0` response.
- The device disconnected from USB immediately afterward, as expected when
  transitioning toward OTA mode.
- The first attempt did not automatically re-enumerate within its observation
  window. A normal power cycle restored version `012`; no write stage had run.
- A later verification run automatically re-enumerated on the same physical
  USB port as Jieli `4D4A:4155`, product `USB Composite Device`.
- Update mode exposes MIDI Streaming interface 1 rather than normal-mode
  interface 4. Its bulk endpoints remain `0x04` OUT and `0x84` IN.
- The native tool now selects the Audio/MIDI Streaming descriptor dynamically
  instead of hard-coding the interface number.
- The second stage issued 1,241 requests, finishing with address `0xF0000000`,
  length 8. The tool returned `success\0` and the device rebooted normally.
- After releasing macOS `MIDIServer`, the device reported
  `SMK-37 Pro_012` again.
- Verification transcript:
  `backups/ota-v012-restore-20260715-attempt2.log`
- Write-stage transcript:
  `backups/ota-v012-restore-20260715-stage2-resume.log`

The host process also exposed a macOS libusb edge case: libusb 1.0.29
`libusb_exit()` can
deadlock with the Darwin hotplug-detach thread after this disconnect. The
process was interrupted only after confirming the device was absent. Before a
retry, the tool must avoid destroying the active libusb context in that
detach-event window and must handle the normal-to-OTA transition without
assuming the original VID/PID immediately returns. The project now requires
libusb 1.0.30, retains one context across re-enumeration, matches the physical
bus/port path, and deliberately avoids `libusb_exit()` after a failed detached
transition.

macOS `MIDIServer` automatically claims the normal-mode MIDI Streaming
interface and may restart when the device re-enumerates. Direct access does
not require CoreMIDI, root, or a VM: `scripts/smk37-fw-direct` terminates the
current user's `MIDIServer` while the operation is active. Launchd can start it
again when a CoreMIDI client later needs it.

After the successful same-version write, subsequent attempts to enter the
verification stage timed out even after a normal power cycle. Device-info and
flash-read commands continued to work and the device remained version `012`.
Jieli documents error `0x400F` for an upgrade file whose contents are identical
to the installed firmware and states that such a file is not allowed. The SMK
did not expose that error through this direct transport, but its behavior is
consistent with the documented same-file rejection. Do not keep repeating the
upgrade command merely to obtain another transcript.

Source:

- <https://doc.zh-jieli.com/Apps/Android/ota/zh-cn/master/other/qa.html>

## First firmware experiment decision

Decision recorded: 2026-07-14

The original decision below is superseded. A validated stock-USB procedure now
exists for dumping the complete live flash, and a full dump has completed.
Unpacking a downloaded `.fwsc` remains a different representation from the
raw live dump.

Reinstalling the same official `.fwsc` with M-UPGRADE is useful later for verifying the normal update path, but it does not prove any of the following:

- that the live flash can be backed up
- that device-specific VM, calibration, Bluetooth, or key data can be restored
- that a modified package will pass validation
- that a non-booting application can enter OTA mode
- that forced bootloader recovery works on this product

Completed milestones:

1. Read exact updater identity `SMK-37 Pro_012` through direct USB-C.
2. Record USB descriptors and direct bulk endpoints.
3. Archive/hash the exact matching v12 package and official macOS updater.
4. Read the live main flash and verify a repeatable full 1-MiB dump.
5. Reproduce official `.fwsc` parsing and update-packet generation offline.
6. Pass a live, read-only same-product/same-version preflight; reject v15.

Completed OTA milestones:

1. Avoid the Darwin detach/`libusb_exit()` deadlock with libusb 1.0.30 and a
   transition-aware context lifetime.
2. Identify normal mode `4C4A:C755`, interface 4 and update mode `4D4A:4155`,
   interface 1 from live descriptors.
3. Match re-enumeration by physical USB bus/port instead of assuming VID/PID.
4. Complete the verification and write stages with the exact archived v12
   package and validate normal version `012` afterward.
5. Extract a second full live dump after the restore.

Next firmware milestones:

1. **Completed statically for M05:** trace MIDI channel dispatch, patch-state
   loading, and the per-event/per-voice `0x9c`-byte timbre snapshot.
2. Map the changed raw-flash regions to code, VM, calibration, and update
   metadata where they affect recovery analysis.
3. Continue product-specific forced-recovery research as a separate safety
   improvement for pre-USB application crashes.
4. Keep downgrade and non-application-region writes as separate safety gates.

Do not downgrade merely to create an upgrade test, and do not use Elite, MKE-P37, or Starrykey images for recovery testing.

## Current execution checkpoint

Checkpoint recorded: 2026-07-15

- Owner unit is connected to macOS in normal USB mode and reports the documented Audio/MIDI interfaces.
- Owner unit display firmware version: `1.05`.
- The exact archived v12 package completed both verification and write stages.
- The unit rebooted and reported `SMK-37 Pro_012` after the write.
- A post-restore 1-MiB dump completed successfully.
- A native macOS M-UPGRADE application was found and analyzed statically.
- Native libusb descriptor access from macOS succeeds against the connected
  unit. The direct path is bulk OUT `0x04` and bulk IN `0x84` on interface 4.
- Native CLI commands currently implemented and verified:
  - `build/smk37-fw probe`
  - `build/smk37-fw claim-test`
  - `build/smk37-fw device-info`
  - `build/smk37-fw flash-read <address> <length>`
  - `build/smk37-fw dump <output> [length]`
  - `build/smk37-fw inspect <firmware.fwsc> [payload-output]`
  - `build/smk37-fw upload-check <firmware.fwsc>`
  - `build/smk37-fw upload-dry-run <firmware.fwsc>`
  - `build/smk37-fw upload <firmware.fwsc> <transcript> --confirm <token>`
  - `build/smk37-fw upload-resume-v12 <firmware.fwsc> <transcript> --confirm <token>`
  - `build/smk37-fw self-test`

Use `scripts/smk37-fw-direct` rather than invoking live-device commands
directly on macOS. It releases `MIDIServer` before and during the operation.

Static analysis of M-UPGRADE and live direct-USB tests establish the following:

- Its imported device APIs are the Windows multimedia MIDI functions
  (`midiIn*` and `midiOut*`). It does not import WinUSB, SetupAPI, HID, or a
  vendor USB driver API.
- M-UPGRADE itself wraps binary updater packets, performs an
  8-bit-to-7-bit packing transform, and sends the result through the class
  transport. A macOS implementation can reproduce this below CoreMIDI by
  talking directly to endpoints `0x04` and `0x84`.
- The six-byte upgrade-mode application command is
  `f0 22 24 35 7f f7`. Its verification-stage behavior is now confirmed live.
- After that command, the updater waits two seconds and the device drives the
  transfer by requesting firmware address ranges.
- A decoded request is 15 bytes. Byte 2 is type `0x30`, byte 6 is the flash
  type, bytes 7-10 are a little-endian address, and bytes 11-13 are a 24-bit
  little-endian length.
- A response begins with `00 59 30`, repeats the flash type, address, and
  24-bit data length, appends the requested firmware data, and ends with the
  one's complement of the 8-bit byte sum. M-UPGRADE then applies its transport
  packing and framing.
- Existing M-UPGRADE logs show successful version downgrades for other
  supported products. A same-version v12 restore has now been exercised on the
  SMK-37 Pro, but downgrade has not.

The former Windows/VM checkpoint is superseded by the direct-USB macOS work.
Live backup extraction, stock same-version writes, application-only modified
uploads, custom-to-custom OTA, and custom-to-official rollback are
demonstrated. Downgrade and forced recovery from a pre-USB application crash
remain separate unproven capabilities.

## Safety gates

### Brick-risk model

Project threat-model decision, 2026-07-15: an application that does not boot is
treated as a recoverable firmware failure, not as the critical brick case, as
long as the stock boot/update loader still exposes a USB recovery transport and
can accept a verified official image. The critical brick boundary is loss of
the USB OTA recovery path itself.

The observed normal-to-update disconnect and two progress stages match Jieli's
single-backup OTA architecture. In that architecture the update loader is the
recovery environment: an interrupted firmware write may prevent the normal app
from booting, but the loader should remain active and wait for the upgrade to
resume. This exact recoverable state was demonstrated as USB `4D4A:4155` and
the native tool successfully resumed it.

Recoverable states currently demonstrated or strongly supported:

- Normal USB `4C4A:C755` still enumerates and accepts the OTA command.
- Update-loader USB `4D4A:4155` enumerates; `upload-resume-v12` can finish the
  exact official v12 write.
- A host disconnect or power loss during the app-writing stage leaves the
  loader and its update record intact, as intended by the documented
  single-backup flow. This last case is vendor-documented but has not been
  deliberately induced on this unit.

Effective-brick states for the current project are states in which the stock
boot/update loader cannot expose a usable USB recovery transport. Plausible
causes are:

- corrupting the flash header, SPL/`uboot.boot`, update loader, or its update
  record/partition metadata;
- changing loader-side clock, USB pinmux, descriptors, endpoint setup, chip
  key, cipher, or flash layout so that the host can no longer recognize or
  communicate with recovery mode;
- writing an image for another product/chip or losing power while low-level
  boot/update metadata is being replaced;
- a full raw-flash write that overwrites boot, calibration, identity, or
  protected/reserved regions rather than only the application area.

The AC79 Boot ROM itself is immutable, so these are not necessarily permanent
silicon bricks. Official AC79 documentation describes update/reset entry on a
development board and a proprietary forced-upgrade tool for internal-flash
parts. The SMK has no documented external update/reset control and that forced
path has not been demonstrated, so a no-USB state is an effective brick for
this project until the board pads and Jieli recovery tooling are mapped.

Accordingly, the first custom-package pipeline must be application-only. It
must keep the official flash header, `uboot.boot`, `isd_config.ini`, loader,
partition/reserved-area definitions, and device-specific regions unchanged.
Only `app.bin` ciphertext and the minimum required enclosing CRC/size/version
metadata may differ. A generated change manifest must reject any unexpected
byte outside those whitelisted locations before upload. Because the live
second stage requested payload offsets beginning at zero, unchanged low-level
boot content must be verified even when the intended modification is only in
the application.

Sources:

- <https://doc.zh-jieli.com/AC79/zh-cn/master/module_example/system/update.html>
- <https://doc.zh-jieli.com/AC79/zh-cn/master/getting_started/preparation/update.html>
- <https://github.com/Jieli-Tech/fw-Bootloader>

Before each staged application-only custom write, require all of the
following:

1. The exact model and current official firmware are archived with hashes.
2. User presets are exported separately.
3. A no-change unpack/repack round trip is byte-identical. **Completed
   offline 2026-07-15.**
4. The full live flash or every device-specific writable region has been
   backed up. **Completed 2026-07-15.**
5. The generated manifest preserves every protected region and the live
   command accepts only that build's exact SHA-256.
6. The owner explicitly authorizes the staged live test. **Granted for M001
   and M02 on 2026-07-15.**

A product-specific forced-recovery procedure remains required to claim safe
recovery from an application that crashes before USB/OTA initialization. Its
absence no longer makes modified-package acceptance unknown: M001 and M02
proved that separate capability live.

### Application-only package boundary

Confirmed from official v12 and enforced by `tools/smk37_app_patch.py`:

- UFW `flash.bin`: payload offset `0x400`, size `0x9C000`
- encrypted application container: physical flash `0x4000..0x9A832`
- nested `app.bin`: physical flash `0x4120`, size 615,828 bytes
- application entry point: `0x02000120`
- SFC chip key: `0x980F`

The live stock-restore commands remain independently locked to the official
v12 package SHA. Each experimental command is separately locked to one build
SHA. This prevents accidental crossing of recovery and experiment paths.

### ESP32-C3 forced-entry tool checkpoint

On 2026-07-15 an ESP32-C3 SuperMini was identified over its native USB
Serial/JTAG interface and loaded with the independent `esp32c3-usbkey/`
project. The tool implements the researched WL82 `USB_KEY` frame `0x16EF`,
MSB-first, with target D+ as the approximately 50 kHz clock and target D- as
data. GPIO4/GPIO5 are input-only with pulls disabled at boot, between attempts,
and after attempts. Output requires the exact console confirmation
`SEND USBKEY 16EF` following a three-second countdown.

Live board-only verification established that the firmware boots, waits for
console input, and rejects an invalid command while keeping both signal GPIOs
high impedance. The real key was deliberately not sent because no reviewed
SMK/host data-line harness was attached. This tool has one responsibility:
pre-enumeration electrical forced entry. Native macOS SCSI transport remains a
separate host tool, and M09 sector preparation remains an offline third tool.

The first console implementation exposed two related behaviors of ESP-IDF's
default USB Serial/JTAG VFS: an empty non-blocking read appeared as end-of-file,
and a later `PING` test was split into individual input fragments. Four
solutions were evaluated: manual byte accumulation, the interrupt-driven USB
Serial/JTAG VFS driver, an `esp_console` REPL, or a separate UART console. The
tool now installs `usb_serial_jtag_driver` and selects its blocking VFS before
using `fgets()`. A repeated `PING` test then produced exactly one rejected
command and left both output lines high impedance.

### `jl-uboot-tool` scope audit

Repository `kagaimiq/jl-uboot-tool` was checked at current `main` commit
`adb3f18889e88ac512ce0a3c4d8cc3d3cb30696a` (2025-03-16). It is the
post-entry host-program half of recovery, not a replacement for the electrical
forced-entry dongle:

- `jldevfind.py` searches Linux SCSI generic devices or Windows disk volumes
  and selects devices whose SCSI product string begins with `UBOOT`, `UDISK`,
  or `DEVICE`;
- `jltech/uboot.py` implements Jieli vendor CDBs over USB Mass Storage for RAM
  read/write/jump and loader-level Flash read/write/erase operations;
- `jluboottool.py` uploads a family-specific loader when the device reports
  `UBOOT1.00`, jumps to it, then exposes interactive `read`, `write`, `erase`,
  `erasechip`, `dump`, and memory commands;
- `jlrunner.py` uploads and runs arbitrary RAM payloads;
- `scsiio/` provides only Linux `SG_IO` and Windows
  `SCSI_PASS_THROUGH_DIRECT` transports. There is no Darwin/macOS backend;
- there is no executable `USB_KEY` signal generator in the repository.

WL82/AC791N metadata is present: protocol v2, the MengLi-encrypted memory-I/O
quirk, `wl82loader.bin`, RAM load address `0x1c02000`, and 512-byte encrypted
loader blocks. However the project README marks real WL82 support `unknown`.
Therefore its first permissible use on this unit would be identification and a
read-only dump after external forced entry, not any erase/write command.

The repository's `docs/how-to-enter-uboot.md` also conflicts with the same
author's newer dedicated USB_KEY note about D+/D- roles: the older repository
file labels D- as clock and D+ as data. The dedicated `kagaimiq/jielie` note at
commit `1657d25e6e51df6b2c18cd55cfc576c4a6370c63` was updated on 2024-06-12
from measurement/capture work and explicitly labels D+ as clock and D- as
data. Its packet and acknowledge captures support that newer assignment, which
matches the current ESP32-C3 code. This resolves the documentation conflict in
favor of D+ clock / D- data, although no waveform has yet been applied to the
SMK-37 Pro.

The same note describes the post-key phase: after acknowledgement the chip
pulls up D+ and measures 1 ms host SOF timing before initializing USB. The
data pair must be handed to an isolated host promptly, or a key generator must
provide carefully timed surrogate SOF falling pulses until calibration ends.
A manual cable swap is therefore plausible with the independently powered SMK,
but its WL82 retry budget and timing remain unvalidated; it is not yet a safe
replacement for an automatic two-line handoff.

## Next measurements

1. Photograph the mainboard underside and LCD FPC marking at high resolution.
2. With power removed, map CS4344 pins 1-4 and 7/10 by continuity.
3. Map PA0, PA5, PH7, and PH4 to determine whether an AUX input pin is available.
4. Measure LCD logic voltage before attaching a logic analyzer, then capture boot commands.
5. Identify the analog stage between CS4344 AOUTL/AOUTR and the rear Audio Out jack before designing a summing circuit.
