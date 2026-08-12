# SMK-37 Pro internal recovery-entry audit

This note records the public schematic and PCB evidence relevant to recovering
an SMK-37 Pro that no longer exposes normal USB or OTA mode. It does not
authorize probing, shorting, or writing the failed instrument.

## Result

No public SMK-37 Pro photo shows a user-operable DIP switch, jumper cap, or
clearly labelled `RESET`, `RST`, `BOOT`, `ISP`, or `UPDATE` header. The public
evidence instead supports this recovery model:

```text
real chip reset/POR edge
        +
usbkey on the existing USB-C D+/D- pair
        |
        v
WL82 UBOOT1.00 forced-loader identity
```

Opening the instrument may still be useful. It can expose the battery
connector and the SoC reset/USB nets so that a genuine reset edge can be
confirmed while the instrument is powered independently from USB VBUS. This
does not imply a battery fault. It does not reveal a documented one-jumper
factory-reset path, and reset alone is not forced-download entry.

## Public SMK board evidence

FCC ID `2ARCP-SMK37PRO` publishes a six-page internal-photo exhibit:

- source:
  <https://fccid.io/2ARCP-SMK37PRO/Internal-Photos/Internal-photos-8656754.pdf>
- SHA-256:
  `d4779d84772d20598d36c3291807377bd10a7fbc7cabd2f962f3fc3ce384709a`
- page 1: complete disassembly;
- page 2: keybed PCB, both sides;
- page 3: main control PCB, component and solder sides;
- page 4: PCB antenna and U10 close-up;
- page 5: key-scan/slider area;
- page 6: internal battery.

The page-3 mainboard views contain no visible DIP switch, jumper cap, labelled
boot/reset header, or unpopulated multi-pin debug connector. This is evidence
that there is no obvious service control, not proof that every small test pad
is absent: the images embedded in the PDF are too low-resolution to read every
silkscreen or trace every via.

The FCC exhibit index lists `SCH` only as long-term-confidential metadata, so
the product schematic itself is not public:

- <https://fccid.io/2ARCP-SMK37PRO>

The linked community repository provides higher-resolution detail photos:

- <https://github.com/jonathaslacerda/smk-37-pro-docs/tree/main/images/smk37pro>

The three high-resolution green-board photographs correspond to the photos
posted by `LarsLinux93` in the SMK reverse-engineering gist on 2025-08-28. The
repository added its copies later and cites that gist discussion for the SoC
identification. The original gist attachment URLs no longer resolve, so an
original-file hash comparison is not possible; the subject, capture date,
resolution, and image contents are consistent. This provenance is separate
from the six-page FCC exhibit reviewed above:
<https://gist.github.com/probonopd/18b3ed65a69d0229eb630c47d7e316dc>.

In `internals-board4.jpg`, the unpopulated three-pin groups at the left edge
are labelled as `+3.3D`, `ADC5`, `GND`, `JP2`, and a similar ADC group. The
separate pitch/modulation-wheel photograph shows the matching three-wire
3.3 V / ADC / ground potentiometer connection. These groups are therefore
analog wheel inputs, not evidence of USB, ISP, or reset headers.

The community and FCC photos do not provide a sufficiently sharp, orthogonal
view of the full USB-C area, the complete U10 pin-42 route, and both sides of
every intervening via. A test pad on either route remains possible but
unconfirmed.

## Owner board-photo audit: 2026-07-16

Nine owner-supplied photographs show the installed board's USB-C area, both
PCB faces around the rear connectors, and U10 at substantially better detail
than the FCC exhibit. The layout matches the public green-board photographs.

Observed facts:

- J5 is the SMK USB-C connector. Its visible signal pins and shell anchors do
  not show an obvious lifted connector, cracked joint, corrosion, or burned
  area. Photography cannot prove data continuity or USB-PHY health.
- U10 is visibly marked `JL C108221-11B8`; its orientation dot is at the
  photograph's upper-right corner. The adjacent 24.000 MHz crystal is present
  and has no visible mechanical damage.
- Rotating the AC7911B QFN48 package diagram to that dot orientation places
  pin 48 `FUSBDP` and pin 47 `FUSBDM` at the top two positions on U10's right
  edge. Pin 42 `PB1` is the seventh position down that same edge. None of
  these routes exposes a clearly labelled service pad in the photographed
  area; traces transition through normal routing/vias.
- The groups of three large round solder joints near J5 are the three
  electrical terminals of the rotary encoders mounted on the opposite PCB
  face, accompanied by their large mechanical anchor joints. They are not USB
  or recovery test points.
- The labelled `+3.3D / ADC5 / GND` and adjacent connector groups remain
  consistent with analog control inputs, not reset or boot headers.
- No new `RESET`, `RST`, `BOOT`, `ISP`, `UPDATE`, DIP switch, or jumper cap is
  visible.
- A subsequent photograph of the PCB face directly behind U10 shows the
  regular central thermal/ground-via grid and normal tented signal vias and
  traces. It does not expose a labelled or bare USB/reset service pad. The
  central via grid belongs to U10's exposed ground/thermal pad and must not be
  used for signal injection.

The photos therefore improve the USB/reset pin-location map but do not reveal
a free one-pad recovery shortcut. The battery connector and its board entry
were not included, so a guaranteed cold-POR procedure must wait for a clear
photo of that connector before it is unplugged.

The owner subsequently identified and photographed the keyed three-pin battery
connector. With USB removed, the battery was disconnected for five minutes,
residual rails were discharged, and the battery was reconnected in its keyed
orientation. A battery-only boot reproduced the same backlight-without-UI
state: instrument power, panel LEDs, and LCD backlight are present, but the LCD
has no pixels/UI. This rules out a merely latched power state and means the
battery disconnect should not be repeated as a recovery attempt.

With the instrument then independently powered and attached directly to a Mac,
the host detected USB-C CC attachment and powered its port, but no
`IOUSBHostDevice` appeared. The connector/cable is therefore visible at the
Type-C attach layer, while USB 2.0 enumeration remains absent. CC detection
does not establish continuity of the separate D+/D- conductors or prove that
U10 asserted its USB pull-up. Rotating the USB-C plug 180 degrees produced a
second clean CC attach and USB2 host-port power-on with the same absence of a
USB device node, excluding a fault limited to only one plug orientation.

## SoC pins that matter

U10 is marked `JL C108221-11B8`. Together with the `AC791N` firmware family
and 1 MiB internal Flash size, this is strong evidence for an AC7911B8-family
QFN48 device. The AC7911B datasheet assigns:

| QFN48 pin | Name | Relevant function |
| --- | --- | --- |
| 42 | `PB1` | pulled-up GPIO, `Long Press reset`, `ISP_DO` alternate function |
| 47 | `FUSBDM` | USB D-, `ISP_DI_A` alternate function |
| 48 | `FUSBDP` | USB D+, `ISP_CLK_A` alternate function |

Datasheet source:
<https://gitee.com/Jieli-Tech/fw-AC79_AIoT_SDK/blob/release/AC79NN_SDK_V1.2.0/doc/datasheet/AC791N规格书/datasheet/AC7911B_Datasheet_V1.4.pdf>.

The stock SMK configuration records `RESET=PB01_08_0`: PB1, active low, held
for eight seconds. That is the firmware's long-press reset input. It may be
valuable for producing a real reset while a V4 continuously transmits
`usbkey`, but it is not itself a boot-mode selector and should not be shorted
until its board route and electrical levels are confirmed.

The same package records `UPDATE_JUMP=0`, and the public AC79 SDK uses that
value as its default. Therefore it is not evidence that SMK wired a panel key
as a ROM-update strap. The highest-C key labelled `RESET` in the SMK UI is
documented as an application/menu action and is part of the scanned keybed;
no public evidence connects that key directly to PB1 or the mask-ROM entry
logic. Holding it is not a demonstrated forced-recovery sequence.

Jieli also documents a separate immediate hardware reset source on `VCM`. Its
reference development-board schematic connects `VDDIO` to `VCOM` through the
S2 RESET button, and the reset-reason documentation describes `SYS_RST_VCM`
when the VCM reset pin is raised to approximately 3.3 V. This is useful
evidence that a real reset can be generated without cycling USB VBUS, but it
is not an SMK wiring diagram. VCM is also the audio-common pin, so it must not
be driven or probed as a reset input until the exact SMK net is identified.

References:

- Jieli development-board MCU schematic:
  <https://gitee.com/Jieli-Tech/fw-AC79_AIoT_SDK/blob/e30b1ee375d1f2993fc23bf92c8b99006a6e5f9d/doc/datasheet/AC791N规格书/schematic/AC79x%20Wifi%20Develop%20V1.0/AC7911B_MCU%20TOP%20V1.0.pdf>
- VCM reset reason:
  <https://doc.zh-jieli.com/AC79/zh-cn/master/module_example/system/system_reset_reason.html>

The data-sheet alternate names `ISP_DI_A`, `ISP_CLK_A`, and `ISP_DO` do not
prove a separate, publicly usable ROM-boot header. The supported AC79 recovery
procedure for internal-Flash parts remains the forced-upgrade tool on USB.

## Paths that do not apply

The official AC79 download documentation distinguishes two device classes:

- external-Flash parts may use the documented Flash MISO-to-ground start-up
  technique;
- internal-Flash parts use the Jieli forced-upgrade tool and succeed as
  `WL82 UBOOT1.00`.

AC7911B8 is the 8-Mbit internal-Flash variant. Do not copy an external-Flash
development-board `LOAD`, SPI-CS, or MISO short onto the SMK board. The SMK
photos also show no separate eight-pin SPI NOR beside U10.

The official B0/B8 reference schematic explicitly marks B8 as the internal
8-Mbit-Flash variant and leaves the external-Flash device and associated parts
unpopulated for B8. Reference:
<https://gitee.com/Jieli-Tech/fw-AC79_AIoT_SDK/blob/e30b1ee375d1f2993fc23bf92c8b99006a6e5f9d/doc/datasheet/AC791N规格书/schematic/AC7911B0%26B8-WIFI音箱%28单MIC差分%29/AC7911B0_AC7911B8_WIFI音箱参考原理图%28单MIC%29-V1.2-20220429.pdf>.

Jieli's SDTAP/JTAG path is not a substitute for dead-application recovery. The
official flow requires firmware built with SDTAP debugging enabled and then a
V4 debug mode; it is not a demonstrated mask-ROM entry strap for the failed
stock SMK application. Reference:
<https://doc.zh-jieli.com/AC79/zh-cn/master/module_example/system/SDTAP.html>.

No reviewed public document exposes a fuse option that disables WL82
USB-key/Mask-ROM entry. This does not prove that no private production option
exists. It does mean there is no positive evidence of such a block here, and
M09 did not modify OTP/eFuse or the preserved boot prefix, so M09 itself has no
known mechanism for newly disabling that path.

## USB-key handoff evidence

The latest dedicated USB-key note in `kagaimiq/jielie`, commit
`1657d25e6e51df6b2c18cd55cfc576c4a6370c63`, documents an observed `0x16EF`
frame with D+ as clock and D- as data. This is newer than the contradictory
D-/D+ wording in `jl-uboot-tool/docs/how-to-enter-uboot.md` and matches the
captured waveform and the current ESP32-C3 implementation:
<https://github.com/kagaimiq/jielie/blob/main/isp/usb/usb-key.md>.

After the target acknowledges, it pulls up D+ and measures host SOF timing
before normal USB enumeration. The same source recommends immediately
switching the pair to an isolated host, or having the key generator supply
precise 1 ms falling pulses until clock calibration completes. This confirms
that a USB data-pair handoff is a real requirement; a normal downstream hub
port does not inject GPIO key signals into another port.

A physical cable swap after acknowledgement is possible in principle because
the SMK has independent power, but it is not yet accepted as a reliable WL82
procedure. The older/newer-chip retry budget is not documented for AC7911,
and unplugging the target USB-C also removes host VBUS and consumes handoff
time. Do not connect a GPIO pair in parallel with an active host port.

## Serial forced-download fallback

The official WL82 SDK contains a second transport configuration that is worth
preserving as a fallback, not attempting first. Both
`cpu/wl82/tools/isd_config_rule.c` and the loader variant contain:

```text
//DOWNLOAD_MODEL=SERIAL
DOWNLOAD_MODEL=usb
SERIAL_DEVICE_NAME=JlVirtualJtagSerial
SERIAL_INIT_BAUD_RATE=9600
SERIAL_SEND_KEY=YES
```

This is positive evidence that Jieli's AC791N/WL82 download stack was built
with a serial-loader route. The V4 manual says its serial mode sends the key
through the tool's TX pin and, for chips newer than AC697x, connects that line
to `LDOIN` while the tool powers the target and shares ground. The generic
reverse-engineered UART key is `0x68AF`, followed by a RAM loader, but that
work does not prove the exact WL82 power-pin circuit or loader timing.

AC7911B's public QFN48 datasheet labels pin 44 `VBAT` / LDO power rather than
exposing a separate `LDOIN` signal. The SMK also has a battery, charger, and
power-switch network. Therefore the public evidence is insufficient to attach
V4 TX to any visible SMK pad or to let the V4 drive the populated power rail.
This route requires the actual board to be unpowered, its battery isolated,
and its power-input route positively mapped first. It is a plausible fallback
if USB D+/D- or the USB PHY proves damaged, but it is materially more invasive
than USB-key entry and is not authorized by this note.

## Safe physical inspection gate

The next useful device-side action is photography only. Before any continuity
or voltage measurement, obtain:

1. one sharp full-board photo of the component side;
2. one sharp full-board photo of the solder side;
3. macro photos of U10 showing its orientation mark and all four pin rows;
4. macro photos of the USB-C connector and nearby parts on both PCB sides;
5. macro photos of the power switch, battery connector, and any PCB revision
   or test-pad labels;
6. a photo showing where the battery and USB ground enter the board.

The instrument must be off and all external cables removed while it is opened.
Do not bridge any pad, touch two pins with a probe, or reconnect USB for powered
testing during this photo stage. Protect the Li-ion pouch from tools, screws,
and PCB edges. If the battery connector is not plainly removable without
pulling wires or flexing the pouch, leave it connected and stop.

After the photos are reviewed, the next request can be limited to unpowered
continuity/resistance mapping of specifically identified candidates:

- U10 pin 42 to the front-panel reset/power network;
- U10 pins 47/48 to USB-C D-/D+ and any intervening pads;
- battery disconnect/power switch behavior needed to guarantee a real POR.

Until that mapping exists, no pad should be called reset, boot, or USB merely
from its shape or proximity.

The instrument was subsequently reassembled and retained exactly the same
power/backlight-without-UI and no-enumeration behavior. Internal inspection is
therefore closed. Do not reopen the chassis for recovery unless a specific
electrically identified point and measurement procedure have first been
documented; continue through the external USB forced-entry path.

## Recovery decision

An internal reset point could solve one important V4 uncertainty: USB VBUS
cycling does not necessarily reset an independently powered SMK. It would not
replace the V4 or reviewed USB-key source, and it would not replace host-side
`WL82 UBOOT1.00` identity checks and a two-pass read-only Flash dump. The
preferred sequence is therefore:

1. inspect and map without powering the open board;
2. obtain the V4 and first try continuous-key mode with a normal power-on;
3. use an internal reset point only if its net is positively identified and
   normal power-on does not produce forced mode;
4. stop at exact `WL82 UBOOT1.00` INQUIRY before any loader command;
5. proceed to the existing volatile-RAM loader and double-dump gates.

If repeated, electrically verified USB-key attempts never produce a target,
retain the serial WL82 configuration above as a separate engineering branch.
Do not combine USB-key probing, serial power injection, and Flash writing in
one experiment.

## Primary references

- SMK FCC filing and exhibit status:
  <https://fccid.io/2ARCP-SMK37PRO>
- SMK FCC internal photos:
  <https://fccid.io/2ARCP-SMK37PRO/Internal-Photos/Internal-photos-8656754.pdf>
- Community SMK board photographs:
  <https://github.com/jonathaslacerda/smk-37-pro-docs/tree/main/images/smk37pro>
- AC7911B datasheet:
  <https://gitee.com/Jieli-Tech/fw-AC79_AIoT_SDK/blob/release/AC79NN_SDK_V1.2.0/doc/datasheet/AC791N规格书/datasheet/AC7911B_Datasheet_V1.4.pdf>
- AC79 forced-upgrade preparation:
  <https://doc.zh-jieli.com/AC79/zh-cn/release_v1.2.0/getting_started/preparation/update.html>
- Jieli forced-upgrade operation:
  <https://doc.zh-jieli.com/Tools/zh-cn/dev_tools/forced_upgrade/upgrade_and_download.html>
- V4 switch modes:
  <https://doc.zh-jieli.com/Tools/zh-cn/dev_tools/forced_upgrade/toggle_switch.html>
