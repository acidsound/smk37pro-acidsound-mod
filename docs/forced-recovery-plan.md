# M09 forced-recovery plan

The failure analysis and ranked root-cause hypotheses are recorded in
`docs/m09-brick-incident.md`.

## Current state

M09 completed the normal OTA write but failed before display and normal USB
initialization. A true power cycle leaves the display and pad LEDs off. macOS
detects neither normal `4C4A:C755` nor updater `4D4A:4155`. The normal OTA and
`upload-resume-v12` paths are therefore unavailable.

Do not reinstall M09. Do not use chip erase, burn a chip key, write another
product's image, or overwrite the whole 1 MiB Flash.

## Required entry hardware

AC7911B8 belongs to the AC791N/WL82 internal-Flash family. Jieli's official
documentation says an internal-Flash part that cannot run its firmware must be
reset while a forced-upgrade tool transmits `usbkey`. The preferred hardware
is Jieli Forced Upgrade Tool 4.0. A generic replacement is now implemented as
the independent ESP-IDF project `esp32c3-usbkey/` for an ESP32-C3 SuperMini.
It generates only the electrical `USB_KEY`; it does not enumerate the WL82,
load code, read Flash, or write Flash.

The ESP32-C3 tool was built and uploaded to the available board on 2026-07-15.
Its boot console confirmed GPIO4/GPIO5 high impedance and no automatic output.
An invalid console command was rejected while the lines remained high
impedance. The real `SEND USBKEY 16EF` command has not been executed, and no
ESP signal wire has yet been connected to the instrument.

Keep the recovery components separate:

- `esp32c3-usbkey/`: forced-entry signal generator only;
- `tools/smk37_wl82_macos.c`: host-side WL82 detection and, after staged
  validation, loader/read/write transport;
- `tools/prepare_m09_forced_recovery.py`: offline exact-sector preparation and
  hash manifest;
- normal SMK application patch/OTA tools: never a dependency of forced entry.

Because SMK-37 Pro has an internal battery, the dongle's switch-1 VBUS cycling
does not guarantee a processor reset. The likely entry sequence is:

1. Turn the instrument fully off.
2. Put the official forced-upgrade tool in switch-3 continuous-`usbkey` mode,
   or arm the reviewed ESP32-C3 tool without yet sending its confirmation
   command.
3. Connect the dongle between an isolated host USB port and the SMK USB-C data
   port using a data-capable adapter.
4. Turn the instrument on once while the dongle is transmitting the key.
5. Confirm a `WL82 UBOOT1.00`-style mass-storage identity before running any
   loader command.

This sequence remains unverified on SMK-37 Pro. Do not open the instrument or
probe the mainboard merely to try it; the forced tool operates on the existing
USB data pair.

Before substituting the ESP32-C3, settle the physical D+/D- routing. The C3's
native USB-C remains connected to macOS for power and console, while GPIO4 is
the target D+ clock and GPIO5 is the target D- data signal. Both GPIO paths
require series resistance. A plain USB hub is not a signal injector: connecting
the C3 and SMK to two downstream ports makes both of them separate devices of
the Mac and gives the C3 no electrical access to the SMK data pair.

The researched protocol requires two data-bus phases. During `USB_KEY`, the C3
must control the target D+/D- pair. After target acknowledgement, the C3 must
release both lines and the target pair must be switched to the Mac host for USB
enumeration. Therefore the reliable topology needs an inline USB data breakout
plus a reviewed two-line switch/multiplexer, or equivalent forced-upgrade
hardware. Do not directly parallel GPIOs onto an active host pair or improvise
a powered USB Y cable. A hub may supply power and an isolated host port, but it
does not replace the data-pair tap or phase switch. Hub traffic from unrelated
full/low-speed devices may also disturb the target's initial USB clock
measurement, so use a dedicated/otherwise empty path for first validation.

## Host software candidates

- Official AC79 SDK v1.2.0 includes `wl82loader.bin` and Windows
  `isd_download.exe`. Its documented direct form supports
  `-todisk <file> <address>`.
- `jl-uboot-tool` commit `adb3f18889e88ac512ce0a3c4d8cc3d3cb30696a`
  includes WL82 protocol metadata and a WL82 loader, but labels real WL82
  support `unknown`. Treat it as read-only until a full dump succeeds.
- The open-source tool has Linux and Windows SCSI transports, not a macOS
  transport. Its Linux implementation sends the JL vendor CDBs through the
  standard `SG_IO` ioctl and is the preferred first recovery host.
- A native macOS port is technically possible. The installed macOS SDK exposes
  `SCSITaskDeviceInterface`, `CreateSCSITask`, `ExecuteTaskSync`, data-transfer
  buffers, sense data, and exclusive-access control. It would require a new
  backend plus device-side validation, so it must not debut with Flash writes.
  The first native checkpoint is implemented as
  `tools/smk37_wl82_macos.c`. It compiles on the current Apple Silicon macOS
  host and exposes only `self-test` and standard read-only SCSI `INQUIRY` via
  `probe`; it contains no JL vendor or Flash commands. Prove INQUIRY, loader
  upload, and full read-only dump in that order before adding a write path.
- Docker on macOS is not equivalent to a Linux USB host for this purpose. Use a
  physical Linux system or a VM that provides real USB-device pass-through.

Build and run the native read-only probe with:

```sh
make macos-wl82
build/smk37-wl82-macos self-test
build/smk37-wl82-macos probe
```

The probe requests exclusive SCSI access but does not automatically unmount
media. If macOS mounts the WL82 pseudo-disk and the probe reports busy, inspect
and unmount that specific disk before retrying; never unmount by an ambiguous
disk number.

Official SDK snapshot used for comparison:

- repository: `https://gitee.com/Jieli-Tech/fw-AC79_AIoT_SDK.git`
- branch: `release/AC79NN_SDK_V1.2.0`
- commit: `e30b1ee375d1f2993fc23bf92c8b99006a6e5f9d`

## Minimal restoration scope

The exact M09 Flash image differs from the exact official-v12 Flash image in
only six 4 KiB sectors:

| Sector | Reason represented in that sector |
| --- | --- |
| `0x04000` | application-area CRC/header |
| `0x20000` | Note Off hook |
| `0x21000` | Note On hook and wrapper |
| `0x27000` | local-pad bridge hook |
| `0x5A000` | display marker |
| `0x99000` | attempted DX7 runtime templates and related ciphertext |

Prepare exact sector files offline with:

```sh
python3 tools/prepare_m09_forced_recovery.py \
  build/SMK-37_Pro_012.fwsc \
  build/SMK37ProMod-M09-dx7-drums-base012.fwsc \
  build/m09-forced-recovery
```

This command does not access USB. Before any write, forced mode must first dump
the entire 1 MiB Flash. Every target sector in that dump must match the
manifest's `expected_m09_sha256`. If any target differs, stop and do not write.

If all six hashes match, erase/write/verify only those six sectors from the
stock files. Preserve `0x00000..0x03FFF`, all non-target application sectors,
and all user/calibration regions. Reboot only after every written sector reads
back with the manifest's `stock_sha256`.

## Evidence needed before declaring recovery

1. Forced-loader identity and chip family are WL82/AC791N.
2. A read-only full dump succeeds and is archived before writing.
3. The six target-sector hashes match exact M09 expectations.
4. Each stock sector reads back with its recorded hash.
5. Normal USB identity returns as `SMK-37 Pro_012`.
6. Display 1.05, audio, local keys, pads, and user banks are checked.

## Sources

- <https://doc.zh-jieli.com/AC79/zh-cn/release_v1.1.0/getting_started/preparation/update.html>
- <https://doc.zh-jieli.com/Tools/zh-cn/dev_tools/forced_upgrade/upgrade_and_download.html>
- <https://doc.zh-jieli.com/Tools/zh-cn/dev_tools/forced_upgrade/toggle_switch.html>
- <https://github.com/kagaimiq/jl-uboot-tool>
- <https://developer.apple.com/documentation/iokit/scsitaskinterface>
- <https://developer.apple.com/documentation/iokit/scsitaskdeviceinterface/1575374-obtainexclusiveaccess>
