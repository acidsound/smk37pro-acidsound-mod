# SLOOP on SMK-37 Pro: pass 2 (LCD) and pass 3 (OTA restored)

Date: 2026-10-11
Device: SMK-37 Pro, SN K3PFQ23200319, running SLOOP pass 1 (installed 2026-10-11,
sha `db0e9d21…`).

## 1. The blank LCD, and what actually caused it

Pass 1 booted, enumerated as `1209:0001` "Felucca", and cycled the pad LED
colours, but the LCD stayed black.

The first hypothesis in `docs/research-notes.md` was that the panel was 240x240
by inference from the CASET/RASET range and was not confirmed. That turned out
to be right, and confirmable from public sources without opening the case:

- The community repo (jonathaslacerda/smk-37-pro-docs) quotes the M-VAVE
  specification verbatim: **1.54" LCD**.
- The decoded v15 driver pumps `0xB40 * 40 = 115200` bytes per frame, which is
  exactly `240*240*2`.
- Jieli's own ST7789V driver sets CASET and RASET to `0x00,0x00,0x00,0xEF`,
  i.e. 240 columns and 240 rows.

So SMK-37 Pro and FM-1 are both 240x240, the board HAL pin assignment decoded
from v15 (D/C = PB5, CS = PC8) is correct, and `SMK37_LCD_W/H = 240` was never in
doubt.

The defect was narrower: `sloop-fm1/firmware/src/lcd.c` inherited FM-1's
init table, which leaves the ST7789V power and gamma registers at power-on
defaults. On this panel that means the driver never starts.

| entry | FM-1 table | Jieli `lcd_st7789v.c` |
|---|---|---|
| `0x3A` COLMOD | `0x55` | `0x05` |
| `0xB2 0xB7 0xBB 0xC2 0xC3 0xC4 0xC6 0xD0` | absent | present |
| `0xE0 0xE1` gamma | absent | present |
| `0x2A 0x2B` | set per fill only | set once at init |

`0x29` DISPON was never actually missing -- `lcd_init()` sends it after the
first fill -- but it was arriving after a full-screen fill with no address
window set, rather than as part of the vendor sequence.

**Rejected:** photographing the LCD FPC. The controller and geometry are
recoverable from published documentation, and the repo already had the v15
decoded table. Teardown was never necessary.

## 2. Pass 2: the fix

`sloop-smk37/board/src/lcd.c` shadows `sloop-fm1/firmware/src/lcd.c` in the
unity build, exactly the way `board/src/panel.c` already shadows the FM-1 panel.
Every line below `LCD_SEQ` is a verbatim copy of upstream; only the table
changed. It is Jieli's ST7789V init transcribed from
`apps/common/ui/lcd_driver/lcd_st7789v.c` in the AC79 SDK, restructured into the
local `{cmd, n, data…}` / `cmd 0x00 = wait` format.

The table is 23 entries and 101 bytes; a checker walks it with the same stride
as the C loop and confirms it ends exactly on the table length.

Built image 535,676 B (`16ca77fd…`, +48 B over pass 1).

## 3. The dead end, and why the LCD fix could not be delivered

Pass 1 is built with `FELUCCA_OTA=0`, so it never answers the M-UPGRADE
upgrade command. The only other way back into the bootloader is the UBOOT soft
key `F0 22 24 35 7D F7`, which `main.c` handles unconditionally -- it is not
gated by `FELUCCA_OTA` or `FELUCCA_FLASH`. A new `uboot-sloop` command in
`smk37-fw` sends it.

That works: the instrument re-enumerates as `4c4a:8057` "WL80UBOOT1.00",
class 08/06/50, bulk IN `0x81` / OUT `0x01`. But that is the Jieli UBOOT
mass-storage path, not the OTA path, and **macOS will not give an unprivileged
process access to it**:

- `IOServiceOpen(USBInterface, kIOServiceExclusive)` -> `kIOReturnExclusiveAccess`
  (`0xe00002c5`)
- `USBInterfaceOpen` shared fallback -> same
- libusb `libusb_claim_interface` -> `-3` (access denied), on all 27 attempts
- device reset then immediate claim -> same

The process is not root, passwordless sudo is unavailable, and SIP is enabled.
libusb *does* claim the MIDI-class interfaces on this instrument, so this is
specifically the mass-storage class being refused.

`docs/forced-recovery-plan.md` records that the Apple-blessed API for this is
`SCSITaskInterface` / `obtainexclusiveaccess`, which requires a SCSI task
node that macOS never creates here -- the device matches with no driver bound
(`WL80UBOOT1.00@00100000 … registered, matched, active` with no children). No
dump artefacts exist in the repository either, so `smk37-wl82-macos-iokit-recovery`
has never actually run against hardware.

**Consequence: the instrument is one-way from the macOS host until it is
flashed with a build that has OTA enabled.** The user was told this plainly
rather than being left with a half-working LCD and an implied next step.

## 4. What was built to remove the dead end

### 4.1 `smk37-wl82-macos-iokit-recovery sloop-write`

A full-package writer for the UBOOT path, added alongside the existing
six-sector `restore`. It is the same operation stage 2 performs, taken from the
captured pass-1 transcript: the FWSC payload at flash address 0, 701,120 bytes,
in request-1-at-`0x00000000` through request-48-at-`0x000aafc0`+481.

It reuses the verified vendor primitives (`erase_sector`, `write_flash` with
CRC-16/XMODEM per chunk, `read_flash`) and pins the payload by SHA-256
(`f39733b2…`) and size, with an explicit confirm token. Negative-tested: the
pass-1 payload is refused, and a wrong token is refused, with no device access.

It is implemented and builds clean. **It cannot run on this Mac** for the reason
above. It is kept because it is correct against the documented CDB contract and
would work wherever the interface can be seized.

### 4.2 Pass 3: storage stubbed, OTA re-enabled

The real problem was the build profile, not the transport.
`sloop-fm1/firmware/src/felucca.c` puts the flash **primitives**
(`st_read`, `fl_erase4k_quiet`, `fl_write`) inside `#if FELUCCA_FLASH`,
together with `#include "storage.c"`. The build pinned `FELUCCA_FLASH=0` to keep
FM-1's store map out -- correctly, because its `FL_DATA 0x97000..` lies inside
this board's app-data slot (`0x4120 + 617,012 B`, ending `0x9AB34`). That in
turn pinned `FELUCCA_OTA=0`, because felucca.c errors on
`"FELUCCA_OTA needs FELUCCA_FLASH"`.

What is actually wanted is narrower than `FELUCCA_FLASH`: the primitives,
without the preset store.

- `ota_erase` requires `ota_in_area(off, 0x1000)` and 4 KiB alignment
- `ota_prog` requires `ota_in_area(off, n)`
- `ota_fread` is `st_read`, read-only

`OTA_AREA` is `0xE0000..0xE4FFF`, well clear of the app-data slot. The three
hooks can write the staging area and nothing else; `ota_session` then writes
the UPDATA_PARM record and resets, and **Jieli's own loader installs the
package**. The application never overwrites its own code.

So `sloop-smk37/board/src/storage.c` replaces FM-1's store with
`st_save`/`st_load` that always return -1, plus the layout constants and
symbols the callers need to compile (`ST_PAYLOAD_MAX`, the `OBJ_*` enum,
`st_hdr_t`, `st_buf`, `st_current`, `st_sector`, `st_crc32`). Every caller
already handles the failure by reporting "SAVE ERROR". With the real store not
linked, nothing can erase or program a preset sector.

The build's symbol gate was updated accordingly: it now forbids `st_body` and
`st_head` (real-store-only symbols) and `fl_plain_window_init`, instead of
forbidding the primitives.

Instrument behaviour: presets and calibration are not stored. That matches the
history of this instrument -- none was ever stored
(`docs/v16-install-brick-restore-record.md`) -- and reporting "SAVE ERROR"
is the honest result rather than a silent loss.

Built image 561,168 B (`a8186b26…`), package `6ec25f3e…`.

## 5. One flashing step remains, and it removes itself

Pass 3 has to reach the instrument by the only route that still works from
Windows: the Jieli Forced Upgrade Tool 4.0, with the pass-3 package.

After that, the app answers the M-UPGRADE command again and every future update
runs from macOS over USB MIDI through `smk37-fw`, with no forced-upgrade
hardware and no Windows host.

Both pass-2 and pass-3 packages are pinned and built:

| pass | package | payload | for |
|---|---|---|---|
| P2 | `SMK37Pro-v15-SMK-37_Pro_015.fwsc` `fdeb0244…` | `f39733b2…` | LCD fix only; no OTA |
| P3 | `SMK37Pro-v15-SLOOP-SMK37-P3.fwsc` `6ec25f3e…` | `52e9c656…` | LCD fix **and** OTA restored |

**Flash P3, not P2.** P2 leaves the instrument in the same one-way state, so
the next change would need Forced Upgrade Tool 4.0 again.

## 6. Rejected alternatives

- **Photographing the LCD FPC** -- the panel's controller and geometry come from
  published documentation and from the v15 decode already in the repo.
- **Setting `FELUCCA_FLASH=1` as-is** -- that links FM-1's `storage.c`, whose
  `FL_DATA 0x97000` is inside the app-data slot. `st_save` would erase running
  code. The stub is the safe way to get the primitives.
- **A generic escape-hatch upload command** -- the allowlist is the repository's
  safety property. Each pass keeps its own pin and confirm token.
- **Raising the Mac's privilege** -- sudo needs a password, SIP is on, and it
  was not requested.
