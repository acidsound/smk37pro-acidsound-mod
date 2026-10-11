# Pass 3 is installed: the vendor tool was never required

Recorded 2026-10-11 on the instrument that this port started from: it was
stuck running pass 1, and pass 1 could not be updated by any host.

## What ran

```
tools/windows_uboot_key.ps1                       MIDI SysEx, host to bootloader
build/SMK37Pro-WL82-v15-H0-.../tools/
  windows_scsi_transport.py loader-probe        official loader to volatile RAM
tools/windows_flash_install.py                   erase 0xFB01, write 0xFB04
```

Result:

```
identity: {"vendor": "WL82", "product": "UBOOT1.00", "revision": "1.00"}
loader info: {"usb_buffer_size": 32768, "device_type": 3,
              "device_id": 15425556, "flash_id": 60256}
erasing 156 sectors, then writing 638976 bytes
written 638976/638976
verifying read-back
PASS: 638976 bytes written and read back identical
```

Then power-cycled. The instrument boots: pad LEDs cycle, so the firmware is
running. **The LCD is still black**, which is not fixed and is the open defect.

An earlier revision of this file claimed the LCD showed SLOOP. That was wrong.
The report it came from was that the instrument had booted into SLOOP, not that
anything was on the LCD.

## What this settles

The Jieli Forced Upgrade Tool 4.0 is not required for any step. The bootloader
is reached with an ordinary MIDI SysEx, the official loader runs from volatile
RAM, and the flash is written through two vendor CDBs that
`tools/build_v15_s1c7_seed_bundle.py` had already characterised against this
same loader.

The block device is irrelevant to all of it. `Get-Disk` reports Size 0 for this
target at every stage, including during a successful write, because the flash
is reached only through vendor CDBs and never presents a usable capacity.
Treating that zero as a fault sent this session in circles; the runbook's
success criteria carried the same error and are corrected in
`docs/sloop-p3-forced-upgrade-runbook.md`.

## What remains unproven

- OTA on pass 3 has not been exercised. It is the reason pass 3 exists, and the
  only untested claim left standing.
- `ota_upload_sloop_exact` in `src/ota.c` is code-complete and has never run
  against hardware.
- Recovery of a pass 3 instrument that fails to boot is still unproven, so
  acceptance criterion A4 in `docs/no-vendor-tool-policy.md` stays open.

## The official 016 cannot answer LCD questions

Checked on 2026-10-11 while chasing the dark panel. `firmware/SMK-37 Pro_016.fwsc`
and `SMK-37 Pro_015.fwsc` both extract to a 638,976-byte payload at offset
0x400 that is opaque: occurrences of `LCD`, `lcd`, `ST7789`, `st7789`, `240`
and `0x52` are all zero, and of 2,758 printable runs five characters or longer
every one is noise rather than a string. The only genuine ASCII sits in the
container header (`AC791N_STORAGE`, a `dead` marker, version `0.01`).

No decryption for the M-VAVE application section exists in this repository.
Searching turns up `fm6_bank.c` and `editor_fm6.c`, which are FM-1's own sound
bank encryption and unrelated, and the fact that M-UPGRADE parsed the
container, which is the manifest layer and does not expose app code.

So the panel cannot be identified from the official firmware. What remains is
the FM-1 init sequence, which is the only configuration known to light this
hardware:

```c
0x01, 0,      /* SWRESET */
0x11, 0,      /* SLPOUT */
0x3A, 1, 0x55,/* COLMOD */
0x36, 1, 0x00,/* MADCTL */
0x21, 0,      /* INVON */
0x13, 0,      /* NORON */
```

Pass 3 replaced this with a longer table adding porch, gate, VCOM, power and
gamma blocks plus CASET and RASET, transcribed from a Jieli SDK driver
`apps/common/ui/lcd_driver/lcd_st7789v.c` that is not present in this
repository and was never verified against this panel. It also dropped NORON.
That table is the most likely cause of the dark screen.
