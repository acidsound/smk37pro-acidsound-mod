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
