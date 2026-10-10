# Record — official v16 installed, bricked, restored to official v15

**Reported by the owner on 2026-10-11.** This fills a gap the repository did not
cover. The 2026-10-11 handoff assumed no v16 had ever been installed and that
no downgrade evidence existed; both premises were wrong.

Package provenance: <https://github.com/jonathaslacerda/smk-37-pro-docs/tree/main/firmware>
(`FIRMWARE.md`). Tool provenance: <https://www.m-vave.com/download>.

## What happened

1. Official `016` was installed with **M-UPGRADE**, the M-VAVE official updater.
2. The instrument then failed. **Power came on, the LCD was frozen and
   inoperable, and neither USB nor BLE enumerated.**
3. It was restored to official `015` on **Windows** with the **Jieli Forced
   Upgrade Tool 4.0**, by supplying the `015` `.fwsc` file. **Three minutes.**
4. Presets and calibration **were never stored on this instrument**, so no user
   data was ever at stake.

## Two recovery tiers, both now demonstrated on this instrument

| | M-UPGRADE | Jieli Forced Upgrade Tool 4.0 |
| --- | --- | --- |
| Path | in-app OTA over USB MIDI | forced `usbkey` entry + vendor write |
| Host | Windows **and macOS** | Windows |
| Needs a booting device | **yes** | **no** |
| Demonstrated here | 012 → 015, logged 2026-08-03 | 016 brick → 015, 3 minutes |

M-UPGRADE is the normal path and it works on this Mac:
`/Applications/M-UPGRADE.app`, `CFBundleIdentifier sinco.M-UPGRADE`, Qt/RtMidi
based, `AppConfig.ini` pointing `OTA_FILE` at `/Users/spectrum/Downloads/`.
Its own log records a successful OTA on this machine:

```
[2026-08-03 03:43:09.071] [INFO] Parsed OTA file (20-slot) - Name: SMK-37 Pro, Version: 15
[2026-08-03 03:43:22.056] [INFO] Second step (upgrade) completed successfully
[2026-08-03 03:43:28.456] [INFO] Device connected successfully: SMK-37 Pro, Version: 15
```

The `015` package staged for that run is byte-identical to the archived
official baseline in this repository:
`f7f1831cd7c9ad8b4831b6e71ea0bdbcdff9ae4c4077276b3c965511bf4d4fff`.

## The brick is the same failure class as M09

[`docs/m09-brick-incident.md`](m09-brick-incident.md) records the M09 custom-app
brick as `BOOT-FAILED / NO-USB`: power on, LCD backlight lit, no UI, no USB
enumeration. The `016` brick matches, with the addition that BLE did not
enumerate either, placing the failure earlier than a USB-only fault. Two
independent causes, one symptom class.

M09's report named the gap that made its brick serious — the forced-upgrade path
"had been researched but had not been physically demonstrated". That gap is
**closed on this instrument**. The procurement decision in
`docs/forced-recovery-plan.md` §"Procurement decision", preferring the genuine
V4.0 over a one-off ESP32-C3 harness, is validated by use.

## The 016 that bricked is an unofficial build

Per the community `FIRMWARE.md` and the existing note in
[`docs/handoff-2026-10-01.md`](handoff-2026-10-01.md), `SMK-37_Pro_016.fwsc` is a
community upload with no vendor signature. An **unofficial** image failing to
boot and being recovered to a stock image is a materially weaker signal than a
vendor-signed image doing the same.

## Open question worth one cheap check

M-UPGRADE logs the metadata slot count when it parses a package:
`Parsed OTA file (**20-slot**) - Name: SMK-37 Pro, Version: 15`.
`15` is 20-slot. The offline analysis in
[`tools/prepare_v16_to_v15_package_diff.py`](../tools/prepare_v16_to_v15_package_diff.py)
verifies that `16` is **36-slot** — a different container shape. No retained
M-UPGRADE log shows a 36-slot parse, and none of them shows a `016` install at
all, so the 016 installation is not evidenced in the surviving logs.

Selecting `SMK-37 Pro_016.fwsc` in M-UPGRADE on a machine with no instrument
attached would settle it: the tool emits the parse line straight after the file
dialog, before any device handshake. That needs no device, no connection and no
write, and a mis-parse would be a strong candidate explanation for the brick.

## What this closes

1. **Vendor downgrade support is demonstrated**, not assumed — blocker 1 of
   [`docs/handoff-2026-10-11-v16-to-v15.md`](handoff-2026-10-11-v16-to-v15.md).
2. **User-data preservation is settled by fact.** Presets and calibration never
   existed here, so blocker 3 — the ownership of `0x9C000..0x9CFFF` and the
   400 KiB at `0x9C000..0xFFFFF` — has nothing to protect.
3. **A self-built writer is not required.** The vendor tool writes the vendor
   package and owns the package-to-chip representation, so blocker 2 only ever
   mattered for a writer this project would operate itself.

## Consequence for the SLOOP port

A boot failure here presents as `BOOT-FAILED / NO-USB`, recoverable only by the
forced-upgrade path — **M-UPGRADE cannot help, because the device never reaches
the code that answers it.** That is the real cost of writing Flash from a custom
app, and it is what the SLOOP port already chose to avoid.

[`sloop-smk37/tools/build_smk37.py`](../sloop-smk37/tools/build_smk37.py) pins
`FELUCCA_OTA=0` because SLOOP's in-app updater speaks the FM-1 M-UPGRADE wire
protocol, not this board's, and
[`sloop-smk37/docs/gap-analysis.md`](../sloop-smk37/docs/gap-analysis.md) lists
in-app M-UPGRADE as MISSING. With the 016 incident on record, that has a sharp
consequence: **a SLOOP build that fails to boot can only be recovered through
the Windows-only V4.0 dongle.** M-UPGRADE is not a fallback for it.

`FELUCCA_FLASH=0` is likewise no longer a precautionary choice. The FM-1 storage
map at `0x97000` lies inside this board's app-data slot and would overwrite
running code, producing exactly the failure just observed.

## Still open

- The 20-slot / 36-slot parse question above.
- A paired forced-loader dump of a healthy unit, so the package-to-dump
  representation mapping is established. Neither item blocks the restore path.
