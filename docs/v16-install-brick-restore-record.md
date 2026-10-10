# Record — official v16 installed, bricked, restored to official v15

**Reported by the owner on 2026-10-11.** This fills a gap the repository did not
cover. The 2026-10-11 handoff assumed no v16 had ever been installed and that
no downgrade evidence existed; both premises were wrong.

Package provenance for both versions:
<https://github.com/jonathaslacerda/smk-37-pro-docs/tree/main/firmware>
(`FIRMWARE.md`).

## What happened

1. Official `016` was installed **with the official upgrade tool**.
2. The instrument then failed. **Power came on, the LCD was frozen and
   inoperable, and neither USB nor BLE enumerated.**
3. It was restored to official `015` on **Windows** with the **Jieli Forced
   Upgrade Tool 4.0**, by supplying the `015` `.fwsc` file. **Three minutes.**
4. Presets and calibration **were never stored on this instrument in the first
   place**, so no user data was at stake at any point.

The Jieli Forced Upgrade Tool 4.0 is the vendor forced-upgrade dongle already
documented in [`docs/forced-recovery-plan.md`](forced-recovery-plan.md) §"Required
entry hardware", with Jieli's own reference at
<https://doc.zh-jieli.com/AC82/zh-cn/master/getting_started/preparation/usb_updater.html>.
What was missing from the repository was the outcome, not the tool.

## The brick is the same failure class as M09

[`docs/m09-brick-incident.md`](m09-brick-incident.md) records the M09 custom-app
brick as `BOOT-FAILED / NO-USB`: power on, LCD backlight lit, no UI, no USB
enumeration. The `016` brick above matches that description, with the addition
that BLE did not enumerate either, which places the failure earlier than a USB-
only fault. Two independent causes, one symptom class.

M09's report also named the gap that made it serious:

> The independent mask-ROM/forced-upgrade path had been researched but had not
> been physically demonstrated before M09 was installed.

That gap is now **closed on this instrument**. The forced-upgrade path is no
longer a research question: a 016 brick was recovered to a working 015 in three
minutes with the vendor tool. The procurement decision in
`docs/forced-recovery-plan.md` §"Procurement decision" — prefer the genuine
V4.0 over a one-off ESP32-C3 harness — is validated by use.

## The 016 that bricked is an unofficial build

Per the community `FIRMWARE.md`, `SMK-37_Pro_016.fwsc` is a community upload, and
[`docs/handoff-2026-10-01.md`](handoff-2026-10-01.md) already recorded it as
"커뮤니티 저장소에서 받은 것... 벤더 서명 검증이 아니다". It carries no vendor
signature. That matters for reading the incident: an **unofficial** image
failing to boot, and being recovered to a stock image, is a materially weaker
signal than a vendor-signed image doing the same. It is not evidence that
official vendor firmware is unsafe on this instrument.

## What this closes

1. **Vendor downgrade support is demonstrated, not assumed.** That was blocker 1
   of [`docs/handoff-2026-10-11-v16-to-v15.md`](handoff-2026-10-11-v16-to-v15.md).
2. **User-data preservation is settled by fact.** Presets and calibration did
   not exist on this instrument, so blocker 3 — the unresolved ownership of
   `0x9C000..0x9CFFF` and the 400 KiB at `0x9C000..0xFFFFF` — has nothing to
   protect. The 400 KiB of device-only bytes is the vendor image plus whatever
   this unit had, and this unit had no user data in it.
3. **A self-built writer is not required.** When the vendor tool writes the
   vendor package it owns the package-to-chip representation, so blocker 2
   only ever mattered for a writer this project would operate itself.

## Consequence for the SLOOP port

A boot failure on this instrument presents as `BOOT-FAILED / NO-USB`, recoverable
only by the forced-upgrade path. That is the real cost of writing Flash from a
custom app, and it is the exact failure the SLOOP port already chose to avoid.

[`sloop-smk37/tools/build_smk37.py`](../sloop-smk37/tools/build_smk37.py) pins
`FELUCCA_FLASH=0` because the upstream FM-1 storage map at `0x97000` lies inside
this board's app-data slot and would overwrite running code. With the 016
incident on record, that decision stops being a precautionary choice and becomes
a measured one: a flash-writing build fails in exactly the way that was just
observed, and the only way back is the vendor dongle.

## What remains open

- The exact 016 install tool is recorded only as "the official upgrade tool";
  whether that was the same V4.0 dongle is not stated.
- A paired forced-loader dump of a healthy unit has still not been taken, so
  the package-to-dump representation mapping is unestablished. This no longer
  blocks the restore path.

## Effect on the offline analysis

None of it is invalidated. The package comparison, the fail-closed inspector,
and the pre-v16 dumps remain the evidence base. What changes is the conclusion:
the restore capability already exists in the vendor tool, so the remaining work
is documentation and the optional representation mapping — not engineering a
recovery path.
