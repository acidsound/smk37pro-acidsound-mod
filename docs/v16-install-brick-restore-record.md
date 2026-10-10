# Record — official v16 installed, bricked, restored to official v15

**Reported by the owner on 2026-10-11.** This fills a gap the repository did not
cover. The prior handoff assumed no v16 had ever been installed and that no
downgrade evidence existed; both premises are now known to be wrong.

## What was reported

- Official `016` firmware **was installed** on this instrument.
- The instrument then **failed in the 016 state** and was **restored to official
  `015`**.
- The restore was performed with the **Jieli Forced Upgrade Tool 4.0**, the
  vendor forced-upgrade dongle documented in
  [`docs/forced-recovery-plan.md`](forced-recovery-plan.md) §"Required entry
  hardware". Jieli's own reference for it is
  <https://doc.zh-jieli.com/AC82/zh-cn/master/getting_started/preparation/usb_updater.html>.
- **There is no SD card** on this instrument, so the SD/USB-disk upgrade route
  (SDK `升级文件.bat`, copy `update.ufw` to a card root) does not apply here.
- **Presets and calibration do not need to be preserved.** Returning the
  instrument to factory state is acceptable.

## What this closes

1. **Vendor downgrade support is now demonstrated, not assumed.** The v16 → v15
   transition has been performed on this very instrument. That was blocker 1 of
   [`docs/handoff-2026-10-11-v16-to-v15.md`](handoff-2026-10-11-v16-to-v15.md).
2. **User-data preservation is out of scope.** Blocker 3 (the unresolved
   ownership of `0x9C000..0x9CFFF` and the 400 KiB at `0x9C000..0xFFFFF`) is no
   longer a constraint, because the owner accepts a factory-state result.
3. **A self-built writer is no longer required.** When the vendor tool writes
   the vendor package, it owns the package-to-chip representation. Blocker 2
   (package `flash.bin` bytes vs forced-loader bytes) only ever mattered for a
   writer this project would build and operate itself.

`docs/forced-recovery-plan.md` previously stated that the forced-entry sequence
"remains unverified on SMK-37 Pro". That sentence is **superseded by this
record**: forced entry and a vendor-tool restore have worked on this unit.

## Still not recorded — needed for a reproducible runbook

These are asked for, not assumed. Until they are filled in, the restore is
known to be *achievable* but not yet *documented*.

- How `016` itself was installed (presumably the same forced tool, but not
  stated).
- The failure symptoms: power, LCD backlight, pixels, USB enumeration.
- The exact restore steps: dongle switch positions, which file was supplied,
  whether the official `015` `.fwsc` was used unmodified, and how long it took.
- Whether presets and calibration survived the restore. This is the one
  observation that would settle the data question empirically rather than by
  accepting the loss.

## Effect on the offline v16 analysis

None of the offline work is invalidated. The package comparison, the fail-closed
inspector, and the archive of the pre-v16 dumps remain the evidence base. What
changes is only the conclusion: the restore path is **already field-proven on
this instrument**, so the open work is documenting the procedure, not
engineering a recovery capability that does not exist.
