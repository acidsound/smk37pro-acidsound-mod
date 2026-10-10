# Runbook — installing SLOOP pass 3 with Jieli Forced Upgrade Tool 4.0

**When:** once, from a Windows host, with a physical Jieli Forced Upgrade Tool 4.0.

**Why this tool and not M-UPGRADE:** the instrument is running SLOOP pass 1,
built with `FELUCCA_OTA=0`. M-UPGRADE asks the *running application* to upgrade
itself, and pass 1 is compiled not to answer. Jieli Forced Upgrade Tool 4.0
drives the bootloader directly and does not care what the application is doing,
or whether it runs at all. After pass 3 is installed the application answers
M-UPGRADE again, and this runbook is never needed again.

## The file

```
sloop-smk37/build/fwsc-offline/SMK37Pro-v15-SLOOP-SMK37-P3.fwsc
size    701,140 bytes
sha256  6ec25f3e119603b8282cc5008c6405f4cb1131fe4b4133b22a1d7596e1523808
```

Copy it to the Windows machine. **Verify the hash there before writing** --
PowerShell:

```powershell
Get-FileHash -Algorithm SHA256 .\SMK37Pro-v15-SLOOP-SMK37-P3.fwsc
```

It must print `6EC25F3E119603B8282CC5008C6405F4CB1131FE4B4133B22A1D7596E1523808`.
If it does not match, stop. Do not write.

**Not `P2`.** The pass-2 package (`fdeb0244…`) also fixes the LCD but has no OTA,
so it would leave the instrument needing this runbook again for the next
change. Pass 3 has both.

### A note on `.fwsc` vs `flash.bin`

`docs/forced-recovery-plan.md` §on the FWSC container says, before any
hardware had been tried, that a `.fwsc` "is an application OTA container, not
a file that V4's forced loader can consume directly."

That prediction was wrong, and the record says so: on 2026-10-11 the official
`015` `.fwsc` was supplied to this same tool on this same instrument and the
instrument was restored in three minutes
(`docs/v16-install-brick-restore-record.md`). The empirical result governs.

This package is the same shape as the official `015` that already worked: a
version-015 FWSC container with 20 metadata slots, built from that same
official container as its template. Supply the `.fwsc`.

If the tool refuses the `.fwsc` for some reason, the fallback representation
is the FWSC-unpacked `flash.bin`, which `tools/extract_fwsc_flash.py`
produces. Report it rather than substituting a different file; the two
representations are not interchangeable and the tool may write the wrong one.

## Steps

### 1. Enter forced-upgrade mode

The instrument is independently powered, so cycling USB VBUS does **not**
reset its processor. The key has to be transmitted while it is coming up.

1. Turn the instrument **fully off**.
2. Put the Jieli Forced Upgrade Tool 4.0 into continuous `usbkey` mode
   (the switch position recorded in `docs/forced-recovery-plan.md`).
3. Connect the tool between an **isolated host USB port** and the instrument's
   **USB-C data port**, with a data-capable adapter.
4. Turn the instrument **on once**, while the tool is transmitting the key.
5. Confirm the bootloader identity **before writing anything**.

### 2. Confirm the bootloader identity

On Windows, Device Manager must show a mass-storage device named
`WL82 UBOOT1.00` (this tool family also reports `WL80UBOOT1.00`; either is
the expected bootloader).

**If it does not appear, stop.** Do not write to whatever device is there.
Go back to step 1. The tool is capable of writing to the wrong target and
there is nothing on this instrument that needs protecting, but a misdirected
write would end the session.

### 3. Write the package

In the tool, select `SMK37Pro-v15-SLOOP-SMK37-P3.fwsc` and run the upgrade.

Expected duration: about three minutes, the same as the `016`→`015` restore.

### 4. Let the instrument restart

Do not cut power while the tool is writing. When the write finishes, unplug the
tool, then power-cycle the instrument once.

## What success looks like

| check | expected |
|---|---|
| LCD | Splash, then the SLOOP UI. 1.54" 240x240, backlit. |
| Pad LEDs | Cycling colours, as on pass 1. |
| USB identity on macOS | `1209:0001`, not `4c4a:8057` and not `4353:cf4d` |
| Preset save | Reports `SAVE ERROR` — see below. |

### Presets are not stored

Pass 3 deliberately links the flash primitives but replaces FM-1's preset store
with one whose `st_save`/`st_load` always fail, because FM-1's store map
(`FL_DATA 0x97000`) lies **inside** this board's app-data slot and would erase
running code. Saving a preset reports `SAVE ERROR`.

This is not a fault and nothing is being lost: no preset or calibration has
ever been stored on this instrument.

## Verify on the Mac afterwards

Once the instrument enumerates, on macOS:

```bash
./build/smk37-fw probe          # USB descriptors only, sends nothing
./build/smk37-fw device-info    # read-only product/version query
```

`probe` must show `1209:0001`. `device-info` will report the `SMK37PRO_P3`
identity rather than `SMK-37 Pro` v15 -- **a custom app changes the reported
identity, and that is expected, not a failure.**

### Confirming OTA is really back

There is deliberately **no harmless probe** for this. `upload-sloop-p3` is not
a probe: it accepts only the pinned pass-3 package and, once past the checks,
actually installs it. Do not run it to test.

Two honest ways to confirm instead:

- Open **M-UPGRADE**. It detected the instrument back on 2026-08-03 and should
  detect it again now. That detection is the upgrade handshake working.
- Or simply do the next real update the usual way, when there is one.

If M-UPGRADE finds no device, the pass-3 install did not take effect and the
runbook steps above need repeating -- do not fall back to pass 2.

## If it fails

- **Bootloader identity never appears** — forced entry did not take. Repeat
  step 1. Do not attempt a different write target.
- **Tool rejects the file** — report it. Do not substitute `P2` or any other
  package.
- **Writes but the LCD stays black** — the write landed but the app does not
  come up. That is a different failure from the entry problem, and the same
  tool and file are still the right next step. Report the USB identity: if it
  enumerates at all, it is recoverable the same way.

## Cross-references

- `docs/sloop-p2-lcd-p3-ota-session.md` — how pass 3 was built and why
- `docs/v16-install-brick-restore-record.md` — the three-minute `015` restore
  that proves this procedure on this instrument
- `docs/forced-recovery-plan.md` — the forced entry sequence and why USB VBUS
  cycling alone is not enough
