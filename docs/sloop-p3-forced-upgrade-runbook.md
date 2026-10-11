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

### What the bootloader actually presents

In forced-upgrade mode the WL82 bootloader exposes its **entire 1 MB flash as
a USB mass-storage disk**. The 2026-08-14 recovery on Windows recorded it as:

```
Device: \.\PHYSICALDRIVE5 (WL82 UBOOT1.00 USB Device, 1MB)
```

So writing the device is not a vendor protocol exchange. It is copying a raw
flash image onto a disk. There is no loader to upload and no CDB to speak.

This makes the host choice trivial:

- **Windows** — the device is a normal physical drive. The repository already
  ships a transport for it in
  `build/SMK37Pro-WL82-M09-rollback-20260802-v1/tools/windows_scsi_transport.py`.
- **Linux** — plain `dd` to the device node.
- **macOS** — blocked, see below.

The Jieli Forced Upgrade Tool 4.0 is one writer among several, not a
requirement. It is used here only because it is the one already proven on this
instrument.

### `.fwsc` versus the raw image

The two are not the same file and must not be substituted for one another.

| file | size | what it is |
| --- | --- | --- |
| `SMK37Pro-v15-SLOOP-SMK37-P3.fwsc` | 701,140 | the OTA container the official updater consumes |
| `SMK37Pro-v15-SLOOP-SMK37-P3-flash.bin` | 638,976 | the raw flash image, payload from `0x400` |

The V4 tool takes the `.fwsc` and unpacks it itself. **Any other writer needs
the `.bin`.** Produce it from the checked-out tree with:

```sh
./build/smk37-fw inspect \
  sloop-smk37/build/fwsc-offline/SMK37Pro-v15-SLOOP-SMK37-P3.fwsc \
  /tmp/p3-payload.bin
python3 -c "
import pathlib
raw = pathlib.Path('/tmp/p3-payload.bin').read_bytes()
pathlib.Path('SMK37Pro-v15-SLOOP-SMK37-P3-flash.bin').write_bytes(raw[0x400:0x400+638976])"
```

Verify it before writing anything:

```
sha256  8944c3a121446481b6bc30545b5d4c676e9c5a2cf9eea75c0820f596f2c4411c
size    638,976 bytes
```

That is the "FWSC-unpacked `flash.bin` bytes" representation the repository has
previously validated against WL82 forced-loader dumps, not a new one.

### Why macOS cannot do this

macOS binds its own mass-storage stack to the device
(`IOUSBMassStorageDriver`, `IOBlockStorageDriver`), which takes the USB interface
exclusively. The device does **not** appear in `diskutil list`, and an unsigned
userland process cannot displace the driver: `IOServiceOpen` on
`IOBlockStorageDriver` returns `kIOReturnNotPrivileged`. A plain `IOServiceOpen`
on `IOUSBHostInterface` succeeds, so the interface is not refused outright — the
*transfer* is what is unreachable. Measured detail in
[`forced-recovery-plan.md`](forced-recovery-plan.md).

This is a macOS host limitation. It is not a property of the device, of the
bootloader, or of the flashing operation, and it does not apply on Windows or
Linux.

## Steps

### 1. Enter forced-upgrade mode

The instrument is independently powered, so cycling USB VBUS does **not**
reset its processor. The key has to be transmitted while it is coming up.

1. Turn the instrument **fully off**.
2. Put the Jieli Forced Upgrade Tool 4.0 into continuous `usbkey` mode
   (the switch position recorded in `docs/forced-recovery-plan.md`).

   > **The tool is required here, and the reason is specific.** Measured
   > 2026-10-11: the SLOOP soft key `F0 22 24 35 7D F7` sent over USB MIDI
   > does reach the bootloader with no vendor hardware at all — the
   > instrument enumerates as `4c4a:8057` and Windows binds it as Disk 5
   > named `WL82 UBOOT1.00`. But that disk reports `Size 0`, `No Media`,
   > and `Set-Disk -IsOffline $false` does not bring it up.
   >
   > Being in the bootloader is not the same as being in download mode. The
   > `usbkey` is a USB-level signal present at reset; the soft key is a MIDI
   > SysEx the application answers by resetting. Only the first makes the
   > flash appear as media. `docs/forced-recovery-plan.md` says the same
   > thing: once the key has been sent, software can operate the device
   > independently of the dongle — independence applies after entry, not to
   > entry itself.

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

### 3. Write the image

On Windows, either:

- select `SMK37Pro-v15-SLOOP-SMK37-P3.fwsc` in the Jieli Forced Upgrade Tool 4.0
  and run it, **or**
- write `SMK37Pro-v15-SLOOP-SMK37-P3-flash.bin` to the 1 MB device yourself.

On Linux:

```sh
sudo dd if=SMK37Pro-v15-SLOOP-SMK37-P3-flash.bin of=/dev/sdX bs=512 conv=fsync
```

where `/dev/sdX` is the 1 MB `WL82 UBOOT1.00` device. Check the size before
writing; it is 1 MB, not a multi-terabyte disk.

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
