# SMK-37 Pro WL82 S1C7 guarded seed bundle

Target live dual-dump SHA-256: `078c13d698ad08a4cfac7723e87014000e5557e655bd1f21d75493dc8f652946`.

This bundle can seed exactly sectors `0x0fb000` and `0x0fc000` and preserves all other bytes. It requires two identical fresh 1 MiB dumps and exact sector prehashes before any write, then readback-verifies every sector. Rollback writes the original two sector images from the locked live dump.

## Dry checks

```sh
python3 restore/smk37_wl82_s1c7_guarded_seed.py self-test
python3 restore/smk37_wl82_s1c7_guarded_seed.py validate-offline
python3 restore/smk37_wl82_s1c7_guarded_seed.py macos-dry-check
```

## macOS live command

macOS live writes are blocked in this target-specific bundle because no audited mutable macOS WL82 transport is present. The supported macOS command is the dry validator above.

## Windows seed command

```powershell
py -3 restore\smk37_wl82_s1c7_guarded_seed.py windows-seed --device \\.\PhysicalDriveN --confirm I_UNDERSTAND_THIS_ERASES_EXACTLY_TWO_S1C7_SEED_SECTORS --confirm I_HAVE_TWO_IDENTICAL_1MIB_DUMPS_SHA_078C13D698AD08A4CFAC7723E87014000E5557E655BD1F21D75493DC8F652946 --confirm WRITE_S1C7_SEED_SECTORS_NOW
```

Replace `PhysicalDriveN` only after identifying the WL82 UBOOT device.
