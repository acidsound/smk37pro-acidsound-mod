# Final independent review of v15 R03 fixed-prefix candidate and rollback v4

Date: 2026-08-02 UTC  
Reviewed commit: `447eea1e80e3acdd55821c5c2141f6d3865ba7ac` (`Fix R03 rollback confirmation wrapper`)  
Scope: exact HEAD `447eea1`, latest v15 R03 app/atomic/SAVE/package/uploader gates, and rollback v4 artifacts requested by the review prompt.  
Device access: none. Flashing/uploading: none. Repo app/tools/build artifacts: not modified.

## Decision

**PASS**

The re-review passes. The v15 R03 app/package/atomic/SAVE/uploader gates validate, and the rollback v4 directory and ZIP correct the previously blocked stale R02 PowerShell confirmations. The wrapper and guard now agree on the exact three R03 confirmations, the rollback plan covers exactly five changed R03 sectors, the ZIP SHA-256 is the requested `ee8af217f78576a69ac1406ad839eb69721f031b8e2996825ef540d07a38c751`, and independent scratch rebuilds reproduce the app, package, rollback directory, and rollback ZIP without modifying tracked build outputs.

## Commands and validation run

All commands were run offline from `/Users/spectrum/Documents/SMK37ProMod`; no device path was opened and no flash/write command was executed.

```sh
PYTHONPATH=tools python3 tools/validate_v15_r03.py

PYTHONPATH=tools python3 tools/build_v15_r03_fixed_prefix.py \
  build/v15-official-app.bin \
  "$JCODE_SCRATCH_DIR/.../v15-R03-fixed-prefix-app.bin" \
  --manifest "$JCODE_SCRATCH_DIR/.../app-manifest.json"

PYTHONPATH=tools python3 tools/smk37_v15_app_patch.py repack-app \
  build/SMK-37_Pro_015.fwsc \
  "$JCODE_SCRATCH_DIR/.../v15-R03-fixed-prefix-app.bin" \
  "$JCODE_SCRATCH_DIR/.../SMK37Pro-v15-R03-fixed-prefix.fwsc" \
  --manifest "$JCODE_SCRATCH_DIR/.../package-manifest.json"

PYTHONPATH=tools python3 tools/build_v15_r03_rollback.py \
  --official build/SMK-37_Pro_015.fwsc \
  --target build/SMK37Pro-v15-R03-fixed-prefix.fwsc \
  --template build/SMK37Pro-WL82-v15-R02-rollback-20260802-v1 \
  --output-dir "$JCODE_SCRATCH_DIR/.../SMK37Pro-WL82-v15-R03-rollback-20260802-v4" \
  --output-zip "$JCODE_SCRATCH_DIR/.../SMK37Pro-WL82-v15-R03-rollback-20260802-v4.zip"

build/smk37-v15-r03-ota check build/SMK37Pro-v15-R03-fixed-prefix.fwsc
build/smk37-v15-r03-ota check build/SMK-37_Pro_015.fwsc   # expected reject
baselines/v15/analysis/r03-owned-ram/atomic-publish/reproduce_trylock.sh
```

Observed validator output:

- `tools/validate_v15_r03.py`: `v15 R03 fixed-prefix artifact, PI32 decode, package, and rollback: PASS`
- app: `3ff9c46b9686c0cea1348a11bed553ebd2d677e2d3452a0f436ce14f3ba5c788`
- package: `001582c097277d6a4a619ed407cf121d5f30097ef82f312d53a2e45c4a9a5a62`
- rollback ZIP: `ee8af217f78576a69ac1406ad839eb69721f031b8e2996825ef540d07a38c751`
- changed rollback sectors: `0x04000 0x20000 0x22000 0x2a000 0x62000`

## Requirement-by-requirement findings

### 1. Exact HEAD commit

Pass.

- `git rev-parse HEAD` returned `447eea1e80e3acdd55821c5c2141f6d3865ba7ac`.
- The working tree contained many pre-existing unrelated dirty files before this review. I did not modify app/tools/build artifacts and committed only this review file.

### 2. R03 app, atomic, SAVE, and package gates

Pass.

- Scratch app rebuild produced byte-identical `build/v15-R03-fixed-prefix-app.bin`.
- Scratch package rebuild produced byte-identical `build/SMK37Pro-v15-R03-fixed-prefix.fwsc`.
- R03 app SHA-256: `3ff9c46b9686c0cea1348a11bed553ebd2d677e2d3452a0f436ce14f3ba5c788`.
- R03 package SHA-256: `001582c097277d6a4a619ed407cf121d5f30097ef82f312d53a2e45c4a9a5a62`.
- Package manifest `safety_gate` is `PASS`.
- App manifest format is `smk37-v15-r03-fixed-heap-prefix-v1`.
- App manifest keeps `reload_after_first_publish` as `rejected until reboot` and `save` as `no-write rejection at 0x02026da6 branches to stock local exit 0x02026dd4; later packer call also neutralized`.
- `tools/validate_v15_r03.py` verifies 187 app changed bytes, 195 flash changed bytes including CRC fields, protected prefix unchanged, and no changed bytes outside declared ranges.
- `baselines/v15/analysis/r03-owned-ram/atomic-publish/reproduce_trylock.sh` rebuilt and objdumped the official PI32 try-lock object: `official PI32 try-lock rebuild and objdump: PASS`.
- Reproducer output includes `testset b[r0]`, `ifeq goto`, `r0 = 1`, and `r0 = 0`, matching the nonblocking try-lock evidence.

### 3. Uploader gates

Pass.

- Uploader source SHA-256: `d0c2afdff619d907a68c12abed55269e38e00b17c0248f3039e7674c8a1f7eac`.
- Source contains the exact R03 confirmation token `INSTALL-SMK37PRO-V15-R03-001582C0`.
- Source contains expected package hash byte fragments for `001582c0...5a62`.
- Offline check accepted the R03 package: `exact v15 R03 package: PASS (701120-byte OTA payload)`.
- Offline check rejected official v15 as expected: `offline check rejected: not exact v15 R03 package`.

### 4. Rollback v4 builder and validator coverage

Pass.

`tools/build_v15_r03_rollback.py` now patches both the guard and elevated PowerShell wrapper:

- `patched_guard()` replaces the R02 bundle text, four-sector text, sector allow-list, R02 confirmation tokens, R02 plan format, and R02 hash wording, then requires no `R02`/`r02` token remains and requires `0x62000`.
- `patched_wrapper()` replaces both stale PowerShell confirmation tokens and then requires no `R02`/`r02` token remains.
- `patched_wrapper()` additionally requires exactly one wrapper command-line occurrence of each R03 confirmation:
  - `--confirm I_UNDERSTAND_THIS_ERASES_EXACTLY_FIVE_R03_SECTORS`
  - `--confirm I_HAVE_TWO_IDENTICAL_1MIB_DUMPS_AND_R03_TARGET_HASHES`
  - `--confirm RESTORE_OFFICIAL_V15_SECTORS_NOW`
- The builder scans every generated bundle file and rejects stale `FOUR_R02` or `R02_TARGET_HASHES` bytes.
- `tools/validate_v15_r03.py` now checks the rollback ZIP SHA-256, wrapper stale-token absence, wrapper confirmation counts, ZIP wrapper equality with the directory wrapper, ZIP stale-token absence, manifest format, sector set/order, sector stock bytes, target hashes, and guard self-test.

### 5. Rollback v4 directory and ZIP content

Pass.

Independent inspection of `build/SMK37Pro-WL82-v15-R03-rollback-20260802-v4` and `build/SMK37Pro-WL82-v15-R03-rollback-20260802-v4.zip` found:

- ZIP SHA-256: `ee8af217f78576a69ac1406ad839eb69721f031b8e2996825ef540d07a38c751`.
- Guard and wrapper agree on all three exact confirmations.
- `restore/run-restore-elevated.ps1` contains each confirmation exactly once as a `--confirm` argument:
  - `I_UNDERSTAND_THIS_ERASES_EXACTLY_FIVE_R03_SECTORS`: 1
  - `I_HAVE_TWO_IDENTICAL_1MIB_DUMPS_AND_R03_TARGET_HASHES`: 1
  - `RESTORE_OFFICIAL_V15_SECTORS_NOW`: 1
- `restore/smk37_wl82_guarded_restore.py` contains the same confirmation values and the R03 plan format `smk37-v15-r03-forced-recovery-plan-v1`.
- Neither wrapper nor guard contains stale confirmation strings:
  - `I_UNDERSTAND_THIS_ERASES_EXACTLY_FOUR_R02_SECTORS`
  - `I_HAVE_TWO_IDENTICAL_1MIB_DUMPS_AND_R02_TARGET_HASHES`
  - `FOUR_R02`
  - `R02_TARGET_HASHES`
- ZIP copies of wrapper and guard match the directory files byte-for-byte.
- Rollback manifest format is `smk37-v15-r03-forced-recovery-plan-v1`.
- Safety policy requires `two identical fresh 1 MiB forced-loader dumps and exact R03 target-sector hashes` before any write.
- Rollback write scope is `five audited 4 KiB application sectors only`.
- Rollback sectors are exactly `0x04000`, `0x20000`, `0x22000`, `0x2a000`, `0x62000`.

### 6. Deterministic rollback rebuild

Pass.

A from-scratch rollback v4 rebuild in `$JCODE_SCRATCH_DIR` produced:

- Guard self-test: `self-test PASS: FakeTransport erase/write/readback, CRC, CDB guards, failure cases`.
- Rebuilt rollback ZIP SHA-256: `ee8af217f78576a69ac1406ad839eb69721f031b8e2996825ef540d07a38c751`.
- Rebuilt directory matched existing `build/SMK37Pro-WL82-v15-R03-rollback-20260802-v4` byte-for-byte across 13 files.
- Rebuilt ZIP matched existing `build/SMK37Pro-WL82-v15-R03-rollback-20260802-v4.zip` in entry order, timestamps, external attributes, compression type, and entry bytes across 17 entries.

## Conclusion

PASS. The stale R02 confirmation-token blocker from rollback v3 is corrected in rollback v4, the validator now covers the corrected wrapper/ZIP checks, the deterministic rebuilds are closed, and all reviewed gates are offline-only and exact-hash bounded. This review makes no live functional claim and did not access a device or flash firmware.
