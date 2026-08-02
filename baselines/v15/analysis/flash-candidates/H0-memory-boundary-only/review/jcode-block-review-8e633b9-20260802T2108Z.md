# BLOCK independent review: v15 H0 memory-boundary-only at commit 8e633b9

Date: 2026-08-02 UTC  
Reviewer: Jcode  
Reviewed commit: `8e633b92ebf246aaf4fa68acb5d98d9c639fa909` (`Add v15 H0 memory-boundary diagnostic`)  
Scope: latest H0 memory-boundary-only baseline artifacts plus generated ignored H0 build artifacts.  
Device/flash action: none. I did not run upload, restore, reset, flash, or live-device commands.

## Decision

**BLOCK**

The H0 app/package integrity checks pass: H0 changes exactly the two intended memory-boundary bytes from official v15, keeps code/event/product/SAVE/UI/packer bytes stock, rebuilds deterministically, and the repacker changes only expected metadata plus the two app flash bytes. The generated guarded H0 rollback bundle is also operationally credible as an offline rollback artifact: exact two 4 KiB sectors, correct H0 confirmations, self-test passing, no stale R02 strings, deterministic ZIP hash.

The release/install review still blocks because I found **no H0-specific exact-hash OTA install gate**. There is no `smk37-v15-h0-ota` equivalent, no H0 package hash constant wired into an install command, no H0 confirmation token, and no offline exact checker accepting H0 while rejecting non-H0. The generic `upload-dry-run` can parse H0 but is not an exact-hash install gate, and the existing R03 exact uploader rejects H0 as expected.

## Exact blocker

### Missing H0 exact-hash OTA install gate

Evidence:

- Search for H0 OTA/upload helpers found no H0-specific executable or source path:
  - no `*h0*ota*`, `*h0*upload*`, `*ota*h0*`, or `*upload*h0*` under `tools`, `src`, or top-level `build` executables.
- Search for H0 install tokens and package hash gate found H0 SHA `114d814b...` only in build/rollback/manifests and `tools/build_v15_h0_rollback.py`, not in an OTA install command.
- `src/main.c` lists exact install commands for existing M/R/v15 cases, but no `upload-h0` or `upload-v15-h0` command.
- `src/ota.c` has exact hash upload functions through v15 R01 and official v15, but no H0 package SHA or H0 upload function.
- `tools/smk37_v15_r03_ota.c` demonstrates the required private exact-gate pattern for R03, but no analogous H0 source exists.
- Existing R03 exact checker rejects H0:

```text
build/smk37-v15-r03-ota check build/SMK37Pro-v15-H0-memory-boundary-only/SMK37Pro-v15-H0-memory-boundary-only.fwsc
offline check rejected: not exact v15 R03 package
exit=1
```

- Generic dry-run is not an install gate:

```text
build/smk37-fw upload-dry-run build/SMK37Pro-v15-H0-memory-boundary-only/SMK37Pro-v15-H0-memory-boundary-only.fwsc
upload dry-run: packet generation and payload bounds ok
package: SMK-37 Pro_015, payload 701120 bytes
```

This proves packet-generation compatibility only. It does not bind install to exact H0 SHA `114d814b5def641c979a5f0fbd2e5dc06d982c807662d5221dc2e0e936e5e566`, does not require an H0-specific confirmation token, and does not provide an offline accept/reject exact checker.

## Passing evidence

### Exact commit and source scope

- `git rev-parse HEAD` returned `8e633b92ebf246aaf4fa68acb5d98d9c639fa909`.
- Commit `8e633b9` adds the H0 baseline directory under `baselines/v15/analysis/flash-candidates/H0-memory-boundary-only/`.
- H0 generated build artifacts reviewed:
  - `build/SMK37Pro-v15-H0-memory-boundary-only/`
  - `build/SMK37Pro-WL82-v15-H0-rollback-20260802-v1/`
  - `build/SMK37Pro-WL82-v15-H0-rollback-20260802-v1.zip`

### Deterministic app/package rebuild

Command:

```sh
python3 baselines/v15/analysis/flash-candidates/H0-memory-boundary-only/build_h0_memory_boundary_only.py \
  --input build/SMK-37_Pro_015.fwsc \
  --output-dir <scratch>/H0-memory-boundary-only \
  --determinism-check
```

Results:

- Determinism check passed.
- Scratch `app.bin` byte-identical to generated build artifact.
- Scratch H0 FWSC byte-identical to generated build artifact.
- H0 app SHA-256: `ab2d4d210605f20e35b96a8471c9f2e1102c24e18f3b062d6eabd4970f9794ce`
- H0 package SHA-256: `114d814b5def641c979a5f0fbd2e5dc06d982c807662d5221dc2e0e936e5e566`
- H0 flash SHA-256: `458d1c0a1e08e5f74ad07ab3dd04cf7d7b591a421668f5ff822a15b250746998`
- Official v15 package SHA-256: `f7f1831cd7c9ad8b4831b6e71ea0bdbcdff9ae4c4077276b3c965511bf4d4fff`
- Official v15 app SHA-256: `36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055`

### Only two app bytes change

Independent parsed-app diff from official v15:

```text
app_diffs ['0x20', '0x5e9fa']
0x0200001e c2ff48cb0300 -> c2ffeccb0300
0x0205e9f8 c5ff2065c401 -> c5ffc065c401
```

These are exactly byte `+2` inside:

- `BSS_SIZE_INSN` at runtime `0x0200001e`
- `HEAP_BEGIN_INSN` at runtime `0x0205e9f8`

### Code/event/product/SAVE/UI/packer bytes remain stock

Independent checks on the H0 app verified these stock bytes:

```text
code_cave_prefix              0x0201e13e 7604e2808980c13042201492831c34e1f01f3516108a5607c60758ee3b4074f1fc403d41
note_off_memcpy_call          0x0201c63e 80ff8ac60200
note_on_memcpy_call           0x0201c67c 80ff4cc60200
product_direct_packer_call    0x0201e468 bfea69fe
product_segmented_packer_call 0x0201e49c bfea4ffe
save_first_persistent_write   0x02026da6 beeaacee
save_packer_call              0x02026dac bfeac7b9
```

Because the full app diff contains only offsets `0x20` and `0x5e9fa`, all other application bytes, including UI and packer body bytes, remain stock.

### Repacker-only metadata changes and protected ranges

Independent FWSC/flash diff:

```text
flash_diffs ['0x4000', '0x4001', '0x4002', '0x4003', '0x4020', '0x4021', '0x4022', '0x4023', '0x4140', '0x62b1a']
metadata_offsets ['0x4000', '0x4001', '0x4002', '0x4003', '0x4020', '0x4021', '0x4022', '0x4023']
```

- App flash offsets: `0x04140`, `0x62b1a`
- Repacker metadata flash offsets: `0x04000`, `0x04001`, `0x04002`, `0x04003`, `0x04020`, `0x04021`, `0x04022`, `0x04023`
- Raw FWSC changed byte count: `16`
- Package manifest `flash_byte_count_including_crc_fields`: `10`
- Protected prefix `0x0000..0x3fff`: unchanged
- Protected prefix hash: `d9f43191777656de01c7bed4f9e9ba2e34e94832c5d2ed02c3fc7ab7a6d9bd67`

### Exact changed sectors

Independent 4 KiB flash-sector diff from official v15:

```text
sectors4k ['0x4000', '0x62000']
```

The H0 rollback helper also reports exact two 4 KiB sectors:

```text
sectors 0x04000 0x62000
```

### Rollback sector replacement

Both rollback representations restore stock flash by sector replacement:

- Baseline sector files under `build/SMK37Pro-v15-H0-memory-boundary-only/rollback/recovery-sectors/` are 8 KiB sector-data files and reconstruct stock flash exactly when applied to H0 flash.
- Guarded rollback bundle under `build/SMK37Pro-WL82-v15-H0-rollback-20260802-v1/` carries two 4 KiB stock sectors and reconstructs stock flash exactly when applied to H0 flash.

Independent results:

```text
baseline_rollback_restores_stock True
guarded_rollback_restores_stock True
```

The generated guarded rollback bundle is the operationally sufficient rollback artifact, not the simple sector-data subdirectory alone. It includes transport, official loader, wrapper, guard, exact confirmations, exact sector allow-list, CRC/readback checks, and self-test.

### Guarded H0 rollback operational checks

Command:

```sh
python3 build/SMK37Pro-WL82-v15-H0-rollback-20260802-v1/restore/smk37_wl82_guarded_restore.py self-test
```

Result:

```text
self-test PASS: FakeTransport erase/write/readback, CRC, CDB guards, failure cases
```

Deterministic guarded rollback rebuild:

```text
H0 rollback bundle 05e22531e82b9b3a15338e09d1fde274e18f4697a17c60e00fcba063c7ea60ed
sectors 0x04000 0x62000
confirmations I_UNDERSTAND_THIS_ERASES_EXACTLY_TWO_H0_SECTORS I_HAVE_TWO_IDENTICAL_1MIB_DUMPS_AND_H0_TARGET_HASHES RESTORE_OFFICIAL_V15_SECTORS_NOW
offline only; no device access or Flash mutation performed
```

- Rebuilt rollback ZIP byte-identical to `build/SMK37Pro-WL82-v15-H0-rollback-20260802-v1.zip`.
- Rollback ZIP SHA-256: `05e22531e82b9b3a15338e09d1fde274e18f4697a17c60e00fcba063c7ea60ed`
- Wrapper confirmations equal guard confirmations:
  - `I_UNDERSTAND_THIS_ERASES_EXACTLY_TWO_H0_SECTORS`
  - `I_HAVE_TWO_IDENTICAL_1MIB_DUMPS_AND_H0_TARGET_HASHES`
  - `RESTORE_OFFICIAL_V15_SECTORS_NOW`
- H0 rollback ZIP stale `R02`/`r02` text entries: none.
- Guard safety policy requires two identical fresh 1 MiB dumps and exact H0 target-sector hashes before erase/write.

## Commands run

All commands were offline and performed no device or flash action:

```sh
git rev-parse HEAD
git show --stat --oneline --decorate --no-renames 8e633b9 --
python3 baselines/v15/analysis/flash-candidates/H0-memory-boundary-only/build_h0_memory_boundary_only.py --input build/SMK-37_Pro_015.fwsc --output-dir <scratch>/H0-memory-boundary-only --determinism-check
python3 tools/build_v15_h0_rollback.py --official build/SMK-37_Pro_015.fwsc --target build/SMK37Pro-v15-H0-memory-boundary-only/SMK37Pro-v15-H0-memory-boundary-only.fwsc --template build/SMK37Pro-WL82-v15-R02-rollback-20260802-v1 --output-dir <scratch>/SMK37Pro-WL82-v15-H0-rollback-20260802-v1 --output-zip <scratch>/SMK37Pro-WL82-v15-H0-rollback-20260802-v1.zip
python3 build/SMK37Pro-WL82-v15-H0-rollback-20260802-v1/restore/smk37_wl82_guarded_restore.py self-test
build/smk37-fw upload-dry-run build/SMK37Pro-v15-H0-memory-boundary-only/SMK37Pro-v15-H0-memory-boundary-only.fwsc
build/smk37-v15-r03-ota check build/SMK37Pro-v15-H0-memory-boundary-only/SMK37Pro-v15-H0-memory-boundary-only.fwsc
# independent Python app/FWSC/flash/rollback/ZIP comparison script
# grep/find search for H0 OTA exact gate, H0 install tokens, and H0 package hash consumers
```

## Required fix before PASS

Add an H0-specific exact-hash OTA install gate equivalent to the R03 private uploader pattern:

- H0 package SHA: `114d814b5def641c979a5f0fbd2e5dc06d982c807662d5221dc2e0e936e5e566`
- H0 identity/version gate: `SMK-37 Pro_015`
- H0-specific confirmation token, for example `INSTALL-SMK37PRO-V15-H0-114D814B`
- offline `check` mode that accepts only this H0 package and rejects official v15, R03, and other packages
- upload mode that calls `ota_upload_exact()` with the H0 package SHA and H0 token

Then rerun deterministic H0 app/package/rollback rebuilds, exact uploader accept/reject checks, and this independent review. Do not flash until the exact H0 install gate is present and reviewed.
