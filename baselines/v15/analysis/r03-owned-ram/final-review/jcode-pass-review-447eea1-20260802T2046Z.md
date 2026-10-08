# PASS final independent review: v15 R03 at commit 447eea1

Date: 2026-08-02 UTC  
Reviewer: Jcode  
Reviewed commit: `447eea1e80e3acdd55821c5c2141f6d3865ba7ac` (`Fix R03 rollback confirmation wrapper`)  
Scope: latest v15 R03 code/artifacts only, including rollback v4.  
Device/flash action: none. I did not run upload, restore, reset, flash, or live-device commands.

## Decision

**PASS**

I independently re-reviewed exact `HEAD` at `447eea1e80e3acdd55821c5c2141f6d3865ba7ac`. The prior rollback wrapper blocker is fixed in latest R03 rollback v4. The elevated wrapper in both the rollback directory and ZIP now passes the exact R03 five-sector confirmations, and independent ZIP scanning found no stale `R02`/`r02` strings in the v4 rollback artifact.

The R03 app/package, nonblocking PI32 try-lock, publication ordering and consumer fallback, SAVE no-write rejection, exact hashes/ranges/sectors/protected prefix, deterministic app/package/rollback v4 rebuilds, and exact uploader offline accept/reject gates all validate.

## Commands run

All checks were offline. Scratch rebuild outputs were written under `$JCODE_SCRATCH_DIR`.

```sh
git rev-parse HEAD
git show --no-patch --format='%h %H %s' HEAD
python3 tools/validate_v15_r03.py
baselines/v15/analysis/r03-owned-ram/atomic-publish/reproduce_trylock.sh
build/smk37-v15-r03-ota check build/SMK37Pro-v15-R03-fixed-prefix.fwsc
build/smk37-v15-r03-ota check build/SMK-37_Pro_015.fwsc  # expected reject
python3 tools/build_v15_r03_fixed_prefix.py build/v15-official-app.bin <scratch>/app/v15-R03-fixed-prefix-app.bin --manifest <scratch>/app/app-manifest.json
cmp -s <scratch>/app/v15-R03-fixed-prefix-app.bin build/v15-R03-fixed-prefix-app.bin
python3 tools/smk37_v15_app_patch.py repack-app build/SMK-37_Pro_015.fwsc build/v15-R03-fixed-prefix-app.bin <scratch>/pkg/SMK37Pro-v15-R03-fixed-prefix.fwsc --manifest <scratch>/pkg/package-manifest.json
cmp -s <scratch>/pkg/SMK37Pro-v15-R03-fixed-prefix.fwsc build/SMK37Pro-v15-R03-fixed-prefix.fwsc
python3 tools/build_v15_r03_rollback.py --official build/SMK-37_Pro_015.fwsc --target build/SMK37Pro-v15-R03-fixed-prefix.fwsc --template build/SMK37Pro-WL82-v15-R02-rollback-20260802-v1 --output-dir <scratch>/rollback/SMK37Pro-WL82-v15-R03-rollback-20260802-v4 --output-zip <scratch>/rollback/SMK37Pro-WL82-v15-R03-rollback-20260802-v4.zip
cmp -s <scratch>/rollback/SMK37Pro-WL82-v15-R03-rollback-20260802-v4.zip build/SMK37Pro-WL82-v15-R03-rollback-20260802-v4.zip
python3 build/SMK37Pro-WL82-v15-R03-rollback-20260802-v4/restore/smk37_wl82_guarded_restore.py self-test
# Python ZIP/directory scans for R02/r02 stale tokens and wrapper-vs-guard confirmation equality
```

Observed results:

- `HEAD`: `447eea1e80e3acdd55821c5c2141f6d3865ba7ac`.
- `tools/validate_v15_r03.py`: `v15 R03 fixed-prefix artifact, PI32 decode, package, and rollback: PASS`; no device access performed.
- official PI32 reproducer: `official PI32 try-lock rebuild and objdump: PASS`.
- R03 uploader offline check accepted R03: `exact v15 R03 package: PASS (701120-byte OTA payload)`.
- R03 uploader offline check rejected official v15: `offline check rejected: not exact v15 R03 package`; wrapper script reported `official v15 rejected as expected`.
- rollback guard self-test: `self-test PASS: FakeTransport erase/write/readback, CRC, CDB guards, failure cases`.
- deterministic scratch rebuilds were byte-identical for app, package, and rollback v4 ZIP.

## Requirement review

### Nonblocking PI32 try-lock failure/success paths

**PASS.**

Evidence:

- `r03-trylock.c` uses one `csync; testset b[r0]; ifeq goto failure; csync; r0 = 1; rts; failure: r0 = 0; rts` attempt.
- `reproduce_trylock.sh` rebuilt `r03-trylock.pi32.o` byte-for-byte and verified objdump lines for `testset b[r0]`, `ifeq goto 6`, `r0 = 1`, and `r0 = 0`.
- `tools/validate_v15_r03.py` checks exact hashes for source, object, objdump, SDK contract, and reproducer, and verifies the official try-lock body bytes.
- Embedded producer contains `csync; testset b[r0]` and failure branch `40e81b00` at `0x0201e1ac`.
- The failure branch target is `0x0201e1e6`, the producer return path. It does not spin and does not unlock another producer's lock.

### Publication ordering and consumer fallback

**PASS.**

Evidence:

- Validated producer layout: `producer=0x0201e19e`, `try_fail_branch=0x0201e1ac`, `producer_unlock=0x0201e1d8`, `producer_return=0x0201e1e6`, `end=0x0201e1e8`.
- Successful producer locks, issues a success barrier, rechecks `valid`, copies `0x9c` bytes from staging `0x01c37fd0` to owned voice `0x01c46520`, stores `valid=1` last at `0x01c465bc`, then clears lock `0x01c465bd` with barriers.
- If `valid` is already nonzero, producer unlocks and returns, preserving one-shot snapshot immutability.
- Note On `0x0201c67c -> 0x0201e16e` and Note Off `0x0201c63e -> 0x0201e13e` wrappers check Channel 10 and then `valid`. Non-Ch10 or invalid state falls back to stock paths.
- Consumers cannot observe a partial owned voice because owned RAM is used only after `valid==1`, and `valid` is stored after the full copy.

### SAVE no-write rejection before both persistent writes

**PASS.**

Evidence:

- Builder patches `SAVE_REJECT_CALL=0x02026da6` to `04960000`, decoded as `goto 0x02026dd4`.
- Builder neutralizes `SAVE_CALL=0x02026dac` with four zero bytes.
- Decoder trace checks `0x02026da6: goto 0x02026dd4`, `0x02026da8: nop`, `0x02026dac: nop`, `0x02026dae: nop`.
- Branch target `0x02026dd4` lands after the later persistent-write sequence, so SAVE is rejected before both persistent writes.

### Official-toolchain provenance and reproduction

**PASS.**

Pinned/revalidated hashes:

- `r03-trylock.c`: `2e82edb679ceb2e2c4e66903ceb96310ad4eb3f18aa24dd0b802fddd1bd8b3be`
- `r03-trylock.pi32.o`: `e12ebf05608c78c4ba81cbea8eded0230ddd26febb89a2412174c694744c22c6`
- `official-objdump.txt`: `faaf49e7fdd8a85c6cf79246a00c48678e3a96688d452a545fbc137200c6fb04`
- `pinned-sdk-spinlock-contract.txt`: `cc2d19dd8d71b015aae3ecaea222013927f269a98904165873b88e6e303a5245`
- `reproduce_trylock.sh`: `c783f5a7b47dd88090c6b152444662ee115533a934d00831baaf25f6b899a91e`

The SDK contract records public AC79 SDK commit `e30b1ee375d1f2993fc23bf92c8b99006a6e5f9d` and explains why R03 rejects embedding the SDK blocking spin loop without the SDK `preempt_disable()` contract.

### Exact hashes, ranges, sectors, and protected prefix

**PASS.**

Verified hashes:

- official v15 app: `36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055`
- R03 app: `3ff9c46b9686c0cea1348a11bed553ebd2d677e2d3452a0f436ce14f3ba5c788`
- official v15 FWSC: `f7f1831cd7c9ad8b4831b6e71ea0bdbcdff9ae4c4077276b3c965511bf4d4fff`
- R03 FWSC: `001582c097277d6a4a619ed407cf121d5f30097ef82f312d53a2e45c4a9a5a62`
- rollback v4 ZIP: `ee8af217f78576a69ac1406ad839eb69721f031b8e2996825ef540d07a38c751`
- uploader source: `d0c2afdff619d907a68c12abed55269e38e00b17c0248f3039e7674c8a1f7eac`

Verified changed scope:

- app changed bytes: `187`
- package flash changed bytes including CRC fields: `195`
- changed sectors: `0x04000`, `0x20000`, `0x22000`, `0x2a000`, `0x62000`
- protected prefix `0x0000..0x3fff`: unchanged
- protected prefix SHA-256: `d9f43191777656de01c7bed4f9e9ba2e34e94832c5d2ed02c3fc7ab7a6d9bd67`

Rollback manifest target-sector hashes:

- `0x04000`: `650025c3707a0318ed02a7a5e5e23bb66bd1fa7fc3b02e44055aa9e4eff8f495`
- `0x20000`: `3d13c5a3c5ba7e9fd51c03732f9acce66d4a94f1e5fcd46b058811809731936e`
- `0x22000`: `e24d3686f50d73081e7b3fad2a51aa45ab6508b9ad05c540573da8e00fef7bbc`
- `0x2a000`: `a58c41f00acf8dab7c326c49ae7d24c97f900b0efabc7a25905886f702b56fc2`
- `0x62000`: `bc70da294bd64036f9e3ea33fa62d026bae7694ef51729c949396303aaf7a6c2`

### Deterministic app/package/rollback v4 rebuild

**PASS.**

Scratch rebuild hashes and byte comparisons:

- app: `3ff9c46b9686c0cea1348a11bed553ebd2d677e2d3452a0f436ce14f3ba5c788`, byte-identical to `build/v15-R03-fixed-prefix-app.bin`.
- package: `001582c097277d6a4a619ed407cf121d5f30097ef82f312d53a2e45c4a9a5a62`, byte-identical to `build/SMK37Pro-v15-R03-fixed-prefix.fwsc`.
- rollback v4 ZIP: `ee8af217f78576a69ac1406ad839eb69721f031b8e2996825ef540d07a38c751`, byte-identical to `build/SMK37Pro-WL82-v15-R03-rollback-20260802-v4.zip`.

### Exact uploader accepting only R03

**PASS.**

- `build/smk37-v15-r03-ota check build/SMK37Pro-v15-R03-fixed-prefix.fwsc` accepted exact R03.
- `build/smk37-v15-r03-ota check build/SMK-37_Pro_015.fwsc` rejected official v15.
- Source contains token `INSTALL-SMK37PRO-V15-R03-001582C0` and package SHA bytes for `001582c0...5a62`.

### Rollback v4 wrapper and ZIP confirmations

**PASS.**

Directory wrapper:

```text
--confirm I_UNDERSTAND_THIS_ERASES_EXACTLY_FIVE_R03_SECTORS
--confirm I_HAVE_TWO_IDENTICAL_1MIB_DUMPS_AND_R03_TARGET_HASHES
--confirm RESTORE_OFFICIAL_V15_SECTORS_NOW
```

Mechanical comparison:

```text
wrapper_confirms= ['I_UNDERSTAND_THIS_ERASES_EXACTLY_FIVE_R03_SECTORS', 'I_HAVE_TWO_IDENTICAL_1MIB_DUMPS_AND_R03_TARGET_HASHES', 'RESTORE_OFFICIAL_V15_SECTORS_NOW']
guard_confirms= ['I_UNDERSTAND_THIS_ERASES_EXACTLY_FIVE_R03_SECTORS', 'I_HAVE_TWO_IDENTICAL_1MIB_DUMPS_AND_R03_TARGET_HASHES', 'RESTORE_OFFICIAL_V15_SECTORS_NOW']
match= True
```

ZIP contents:

- `SMK37Pro-WL82-v15-R03-rollback-20260802-v4/restore/run-restore-elevated.ps1` contains the same three R03 confirmations.
- v4 rollback directory stale token hits: `0`.
- v4 rollback ZIP stale token hits for `R02`/`r02`/`FOUR_R02`/`R02_TARGET_HASHES`: `0`.
- `tools/validate_v15_r03.py` now checks the wrapper in both directory and ZIP and rejects stale R02 confirmations.

### Old blocking artifacts and stale hashes absent

**PASS for latest v15 R03 artifacts.**

- No tracked `r03-spinlock.c` or `r03-spinlock.pi32.o` artifacts in the R03 atomic-publish scope.
- No `active_count` in the R03 app manifest.
- No stale rollback v3 hash `15dd52db...` found in latest R03 validator output or v4 artifact evidence.
- The only remaining `R02` tokens found in tracked source are intentional template-replacement inputs in `tools/build_v15_r03_rollback.py` and negative assertions in `tools/validate_v15_r03.py`, plus explanatory text that the earlier blocking spin loop is superseded. The actual v4 rollback directory and ZIP have zero stale R02 text hits.

## Residual caution

This is an offline artifact review and not a live functional claim. I performed no device access and no firmware or flash action.
