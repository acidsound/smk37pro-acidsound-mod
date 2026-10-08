# Final independent review of v15 R03 fixed-prefix candidate

Date: 2026-08-02 UTC  
Reviewed commit: `64a9a2c0bf737c491432ffc6e5d0c4aedd4dd9df` (`Replace R03 spinlock with safe atomic try-lock`)  
Scope: latest v15 R03 artifacts and code requested by the review prompt.  
Device access: none. Flashing/uploading: none. Firmware artifacts: not modified.

## Decision

**BLOCK**

The core R03 app/package/PI32 atomic publication evidence validates, and the exact uploader offline gates validate. However, the existing rollback v3 build artifact contains a stale R02 PowerShell entrypoint that passes R02 confirmation tokens into the R03 guarded restore script. The R03 guard requires different R03 confirmations, so the shipped wrapper's rollback accept gate is inconsistent with the guarded restore implementation and would safe-stop before rollback. Because the prompt explicitly required exact rollback v3 and exact accept/reject gates, this prevents PASS.

## Blocking evidence

Rollback v3 directory and ZIP both contain stale R02 confirmation tokens in the elevated wrapper:

- `build/SMK37Pro-WL82-v15-R03-rollback-20260802-v3/restore/run-restore-elevated.ps1:20-21`
  - `--confirm I_UNDERSTAND_THIS_ERASES_EXACTLY_FOUR_R02_SECTORS`
  - `--confirm I_HAVE_TWO_IDENTICAL_1MIB_DUMPS_AND_R02_TARGET_HASHES`
- Independent ZIP inspection found the same two stale strings inside `build/SMK37Pro-WL82-v15-R03-rollback-20260802-v3.zip`.
- The actual R03 guarded restore requires R03 confirmations at `build/SMK37Pro-WL82-v15-R03-rollback-20260802-v3/restore/smk37_wl82_guarded_restore.py:39-42`:
  - `I_UNDERSTAND_THIS_ERASES_EXACTLY_FIVE_R03_SECTORS`
  - `I_HAVE_TWO_IDENTICAL_1MIB_DUMPS_AND_R03_TARGET_HASHES`
  - `RESTORE_OFFICIAL_V15_SECTORS_NOW`
- The guard compares exact ordered confirmations before opening a device at `smk37_wl82_guarded_restore.py:244-250`; line 245 raises `SafetyError("missing exact explicit confirmations")` if the wrapper's list is used.

This is not a flash-safety bypass. It is a rollback packaging/gate correctness failure: the provided elevated R03 rollback entrypoint is stale and rejects itself.

## Validators and independent checks run

Commands run, all without flashing or device access:

```sh
python3 tools/validate_v15_r03.py
build/smk37-v15-r03-ota check build/SMK37Pro-v15-R03-fixed-prefix.fwsc
build/smk37-v15-r03-ota check build/SMK-37_Pro_015.fwsc   # expected reject
baselines/v15/analysis/r03-owned-ram/atomic-publish/reproduce_trylock.sh
```

Observed results:

- `tools/validate_v15_r03.py`: `v15 R03 fixed-prefix artifact, PI32 decode, package, and rollback: PASS`; app `3ff9c46b9686c0cea1348a11bed553ebd2d677e2d3452a0f436ce14f3ba5c788`; package `001582c097277d6a4a619ed407cf121d5f30097ef82f312d53a2e45c4a9a5a62`; rollback ZIP `15dd52dbb18e9267cbc7f3ea7f1c493ba14a9501ca5c073d06f19c6f07cb8ad9`; sectors `0x04000 0x20000 0x22000 0x2a000 0x62000`.
- R03 uploader offline check accepted only the R03 package: `exact v15 R03 package: PASS (701120-byte OTA payload)`.
- Same uploader offline check rejected official v15: `offline check rejected: not exact v15 R03 package`.
- Official PI32 try-lock reproduction rebuilt byte-identically and found `testset b[r0]`, `ifeq goto 6`, `r0 = 1`, `r0 = 0`.

Additional independent scratch rebuild:

- Rebuilt app with `tools/build_v15_r03_fixed_prefix.py` into `$JCODE_SCRATCH_DIR/r03-independent-review/` and repacked with `tools/smk37_v15_app_patch.py repack-app`.
- Rebuilt app was byte-identical to `build/v15-R03-fixed-prefix-app.bin`.
- Rebuilt FWSC was byte-identical to `build/SMK37Pro-v15-R03-fixed-prefix.fwsc`.
- Rebuilt hashes:
  - app `3ff9c46b9686c0cea1348a11bed553ebd2d677e2d3452a0f436ce14f3ba5c788`
  - package `001582c097277d6a4a619ed407cf121d5f30097ef82f312d53a2e45c4a9a5a62`

## Requirement-by-requirement findings

### 1. PI32 nonblocking `testset` try-lock cannot spin/deadlock

Pass for the app code.

Evidence:

- `baselines/v15/analysis/r03-owned-ram/atomic-publish/r03-trylock.c` defines the official-toolchain primitive as a single `csync; testset b[r0]; ifeq goto failure; csync; r0 = 1; rts; failure: r0 = 0; rts` sequence.
- `baselines/v15/analysis/r03-owned-ram/atomic-publish/reproduce_trylock.sh` rebuilt the PI32 object and verified the objdump transcript.
- `tools/validate_v15_r03.py` verifies exact hashes for the source, object, objdump, SDK contract, and reproducer, and confirms the official body bytes are present in the object.
- Embedded R03 producer bytes contain exactly one try-lock attempt: `2000 b000 40e81b00` at `0x0201e1a8..0x0201e1af`.
- Independent branch decode: bytes `40e81b00` at `try_fail_branch=0x0201e1ac` target `0x0201e1e6`, exactly `producer_return`, not `producer_unlock=0x0201e1d8`.
- Therefore failed or reentrant acquisition returns immediately and does not spin, and the failure branch does not unlock another producer's lock.

### 2. Producer publication order and consumer fallback prevent partial reads

Pass for the app code.

Evidence:

- Producer layout from independent rebuild: `producer=0x0201e19e`, `try_fail_branch=0x0201e1ac`, `producer_unlock=0x0201e1d8`, `producer_return=0x0201e1e6`, `end=0x0201e1e8`.
- Producer flow after successful lock:
  1. success barrier `csync` at `0x0201e1b0`
  2. load `valid` at `0x01c465bc`
  3. if `valid != 0`, branch to `producer_unlock` and return, preserving one-shot immutability
  4. copy `0x9c` bytes from stock staging `0x01c37fd0` to owned voice `0x01c46520`
  5. store `valid=1` at `0x01c465bc` last
  6. clear lock at `0x01c465bd`, with `csync` before and after
- Note Off wrapper at `0x0201c63e -> 0x0201e13e` and Note On wrapper at `0x0201c67c -> 0x0201e16e` both check Channel 10 and then `valid` before copying from owned RAM. If channel is not Ch10 or `valid != 1`, they branch to the stock source path.
- Because consumers use the owned voice only after `valid==1`, and the producer stores `valid` after the full voice copy, a consumer racing before publication falls back to stock rather than reading a partial owned voice.

### 3. SAVE branches before both persistent-write calls and makes no write

Pass for the app code.

Evidence from `baselines/v15/analysis/flash-candidates/R03/decoder-trace.tsv`:

- `0x02026da6`: bytes `0496`, decoded as `goto 0x02026dd4`.
- `0x02026da8`: `nop`.
- `0x02026dac`: bytes `0000`, decoded as `nop`; `0x02026dae`: `nop`.
- The bypassed sequence includes the later persistent write call at `0x02026dd0` (`call 0x02004b02`), but branch target `0x02026dd4` lands after it.
- `tools/build_v15_r03_fixed_prefix.py` replaces `SAVE_REJECT_CALL=0x02026da6` with `SAVE_REJECT_BRANCH=04960000` and neutralizes `SAVE_CALL=0x02026dac` with four zero bytes.

### 4. Official PI32 source/object/objdump/reproduction provenance is closed

Pass.

Evidence:

- Validator-pinned hashes:
  - source `2e82edb679ceb2e2c4e66903ceb96310ad4eb3f18aa24dd0b802fddd1bd8b3be`
  - object `e12ebf05608c78c4ba81cbea8eded0230ddd26febb89a2412174c694744c22c6`
  - objdump `faaf49e7fdd8a85c6cf79246a00c48678e3a96688d452a545fbc137200c6fb04`
  - SDK contract `cc2d19dd8d71b015aae3ecaea222013927f269a98904165873b88e6e303a5245`
  - reproducer `c783f5a7b47dd88090c6b152444662ee115533a934d00831baaf25f6b899a91e`
- Reproducer output confirmed the rebuilt official object and objdump semantics.
- `decoder-provenance.json` records the only decoder gap at `0x0201e1ac`, with official objdump opcode `40 e8 03 00 = ifeq goto forward failure path`, and the candidate target `0x0201e1e6 producer return without unlock or spin`.

### 5. Hashes, changed ranges/sectors, protected prefix, deterministic rebuild, rollback v3, uploader gates

Mixed: pass except rollback v3 wrapper gate blocker.

Verified exact hashes:

- official v15 app `36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055`
- R03 app `3ff9c46b9686c0cea1348a11bed553ebd2d677e2d3452a0f436ce14f3ba5c788`
- official v15 FWSC `f7f1831cd7c9ad8b4831b6e71ea0bdbcdff9ae4c4077276b3c965511bf4d4fff`
- R03 FWSC `001582c097277d6a4a619ed407cf121d5f30097ef82f312d53a2e45c4a9a5a62`
- rollback v3 ZIP `15dd52dbb18e9267cbc7f3ea7f1c493ba14a9501ca5c073d06f19c6f07cb8ad9`

Verified changed bytes/ranges:

- app changed byte count: `187`
- package manifest app ranges and flash ranges match validator expectations.
- changed flash sectors: `0x04000`, `0x20000`, `0x22000`, `0x2a000`, `0x62000`
- protected prefix `0x0000..0x3fff` unchanged; SHA-256 `d9f43191777656de01c7bed4f9e9ba2e34e94832c5d2ed02c3fc7ab7a6d9bd67`

Deterministic rebuild:

- scratch app rebuild byte-identical to checked-in build artifact
- scratch FWSC rebuild byte-identical to checked-in package artifact

Uploader gates:

- `build/smk37-v15-r03-ota check build/SMK37Pro-v15-R03-fixed-prefix.fwsc`: accept
- `build/smk37-v15-r03-ota check build/SMK-37_Pro_015.fwsc`: reject
- source has package hash bytes for `001582c0...5a62` and confirmation token `INSTALL-SMK37PRO-V15-R03-001582C0`

Rollback v3:

- Guard self-test passes and sector manifest is correct for the five changed sectors.
- The rollback directory and ZIP include the stale R02 elevated wrapper tokens described in the blocking evidence section. This makes rollback v3 packaging/gate evidence incomplete and blocks release.

### 6. No stale blocking candidate or stale hashes remain

Mixed.

- `active_count` search in scoped R03 artifacts: no matches.
- Superseded package-hash fragment `fb5a64c` search in scoped R03 artifacts: no matches.
- `blocking` search found only explanatory statements that the earlier blocking-spin candidate is superseded and must not be flashed, plus the intentional `nonblocking` protocol language. I did not find a stale blocking-spin candidate artifact in the reviewed R03 scope.
- Stale R02 rollback confirmation tokens remain in the rollback v3 elevated wrapper and ZIP. They are not stale hashes, but they are stale rollback gate strings in an existing rollback v3 build artifact and are the basis for BLOCK.

## Required fix before PASS

Regenerate or patch the R03 rollback v3 bundle so `restore/run-restore-elevated.ps1` passes the exact R03 confirmations:

```text
I_UNDERSTAND_THIS_ERASES_EXACTLY_FIVE_R03_SECTORS
I_HAVE_TWO_IDENTICAL_1MIB_DUMPS_AND_R03_TARGET_HASHES
RESTORE_OFFICIAL_V15_SECTORS_NOW
```

Then rebuild the ZIP, update its SHA-256 and manifests/checksums as appropriate, rerun `tools/validate_v15_r03.py`, rerun rollback guard self-test, re-check the ZIP content, rerun deterministic rebuild, and repeat independent review. Do not flash until that review returns PASS.
