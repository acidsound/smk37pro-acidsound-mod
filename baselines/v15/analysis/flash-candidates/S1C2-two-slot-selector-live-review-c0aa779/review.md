# Independent review of `c0aa779` S1-C2 two-slot selector live candidate

Date: 2026-08-03 UTC

Reviewed commit: `c0aa7798df7f2edb7d2f7ac2a0734b9c6225dde7`

Scope: `baselines/v15/analysis/flash-candidates/S1C2-two-slot-selector-live` plus pinned parent inputs referenced by the committed tools/manifests. I reviewed an isolated `git archive c0aa779` materialization under `/Users/spectrum/.jcode/scratch/smk37-c0aa779-review`. I did not use the concurrently modified working tree for validation. I did not touch device, flash, OTA, reset, or live MIDI transport.

## Decision

**BLOCK**

The raw candidate app/package artifacts contain several byte-level properties claimed by the report, but the commit is not independently reproducible or live-usable from committed files. It hits multiple explicit BLOCK criteria from the review request.

## Exact blockers

1. **Committed checksum ledger fails.**
   - `shasum -a 256 -c SHA256SUMS` fails for `validate.py` in the archived commit.
   - Expected in `SHA256SUMS`: `cad409b6412381d949173221df1b3c1e595e0d5d5e3abfa17aa66af873b8c839  validate.py`
   - Actual archived `validate.py`: `12aafc05fdde85ee0ef7d13036d157aab730509f9b62a3aa8df4ff71868de3bc`

2. **Committed validator and builder rely on files not committed in `c0aa779`.**
   - `python3 validate.py` fails immediately with `ModuleNotFoundError: No module named 'smk37_v15_app_patch'`.
   - `python3 build_s1c2_two_slot_selector_live.py` fails with the same missing module.
   - The archived commit does not contain `tools/smk37_v15_app_patch.py`.
   - The tools also reference missing parent binaries under `build/`:
     - `build/SMK-37_Pro_015.fwsc`
     - `build/v15-official-app.bin`
     - `build/SMK37Pro-v15-S1C1-boundary-only/app.bin`
   - This directly matches the requested BLOCK condition for committed validators relying on uncommitted files.

3. **Deterministic regeneration is not verifiable from the commit.**
   - Because the builder cannot import its committed dependency and the pinned `build/` parent artifacts are absent, I could not regenerate `app.bin`, the FWSC, manifests, rollback sectors, senders, or checksum ledger from `c0aa779` alone.
   - Therefore the deterministic-builder claim is blocked.

4. **Committed `validate.py` is stale/inconsistent with the split-entry artifacts.**
   - Static inspection of archived `validate.py` shows it is still an LR-gated validator. It asserts:
     - `"saved LR 0x0201e46c" in evidence["route_identity"]`
     - producer prefix ops `push, mov_reg, lw_sp, mov_imm32, jne_reg, mov_imm8, jne_reg`
     - segmented product call target equals `PRODUCER_START` (`0x0201e1a2`)
   - The actual artifact bytes show the current split-entry/r9 design:
     - direct callsite `0x0201e468`: `bfea9bfe -> 0x0201e1a2`
     - segmented callsite `0x0201e49c`: `bfeac9fe -> 0x0201e232`
     - producer prefix: `790404169016e020f03d80f84000`, i.e. r9 length gate before lock/testset, not the stale LR-prefix validator.
   - The committed `validation.txt` cannot be reproduced by the committed validator in the archived commit.

5. **Uploader and live sender are validation-only, not actual live-usable tools.**
   - `guarded_sender.py` default run verifies packet hashes only and prints `dry-run only: no MIDI/device transport opened`.
   - `guarded_sender.py --live-send` exits nonzero with `refusing live MIDI send: no device/OTA/flash/reset permitted by this package`.
   - `exact_uploader.py` verifies only package identity and prints `validation only: no transport opened`.
   - `exact_uploader.py --attempt-upload` exits nonzero with `refusing upload: no device/OTA/flash/reset permitted by this package`.
   - This directly matches the requested BLOCK condition if sender/uploader are validation-only.

6. **Additional sender-plan breakage.**
   - `host_sender_dry_run.py --json` fails in the archived commit with `KeyError: 'host_sender_dry_run'` because the committed `evidence.json` has `host_packets`, not `host_sender_dry_run`.

## Positive checks independently verified from archived bytes

These checks do not clear the blockers above, but they reduce ambiguity about the raw artifacts.

### Exact artifact hashes

- `app.bin`: `4afd13d7301c2ae209c11d3fe932d019faa770b551f2d8a38cf4c018c7aafa8a`, size `617012`.
- `SMK37Pro-v15-S1C2-two-slot-selector-live.fwsc`: `63e3cfa39473df08bd225df2c8ae81dbfe7aafbd31da6cc6dcf64ca03453681e`, size `701140`.
- selector slice `0x0201e13e..0x0201e19e`: `adb8774971811f6dbdce8b7338f2265f18b8bb22544ccab746e74610366d4e35`, 96 bytes, equals `selector.bin`.
- producer/stub slice `0x0201e1a2..0x0201e236`: `a05e79c0b46e1e12b1244af3f49866c911fcc41937bc14196825d3080d780784`, 148 bytes, equals `producer.bin`.

### FWSC embeds the candidate app

Using the committed generic `tools/smk37_app_patch.py` parser with v15 layout constants from `package-manifest.json`, I independently unpacked the candidate FWSC and extracted the app:

- embedded app SHA-256: `4afd13d7301c2ae209c11d3fe932d019faa770b551f2d8a38cf4c018c7aafa8a`
- embedded app bytes exactly match committed `app.bin`.

### S1-C1 lineage by reversible manifest

Applying the committed `app-manifest.json` changes in reverse to `app.bin` reconstructs an S1-C1 parent image with SHA-256:

- reconstructed S1-C1 app: `16023c9006f2d4d6467ef2d72d6165c14ffeb6cb758d074f7d8163a68146fb2e`
- matches `app-manifest.json` claim.
- reverse diff count: `234`, matching `s1c1_relative_changed_byte_count`.
- reverse diff ranges match the manifest.

Caveat: the actual S1-C1 `app.bin` parent binary is not committed at the referenced `build/` path, so this is a reversible-manifest check, not a committed-parent-binary check.

### Selector ABI and fallback surface

Raw call hook targets decode as:

- Note Off Ch10 hook at `0x0201c63e`: `80fffa1a0000 -> 0x0201e13e`.
- Note On Ch10 hook at `0x0201c67c`: `80ffc01a0000 -> 0x0201e142`.

The committed independent decode shows the selector checks channel 10 (`r9 == 9`) and maps the two fixed notes through slot metadata, then calls the prior handler at `0x02048cce`. For nonmatching state/note paths it falls through to the same call target. I did not find a byte-level contradiction in the selector slice.

### Split-entry direct/segmented call targets

Independent short-call decoding from `app.bin`:

- direct accepted product callsite `0x0201e468`: bytes `bfea9bfe`, target `0x0201e1a2`.
- segmented accepted product callsite `0x0201e49c`: bytes `bfeac9fe`, target `0x0201e232`.
- segmented stub bytes at `0x0201e232`: `79045904`, decoded as push/pop-return with no intervening mutation bytes.

This proves the raw split-entry target separation at the byte level, despite the stale committed validator.

### `r9 == 0xa3` pre-mutation gate

Producer prefix at `0x0201e1a2`:

- `7904` push
- `0416` save staging pointer
- `9016` copy `r9` to `r0`
- `e020` subtract `0x80`
- `f03d` subtract `0x23`, resulting in `r9 - 0xa3`
- `80f84000` branch to return if nonzero

The first lock/testset sequence starts after this at `0x0201e1b0..0x0201e1b9` (`c0ffbd65c4012000b000`). This supports the claimed wrong-length pre-mutation reject path in the raw bytes.

### Producer state-machine publication order and rejection paths

The committed decode and raw instruction bytes show this publication order:

1. First direct exact packet in EMPTY state:
   - state set to LOADING (`0x0201e1ce`), then `csync`.
   - note0 set to 36.
   - `memcpy(slot0, staging, 0x9c)`.
   - `csync`, then `valid0 = 1`.
2. Second direct exact packet in LOADING with valid0 and empty valid1:
   - note1 set to 45.
   - `memcpy(slot1, staging, 0x9c)`.
   - `csync`, then `valid1 = 1`.
   - `csync`, then state set to ARMED last.
3. Reject/no-slot-publication paths present in bytes:
   - wrong direct length branches before lock/testset.
   - segmented route returns via stub before producer mutation.
   - failed trylock returns without clearing another lock.
   - state not LOADING, valid0 missing, valid1 already present, and later exact packets branch to unlock/no slot mutation.

Because the committed validator cannot run and is stale, these are independent byte-review findings, not a passing committed-validation result.

### Official handler/reload preservation

Using rollback reconstruction from the candidate flash, I recovered the official app hash:

- reconstructed official app SHA-256: `36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055`.

The candidate app matches the reconstructed official app at:

- official handler slice `0x0201e254..0x0201e274`: unchanged.
- direct reload `0x0201e46c`: `bfeaf838`, unchanged.
- segmented reload `0x0201e4a0`: `bfeade38`, unchanged.

### Packet hashes and order

Committed packet files verify in order:

1. `host/packets/slot0-note36-direct-product-163.bin`
   - length `163`
   - header `f0430000011b`
   - terminator `f7`
   - SHA-256 `6a9b4097cce1d28780ef3a507f42999743cc10e09770c17c5c78d185e9abff27`
2. `host/packets/slot1-note45-direct-product-163.bin`
   - length `163`
   - header `f0430000011b`
   - terminator `f7`
   - SHA-256 `c4e8458edeb04d8106ca60a35243525e6b5f3f5de272091492409a440e3a9a8d`

### Rollback sectors and protected hashes

I parsed the candidate FWSC to flash, applied the five rollback sector files, and recomputed:

- candidate flash SHA-256: `2592990c071fcd7654f3ea913d70f341553d19f79801e693f74801fe160021ad`, matching rollback manifest.
- reconstructed flash SHA-256: `f77e9ab3cee79113be78f3efacffb03c6cb9b87b78263010e16e81c472df0f9a`, matching rollback manifest and its official flash hash field.

Rollback sector files are exactly `8192` bytes each and match their manifest hashes:

- `0x04000`: `84c51914e8203e19d5b951a6ddba50aa1523a1f49bc2a6f5e19715049bc6750b`
- `0x20000`: `f98d64e12bcb68b03a2893bf83f4165b6ab55dbd2f8adb3ec9849842b3ea88c1`
- `0x22000`: `e7c4eaa78ccacdc03e0b376ca095a28a8d28594c809621e3824dbda9b0d020f0`
- `0x2a000`: `fffa39e60d1f79efba65fffcb55fd29fe5f8b9fd3fd580e738e1cb9a1c621c5d`
- `0x62000`: `571f97c9f0922b1e107f64f3524c9d620f0e35fcf78e9ae3c50cc49a3104122e`

Candidate protected hashes recomputed from parsed candidate flash match `package-manifest.json` `protected_flash_hashes_after`:

- boot/layout `0x0000..0x3fff`: `d9f43191777656de01c7bed4f9e9ba2e34e94832c5d2ed02c3fc7ab7a6d9bd67`
- uboot boot raw `0x00a0..0x38cf`: `b5a0715940db344f951595e2d5a66050631c7721703cb06d33d8dc94eca3c861`
- ISD config raw `0x38d0..0x3b8a`: `0952afd96f533dd0fba72a8fab9cb4a4336f55424a1a89eecb13ff8a51a0eff0`
- post-app resources/reserved: `53718db6501441b091aeb48e21eedd480faebcae4743add53d1ae36d57b327e7`

## Commands and outcomes summarized

All commands were run inside the archived scratch tree unless noted.

- `git archive c0aa779 | tar -x -C /Users/spectrum/.jcode/scratch/smk37-c0aa779-review`: used for isolation.
- `shasum -a 256 -c SHA256SUMS`: failed for `validate.py`.
- `python3 validate.py`: failed with missing `smk37_v15_app_patch`.
- `python3 build_s1c2_two_slot_selector_live.py`: failed with missing `smk37_v15_app_patch`.
- `python3 guarded_sender.py`: packet hash dry-run succeeds, no MIDI/device transport opened.
- `python3 guarded_sender.py --live-send`: refused live send, nonzero exit.
- `python3 exact_uploader.py`: package identity dry-run succeeds, no transport opened.
- `python3 exact_uploader.py --attempt-upload`: refused upload, nonzero exit.
- `python3 host_sender_dry_run.py --json`: failed with `KeyError: 'host_sender_dry_run'`.

## Required remediation before PASS can be considered

- Commit the exact v15 helper/parser dependency used by the builder/validator, or update tools to use an already committed parser.
- Commit or otherwise materialize the pinned parent artifacts needed by the builder/validator, especially official v15 FWSC/app and S1-C1 parent app, or make the builder reconstruct them deterministically from committed bytes.
- Regenerate and commit `SHA256SUMS` so it matches every committed file.
- Replace the stale `validate.py` with one that validates the actual split-entry/r9-gated design and fails if segmented does not target `0x0201e232`.
- Commit a reproducible `validation.txt` generated by the committed validator from a clean archive.
- Provide an actual approved live sender/uploader if live availability is required, or mark the package non-live and remove PASS/live claims.
- Fix or remove `host_sender_dry_run.py` so it matches the current `evidence.json` schema.
