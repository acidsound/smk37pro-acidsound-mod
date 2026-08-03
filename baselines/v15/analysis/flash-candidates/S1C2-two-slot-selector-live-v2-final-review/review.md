# Independent final review of exact `0f2c1f4` S1-C2 live v2

Date: 2026-08-03 UTC

Reviewed commit: `0f2c1f4acd76504b31b6fb624ec619110d0d611d`

Decision: **BLOCK**

## Scope and isolation

I reviewed a `git archive 0f2c1f4` materialization at `/Users/spectrum/.jcode/scratch/s1c2-v2-final-review-0f2c1f4.bVQLcj`, not the concurrently modified working tree. All executed paths were offline. I did not open a device, USB interface, MIDI interface, OTA session, flash path, or reset path.

Only review artifacts under this directory are included in the review commit.

## Blocking defect

The v2 candidate package and sender pass their offline and byte-level checks, but the committed live uploader cannot accept the exact v15 candidate in `upload` mode.

- `tools/smk37_v15_s1c2_ota.c:27-28` correctly accepts version `15` in `check_exact` when the package SHA-256 is exact.
- `tools/smk37_v15_s1c2_ota.c:51-55` sends live `upload` mode to `ota_upload_exact`.
- `src/ota.c:642-644` calls `validate_exact_same_version`.
- `src/ota.c:513-520` rejects every firmware whose version is not `12`.
- The device identity read is later at `src/ota.c:521`, so the exact v15 rejection happens before device access.

A safe invocation with the exact package and exact confirmation token produced:

```text
package is not the exact SMK37ProMod v15 S1-C2 split-entry two-slot selector live v2 image
exit=1
transcript_created=no
device_access_reached=no
```

Therefore the claimed v15 live uploader is not live-usable at this commit. This is an explicit BLOCK for the requested uploader exact accept/reject requirement.

Full evidence: [`uploader-live-path-block.txt`](uploader-live-path-block.txt).

## Passing firmware and package checks

### Deterministic rebuild and SHA ledgers

- All `31` committed `SHA256SUMS` entries pass.
- The committed `validate.py` passes from the isolated archive.
- `build_s1c2_two_slot_selector_live.py --determinism-check` completes successfully.
- Its two internal rebuilds are identical.
- Every generated app, FWSC, manifest, decode, packet, report, and rollback-sector artifact compared was byte-identical to the committed candidate.
- The regenerated output ledger passes.

Pinned outputs:

- App SHA-256: `4afd13d7301c2ae209c11d3fe932d019faa770b551f2d8a38cf4c018c7aafa8a`
- FWSC SHA-256: `63e3cfa39473df08bd225df2c8ae81dbfe7aafbd31da6cc6dcf64ca03453681e`
- Selector SHA-256: `adb8774971811f6dbdce8b7338f2265f18b8bb22544ccab746e74610366d4e35`
- Producer SHA-256: `a05e79c0b46e1e12b1244af3f49866c911fcc41937bc14196825d3080d780784`

Full evidence: [`deterministic-rebuild-and-ledgers.txt`](deterministic-rebuild-and-ledgers.txt).

### Independent PI32 selector decode

The independent decoder consumed the complete `96`-byte selector as `33` instructions with no undecoded bytes.

Verified route and policy behavior:

- Note Off adapter at `0x0201e13e` normalizes `r5` into `r3`.
- Note On adapter at `0x0201e142` normalizes `r6` into `r3`.
- Non-Ch10, invalid/LOADING state, invalid selected slots, and unmatched notes branch to common fallback copy at `0x0201e194`.
- ARMED slot0 miss advances to the slot1 test.
- Slot0 and slot1 accepted paths reach the common copy.
- The shared call at `0x0201e196` targets `memcpy` at `0x02048cce`.
- The selector returns at `0x0201e19c`.

Exact hook targets:

- Note Off `0x0201c63e -> 0x0201e13e`
- Note On `0x0201c67c -> 0x0201e142`

Full decode: [`pi32-selector-decode.tsv`](pi32-selector-decode.tsv).

### Independent PI32 producer decode and route gates

The independent decoder consumed the complete `148`-byte producer/stub as `52` instructions with no undecoded bytes.

Verified gates and publication order:

- `r9` is copied to `r0` at `0x0201e1a6`.
- Subtractions `-0x80` and `-0x23` compute `r9 - 0xa3`.
- The branch at `0x0201e1ac` returns at `0x0201e230` when the length is wrong.
- The first memory-mutating operation is the try-lock at `0x0201e1b6`, after the length gate.
- Failed try-lock returns without clearing another lock.
- First publication stores LOADING before slot0 copy and `valid0` after the copy/barrier.
- Second publication stores `valid1` before the final ARMED state.
- Nonloading, missing-valid0, already-valid1, and post-armed paths reach unlock without another slot publication.
- Both copy calls target `memcpy` at `0x02048cce`.
- The segmented stub at `0x0201e232` is exactly push then pop-return with no mutation.

Product routes:

- Direct `0x0201e468 -> 0x0201e1a2`
- Segmented `0x0201e49c -> 0x0201e232`
- Direct reload `0x0201e46c` remains `bfeaf838`.
- Segmented reload `0x0201e4a0` remains `bfeade38`.
- Official handler bytes at `0x0201e254..0x0201e273` remain parent-exact.

Full decode: [`pi32-producer-decode.tsv`](pi32-producer-decode.tsv).

### Changed sectors, protected prefix, and rollback

Independent FWSC extraction found exactly `270` changed flash bytes in exactly these five 8 KiB sectors:

- `0x04000`
- `0x20000`
- `0x22000`
- `0x2a000`
- `0x62000`

The protected flash prefix `0x0000..0x3fff` is byte-identical to official v15.

Each rollback sector is exactly the corresponding official-v15 sector. Applying all five to the candidate reconstructs:

- Official flash SHA-256: `f77e9ab3cee79113be78f3efacffb03c6cb9b87b78263010e16e81c472df0f9a`
- Official app SHA-256: `36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055`

The reconstructed flash and app are byte-for-byte exact official v15.

Structured evidence: [`independent-verification.json`](independent-verification.json).

## Passing sender checks

The exact C sender compiled with strict warnings enabled.

Offline accept/reject matrix:

- Accepts only slot0 packet then slot1 packet in `dry-run` mode.
- Rejects reversed order.
- Rejects short, long, content-mutated, bad-header, and bad-terminator packet fixtures.
- Rejects `send` with missing or wrong confirmation before `send_pair` can be called.

A separate harness replaced every libusb function with local stubs. It verified the exact packet buffers and observed no hardware:

- Each `163`-byte SysEx becomes `55` USB-MIDI events and `220` bytes.
- Events `0..53` use CIN `0x04` with three source bytes each.
- Final event is exactly `05f70000`.
- Reconstructing the SysEx from events returns the exact original packet.
- Stubbed bulk transfer order is exactly slot0, then slot1.
- Slot0 USB-MIDI SHA-256: `2a355aebde158078d6a406920efa8c28ea9a02d43dbefe2f459111332c653ba8`
- Slot1 USB-MIDI SHA-256: `78fb13023a945758856bff84afe55cbef0f9449c90648894751e1ac9d5153828`

Evidence:

- [`transport-offline-tests.txt`](transport-offline-tests.txt)
- [`sender-packetization-and-order.txt`](sender-packetization-and-order.txt)
- [`sender_packetization_harness.c`](sender_packetization_harness.c)

## Overall decision

**BLOCK**

The firmware candidate, rollback data, PI32 route gates, sender order, and sender packetization pass independent offline review. The live uploader does not: its exact version-15 package is rejected by an inherited hardcoded version-12 gate before device access. Fix that version gate, then repeat the full uploader accept/reject matrix and this final review before any live action.
