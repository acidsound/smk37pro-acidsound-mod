# S1C5 independent offline review

Decision: **FAIL**.

Reviewed exact commit `90080a59564e6255a30aa08dcf05d3ae4d8831df` (tree `ae88bd64345e29fe542984307f49d372f52ab675`), parent `71954397c2a91dc3a9a34f86eb02095a42cb3063`. No device, USB, MIDI, OTA, live send, reset, or flash action was performed.

## Release gates

- **PASS** `deterministic-app-fwsc-rebuild`
- **PASS** `parent-relative-four-changed-bytes`
- **PASS** `pi32-lb-z-decode-and-semantics`
- **PASS** `selector-r0-return-contract`
- **PASS** `note-on-velocity-and-note-off-symmetry`
- **PASS** `repeated-playback-note-60-no-slot-collapse`
- **PASS** `protected-regions`
- **PASS** `rollback-reconstructs-official-v15`
- **FAIL** `exact-ota-current-src-api-compilation`
- **BLOCKED** `exact-ota-candidate-accept-parent-official-reject`

## Verified technical results

- Two clean exact-object rebuilds produced byte-identical `app.bin` `8b16e9f5a3ec873ac9a51e64f12c5be20156a01a6e8eb65878eed9636179f189` and FWSC `0a6ac1ae7d4bd34e252eb8f23a4d2c5f39d7454376ade1a3b75ff7d03155ea91`.
- Parent-relative app differences are exactly four bytes at runtime addresses `0x0201c644`, `0x0201c645`, `0x0201c682`, and `0x0201c683`. The remaining four bytes in each six-byte window are unchanged `mov r0,r0` padding.
- PI32 little-endian words `0x400d` and `0x400e` decode to unsigned byte loads `lb.z r5,[r0]` and `lb.z r6,[r0]`. They zero-extend the byte and preserve `r0`.
- The unchanged selector saves destination in `r4`, chooses source from `trigger_note-36`, stores the mapped byte at `[dest+0x9c]`, and returns `r0=dest+0x9c` because the final pop does not restore `r0`.
- Note On reloads the mapped note into `r6`; velocity remains in preserved `r5` and stock `sb [r0+2],r5` at `0x0201c68c` is unchanged. Note Off symmetrically reloads mapped note into native note register `r5`.
- Producer slot assignment uses sequential loaded count, map storage uses `map_base+slot`, and selector source uses `trigger_note-36`. All 16 packet artifacts contain playback byte 60 while retaining source slots 0 through 15, so repeated note 60 does not collapse trigger-slot identity.
- Rollback sector files independently reconstruct the byte-exact official v15 flash. Protected boot/layout, U-Boot, ISD config, and post-app resource hashes match official; no changed flash byte is below `0x4000`.

## Release blocker

- **B-EXACT-OTA-API:** committed `exact_ota.c` calls current `ota_upload_exact` with eight arguments by retaining obsolete version argument `15`. Current `src/ota.c` declares seven arguments, so compilation fails with `too many arguments to function call, expected 7, have 8`.
- Therefore the committed exact wrapper cannot close candidate-accept, parent-reject, or official-reject gates. A scratch diagnostic removing only that obsolete argument compiled and returned candidate/parent/official codes `0/1/1`, but it is not the committed artifact and does not change this **FAIL** decision.

See `review.json` for exact byte evidence, compile stderr, packet rows, rollback hashes, and protected-region hashes.
