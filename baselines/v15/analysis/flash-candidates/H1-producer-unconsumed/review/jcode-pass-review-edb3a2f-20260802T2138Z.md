# PASS review for exact H1 commit edb3a2f

Review timestamp: 2026-08-02T21:38Z  
Reviewer: Jcode  
Scope: offline-only review of `edb3a2f53edfaa206e2f166f51bab7c62ee8d47b` (`Add H1 producer-unconsumed discriminator`). I did not access the device, flash, run upload mode, or perform firmware/device action.

## Verdict

PASS. I found no blocker in the exact H1 code/artifacts reviewed. The generated ignored H1 build artifacts and rollback ZIP match the release claims, the uploader exact-hash gate accepts only H1, and the code layout implements the intended discriminator: R02 staging consumers plus R03-derived producer side effect, without consumer reads from owned RAM.

## Commands and validators run

- Confirmed exact HEAD and target commit: `edb3a2f53edfaa206e2f166f51bab7c62ee8d47b`, parent `bc7818d3c847c51ef7587ee004b1ffaf9e3ca5cf`.
- Ran supplied validator: `python3 tools/validate_v15_h1.py`.
  - Result: `status: PASS`.
  - H1 app SHA-256: `b082e8058cfacdb6e9d548dbe7033f31c0848fcf7d865859bc7c8fd969eac463`.
  - H1 package SHA-256: `139ab42b3746477b8bf49e592ba94efd9f6c18b4a360e0e62807bc12e545dacf`.
  - H1 rollback ZIP SHA-256: `c1db8c1d24c01bef32953d1d52f9975c45298f729ab056894decc5097e14b4d2`.
- Independently rebuilt H1 app/package to scratch with `tools/build_v15_h1_producer_unconsumed.py --determinism-check`.
  - Scratch `app.bin` matched committed generated artifact byte-for-byte.
  - Scratch `SMK37Pro-v15-H1-producer-unconsumed.fwsc` matched committed generated artifact byte-for-byte.
  - Scratch `app-manifest.json` and `package-manifest.json` matched baseline review artifacts byte-for-byte.
- Independently rebuilt rollback bundle to scratch with `tools/build_v15_h1_rollback.py`.
  - Scratch ZIP matched committed generated ZIP byte-for-byte.
  - Scratch ZIP SHA-256: `c1db8c1d24c01bef32953d1d52f9975c45298f729ab056894decc5097e14b4d2`.
  - Guard `self-test` passed.
- Independently compiled `tools/smk37_v15_h1_ota.c` to scratch and ran `check` mode only.
  - H1 accepted with return code 0.
  - Official v15, H0, R02, and R03 rejected with return code 1.

## Official-v15-only and deterministic artifact checks

Input and output hashes verified independently:

| Artifact | SHA-256 |
| --- | --- |
| `build/v15-official-app.bin` | `36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055` |
| `build/SMK-37_Pro_015.fwsc` | `f7f1831cd7c9ad8b4831b6e71ea0bdbcdff9ae4c4077276b3c965511bf4d4fff` |
| H1 app | `b082e8058cfacdb6e9d548dbe7033f31c0848fcf7d865859bc7c8fd969eac463` |
| H1 package | `139ab42b3746477b8bf49e592ba94efd9f6c18b4a360e0e62807bc12e545dacf` |
| H1 rollback ZIP | `c1db8c1d24c01bef32953d1d52f9975c45298f729ab056894decc5097e14b4d2` |

The H1 builder refuses non-official v15 input by exact app SHA and the repacker safety gate reported `PASS`. The scratch deterministic rebuild reproduced the app, package, and manifests exactly.

## Exact app and package changes

Independent app diff against official v15:

- Changed app byte count: `127`.
- Changed app ranges:
  - `0x02000020..0x02000021`
  - `0x0201c640..0x0201c643`
  - `0x0201c67e..0x0201c681`
  - `0x0201e13e..0x0201e13f`
  - `0x0201e140..0x0201e1ac`
  - `0x0201e46a..0x0201e46b`
  - `0x0201e49e..0x0201e49f`
  - `0x02026da6..0x02026daa`
  - `0x02026dac..0x02026db0`
  - `0x0205e9fa..0x0205e9fb`

Independent unpacked package diff against official v15:

- Changed flash byte count including CRC fields: `135`.
- Changed flash sectors: `0x04000`, `0x20000`, `0x22000`, `0x2a000`, `0x62000`.
- Protected prefix and non-app hashes in `package-manifest.json` were unchanged before/after:
  - `boot_and_flash_layout_0x0000_0x3fff`: `d9f43191777656de01c7bed4f9e9ba2e34e94832c5d2ed02c3fc7ab7a6d9bd67`
  - `uboot_boot_raw_0x00a0_0x38cf`: `b5a0715940db344f951595e2d5a66050631c7721703cb06d33d8dc94eca3c861`
  - `isd_config_raw_0x38d0_0x3b8a`: `0952afd96f533dd0fba72a8fab9cb4a4336f55424a1a89eecb13ff8a51a0eff0`
  - `post_app_resources_and_reserved`: `53718db6501441b091aeb48e21eedd480faebcae4743add53d1ae36d57b327e7`

## Exact H0 memory boundary

H1 includes exactly the H0 BSS/heap boundary bytes:

- `0x0200001e`: `c2ff48cb0300` to `c2ffeccb0300`.
- `0x0205e9f8`: `c5ff2065c401` to `c5ffc065c401`.

This matches the H0 boundary through `0x01c465c0`.

## R02 consumer source and no consumer owned-RAM reads

The H1 cave layout is:

- R02 consumer entry: `0x0201e13e`.
- R02 special path: `0x0201e146`.
- R02 stock fallback: `0x0201e15a`.
- Producer: `0x0201e162`.
- Producer return: `0x0201e1aa`.
- Cave end: `0x0201e1ac`.

Consumer evidence:

- Note Off call at `0x0201c63e`: `80fffa1a0000`, routing to `0x0201e13e`.
- Note On call at `0x0201c67c`: `80ffbc1a0000`, routing to `0x0201e13e`.
- Consumer source immediate at `0x0201e148`: `c1ffd07fc301`, i.e. `0x01c37fd0`.
- Full app immediate scan found staging `0x01c37fd0` at `0x0201e14a` only.
- Consumer range `0x0201e13e..0x0201e162` contains no little-endian `0x01c46520` owned-voice immediate.
- Full app scan found owned voice `0x01c46520` at `0x0201e184` only, inside the producer range.

I therefore confirm the H1 consumer path uses the R02 live-proven staging source and does not reference/read owned `0x01c46520`.

## R03-derived producer try-lock and publication ordering

Producer evidence:

- Producer start `0x0201e162` begins `79040416...`, preserving the accepted staging pointer in `r4`.
- Lock immediate `0x01c465bd` appears at `0x0201e168` and `0x0201e19e`.
- Nonblocking PI32 try-lock sequence is `csync; testset b[r0]`, bytes `2000b000`, immediately before branch `40e81b00` at `0x0201e170`.
- The `ifeq` failure branch targets producer return `0x0201e1aa`. This matches the R03/offline-validator interpretation that zero from `testset` is lock-acquisition failure and non-zero fall-through is the acquired path.
- Producer owned destination immediate `0x01c46520` appears at `0x0201e184` only inside producer.
- Producer has no embedded staging immediate. It receives source from the official callsite via `r0`, then preserves it in `r4`.
- Valid byte immediate `0x01c465bc` appears at `0x0201e178` and `0x0201e194`.
- Valid is stored after the `memcpy` and before unlock, i.e. copy completes before publication.
- Unlock path begins at `0x0201e19c`, clears lock to zero, then returns at `0x0201e1aa`.

This confirms nonblocking failure returns without copy/publish, while success copies `0x9c` bytes to owned RAM, publishes valid last, then unlocks.

## Product callsites, final-F7 placement, and reload behavior

H1 modifies only the two accepted product-packet packer callsites and leaves the reload calls intact:

- Direct accepted product callsite `0x0201e468`: official `bfea69fe`, H1 `bfea7bfe`, calls producer.
- Direct reload `0x0201e46c`: remains `bfeaf838`.
- Segmented/final accepted product callsite `0x0201e49c`: official `bfea4ffe`, H1 `bfea61fe`, calls producer.
- Segmented reload `0x0201e4a0`: remains `bfeade38`.

Prior analysis in `channel-separation-reanalysis/sysex-staging/report.md` identifies these callsites as post-acceptance paths: direct complete message verifies `F0 43 00 00 01 1B`, length, and final `F7`, then calls packer and reload; segmented/final path similarly gates on final `F7` and accumulated length. H1 preserves the reload call sequence after the inserted producer call, which is equivalent to the R02 live-success path with respect to the official post-accepted-packet reload behavior.

## SAVE no-write safety

H1 blocks SAVE before the first persistent write and neutralizes the later call into the replaced packer body:

- `0x02026da6`: official `beeaacee`, H1 `04960000`, branching to the local stock exit before the first persistent write.
- `0x02026dac`: official `bfeac7b9`, H1 `00000000`, neutralizing the now-unreachable packer call.

The surrounding bytes show the branch precedes the original persistent-write sequence and the packer call is zeroed.

## Exact uploader gate

`tools/smk37_v15_h1_ota.c` hard-codes:

- Package SHA-256: `139ab42b3746477b8bf49e592ba94efd9f6c18b4a360e0e62807bc12e545dacf`.
- Confirmation token: `INSTALL-SMK37PRO-V15-H1-139AB42B`.
- Identity/version gate: `SMK-37 Pro`, version `15`.
- Upload descriptor includes identity `015`.

Offline `check` matrix from independently compiled scratch binary:

| Package | Result |
| --- | --- |
| H1 `139ab42b...` | accepted, return code 0, `exact v15 H1 package: PASS` |
| official `f7f1831c...` | rejected, return code 1 |
| H0 `114d814b...` | rejected, return code 1 |
| R02 `93bdf1a7...` | rejected, return code 1 |
| R03 `001582c0...` | rejected, return code 1 |

I did not run upload mode.

## Rollback bundle sufficiency

Rollback bundle evidence:

- ZIP SHA-256: `c1db8c1d24c01bef32953d1d52f9975c45298f729ab056894decc5097e14b4d2`.
- Scratch rebuild produced a byte-identical ZIP.
- ZIP contains exactly one `recovery-sectors/manifest.json` entry under the H1 top-level directory.
- Guard `self-test` passed.
- Sector allow-list: `0x04000`, `0x20000`, `0x22000`, `0x2a000`, `0x62000`.
- Confirmations:
  - `I_UNDERSTAND_THIS_ERASES_EXACTLY_FIVE_H1_SECTORS`
  - `I_HAVE_TWO_IDENTICAL_1MIB_DUMPS_AND_H1_TARGET_HASHES`
  - `RESTORE_OFFICIAL_V15_SECTORS_NOW`

Rollback manifest sector records independently matched official and H1 unpacked flash bytes:

| Sector | Changed bytes | Stock SHA-256 | H1 target SHA-256 |
| --- | ---: | --- | --- |
| `0x04000` | 9 | `f0dbdd1756fdb0fbf31def403c74c4f4c69ec30bfc6a405f88d9bd540a9cf8e9` | `30fe4b8a820ce78127cfbef655ea9417f2bad2e0796833db592b64ebe6fe6164` |
| `0x20000` | 6 | `1dc90a318976cead8c55bb071b4096b242c354329eaf0cba74204866c0011f64` | `ded10e50863409002326d4114766db9b2cdaa16165991633dfb1b5afc6ce725d` |
| `0x22000` | 111 | `dd533edf9d53f120d66c54b0e40769b5a8774b4de9e114c1f1865f7d470f1dcc` | `a434b7c4f3cebd635a10f7a093e29c2ed89b111dd78f10dcf88b10f67a14c7a2` |
| `0x2a000` | 8 | `630e50034f661f0a2d1d94e56f25b056ae99c8d1d379d6e7b082bd868d619409` | `a58c41f00acf8dab7c326c49ae7d24c97f900b0efabc7a25905886f702b56fc2` |
| `0x62000` | 1 | `7fbd04123b6ffecd937f5b9896e385c62a12a1ef16a316888dd071fa43649f6d` | `bc70da294bd64036f9e3ea33fa62d026bae7694ef51729c949396303aaf7a6c2` |

Operational sufficiency assessment: for offline artifact sufficiency, PASS. The bundle is exact-sector scoped, requires H1 target-sector hashes and two identical 1 MiB dumps before write, blocks stale R02 identifiers in the generated guard/wrapper, and restores only the five sectors that differ between exact official v15 and exact H1. I did not and should not validate actual device recovery behavior in this review.

## Stale/old artifact scan

Generated H1 rollback wrapper, guard, and manifest did not contain stale `R02`/`r02`, `R03`/`r03`, H0 token/hash, or R03 token/hash strings. The H1 uploader source likewise did not contain those stale install tokens/hashes. The H1 rollback builder source still references R02 only as its explicit template input and replacement source, which is expected and not a generated stale artifact.

## Discriminator interpretation

The documented discriminator interpretations are coherent for this artifact:

- `packet_time_reboot`: producer/owned-RAM write or post-product reload path is sufficient to fault before any Ch10 consumer runs.
- `first_pad_reboot`: R02 staging consumer plus H0 boundary plus producer side effect still faults, which argues against owned-source consumption as the sole R03 fault mechanism.
- `PASS`: producer write/publish and R02 staging consumers coexist, isolating R03 first-pad reboot to owned-source consumption or R03 consumer/fallback behavior.

These are offline interpretations only. They do not claim live functional success.

## Blockers

None found in this offline review.
