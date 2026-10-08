# Independent review: S1-C4 Playback Note v3 segmented-final at `1b3fc11`

Verdict: **BLOCK**

Scope: offline review only. I did not access a device, open MIDI transport, perform OTA, flash, reset, or send packets.

## Blocking finding

`baselines/v15/analysis/flash-candidates/S1C4-playback-note-v3-segmented-final/validate.py` fails in a clean worktree at exact commit `1b3fc113939b6fabb5c0a7646f9858a1bcdb671e` because `exact_ota.c` does not compile against that commit's `src/ota.c` API.

Evidence from `review.json`:

- Clean worktree command: `python3 validate.py`
- Return code: `1`
- Failing compile command includes `exact_ota.c ../../../../../src/device_info.c ../../../../../src/fwsc.c ../../../../../src/protocol.c ../../../../../src/sha256.c ../../../../../src/usb_probe.c`
- Compiler error:

```text
exact_ota.c:10:268: error: too many arguments to function call, expected 7, have 8
... return ota_upload_exact(argv[2],argv[3],argv[5],15,PACKAGE_SHA256,DESCRIPTION,CONFIRM,"v15 S1-C4 Playback Note v3 segmented-final candidate installed");
./../../../../../src/ota.c:623:12: note: 'ota_upload_exact' declared here
  623 | static int ota_upload_exact(
  624 |     const char *firmware_path, const char *transcript_path,
  625 |     const char *confirmation,
  626 |     const uint8_t expected_sha256[SMK37_SHA256_LENGTH],
  627 |     const char *package_description, const char *expected_confirmation,
  628 |     const char *completion_message) {
1 error generated.
```

Impact: exact OTA accept/reject cannot be verified from the committed candidate. The committed `validation.txt` is stale or misleading because it reports build validation PASS while `validate.py` fails at the exact commit under review.

Note: a dirty main working tree can mask this because local uncommitted source changes may have a different `ota_upload_exact` signature. This review used a clean scratch worktree checked out at `1b3fc11`.

## Passing evidence before the OTA blocker

These checks passed or matched exactly, but they do not override the BLOCK above.

### Commit and deterministic rebuild

- Requested commit resolves to `1b3fc113939b6fabb5c0a7646f9858a1bcdb671e`.
- HEAD in the clean review worktree was `1b3fc11`.
- `git diff --name-only 1b3fc11 --` for both canonical final directories was empty.
- Full rebuild in the clean worktree completed and `git status --short` for the final candidate and code evidence directories remained empty.

### Official and parent hashes

Actual hashes matched the candidate evidence:

| Artifact | SHA-256 |
| --- | --- |
| official FWSC | `f7f1831cd7c9ad8b4831b6e71ea0bdbcdff9ae4c4077276b3c965511bf4d4fff` |
| official app | `36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055` |
| parent S1-C3 app | `7c672938023beee74d599f43ccd5c7642396b89819e929501274239aed5e5d4b` |
| parent S1-C3 FWSC | `0f1c4bf42329a0ca184ac38bb228195b239ed07820fcc0d39be352c2f15982b9` |

### Candidate hashes

| Artifact | SHA-256 |
| --- | --- |
| app | `c6e4cf567b2f22d7e39d3b4e0f6cae8c7fd140661e31763567b15a9fcf1e3a3d` |
| package | `376d931e9f5fbdfb5737347b6984fad493f35f023134f8309d4792286c1c7aec` |
| combined code | `4293474041bd40b697be88dcdc936eb92a2b6ce6d20fb95dc2e9dcbe9205cae1` |
| selector | `900e8f05c8157737e89a22338b9a4575aa3ff124bd70ff132de0226654fce29f` |
| producer | `a7627984549f62592384189a707ef04512921ad693b18409eb483dcccb53c438` |

### Exact delta from v2 failclosed

App delta from `S1C4-playback-note-v2-failclosed/app.bin` to segmented-final is exactly one byte:

- Offset `124062`, runtime `0x0201e49e..0x0201e49f`: old `c2`, new `c4`.
- This changes the segmented final callsite encoding from v2's no-mutation stub target to v3's reset wrapper target.

Package delta from v2 failclosed is 15 bytes total, all attributable to wrapper/package CRC or hash fields plus the one embedded app byte. See `review.json` for exact package byte ranges.

### Product callsites and preserved reloads

- `0x0201e468`: bytes `bfeadefe`, decoded target `0x0201e228`.
- `0x0201e49c`: bytes `bfeac4fe`, decoded target `0x0201e228`.
- Direct reload at `0x0201e46c` preserved as `bfeaf838`.
- Segmented reload at `0x0201e4a0` preserved as `bfeade38`.

### ABI and pre-gate evidence

The final evidence pins the existing ABI reports and their hashes matched actual files:

- Producer ABI report: `baselines/v15/analysis/patch-set-ui/s1c2-unblock/producer-abi/report.md`
- Producer ABI report SHA-256: `f108346a1dd81747be1627e1f6e297fb20df354727ad9f17e94fa6628b6350bf`
- Copy path report SHA-256: `5296c466c2819995fa215e527b36380ae23fcf39f940ab172488435f6d14e4b2`
- Direct path evidence: `r9 == 0x000000a3`, LR `0x0201e46c`.
- Segmented-final evidence: stage pointer `0x01c37fd0`, `r5 == 0x0000009e`, LR `0x0201e4a0`.

### Selector, staging, reset, and publication ordering

From `candidate-v3-segmented-final/decode.tsv`:

- Selector fail-closed ordering indices: `default_note` 5, `gate_state` 14, `gate_valid` 20, `load_playback_note` 23, `select_source` 24.
- Producer publication ordering indices: `playback_store` 59, `restore_staging_last` 61, `memcpy_call` 65, `restore_slot_last` 67, `valid_store` 70, `count_store` 73, `armed_store` 77.
- Reset ordering indices: `reset_lock_store` 93, `reset_count_store` 94, `reset_state_store` 95, `reset_csync` 96, `reset_call_producer` 98.

This supports the intended reset/publication order and staging/slot `0x9b -> 0x3f` restoration before publication.

### Metadata and velocity bytes

- Note Off hook unchanged: `80fffa1a0000` at `0x0201c63e`.
- Note Off stock metadata store neutralized: `001600160016` at `0x0201c644`.
- Note On hook unchanged: `80ffc01a0000` at `0x0201c67c`.
- Note On stock metadata store neutralized: `001600160016` at `0x0201c682`.
- Note On velocity store preserved: `8d42` at `0x0201c68c`.

### Rollback reconstruction evidence

Rollback manifest states `rollback_restores_official_flash: true`. All five sector files matched manifest hashes:

- `0x04000`: `84c51914e8203e19d5b951a6ddba50aa1523a1f49bc2a6f5e19715049bc6750b`
- `0x20000`: `f98d64e12bcb68b03a2893bf83f4165b6ab55dbd2f8adb3ec9849842b3ea88c1`
- `0x22000`: `e7c4eaa78ccacdc03e0b376ca095a28a8d28594c809621e3824dbda9b0d020f0`
- `0x2a000`: `fffa39e60d1f79efba65fffcb55fd29fe5f8b9fd3fd580e738e1cb9a1c621c5d`
- `0x62000`: `571f97c9f0922b1e107f64f3524c9d620f0e35fcf78e9ae3c50cc49a3104122e`

### Transport and tokens

- Dry run returned `DRY_RUN_PASS`, `device_accessed: false`, `midi_transport_opened: false`, `send_enabled: false`.
- Packet count: `16`.
- Wire Playback Note offset: `161`.
- Supported ingress modes in the packet manifest: `direct_163_byte_sysex` and `segmented_final_sysex_after_final_f7_total_0x9e`.
- Default Original packets have `playback_note == trigger_note` for all slots and only change wire offset `161` versus templates.
- OTA token: `INSTALL-SMK37PRO-V15-S1C4-PLAYBACK-NOTE-V3SEG-376D931E`.
- Sender token: `SEND-SMK37PRO-V15-S1C4-PLAYBACK-NOTE-V3SEG-EBB0A98D-182E4A54-964715E7-A16C453B`.

## Required fix before PASS

Update `exact_ota.c` and its generator so the committed source compiles against the committed `src/ota.c` signature, then rerun `validate.py` in a clean worktree and regenerate `validation.txt`. Only after exact OTA check accepts the candidate package and rejects nonmatching packages under exact commit state should this candidate be re-reviewed for PASS.
