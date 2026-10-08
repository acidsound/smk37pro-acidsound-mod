# Independent review: S1-C3 16-slot functional v2 r3-reload

Decision: **PASS**

Scope: offline only; no USB, MIDI, OTA upload, flash, reset, or live send.

## Verified

- Official v15 hashes: FWSC `f7f1831cd7c9ad8b4831b6e71ea0bdbcdff9ae4c4077276b3c965511bf4d4fff`, flash `f77e9ab3cee79113be78f3efacffb03c6cb9b87b78263010e16e81c472df0f9a`, app `36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055`.
- Candidate deterministic hashes: package `0f1c4bf42329a0ca184ac38bb228195b239ed07820fcc0d39be352c2f15982b9`, app `7c672938023beee74d599f43ccd5c7642396b89819e929501274239aed5e5d4b`.
- Parent boundary: `c18ed6f4e8ba2c16b99c41e6264cc36804fb38d8800d03ec518ab6bd838a8d14`, `221` exact byte changes.
- Producer exact hash: `48abedfe48368aed6528900725404a4c8f41c0957f25196cc91b246a9b7a8607`, window `0x0201e1a2..0x0201e250` within `0x0201e254`.
- Stock `memcpy` at `0x02048cce` preserves only `r6/r5/r4` and clobbers volatile `r3`; producer reloads `lb.z r3,[r5+1]` at `0x0201e208` before increment/store.
- Selector unchanged: `ea2c76595a93cf2cf6a39236e09b749781e2721e3575d0c1b40194855cd4e915`; branch/call route targets and reload callsites match expected values.
- Rollback reconstructs official flash exactly from sectors `0x04000, 0x20000, 0x22000, 0x2a000, 0x62000`.
- Exact OTA check accepts the candidate package and rejects official/app inputs. Sender dry-run uses note order slots `0..15` -> notes `36..51`; live send is fail-closed in the offline build.

## Offline validation

- Candidate validator tail: `app_sha256=7c672938023beee74d599f43ccd5c7642396b89819e929501274239aed5e5d4b; package_sha256=0f1c4bf42329a0ca184ac38bb228195b239ed07820fcc0d39be352c2f15982b9; ota_confirmation_token=INSTALL-SMK37PRO-V15-S1C3-16SLOT-FUNCTIONAL-0F1C4BF4; sender_confirmation_token=SEND-SMK37PRO-V15-S1C3-16SLOT-FUNCTIONAL-1C923962-AFA89570-8A87A409-A5C086A7; BLOCK device access, flash/upload, reset, MIDI transport, and live send during validation`
- Dry-run status: `DRY_RUN_PASS`
- Exact OTA compiled: `True`
- Sender: `S1-C3 16-slot sender dry-run PASS: note order slots 0..15 -> notes 36..51, 16 exact packets, no USB/MIDI opened`

Artifacts: `independent_verify.py`, `producer-independent-decode.tsv`, `selector-independent-decode.tsv`, `review.json`, `review.md`, `SHA256SUMS`.
